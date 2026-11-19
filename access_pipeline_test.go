// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2/internal/consts"
)

const pipelineTestGrantType = "urn:test:params:grant-type:stored"

type pipelineTestGrant struct {
	scopes  Arguments
	refresh bool
}

// pipelineTestHandler is an authorization code like grant handler: it restores a stored grant named by the 'code'
// form value and issues tokens from it.
type pipelineTestHandler struct {
	grants map[string]pipelineTestGrant

	sawRequest  bool
	sawInternal bool
}

func (h *pipelineTestHandler) CanHandleTokenEndpointRequest(_ context.Context, request AccessRequester) bool {
	return request.GetGrantTypes().ExactOne(pipelineTestGrantType)
}

func (h *pipelineTestHandler) CanSkipClientAuth(_ context.Context, _ AccessRequester) bool {
	return true
}

func (h *pipelineTestHandler) HandleTokenEndpointRequest(ctx context.Context, request AccessRequester) error {
	r, _ := ctx.Value(RequestContextKey).(*http.Request)
	h.sawRequest = r != nil
	h.sawInternal = IsInternalIssuance(ctx)

	grant, ok := h.grants[request.GetRequestForm().Get(consts.FormParameterAuthorizationCode)]
	if !ok {
		return ErrInvalidGrant
	}

	for _, scope := range grant.scopes {
		request.GrantScope(scope)
	}

	return nil
}

func (h *pipelineTestHandler) PopulateTokenEndpointResponse(_ context.Context, request AccessRequester, response AccessResponder) error {
	if !h.CanHandleTokenEndpointRequest(context.TODO(), request) {
		return ErrUnknownRequest
	}

	grant := h.grants[request.GetRequestForm().Get(consts.FormParameterAuthorizationCode)]

	response.SetAccessToken("access-token")
	response.SetTokenType(BearerAccessToken)
	response.SetExpiresIn(time.Hour)
	response.SetScopes(request.GetGrantedScopes())

	if grant.refresh {
		response.SetExtra(consts.AccessResponseRefreshToken, "refresh-token")
	}

	return nil
}

func (h *pipelineTestHandler) GrantTypesSupported(_ context.Context) []string {
	return []string{pipelineTestGrantType}
}

func (h *pipelineTestHandler) CodeChallengeMethodsSupported(_ context.Context) []string { return nil }

func (h *pipelineTestHandler) IDTokenSigningAlgValuesSupported(_ context.Context) []string {
	return nil
}

func (h *pipelineTestHandler) RFC8693TokenTypesSupported(_ context.Context) []string { return nil }

func newPipelineTestProvider(handler *pipelineTestHandler, config *Config) *Fosite {
	config.TokenEndpointHandlers = TokenEndpointHandlers{handler}
	config.DisableRefreshTokenExpirationParameters = true

	return &Fosite{Config: config}
}

func TestIssueInternalAccessResponseMatchesTokenEndpoint(t *testing.T) {
	testCases := []struct {
		name  string
		grant pipelineTestGrant
	}{
		{"ShouldMatchWithRefreshToken", pipelineTestGrant{scopes: Arguments{"openid", "offline_access"}, refresh: true}},
		{"ShouldMatchWithoutRefreshToken", pipelineTestGrant{scopes: Arguments{"profile"}}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			handler := &pipelineTestHandler{grants: map[string]pipelineTestGrant{"stored": tc.grant}}
			provider := newPipelineTestProvider(handler, &Config{})
			ctx := context.Background()

			form := url.Values{
				consts.FormParameterGrantType:         {pipelineTestGrantType},
				consts.FormParameterAuthorizationCode: {"stored"},
			}

			r := httptest.NewRequest(http.MethodPost, "https://op.example.com/token", strings.NewReader(form.Encode()))
			r.Header.Set(consts.HeaderContentType, consts.ContentTypeApplicationURLEncodedForm)

			ar, err := provider.NewAccessRequest(ctx, r, &DefaultSession{})
			require.NoError(t, err)
			assert.True(t, handler.sawRequest)
			assert.False(t, handler.sawInternal)

			viaEndpoint, err := provider.NewAccessResponse(ctx, ar)
			require.NoError(t, err)

			requester := NewAccessRequest(&DefaultSession{})
			requester.GrantTypes = Arguments{pipelineTestGrantType}
			requester.Form = url.Values{consts.FormParameterAuthorizationCode: {"stored"}}
			requester.Client = &DefaultClient{ID: "client"}

			viaInternal, err := provider.issueInternalAccessResponse(ctx, requester)
			require.NoError(t, err)
			assert.False(t, handler.sawRequest)
			assert.True(t, handler.sawInternal)

			assert.Equal(t, viaEndpoint.GetTokenType(), viaInternal.GetTokenType())
			assert.Equal(t, viaEndpoint.ToMap()[consts.AccessResponseScope], viaInternal.ToMap()[consts.AccessResponseScope])
			assert.Equal(t, viaEndpoint.ToMap()[consts.AccessResponseExpiresIn], viaInternal.ToMap()[consts.AccessResponseExpiresIn])
			assert.Equal(t, viaEndpoint.GetExtra(consts.AccessResponseRefreshToken) != nil, viaInternal.GetExtra(consts.AccessResponseRefreshToken) != nil)
			assert.Equal(t, tc.grant.refresh, viaInternal.GetExtra(consts.AccessResponseRefreshToken) != nil)
		})
	}
}

func TestIssueInternalAccessResponseRejectsUnhandledGrant(t *testing.T) {
	provider := newPipelineTestProvider(&pipelineTestHandler{}, &Config{})

	requester := NewAccessRequest(&DefaultSession{})
	requester.GrantTypes = Arguments{"urn:test:params:grant-type:unknown"}
	requester.Client = &DefaultClient{ID: "client"}

	_, err := provider.issueInternalAccessResponse(context.Background(), requester)
	assert.ErrorIs(t, err, ErrUnsupportedGrantType)
}

func TestIsInternalIssuance(t *testing.T) {
	assert.False(t, IsInternalIssuance(context.Background()))
	assert.True(t, IsInternalIssuance(context.WithValue(context.Background(), internalIssuanceKey{}, true)))
}

func TestInternalIssuanceSenderConstraintFromSession(t *testing.T) {
	testCases := []struct {
		name    string
		config  *Config
		session *DefaultSession
		err     error
	}{
		{
			name:    "ShouldPassWithMTLSThumbprint",
			config:  &Config{EnforceSenderConstrainedAccessTokens: true, MTLSEnabled: true},
			session: &DefaultSession{ClientCertificateThumbprint: "x5t"},
		},
		{
			name:    "ShouldPassWithDPoPThumbprint",
			config:  &Config{EnforceSenderConstrainedAccessTokens: true, DPoPEnabled: true},
			session: &DefaultSession{JWKThumbprint: "jkt"},
		},
		{
			name:    "ShouldFailWithoutThumbprint",
			config:  &Config{EnforceSenderConstrainedAccessTokens: true, MTLSEnabled: true, DPoPEnabled: true},
			session: &DefaultSession{},
			err:     ErrInvalidRequest,
		},
		{
			name:    "ShouldFailWithMTLSThumbprintWhenMTLSDisabled",
			config:  &Config{EnforceSenderConstrainedAccessTokens: true},
			session: &DefaultSession{ClientCertificateThumbprint: "x5t"},
			err:     ErrInvalidRequest,
		},
		{
			name:    "ShouldPassWithoutThumbprintWhenNotEnforced",
			config:  &Config{},
			session: &DefaultSession{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			handler := &pipelineTestHandler{grants: map[string]pipelineTestGrant{"stored": {scopes: Arguments{"openid"}}}}
			provider := newPipelineTestProvider(handler, tc.config)

			requester := NewAccessRequest(tc.session)
			requester.GrantTypes = Arguments{pipelineTestGrantType}
			requester.Form = url.Values{consts.FormParameterAuthorizationCode: {"stored"}}
			requester.Client = &DefaultClient{ID: "client"}

			response, err := provider.issueInternalAccessResponse(context.Background(), requester)

			if tc.err != nil {
				assert.ErrorIs(t, err, tc.err)
				assert.Nil(t, response)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, "access-token", response.GetAccessToken())
		})
	}
}

// RFC 10027 Section 6.1.12.
func TestInternalIssuanceCrossDeviceSenderConstraintFromSession(t *testing.T) {
	testCases := []struct {
		name    string
		gt      GrantType
		config  *Config
		client  Client
		session *DefaultSession
		err     error
	}{
		{
			name:    "ShouldFailCIBAWithoutThumbprintWhenEnforced",
			gt:      GrantTypeCIBA,
			config:  &Config{CIBAEnforceSenderConstrainedAccessTokens: true, MTLSEnabled: true, DPoPEnabled: true},
			session: &DefaultSession{},
			err:     ErrInvalidRequest,
		},
		{
			name:    "ShouldPassCIBAWithMTLSThumbprintWhenEnforced",
			gt:      GrantTypeCIBA,
			config:  &Config{CIBAEnforceSenderConstrainedAccessTokens: true, MTLSEnabled: true},
			session: &DefaultSession{ClientCertificateThumbprint: "x5t"},
		},
		{
			name:    "ShouldFailCIBAWithoutThumbprintWhenTheClientEnforces",
			gt:      GrantTypeCIBA,
			config:  &Config{MTLSEnabled: true, DPoPEnabled: true},
			client:  &DefaultRegisteredClient{DefaultClient: &DefaultClient{ID: "client"}, CIBAEnforceSenderConstrainedAccessTokens: true},
			session: &DefaultSession{},
			err:     ErrInvalidRequest,
		},
		{
			name:    "ShouldPassCIBAWithoutThumbprintWhenOnlyTheDeviceGrantIsEnforced",
			gt:      GrantTypeCIBA,
			config:  &Config{RFC8628EnforceSenderConstrainedAccessTokens: true},
			session: &DefaultSession{},
		},
		{
			name:    "ShouldFailTheDeviceGrantWithoutThumbprintWhenEnforced",
			gt:      GrantTypeDeviceCode,
			config:  &Config{RFC8628EnforceSenderConstrainedAccessTokens: true, MTLSEnabled: true, DPoPEnabled: true},
			session: &DefaultSession{},
			err:     ErrInvalidRequest,
		},
		{
			name:    "ShouldPassTheDeviceGrantWithDPoPThumbprintWhenEnforced",
			gt:      GrantTypeDeviceCode,
			config:  &Config{RFC8628EnforceSenderConstrainedAccessTokens: true, DPoPEnabled: true},
			session: &DefaultSession{JWKThumbprint: "jkt"},
		},
		{
			name:    "ShouldFailTheDeviceGrantWithoutThumbprintWhenTheClientEnforces",
			gt:      GrantTypeDeviceCode,
			config:  &Config{DPoPEnabled: true},
			client:  &DefaultRegisteredClient{DefaultClient: &DefaultClient{ID: "client"}, RFC8628EnforceSenderConstrainedAccessTokens: true},
			session: &DefaultSession{},
			err:     ErrInvalidRequest,
		},
		{
			name:    "ShouldPassTheDeviceGrantWithoutThumbprintWhenOnlyCIBAIsEnforced",
			gt:      GrantTypeDeviceCode,
			config:  &Config{CIBAEnforceSenderConstrainedAccessTokens: true},
			session: &DefaultSession{},
		},
		{
			name:    "ShouldPassAnotherGrantWithoutThumbprintWhenBothAreEnforced",
			gt:      pipelineTestGrantType,
			config:  &Config{RFC8628EnforceSenderConstrainedAccessTokens: true, CIBAEnforceSenderConstrainedAccessTokens: true},
			session: &DefaultSession{},
		},
		{
			name:    "ShouldPassWithoutThumbprintByDefault",
			gt:      GrantTypeDeviceCode,
			config:  &Config{},
			session: &DefaultSession{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			handler := &grantTypePipelineTestHandler{
				pipelineTestHandler: &pipelineTestHandler{grants: map[string]pipelineTestGrant{"stored": {scopes: Arguments{"openid"}}}},
				gt:                  string(tc.gt),
			}

			tc.config.TokenEndpointHandlers = TokenEndpointHandlers{handler}
			tc.config.DisableRefreshTokenExpirationParameters = true

			provider := &Fosite{Config: tc.config}

			requester := NewAccessRequest(tc.session)
			requester.GrantTypes = Arguments{string(tc.gt)}
			requester.Form = url.Values{consts.FormParameterAuthorizationCode: {"stored"}}
			requester.Client = &DefaultClient{ID: "client"}

			if tc.client != nil {
				requester.Client = tc.client
			}

			response, err := provider.issueInternalAccessResponse(context.Background(), requester)

			if tc.err != nil {
				assert.ErrorIs(t, err, tc.err)
				assert.Nil(t, response)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, "access-token", response.GetAccessToken())
		})
	}
}

type grantTypePipelineTestHandler struct {
	*pipelineTestHandler

	gt string
}

func (h *grantTypePipelineTestHandler) CanHandleTokenEndpointRequest(_ context.Context, request AccessRequester) bool {
	return request.GetGrantTypes().ExactOne(h.gt)
}

func (h *grantTypePipelineTestHandler) PopulateTokenEndpointResponse(_ context.Context, _ AccessRequester, response AccessResponder) error {
	response.SetAccessToken("access-token")
	response.SetTokenType(BearerAccessToken)
	response.SetExpiresIn(time.Hour)

	return nil
}
