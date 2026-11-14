// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	. "authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/handler/rfc8705"
	"authelia.com/provider/oauth2/handler/rfc9449"
)

const internalBindingTestGrantType = "urn:test:params:grant-type:internal"

// internalBindingTestHandler accepts its grant type and issues a bearer access token, failing if it observes an HTTP
// request.
type internalBindingTestHandler struct{}

func (h *internalBindingTestHandler) CanHandleTokenEndpointRequest(_ context.Context, request AccessRequester) bool {
	return request.GetGrantTypes().ExactOne(internalBindingTestGrantType)
}

func (h *internalBindingTestHandler) CanSkipClientAuth(_ context.Context, _ AccessRequester) bool {
	return false
}

func (h *internalBindingTestHandler) HandleTokenEndpointRequest(ctx context.Context, _ AccessRequester) error {
	if r, _ := ctx.Value(RequestContextKey).(*http.Request); r != nil {
		return ErrServerError.WithDebug("An HTTP request was visible to an internally issued request.")
	}

	return nil
}

func (h *internalBindingTestHandler) PopulateTokenEndpointResponse(_ context.Context, request AccessRequester, response AccessResponder) error {
	if !request.GetGrantTypes().ExactOne(internalBindingTestGrantType) {
		return ErrUnknownRequest
	}

	response.SetAccessToken("access-token")
	response.SetTokenType(BearerAccessToken)
	response.SetExpiresIn(time.Hour)

	return nil
}

func (h *internalBindingTestHandler) GrantTypesSupported(_ context.Context) []string {
	return []string{internalBindingTestGrantType}
}

func (h *internalBindingTestHandler) CodeChallengeMethodsSupported(_ context.Context) []string {
	return nil
}

func (h *internalBindingTestHandler) IDTokenSigningAlgValuesSupported(_ context.Context) []string {
	return nil
}

func (h *internalBindingTestHandler) RFC8693TokenTypesSupported(_ context.Context) []string {
	return nil
}

func TestInternalIssuanceBindingHandlers(t *testing.T) {
	testCases := []struct {
		name      string
		config    *Config
		session   *DefaultSession
		tokenType string
		err       error
	}{
		{
			name:      "ShouldBindDPoPFromSession",
			config:    &Config{DPoPEnabled: true},
			session:   &DefaultSession{JWKThumbprint: "jkt", RequestedJWKThumbprint: "jkt"},
			tokenType: DPoPAccessToken,
		},
		{
			name:      "ShouldIssueBearerWithoutDPoPBinding",
			config:    &Config{DPoPEnabled: true},
			session:   &DefaultSession{},
			tokenType: BearerAccessToken,
		},
		{
			name:    "ShouldRejectEnforcedDPoPWithoutRecordedKey",
			config:  &Config{DPoPEnforce: true},
			session: &DefaultSession{},
			err:     ErrInvalidDPoPProof,
		},
		{
			name:    "ShouldRejectRequestedDPoPKeyNotBound",
			config:  &Config{DPoPEnabled: true},
			session: &DefaultSession{RequestedJWKThumbprint: "jkt"},
			err:     ErrInvalidDPoPProof,
		},
		{
			name:      "ShouldBindMTLSFromSession",
			config:    &Config{MTLSEnabled: true},
			session:   &DefaultSession{ClientCertificateThumbprint: "x5t"},
			tokenType: BearerAccessToken,
		},
		{
			name:      "ShouldBindMTLSFromSessionWhenSenderConstrained",
			config:    &Config{MTLSEnabled: true, EnforceSenderConstrainedAccessTokens: true},
			session:   &DefaultSession{ClientCertificateThumbprint: "x5t"},
			tokenType: BearerAccessToken,
		},
		{
			name:    "ShouldRejectEnforcedMTLSWithoutRecordedCertificate",
			config:  &Config{MTLSEnforce: true},
			session: &DefaultSession{},
			err:     ErrInvalidRequest,
		},
		{
			name:    "ShouldRejectSenderConstrainedWithoutRecordedBinding",
			config:  &Config{MTLSEnabled: true, DPoPEnabled: true, EnforceSenderConstrainedAccessTokens: true},
			session: &DefaultSession{},
			err:     ErrInvalidRequest,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tc.config.TokenEndpointHandlers = TokenEndpointHandlers{&internalBindingTestHandler{}}
			tc.config.TokenEndpointBindingHandlers = TokenEndpointBindingHandlers{
				&rfc9449.Handler{Config: tc.config},
				&rfc8705.Handler{Config: tc.config},
			}
			tc.config.DisableRefreshTokenExpirationParameters = true

			provider := &Fosite{Config: tc.config}

			requester := NewAccessRequest(tc.session)
			requester.GrantTypes = Arguments{internalBindingTestGrantType}
			requester.Client = &DefaultClient{ID: "client"}

			// The context of the call that triggers issuance must not leak its HTTP request into the pipeline.
			ctx := context.WithValue(context.Background(), RequestContextKey, &http.Request{Header: http.Header{}})

			response, err := provider.IssueInternalAccessResponseForTest(ctx, requester)

			if tc.err != nil {
				assert.ErrorIs(t, err, tc.err)
				assert.Nil(t, response)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.tokenType, response.GetTokenType())
		})
	}
}
