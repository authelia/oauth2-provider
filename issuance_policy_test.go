// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/compose"
	"authelia.com/provider/oauth2/handler/openid"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestIssuancePolicyClientCredentials(t *testing.T) {
	testCases := []struct {
		name     string
		decision *oauth2.IssuanceDecision
		err      error
		implicit bool
		expected error
		scopes   oauth2.Arguments
	}{
		{name: "ShouldIssueOnPermit", decision: &oauth2.IssuanceDecision{}, scopes: oauth2.Arguments{"a", "b"}},
		{name: "ShouldFailOnDeny", decision: &oauth2.IssuanceDecision{Denied: true}, expected: oauth2.ErrAccessDenied},
		{name: "ShouldFailOnNilDecision", expected: oauth2.ErrTemporarilyUnavailable},
		{name: "ShouldFailClosedOnPolicyError", err: errors.New("unreachable"), expected: oauth2.ErrTemporarilyUnavailable},
		{name: "ShouldNarrowScopes", decision: &oauth2.IssuanceDecision{Scopes: oauth2.Arguments{"a"}}, scopes: oauth2.Arguments{"a"}},
		{name: "ShouldNarrowImplicitlyGrantedScopes", implicit: true, decision: &oauth2.IssuanceDecision{Scopes: oauth2.Arguments{"a"}}, scopes: oauth2.Arguments{"a"}},
		{name: "ShouldFailWhenNoScopeSurvives", decision: &oauth2.IssuanceDecision{Scopes: oauth2.Arguments{}}, expected: oauth2.ErrInvalidScope},
		{name: "ShouldDenyBroadeningScopes", decision: &oauth2.IssuanceDecision{Scopes: oauth2.Arguments{"a", "admin"}}, expected: oauth2.ErrAccessDenied},
		{name: "ShouldFailWithRejection", decision: &oauth2.IssuanceDecision{Rejection: oauth2.ErrInvalidScope}, expected: oauth2.ErrInvalidScope},
		{name: "ShouldDenyNonPositiveLifespan", decision: &oauth2.IssuanceDecision{Lifespans: map[oauth2.TokenType]time.Duration{oauth2.AccessToken: 0}}, expected: oauth2.ErrAccessDenied},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			policy := &issuancePolicyStub{decision: tc.decision, err: tc.err}
			provider := newIssuanceProvider(t, policy, tc.implicit)

			ctx := context.Background()

			request, err := provider.NewAccessRequest(ctx, newClientCredentialsRequest(), &openid.DefaultSession{})
			require.NoError(t, err)

			if !tc.implicit {
				request.GrantScope("a")
				request.GrantScope("b")
			}

			response, err := provider.NewAccessResponse(ctx, request)

			require.NotNil(t, policy.request)
			assert.Equal(t, oauth2.Arguments{"a", "b"}, policy.request.Scopes)
			assert.Equal(t, consts.GrantTypeClientCredentials, policy.request.GrantType)
			assert.Equal(t, "issuance", policy.request.ClientID)
			assert.Equal(t, []oauth2.TokenType{oauth2.AccessToken}, policy.request.Tokens)

			if tc.expected != nil {
				assert.ErrorIs(t, err, tc.expected)

				return
			}

			require.NoError(t, err)
			assert.ElementsMatch(t, []string(tc.scopes), strings.Fields(response.GetExtra(consts.AccessResponseScope).(string)))
		})
	}
}

func TestIssuancePolicyLifespanIsACeiling(t *testing.T) {
	testCases := []struct {
		name     string
		lifespan time.Duration
		min, max time.Duration
	}{
		{name: "ShouldShorten", lifespan: time.Minute, min: 50 * time.Second, max: time.Minute + time.Second},
		{name: "ShouldNotExtend", lifespan: 24 * time.Hour, min: 50 * time.Minute, max: time.Hour + time.Second},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			policy := &issuancePolicyStub{decision: &oauth2.IssuanceDecision{Lifespans: map[oauth2.TokenType]time.Duration{oauth2.AccessToken: tc.lifespan}}}
			provider := newIssuanceProvider(t, policy, false)

			ctx := context.Background()

			request, err := provider.NewAccessRequest(ctx, newClientCredentialsRequest(), &openid.DefaultSession{})
			require.NoError(t, err)

			response, err := provider.NewAccessResponse(ctx, request)
			require.NoError(t, err)

			expiresIn := time.Duration(response.GetExtra(consts.AccessResponseExpiresIn).(int64)) * time.Second

			assert.GreaterOrEqual(t, expiresIn, tc.min)
			assert.LessOrEqual(t, expiresIn, tc.max)
		})
	}
}

func TestIssuancePolicyAuthorizationCode(t *testing.T) {
	testCases := []struct {
		name       string
		decision   *oauth2.IssuanceDecision
		expected   error
		scope      []string
		hasRefresh bool
		hasID      bool
	}{
		{name: "ShouldIssueEveryToken", decision: &oauth2.IssuanceDecision{}, scope: []string{"openid", "offline_access", "a"}, hasRefresh: true, hasID: true},
		{name: "ShouldNarrowScopes", decision: &oauth2.IssuanceDecision{Scopes: oauth2.Arguments{"openid", "offline_access"}}, scope: []string{"openid", "offline_access"}, hasRefresh: true, hasID: true},
		{name: "ShouldOmitRefreshToken", decision: &oauth2.IssuanceDecision{DeniedTokens: []oauth2.TokenType{oauth2.RefreshToken}}, scope: []string{"openid", "offline_access", "a"}, hasID: true},
		{name: "ShouldOmitIDToken", decision: &oauth2.IssuanceDecision{DeniedTokens: []oauth2.TokenType{oauth2.IDToken}}, scope: []string{"openid", "offline_access", "a"}, hasRefresh: true},
		{name: "ShouldFailOnDeniedAccessToken", decision: &oauth2.IssuanceDecision{DeniedTokens: []oauth2.TokenType{oauth2.AccessToken}}, expected: oauth2.ErrAccessDenied},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			policy := &issuancePolicyStub{decision: tc.decision}
			provider := newIssuanceProvider(t, policy, false)

			ctx := context.Background()

			request, err := provider.NewAccessRequest(ctx, newCodeTokenRequest(t, provider), openid.NewDefaultSession())
			require.NoError(t, err)

			response, err := provider.NewAccessResponse(ctx, request)

			require.NotNil(t, policy.request)
			assert.Equal(t, oauth2.Arguments{"openid", "offline_access", "a"}, policy.request.Scopes)
			assert.Equal(t, "peter", policy.request.Subject)
			assert.ElementsMatch(t, []oauth2.TokenType{oauth2.AccessToken, oauth2.RefreshToken, oauth2.IDToken}, policy.request.Tokens)

			if tc.expected != nil {
				assert.ErrorIs(t, err, tc.expected)

				return
			}

			require.NoError(t, err)
			assert.ElementsMatch(t, tc.scope, strings.Fields(response.GetExtra(consts.AccessResponseScope).(string)))
			assert.Equal(t, tc.hasRefresh, response.GetExtra(consts.AccessResponseRefreshToken) != nil)
			assert.Equal(t, tc.hasID, response.GetExtra(consts.AccessResponseIDToken) != nil)
		})
	}
}

func TestIssuancePolicyDenialLeavesCodeRedeemable(t *testing.T) {
	policy := &issuancePolicyStub{decision: &oauth2.IssuanceDecision{Denied: true}}
	provider := newIssuanceProvider(t, policy, false)

	ctx := context.Background()
	body := newCodeTokenRequestBody(t, provider)

	request, err := provider.NewAccessRequest(ctx, newTokenRequest(body), openid.NewDefaultSession())
	require.NoError(t, err)

	_, err = provider.NewAccessResponse(ctx, request)
	require.ErrorIs(t, err, oauth2.ErrAccessDenied)

	policy.decision = &oauth2.IssuanceDecision{}

	request, err = provider.NewAccessRequest(ctx, newTokenRequest(body), openid.NewDefaultSession())
	require.NoError(t, err)

	_, err = provider.NewAccessResponse(ctx, request)
	assert.NoError(t, err)
}

func TestIssuancePolicyPasswordGrantOmitsDeniedRefreshToken(t *testing.T) {
	policy := &issuancePolicyStub{decision: &oauth2.IssuanceDecision{DeniedTokens: []oauth2.TokenType{oauth2.RefreshToken}}}
	provider := newIssuanceProvider(t, policy, false)

	ctx := context.Background()

	request, err := provider.NewAccessRequest(ctx, newTokenRequest(url.Values{
		consts.FormParameterGrantType: {consts.GrantTypeResourceOwnerPasswordCredentials},
		"username":                    {"peter"},
		"password":                    {"secret"},
		consts.FormParameterScope:     {"offline_access"},
	}), &openid.DefaultSession{})
	require.NoError(t, err)

	request.GrantScope("offline_access")

	response, err := provider.NewAccessResponse(ctx, request)
	require.NoError(t, err)

	assert.Contains(t, policy.request.Tokens, oauth2.RefreshToken)
	assert.NotEmpty(t, response.GetAccessToken())
	assert.Nil(t, response.GetExtra(consts.AccessResponseRefreshToken))
}

func TestIssuancePolicyCapsIDTokenLifespan(t *testing.T) {
	provider := newIssuanceProvider(t, &issuancePolicyStub{decision: &oauth2.IssuanceDecision{Lifespans: map[oauth2.TokenType]time.Duration{oauth2.IDToken: time.Minute}}}, false)

	ctx := context.Background()

	request, err := provider.NewAccessRequest(ctx, newCodeTokenRequest(t, provider), openid.NewDefaultSession())
	require.NoError(t, err)

	response, err := provider.NewAccessResponse(ctx, request)
	require.NoError(t, err)

	payload, err := base64.RawURLEncoding.DecodeString(strings.Split(response.GetExtra(consts.AccessResponseIDToken).(string), ".")[1])
	require.NoError(t, err)

	var claims struct {
		Expiry int64 `json:"exp"`
	}

	require.NoError(t, json.Unmarshal(payload, &claims))
	assert.InDelta(t, time.Now().Add(time.Minute).Unix(), claims.Expiry, 5)
}

func TestIssuancePolicyDeviceCodeGrant(t *testing.T) {
	policy := &issuancePolicyStub{decision: &oauth2.IssuanceDecision{Scopes: oauth2.Arguments{"offline_access"}, DeniedTokens: []oauth2.TokenType{oauth2.RefreshToken}}}
	provider := newIssuanceProvider(t, policy, false)

	ctx := context.Background()

	device, err := provider.NewRFC862DeviceAuthorizeRequest(ctx, newTokenRequest(url.Values{consts.FormParameterScope: {"offline_access a"}}))
	require.NoError(t, err)

	session := openid.NewDefaultSession()
	session.Subject = "peter"

	codes, err := provider.NewRFC862DeviceAuthorizeResponse(ctx, device, session)
	require.NoError(t, err)

	verify := newTokenRequest(url.Values{consts.FormParameterUserCode: {codes.GetUserCode()}})

	authorize, err := provider.NewRFC8628UserAuthorizeRequest(ctx, verify, session)
	require.NoError(t, err)

	for _, scope := range authorize.GetRequestedScopes() {
		authorize.GrantScope(scope)
	}

	authorize.SetStatus(oauth2.DeviceAuthorizeStatusApproved)

	_, err = provider.NewRFC8628UserAuthorizeResponse(ctx, authorize, session)
	require.NoError(t, err)

	request, err := provider.NewAccessRequest(ctx, newTokenRequest(url.Values{
		consts.FormParameterGrantType:  {consts.GrantTypeOAuthDeviceCode},
		consts.FormParameterDeviceCode: {codes.GetDeviceCode()},
	}), openid.NewDefaultSession())
	require.NoError(t, err)

	response, err := provider.NewAccessResponse(ctx, request)
	require.NoError(t, err)

	assert.Equal(t, oauth2.Arguments{"offline_access", "a"}, policy.request.Scopes)
	assert.Equal(t, consts.GrantTypeOAuthDeviceCode, policy.request.GrantType)
	assert.Equal(t, "offline_access", response.GetExtra(consts.AccessResponseScope))
	assert.Nil(t, response.GetExtra(consts.AccessResponseRefreshToken))
}

func TestIssuancePolicyRefreshGrant(t *testing.T) {
	policy := &issuancePolicyStub{decision: &oauth2.IssuanceDecision{}}
	provider := newIssuanceProvider(t, policy, false)

	ctx := context.Background()

	request, err := provider.NewAccessRequest(ctx, newCodeTokenRequest(t, provider), openid.NewDefaultSession())
	require.NoError(t, err)

	response, err := provider.NewAccessResponse(ctx, request)
	require.NoError(t, err)

	policy.decision = &oauth2.IssuanceDecision{DeniedTokens: []oauth2.TokenType{oauth2.RefreshToken, oauth2.IDToken}}

	request, err = provider.NewAccessRequest(ctx, newTokenRequest(url.Values{
		consts.FormParameterGrantType:    {consts.GrantTypeRefreshToken},
		consts.FormParameterRefreshToken: {response.GetExtra(consts.AccessResponseRefreshToken).(string)},
	}), openid.NewDefaultSession())
	require.NoError(t, err)

	response, err = provider.NewAccessResponse(ctx, request)
	require.NoError(t, err)

	assert.Equal(t, consts.GrantTypeRefreshToken, policy.request.GrantType)
	assert.NotEmpty(t, response.GetAccessToken())
	assert.Nil(t, response.GetExtra(consts.AccessResponseRefreshToken))
	assert.Nil(t, response.GetExtra(consts.AccessResponseIDToken))
}

func TestIssuancePolicyAuthorizationDetailsCannotBroaden(t *testing.T) {
	granted := oauth2.AuthorizationDetails{{Type: "payment", Actions: []string{"read"}}, {Type: "account"}}

	testCases := []struct {
		name     string
		details  oauth2.AuthorizationDetails
		expected error
		result   oauth2.AuthorizationDetails
	}{
		{name: "ShouldKeepSubset", details: oauth2.AuthorizationDetails{{Type: "account"}}, result: oauth2.AuthorizationDetails{{Type: "account"}}},
		{name: "ShouldDenyUnknownEntry", details: oauth2.AuthorizationDetails{{Type: "admin"}}, expected: oauth2.ErrAccessDenied},
		{name: "ShouldDenyAlteredEntry", details: oauth2.AuthorizationDetails{{Type: "payment", Actions: []string{"write"}}}, expected: oauth2.ErrAccessDenied},
		{name: "ShouldFailWhenNoEntrySurvives", details: oauth2.AuthorizationDetails{}, expected: oauth2.ErrInvalidAuthorizationDetails},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			provider := newIssuanceProvider(t, &issuancePolicyStub{decision: &oauth2.IssuanceDecision{AuthorizationDetails: tc.details}}, false)

			ctx := context.Background()

			request, err := provider.NewAccessRequest(ctx, newClientCredentialsRequest(), &openid.DefaultSession{})
			require.NoError(t, err)

			request.SetGrantedAuthorizationDetails(granted)

			_, err = provider.NewAccessResponse(ctx, request)

			if tc.expected != nil {
				assert.ErrorIs(t, err, tc.expected)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.result, request.GetGrantedAuthorizationDetails())
		})
	}
}

func TestIssuancePolicyImplicitGrantCannotRestoreNarrowedScopes(t *testing.T) {
	provider := newIssuanceProvider(t, &issuancePolicyStub{decision: &oauth2.IssuanceDecision{Scopes: oauth2.Arguments{}}}, true)

	ctx := context.Background()

	r := newTokenRequest(url.Values{
		consts.FormParameterGrantType:            {consts.GrantTypeClientCredentials},
		consts.FormParameterScope:                {"a b"},
		consts.FormParameterAuthorizationDetails: {`[{"type":"account"}]`},
	})

	request, err := provider.NewAccessRequest(ctx, r, &openid.DefaultSession{})
	require.NoError(t, err)

	_, err = provider.NewAccessResponse(ctx, request)
	require.NoError(t, err)

	assert.Empty(t, request.GetGrantedScopes())
	assert.Len(t, request.GetGrantedAuthorizationDetails(), 1)
}

func TestIssuancePolicyAbsentLeavesIssuanceUnchanged(t *testing.T) {
	provider := newIssuanceProvider(t, nil, false)

	ctx := context.Background()

	request, err := provider.NewAccessRequest(ctx, newCodeTokenRequest(t, provider), openid.NewDefaultSession())
	require.NoError(t, err)

	response, err := provider.NewAccessResponse(ctx, request)
	require.NoError(t, err)

	assert.NotNil(t, response.GetExtra(consts.AccessResponseRefreshToken))
	assert.NotNil(t, response.GetExtra(consts.AccessResponseIDToken))
}

func TestIssuancePolicyAbsentKeepsGrantsInPopulate(t *testing.T) {
	provider := newIssuanceProvider(t, nil, false)

	ctx := context.Background()

	request, err := provider.NewAccessRequest(ctx, newCodeTokenRequest(t, provider), openid.NewDefaultSession())
	require.NoError(t, err)

	assert.Empty(t, request.GetGrantedScopes())
	assert.Empty(t, request.GetGrantedAudience())

	response, err := provider.NewAccessResponse(ctx, request)
	require.NoError(t, err)

	assert.Equal(t, oauth2.Arguments{"openid", "offline_access", "a"}, request.GetGrantedScopes())
	assert.NotEmpty(t, response.GetAccessToken())
}

func TestIssuancePolicyIsConsultedThroughAWrappedConfigurator(t *testing.T) {
	policy := &issuancePolicyStub{err: errors.New("consulted")}
	provider := newIssuanceProvider(t, policy, false)

	fosite, ok := provider.(*oauth2.Fosite)
	require.True(t, ok)

	fosite.Config = struct{ oauth2.Configurator }{fosite.Config}

	ctx := context.Background()

	request, err := provider.NewAccessRequest(ctx, newCodeTokenRequest(t, provider), openid.NewDefaultSession())
	require.NoError(t, err)

	_, err = provider.NewAccessResponse(ctx, request)
	require.ErrorIs(t, err, oauth2.ErrTemporarilyUnavailable)
}

func TestIssuancePolicyNarrowingScopesWithholdsTheirTokens(t *testing.T) {
	testCases := []struct {
		name    string
		scopes  oauth2.Arguments
		refresh bool
		id      bool
	}{
		{name: "ShouldWithholdBoth", scopes: oauth2.Arguments{"a"}},
		{name: "ShouldWithholdRefreshToken", scopes: oauth2.Arguments{"openid", "a"}, id: true},
		{name: "ShouldWithholdIDToken", scopes: oauth2.Arguments{"offline_access", "a"}, refresh: true},
		{name: "ShouldKeepBoth", scopes: oauth2.Arguments{"openid", "offline_access"}, refresh: true, id: true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			forEachIssuanceStore(t, func(t *testing.T, newProvider func(oauth2.IssuancePolicy) oauth2.Provider) {
				decision := &oauth2.IssuanceDecision{Scopes: tc.scopes}
				provider := newProvider(&issuancePolicyStub{decision: decision})

				ctx := context.Background()

				request, err := provider.NewAccessRequest(ctx, newCodeTokenRequest(t, provider), openid.NewDefaultSession())
				require.NoError(t, err)

				response, err := provider.NewAccessResponse(ctx, request)
				require.NoError(t, err)

				assert.Equal(t, tc.refresh, response.GetExtra(consts.AccessResponseRefreshToken) != nil)
				assert.Equal(t, tc.id, response.GetExtra(consts.AccessResponseIDToken) != nil)
				assert.Empty(t, decision.DeniedTokens)
			})
		})
	}
}

func TestIssuancePolicyNarrowingScopesWithholdsTheRefreshTokenOfADeviceCode(t *testing.T) {
	forEachIssuanceStore(t, func(t *testing.T, newProvider func(oauth2.IssuancePolicy) oauth2.Provider) {
		provider := newProvider(&issuancePolicyStub{decision: &oauth2.IssuanceDecision{Scopes: oauth2.Arguments{"a"}}})

		ctx := context.Background()

		request, err := provider.NewAccessRequest(ctx, newTokenRequest(newDeviceTokenRequestBody(t, provider)), openid.NewDefaultSession())
		require.NoError(t, err)

		response, err := provider.NewAccessResponse(ctx, request)
		require.NoError(t, err)

		assert.Nil(t, response.GetExtra(consts.AccessResponseRefreshToken))
	})
}

func TestIssuancePolicyFailsWhenAPreparerIsHidden(t *testing.T) {
	for name, body := range issuanceCodeBodies() {
		t.Run(name, func(t *testing.T) {
			forEachIssuanceStore(t, func(t *testing.T, newProvider func(oauth2.IssuancePolicy) oauth2.Provider) {
				provider := newProvider(&issuancePolicyStub{decision: &oauth2.IssuanceDecision{}})
				values := body(t, provider)

				hideIssuanceGrantPreparers(t, provider)

				ctx := context.Background()

				request, err := provider.NewAccessRequest(ctx, newTokenRequest(values), openid.NewDefaultSession())
				require.NoError(t, err)

				_, err = provider.NewAccessResponse(ctx, request)
				require.ErrorIs(t, err, oauth2.ErrServerError)
			})
		})
	}

	t.Run("ClientCredentials", func(t *testing.T) {
		provider := newIssuanceProvider(t, &issuancePolicyStub{decision: &oauth2.IssuanceDecision{}}, true)

		hideIssuanceGrantPreparers(t, provider)

		ctx := context.Background()

		request, err := provider.NewAccessRequest(ctx, newClientCredentialsRequest(), &openid.DefaultSession{})
		require.NoError(t, err)

		_, err = provider.NewAccessResponse(ctx, request)
		require.ErrorIs(t, err, oauth2.ErrServerError)
	})
}

func TestIssuancePolicyAbsentKeepsCodeGrantsInPopulate(t *testing.T) {
	for name, body := range issuanceCodeBodies() {
		t.Run(name, func(t *testing.T) {
			forEachIssuanceStore(t, func(t *testing.T, newProvider func(oauth2.IssuancePolicy) oauth2.Provider) {
				provider := newProvider(nil)

				ctx := context.Background()

				request, err := provider.NewAccessRequest(ctx, newTokenRequest(body(t, provider)), openid.NewDefaultSession())
				require.NoError(t, err)

				assert.Empty(t, request.GetGrantedScopes())

				response, err := provider.NewAccessResponse(ctx, request)
				require.NoError(t, err)

				assert.NotEmpty(t, request.GetGrantedScopes())
				assert.NotEmpty(t, response.GetAccessToken())
			})
		})
	}
}

func TestIssuancePolicyPreparationSeesTheReplayOfACode(t *testing.T) {
	for name, body := range issuanceCodeBodies() {
		t.Run(name, func(t *testing.T) {
			forEachIssuanceStore(t, func(t *testing.T, newProvider func(oauth2.IssuancePolicy) oauth2.Provider) {
				policy := &issuancePolicyStub{decision: &oauth2.IssuanceDecision{}}
				provider := newProvider(policy)
				values := body(t, provider)

				ctx := context.Background()

				first, err := provider.NewAccessRequest(ctx, newTokenRequest(values), openid.NewDefaultSession())
				require.NoError(t, err)

				second, err := provider.NewAccessRequest(ctx, newTokenRequest(values), openid.NewDefaultSession())
				require.NoError(t, err)

				response, err := provider.NewAccessResponse(ctx, first)
				require.NoError(t, err)

				policy.request = nil

				_, err = provider.NewAccessResponse(ctx, second)
				require.ErrorIs(t, err, oauth2.ErrInvalidGrant)
				assert.Nil(t, policy.request)

				_, _, err = provider.IntrospectToken(ctx, response.GetAccessToken(), oauth2.AccessToken, openid.NewDefaultSession())
				require.Error(t, err)
			})
		})
	}
}

func TestIssuancePolicyUnavailableWritesRetryAfter(t *testing.T) {
	provider := newIssuanceProvider(t, &issuancePolicyStub{err: errors.New("unreachable")}, false)

	ctx := context.Background()

	request, err := provider.NewAccessRequest(ctx, newClientCredentialsRequest(), &openid.DefaultSession{})
	require.NoError(t, err)

	_, err = provider.NewAccessResponse(ctx, request)
	require.Error(t, err)

	recorder := httptest.NewRecorder()

	provider.WriteAccessError(ctx, recorder, request, err)

	assert.Equal(t, http.StatusServiceUnavailable, recorder.Code)
	assert.NotEmpty(t, recorder.Header().Get(consts.HeaderRetryAfter))
	assert.NotContains(t, recorder.Body.String(), "unreachable")
}

func forEachIssuanceStore(t *testing.T, test func(t *testing.T, newProvider func(policy oauth2.IssuancePolicy) oauth2.Provider)) {
	t.Helper()

	t.Run("MemoryStore", func(t *testing.T) {
		test(t, func(policy oauth2.IssuancePolicy) oauth2.Provider {
			return newIssuanceProviderWithStore(t, policy, false, storage.NewMemoryStore(), nil)
		})
	})

	t.Run("HydratingMemoryStore", func(t *testing.T) {
		test(t, func(policy oauth2.IssuancePolicy) oauth2.Provider {
			store := storage.NewHydratingMemoryStore()

			return newIssuanceProviderWithStore(t, policy, false, store.MemoryStore, store)
		})
	})
}

func newDeviceTokenRequestBody(t *testing.T, provider oauth2.Provider) url.Values {
	t.Helper()

	ctx := context.Background()

	device, err := provider.NewRFC862DeviceAuthorizeRequest(ctx, newTokenRequest(url.Values{consts.FormParameterScope: {"offline_access a"}}))
	require.NoError(t, err)

	session := openid.NewDefaultSession()
	session.Subject = "peter"

	codes, err := provider.NewRFC862DeviceAuthorizeResponse(ctx, device, session)
	require.NoError(t, err)

	authorize, err := provider.NewRFC8628UserAuthorizeRequest(ctx, newTokenRequest(url.Values{consts.FormParameterUserCode: {codes.GetUserCode()}}), session)
	require.NoError(t, err)

	for _, scope := range authorize.GetRequestedScopes() {
		authorize.GrantScope(scope)
	}

	authorize.SetStatus(oauth2.DeviceAuthorizeStatusApproved)

	_, err = provider.NewRFC8628UserAuthorizeResponse(ctx, authorize, session)
	require.NoError(t, err)

	return url.Values{
		consts.FormParameterGrantType:  {consts.GrantTypeOAuthDeviceCode},
		consts.FormParameterDeviceCode: {codes.GetDeviceCode()},
	}
}

func hideIssuanceGrantPreparers(t *testing.T, provider oauth2.Provider) {
	t.Helper()

	fosite, ok := provider.(*oauth2.Fosite)
	require.True(t, ok)

	config, ok := fosite.Config.(*oauth2.Config)
	require.True(t, ok)

	for i, handler := range config.TokenEndpointHandlers {
		config.TokenEndpointHandlers[i] = struct{ oauth2.TokenEndpointHandler }{handler}
	}
}

func issuanceCodeBodies() map[string]func(t *testing.T, provider oauth2.Provider) url.Values {
	return map[string]func(t *testing.T, provider oauth2.Provider) url.Values{
		"AuthorizationCode": newCodeTokenRequestBody,
		"DeviceCode":        newDeviceTokenRequestBody,
	}
}

type issuanceDetailsType string

func (h issuanceDetailsType) Type() string { return string(h) }

func (h issuanceDetailsType) Validate(context.Context, oauth2.Requester, oauth2.AuthorizationDetail) error {
	return nil
}

func (h issuanceDetailsType) Assign(_ context.Context, _ oauth2.AccessRequester, granted, _ oauth2.AuthorizationDetails) (oauth2.AuthorizationDetails, error) {
	return granted, nil
}

type issuancePolicyStub struct {
	decision *oauth2.IssuanceDecision
	err      error
	request  *oauth2.IssuanceRequest
}

func (s *issuancePolicyStub) EvaluateIssuance(_ context.Context, request *oauth2.IssuanceRequest) (*oauth2.IssuanceDecision, error) {
	s.request = request

	return s.decision, s.err
}

func newIssuanceProvider(t *testing.T, policy oauth2.IssuancePolicy, implicit bool) oauth2.Provider {
	t.Helper()

	return newIssuanceProviderWithStore(t, policy, implicit, storage.NewMemoryStore(), nil)
}

func newIssuanceProviderWithStore(t *testing.T, policy oauth2.IssuancePolicy, implicit bool, store *storage.MemoryStore, composed any) oauth2.Provider {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	if composed == nil {
		composed = store
	}

	store.Clients["issuance"] = &oauth2.DefaultClient{
		ID:            "issuance",
		ClientSecret:  oauth2.NewPlainTextClientSecret("secret"),
		RedirectURIs:  []string{"https://client.example/cb"},
		GrantTypes:    []string{consts.GrantTypeAuthorizationCode, consts.GrantTypeRefreshToken, consts.GrantTypeClientCredentials, consts.GrantTypeResourceOwnerPasswordCredentials, consts.GrantTypeOAuthDeviceCode},
		ResponseTypes: []string{consts.ResponseTypeAuthorizationCodeFlow},
		Scopes:        []string{"openid", "offline_access", "a", "b"},
		Audience:      []string{"https://api.example"},
	}

	store.Users["peter"] = storage.MemoryUserRelation{Username: "peter", Password: "secret"}

	config := &oauth2.Config{
		RFC8628UserVerificationURL:                  "https://as.example/device",
		RFC7591ClientRegistrationGlobalSecret:       []byte("another-secret-that-is-32-bytes-long"),
		AuthorizationDetailsTypeHandlers:            []oauth2.AuthorizationDetailsTypeHandler{issuanceDetailsType("payment"), issuanceDetailsType("account")},
		GlobalSecret:                                []byte("some-secret-that-is-32-bytes-long"),
		IssuancePolicy:                              policy,
		AccessTokenLifespan:                         time.Hour,
		ClientCredentialsFlowImplicitGrantRequested: implicit,
	}

	return compose.ComposeAllEnabled(config, composed, key)
}

func newClientCredentialsRequest() *http.Request {
	return newTokenRequest(url.Values{
		consts.FormParameterGrantType: {consts.GrantTypeClientCredentials},
		consts.FormParameterScope:     {"a b"},
	})
}

func newCodeTokenRequest(t *testing.T, provider oauth2.Provider) *http.Request {
	t.Helper()

	return newTokenRequest(newCodeTokenRequestBody(t, provider))
}

func newCodeTokenRequestBody(t *testing.T, provider oauth2.Provider) url.Values {
	t.Helper()

	ctx := context.Background()

	query := url.Values{
		consts.FormParameterClientID:     {"issuance"},
		consts.FormParameterResponseType: {consts.ResponseTypeAuthorizationCodeFlow},
		consts.FormParameterRedirectURI:  {"https://client.example/cb"},
		consts.FormParameterScope:        {"openid offline_access a"},
		consts.FormParameterState:        {"state-that-is-long-enough"},
		consts.FormParameterNonce:        {"nonce-that-is-long-enough"},
	}

	r := httptest.NewRequest(http.MethodGet, "https://as.example/authorize?"+query.Encode(), nil)

	authorize, err := provider.NewAuthorizeRequest(ctx, r)
	require.NoError(t, err)

	for _, scope := range authorize.GetRequestedScopes() {
		authorize.GrantScope(scope)
	}

	session := openid.NewDefaultSession()
	session.Subject = "peter"
	session.Claims = &jwt.IDTokenClaims{Subject: "peter", Issuer: "https://as.example", AuthTime: jwt.Now()}

	response, err := provider.NewAuthorizeResponse(ctx, authorize, session)
	require.NoError(t, err)

	return url.Values{
		consts.FormParameterGrantType:         {consts.GrantTypeAuthorizationCode},
		consts.FormParameterAuthorizationCode: {response.GetCode()},
		consts.FormParameterRedirectURI:       {"https://client.example/cb"},
	}
}

func newTokenRequest(body url.Values) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "https://as.example/token", strings.NewReader(body.Encode()))
	r.Header.Set(consts.HeaderContentType, consts.ContentTypeApplicationURLEncodedForm)
	r.SetBasicAuth("issuance", "secret")

	return r
}
