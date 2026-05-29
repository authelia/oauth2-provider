// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"net/url"
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/testing/mock"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestAuthorizeCode_PopulateTokenEndpointResponse_HMAC(t *testing.T) {
	testCases := []struct {
		name     string
		have     *oauth2.AccessRequest
		setup    func(t *testing.T, r *oauth2.AccessRequest, config *oauth2.Config, strategy CoreStrategy, store CoreStorage)
		expected func(t *testing.T, r *oauth2.AccessResponse)
		err      error
		errStr   string
	}{
		{
			name: "ShouldFailBecauseNotResponsible",
			have: &oauth2.AccessRequest{
				GrantTypes: oauth2.Arguments{"123"},
			},
			err:    oauth2.ErrUnknownRequest,
			errStr: "The handler is not responsible for this request.",
		},
		{
			name: "ShouldFailBecauseCodeNotFound",
			have: &oauth2.AccessRequest{
				GrantTypes: oauth2.Arguments{consts.GrantTypeAuthorizationCode},
				Request: oauth2.Request{
					Form: url.Values{},
					Client: &oauth2.DefaultClient{
						GrantTypes: oauth2.Arguments{consts.GrantTypeAuthorizationCode},
					},
					Session:     &oauth2.DefaultSession{},
					RequestedAt: time.Now().UTC(),
				},
			},
			setup: func(t *testing.T, r *oauth2.AccessRequest, config *oauth2.Config, strategy CoreStrategy, store CoreStorage) {
				code, _, err := strategy.GenerateAuthorizeCode(t.Context(), nil)
				require.NoError(t, err)
				r.Form.Set(consts.FormParameterAuthorizationCode, code)
			},
			err:    oauth2.ErrServerError,
			errStr: "The authorization server encountered an unexpected condition that prevented it from fulfilling the request. Could not find the requested resource(s).",
		},
		{
			name: "ShouldFailBecauseValidationFailed",
			have: &oauth2.AccessRequest{
				GrantTypes: oauth2.Arguments{consts.GrantTypeAuthorizationCode},
				Request: oauth2.Request{
					Form: url.Values{consts.FormParameterAuthorizationCode: []string{"authelia_ac_foo.bar"}},
					Client: &oauth2.DefaultClient{
						GrantTypes: oauth2.Arguments{consts.GrantTypeAuthorizationCode},
					},
					Session:     &oauth2.DefaultSession{},
					RequestedAt: time.Now().UTC(),
				},
			},
			setup: func(t *testing.T, r *oauth2.AccessRequest, config *oauth2.Config, strategy CoreStrategy, store CoreStorage) {
				require.NoError(t, store.CreateAuthorizeCodeSession(t.Context(), "bar", r))
			},
			err:    oauth2.ErrInvalidGrant,
			errStr: "The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client. Token signature mismatch. Check that you provided a valid token in the right format.",
		},
		{
			name: "ShouldPassWithOfflineScopeAndRefreshToken",
			have: &oauth2.AccessRequest{
				GrantTypes: oauth2.Arguments{consts.GrantTypeAuthorizationCode},
				Request: oauth2.Request{
					Form: url.Values{},
					Client: &oauth2.DefaultClient{
						GrantTypes: oauth2.Arguments{consts.GrantTypeAuthorizationCode, consts.GrantTypeRefreshToken},
					},
					GrantedScope: oauth2.Arguments{"foo", consts.ScopeOffline},
					Session:      &oauth2.DefaultSession{},
					RequestedAt:  time.Now().UTC(),
				},
			},
			setup: func(t *testing.T, r *oauth2.AccessRequest, config *oauth2.Config, strategy CoreStrategy, store CoreStorage) {
				code, sig, err := strategy.GenerateAuthorizeCode(t.Context(), nil)
				require.NoError(t, err)
				r.Form.Add(consts.FormParameterAuthorizationCode, code)

				require.NoError(t, store.CreateAuthorizeCodeSession(t.Context(), sig, r))
			},
			expected: func(t *testing.T, aresp *oauth2.AccessResponse) {
				assert.NotEmpty(t, aresp.AccessToken)
				assert.Equal(t, oauth2.BearerAccessToken, aresp.TokenType)
				assert.NotEmpty(t, aresp.GetExtra(consts.AccessResponseRefreshToken))
				assert.NotEmpty(t, aresp.GetExtra(consts.AccessResponseExpiresIn))
				assert.Equal(t, "foo offline", aresp.GetExtra(consts.AccessResponseScope))
			},
		},
		{
			name: "ShouldPassWithRefreshTokenAlwaysProvided",
			have: &oauth2.AccessRequest{
				GrantTypes: oauth2.Arguments{consts.GrantTypeAuthorizationCode},
				Request: oauth2.Request{
					Form: url.Values{},
					Client: &oauth2.DefaultClient{
						GrantTypes: oauth2.Arguments{consts.GrantTypeAuthorizationCode, consts.GrantTypeRefreshToken},
					},
					GrantedScope: oauth2.Arguments{"foo"},
					Session:      &oauth2.DefaultSession{},
					RequestedAt:  time.Now().UTC(),
				},
			},
			setup: func(t *testing.T, r *oauth2.AccessRequest, config *oauth2.Config, strategy CoreStrategy, store CoreStorage) {
				config.RefreshTokenScopes = []string{}
				code, sig, err := strategy.GenerateAuthorizeCode(t.Context(), nil)
				require.NoError(t, err)
				r.Form.Add(consts.FormParameterAuthorizationCode, code)

				require.NoError(t, store.CreateAuthorizeCodeSession(t.Context(), sig, r))
			},
			expected: func(t *testing.T, aresp *oauth2.AccessResponse) {
				assert.NotEmpty(t, aresp.AccessToken)
				assert.Equal(t, oauth2.BearerAccessToken, aresp.TokenType)
				assert.NotEmpty(t, aresp.GetExtra(consts.AccessResponseRefreshToken))
				assert.NotEmpty(t, aresp.GetExtra(consts.AccessResponseExpiresIn))
				assert.Equal(t, "foo", aresp.GetExtra(consts.AccessResponseScope))
			},
		},
		{
			name: "ShouldPassWithNoRefreshToken",
			have: &oauth2.AccessRequest{
				GrantTypes: oauth2.Arguments{consts.GrantTypeAuthorizationCode},
				Request: oauth2.Request{
					Form: url.Values{},
					Client: &oauth2.DefaultClient{
						GrantTypes: oauth2.Arguments{consts.GrantTypeAuthorizationCode},
					},
					GrantedScope: oauth2.Arguments{},
					Session:      &oauth2.DefaultSession{},
					RequestedAt:  time.Now().UTC(),
				},
			},
			setup: func(t *testing.T, r *oauth2.AccessRequest, config *oauth2.Config, strategy CoreStrategy, store CoreStorage) {
				config.RefreshTokenScopes = []string{}
				code, sig, err := strategy.GenerateAuthorizeCode(t.Context(), nil)
				require.NoError(t, err)
				r.Form.Add(consts.FormParameterAuthorizationCode, code)

				require.NoError(t, store.CreateAuthorizeCodeSession(t.Context(), sig, r))
			},
			expected: func(t *testing.T, aresp *oauth2.AccessResponse) {
				assert.NotEmpty(t, aresp.AccessToken)
				assert.Equal(t, oauth2.BearerAccessToken, aresp.TokenType)
				assert.Empty(t, aresp.GetExtra(consts.AccessResponseRefreshToken))
				assert.NotEmpty(t, aresp.GetExtra(consts.AccessResponseExpiresIn))
				assert.Empty(t, aresp.GetExtra(consts.AccessResponseScope))
			},
		},
		{
			name: "ShouldNotHaveRefreshToken",
			have: &oauth2.AccessRequest{
				GrantTypes: oauth2.Arguments{consts.GrantTypeAuthorizationCode},
				Request: oauth2.Request{
					Form: url.Values{},
					Client: &oauth2.DefaultClient{
						GrantTypes: oauth2.Arguments{consts.GrantTypeAuthorizationCode},
					},
					GrantedScope: oauth2.Arguments{"foo"},
					Session:      &oauth2.DefaultSession{},
					RequestedAt:  time.Now().UTC(),
				},
			},
			setup: func(t *testing.T, r *oauth2.AccessRequest, config *oauth2.Config, strategy CoreStrategy, store CoreStorage) {
				code, sig, err := strategy.GenerateAuthorizeCode(t.Context(), nil)
				require.NoError(t, err)
				r.Form.Add(consts.FormParameterAuthorizationCode, code)

				require.NoError(t, store.CreateAuthorizeCodeSession(t.Context(), sig, r))
			},
			expected: func(t *testing.T, aresp *oauth2.AccessResponse) {
				assert.NotEmpty(t, aresp.AccessToken)
				assert.Equal(t, oauth2.BearerAccessToken, aresp.TokenType)
				assert.Empty(t, aresp.GetExtra(consts.AccessResponseRefreshToken))
				assert.NotEmpty(t, aresp.GetExtra(consts.AccessResponseExpiresIn))
				assert.Equal(t, "foo", aresp.GetExtra(consts.AccessResponseScope))
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			store := storage.NewMemoryStore()
			strategy := &hmacshaStrategy
			config := &oauth2.Config{
				ScopeStrategy:       oauth2.HierarchicScopeStrategy,
				AudienceStrategy:    oauth2.DefaultAudienceStrategy,
				AccessTokenLifespan: time.Minute,
				RefreshTokenScopes:  []string{consts.ScopeOffline},
			}

			handler := AuthorizeExplicitGrantHandler{
				CoreStorage:           store,
				AuthorizeCodeStrategy: strategy,
				AccessTokenStrategy:   strategy,
				RefreshTokenStrategy:  strategy,
				Config:                config,
			}

			if tc.setup != nil {
				tc.setup(t, tc.have, config, strategy, store)
			}

			response := oauth2.NewAccessResponse()

			err := handler.PopulateTokenEndpointResponse(t.Context(), tc.have, response)

			if tc.err != nil {
				assert.EqualError(t, err, tc.err.Error())
				assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), tc.errStr)
			} else {
				require.NoError(t, err)
			}

			if tc.expected != nil {
				tc.expected(t, response)
			}
		})
	}
}

func TestAuthorizeExplicitGrantHandler_HandleTokenEndpointRequest(t *testing.T) {
	strategy := &hmacshaStrategy

	testCases := []struct {
		name     string
		r        *oauth2.AccessRequest
		ar       *oauth2.AuthorizeRequest
		setup    func(t *testing.T, s CoreStorage, r *oauth2.AccessRequest, ar *oauth2.AuthorizeRequest)
		check    func(t *testing.T, s CoreStorage, r *oauth2.AccessRequest, ar *oauth2.AuthorizeRequest)
		expected string
	}{
		{
			"ShouldPassOAuth20",
			&oauth2.AccessRequest{
				GrantTypes: oauth2.Arguments{consts.GrantTypeAuthorizationCode},
				Request: oauth2.Request{
					Client:      &oauth2.DefaultClient{ID: "foo", GrantTypes: []string{consts.GrantTypeAuthorizationCode}},
					Form:        url.Values{consts.FormParameterRedirectURI: []string{"request-redir"}},
					Session:     &oauth2.DefaultSession{},
					RequestedAt: time.Now().UTC(),
				},
			},
			&oauth2.AuthorizeRequest{
				Request: oauth2.Request{
					Client:         &oauth2.DefaultClient{ID: "foo", GrantTypes: []string{"authorization_code"}},
					Form:           url.Values{consts.FormParameterRedirectURI: []string{"request-redir"}},
					Session:        &oauth2.DefaultSession{},
					RequestedScope: oauth2.Arguments{"a", "b"},
					RequestedAt:    time.Now().UTC(),
				},
			},
			nil,
			nil,
			"",
		},
		{
			"ShouldPassOpenIDConnect",
			&oauth2.AccessRequest{
				GrantTypes: oauth2.Arguments{consts.GrantTypeAuthorizationCode},
				Request: oauth2.Request{
					Client:      &oauth2.DefaultClient{ID: "foo", GrantTypes: []string{consts.GrantTypeAuthorizationCode}},
					Form:        url.Values{consts.FormParameterRedirectURI: []string{"request-redir"}},
					Session:     &oauth2.DefaultSession{},
					RequestedAt: time.Now().UTC(),
				},
			},
			&oauth2.AuthorizeRequest{
				Request: oauth2.Request{
					Client:         &oauth2.DefaultClient{ID: "foo", GrantTypes: []string{"authorization_code"}},
					Form:           url.Values{consts.FormParameterRedirectURI: []string{"request-redir"}},
					Session:        &oauth2.DefaultSession{},
					RequestedScope: oauth2.Arguments{consts.ScopeOpenID, "a", "b"},
					RequestedAt:    time.Now().UTC(),
				},
			},
			nil,
			nil,
			"",
		},
		{
			"ShouldPass",
			&oauth2.AccessRequest{
				GrantTypes: oauth2.Arguments{consts.GrantTypeAuthorizationCode},
				Request: oauth2.Request{
					Client:      &oauth2.DefaultClient{ID: "foo", GrantTypes: []string{consts.GrantTypeAuthorizationCode}},
					Form:        url.Values{consts.FormParameterRedirectURI: []string{"request-redir"}},
					Session:     &oauth2.DefaultSession{},
					RequestedAt: time.Now().UTC(),
				},
			},
			&oauth2.AuthorizeRequest{
				Request: oauth2.Request{
					Client:         &oauth2.DefaultClient{ID: "foo", GrantTypes: []string{"authorization_code"}},
					Session:        &oauth2.DefaultSession{},
					RequestedScope: oauth2.Arguments{"openid"},
					RequestedAt:    time.Now().UTC(),
				},
			},
			func(t *testing.T, s CoreStorage, areq *oauth2.AccessRequest, authreq *oauth2.AuthorizeRequest) {
				token, signature, err := strategy.GenerateAuthorizeCode(t.Context(), nil)
				require.NoError(t, err)

				areq.Form = url.Values{consts.FormParameterAuthorizationCode: {token}}
				require.NoError(t, s.CreateAuthorizeCodeSession(t.Context(), signature, authreq))
			},
			nil,
			"The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client. The 'redirect_uri' parameter is required when using OpenID Connect 1.0.",
		},
		{
			"ShouldFailNotResponsible",
			&oauth2.AccessRequest{
				GrantTypes: oauth2.Arguments{"12345678"},
			},
			nil,
			nil,
			nil,
			"The handler is not responsible for this request.",
		},
		{
			"ShouldFailNotGranted",
			&oauth2.AccessRequest{
				GrantTypes: oauth2.Arguments{consts.GrantTypeAuthorizationCode},
				Request: oauth2.Request{
					Client:      &oauth2.DefaultClient{ID: "foo", GrantTypes: []string{""}},
					Session:     &oauth2.DefaultSession{},
					RequestedAt: time.Now().UTC(),
				},
			},
			nil,
			nil,
			nil,
			"The client is not authorized to request a token using this method. The OAuth 2.0 Client is not allowed to use authorization grant 'authorization_code'.",
		},
		{
			"ShouldFailAuthCodeRetrieval",
			&oauth2.AccessRequest{
				GrantTypes: oauth2.Arguments{consts.GrantTypeAuthorizationCode},
				Request: oauth2.Request{
					Client:      &oauth2.DefaultClient{GrantTypes: []string{"authorization_code"}},
					Session:     &oauth2.DefaultSession{},
					RequestedAt: time.Now().UTC(),
				},
			},
			nil,
			func(t *testing.T, s CoreStorage, r *oauth2.AccessRequest, ar *oauth2.AuthorizeRequest) {
				token, _, err := strategy.GenerateAuthorizeCode(t.Context(), nil)
				require.NoError(t, err)
				r.Form = url.Values{consts.FormParameterAuthorizationCode: {token}}
			},
			nil,
			"The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client. The authorization code session for the given authorization code was not found.",
		},
		{
			"ShouldFailInvalidCode",
			&oauth2.AccessRequest{
				GrantTypes: oauth2.Arguments{consts.GrantTypeAuthorizationCode},
				Request: oauth2.Request{
					Form:        url.Values{consts.FormParameterAuthorizationCode: {"foo.bar"}},
					Client:      &oauth2.DefaultClient{GrantTypes: []string{consts.GrantTypeAuthorizationCode}},
					Session:     &oauth2.DefaultSession{},
					RequestedAt: time.Now().UTC(),
				},
			},
			nil,
			nil,
			nil,
			"The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client. The authorization code session for the given authorization code was not found.",
		},
		{
			"ShouldFailClientIDMismatch",
			&oauth2.AccessRequest{
				GrantTypes: oauth2.Arguments{consts.GrantTypeAuthorizationCode},
				Request: oauth2.Request{
					Client:      &oauth2.DefaultClient{ID: "foo", GrantTypes: []string{consts.GrantTypeAuthorizationCode}},
					Session:     &oauth2.DefaultSession{},
					RequestedAt: time.Now().UTC(),
				},
			},
			&oauth2.AuthorizeRequest{
				Request: oauth2.Request{
					Client:         &oauth2.DefaultClient{ID: "bar"},
					RequestedScope: oauth2.Arguments{"a", "b"},
				},
			},
			func(t *testing.T, s CoreStorage, r *oauth2.AccessRequest, ar *oauth2.AuthorizeRequest) {
				token, signature, err := strategy.GenerateAuthorizeCode(t.Context(), nil)
				require.NoError(t, err)
				r.Form = url.Values{consts.FormParameterAuthorizationCode: {token}}

				require.NoError(t, s.CreateAuthorizeCodeSession(t.Context(), signature, ar))
			},
			nil,
			"The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client. The OAuth 2.0 Client ID from this request does not match the one from the authorize request.",
		},
		{
			"ShouldFailRedirectURIPresentInAuthorizeRequestButMissingFromAccessRequest",
			&oauth2.AccessRequest{
				GrantTypes: oauth2.Arguments{consts.GrantTypeAuthorizationCode},
				Request: oauth2.Request{
					Client:      &oauth2.DefaultClient{ID: "foo", GrantTypes: []string{consts.GrantTypeAuthorizationCode}},
					Session:     &oauth2.DefaultSession{},
					RequestedAt: time.Now().UTC(),
				},
			},
			&oauth2.AuthorizeRequest{
				Request: oauth2.Request{
					Client:  &oauth2.DefaultClient{ID: "foo", GrantTypes: []string{consts.GrantTypeAuthorizationCode}},
					Form:    url.Values{consts.FormParameterRedirectURI: []string{"request-redir"}},
					Session: &oauth2.DefaultSession{},
				},
			},
			func(t *testing.T, s CoreStorage, r *oauth2.AccessRequest, ar *oauth2.AuthorizeRequest) {
				token, signature, err := strategy.GenerateAuthorizeCode(t.Context(), nil)
				require.NoError(t, err)
				r.Form = url.Values{consts.FormParameterAuthorizationCode: {token}}

				require.NoError(t, s.CreateAuthorizeCodeSession(t.Context(), signature, ar))
			},
			nil,
			"The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client. The 'redirect_uri' from this request does not match the one from the authorize request. The 'redirect_uri' parameter value '' utilized in the Access Request does not match the original 'redirect_uri' parameter value 'request-redir' requested in the Authorize Request which is not permitted.",
		},
		{
			"ShouldFailCodeAlreadyUsed",
			&oauth2.AccessRequest{
				GrantTypes: oauth2.Arguments{"authorization_code"},
				Request: oauth2.Request{
					Form: url.Values{},
					Client: &oauth2.DefaultClient{
						GrantTypes: oauth2.Arguments{"authorization_code"},
					},
					GrantedScope: oauth2.Arguments{"foo", consts.ScopeOffline},
					Session:      &oauth2.DefaultSession{},
					RequestedAt:  time.Now().UTC(),
				},
			},
			nil,
			func(t *testing.T, s CoreStorage, r *oauth2.AccessRequest, ar *oauth2.AuthorizeRequest) {
				code, sig, err := strategy.GenerateAuthorizeCode(t.Context(), nil)
				require.NoError(t, err)
				r.Form.Add("code", code)

				require.NoError(t, s.CreateAuthorizeCodeSession(t.Context(), sig, r))
				require.NoError(t, s.InvalidateAuthorizeCodeSession(t.Context(), sig))
			},
			func(t *testing.T, s CoreStorage, r *oauth2.AccessRequest, ar *oauth2.AuthorizeRequest) {
				assert.Equal(t, time.Now().Add(time.Minute).UTC().Truncate(jwt.TimePrecision), r.GetSession().GetExpiresAt(oauth2.AccessToken))
				assert.Equal(t, time.Now().Add(time.Minute).UTC().Truncate(jwt.TimePrecision), r.GetSession().GetExpiresAt(oauth2.RefreshToken))
			},
			"The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client. The authorization code has already been used.",
		},
		{
			// RFC 8707 Section 2.2: resources requested at the token endpoint MUST be a subset
			// of those granted at the authorization endpoint. Requesting a resource that was
			// not granted at the authorize endpoint must result in an error.
			"ShouldFailWhenAccessRequestResourcesExceedAuthorizationRequest",
			&oauth2.AccessRequest{
				GrantTypes: oauth2.Arguments{consts.GrantTypeAuthorizationCode},
				Request: oauth2.Request{
					Client: &oauth2.DefaultClient{ID: "foo", GrantTypes: []string{consts.GrantTypeAuthorizationCode}},
					Form: url.Values{
						consts.FormParameterRedirectURI: []string{"request-redir"},
						consts.FormParameterResource:    []string{"https://api.example.com/users", "https://api.example.com/tenants"},
					},
					Session:           &oauth2.DefaultSession{},
					RequestedAudience: oauth2.Arguments{"https://api.example.com/users", "https://api.example.com/tenants"},
					RequestedAt:       time.Now().UTC(),
				},
			},
			&oauth2.AuthorizeRequest{
				Request: oauth2.Request{
					Client: &oauth2.DefaultClient{ID: "foo", GrantTypes: []string{consts.GrantTypeAuthorizationCode}},
					Form: url.Values{
						consts.FormParameterRedirectURI: []string{"request-redir"},
						consts.FormParameterResource:    []string{"https://api.example.com/users"},
					},
					Session:           &oauth2.DefaultSession{},
					RequestedScope:    oauth2.Arguments{"a"},
					RequestedAudience: oauth2.Arguments{"https://api.example.com/users"},
					GrantedAudience:   oauth2.Arguments{"https://api.example.com/users"},
					RequestedAt:       time.Now().UTC(),
				},
			},
			nil,
			nil,
			"The requested resource is invalid, missing, unknown, or malformed. Ensure the requested resource is an absolute URI without a fragment component that identifies a resource server known to the authorization server and that it is permitted for this client. Requested audience 'https://api.example.com/tenants' has not been whitelisted by the OAuth 2.0 Client.",
		},
		{
			// When the access request resources are a proper subset of those granted at the
			// authorize endpoint, the access request's requested audience is preserved.
			"ShouldKeepAccessRequestResourcesWhenSubsetOfAuthorizationRequestGranted",
			&oauth2.AccessRequest{
				GrantTypes: oauth2.Arguments{consts.GrantTypeAuthorizationCode},
				Request: oauth2.Request{
					Client: &oauth2.DefaultClient{ID: "foo", GrantTypes: []string{consts.GrantTypeAuthorizationCode}},
					Form: url.Values{
						consts.FormParameterRedirectURI: []string{"request-redir"},
						consts.FormParameterResource:    []string{"https://api.example.com/users"},
					},
					Session:           &oauth2.DefaultSession{},
					RequestedAudience: oauth2.Arguments{"https://api.example.com/users"},
					RequestedAt:       time.Now().UTC(),
				},
			},
			&oauth2.AuthorizeRequest{
				Request: oauth2.Request{
					Client: &oauth2.DefaultClient{ID: "foo", GrantTypes: []string{consts.GrantTypeAuthorizationCode}},
					Form: url.Values{
						consts.FormParameterRedirectURI: []string{"request-redir"},
						consts.FormParameterResource:    []string{"https://api.example.com/users", "https://api.example.com/tenants"},
					},
					Session:           &oauth2.DefaultSession{},
					RequestedScope:    oauth2.Arguments{"a"},
					RequestedAudience: oauth2.Arguments{"https://api.example.com/users", "https://api.example.com/tenants"},
					GrantedAudience:   oauth2.Arguments{"https://api.example.com/users", "https://api.example.com/tenants"},
					RequestedAt:       time.Now().UTC(),
				},
			},
			nil,
			func(t *testing.T, s CoreStorage, r *oauth2.AccessRequest, ar *oauth2.AuthorizeRequest) {
				assert.Equal(t, oauth2.Arguments{"https://api.example.com/users"}, r.GetRequestedAudience())
				assert.NotContains(t, r.GetRequestedAudience(), "https://api.example.com/tenants")
			},
			"",
		},
		{
			// When the access request does not include any resource indicators, the authorize
			// request's requested audience is used as a fallback (the previous override
			// behavior).
			"ShouldFallBackToAuthorizationRequestAudienceWhenAccessRequestHasNone",
			&oauth2.AccessRequest{
				GrantTypes: oauth2.Arguments{consts.GrantTypeAuthorizationCode},
				Request: oauth2.Request{
					Client:      &oauth2.DefaultClient{ID: "foo", GrantTypes: []string{consts.GrantTypeAuthorizationCode}},
					Form:        url.Values{consts.FormParameterRedirectURI: []string{"request-redir"}},
					Session:     &oauth2.DefaultSession{},
					RequestedAt: time.Now().UTC(),
				},
			},
			&oauth2.AuthorizeRequest{
				Request: oauth2.Request{
					Client: &oauth2.DefaultClient{ID: "foo", GrantTypes: []string{consts.GrantTypeAuthorizationCode}},
					Form: url.Values{
						consts.FormParameterRedirectURI: []string{"request-redir"},
						consts.FormParameterResource:    []string{"https://api.example.com/users"},
					},
					Session:           &oauth2.DefaultSession{},
					RequestedScope:    oauth2.Arguments{"a"},
					RequestedAudience: oauth2.Arguments{"https://api.example.com/users"},
					GrantedAudience:   oauth2.Arguments{"https://api.example.com/users"},
					RequestedAt:       time.Now().UTC(),
				},
			},
			nil,
			func(t *testing.T, s CoreStorage, r *oauth2.AccessRequest, ar *oauth2.AuthorizeRequest) {
				assert.Equal(t, oauth2.Arguments{"https://api.example.com/users"}, r.GetRequestedAudience())
			},
			"",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			s := storage.NewMemoryStore()

			handle := AuthorizeExplicitGrantHandler{
				CoreStorage:            s,
				AuthorizeCodeStrategy:  strategy,
				TokenRevocationStorage: s,
				Config: &oauth2.Config{
					ScopeStrategy:         oauth2.HierarchicScopeStrategy,
					AudienceStrategy:      oauth2.DefaultAudienceStrategy,
					AuthorizeCodeLifespan: time.Minute,
				},
			}

			if tc.ar != nil {
				code, sig, err := strategy.GenerateAuthorizeCode(t.Context(), nil)
				require.NoError(t, err)

				if tc.r != nil {
					if tc.r.Form == nil {
						tc.r.Form = url.Values{}
					}

					tc.r.Form.Add("code", code)
				}

				require.NoError(t, s.CreateAuthorizeCodeSession(t.Context(), sig, tc.ar))
			}

			if tc.setup != nil {
				tc.setup(t, s, tc.r, tc.ar)
			}

			err := handle.HandleTokenEndpointRequest(context.Background(), tc.r)
			if tc.expected != "" {
				require.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), tc.expected)
			} else {
				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
				if tc.check != nil {
					tc.check(t, s, tc.r, tc.ar)
				}
			}
		})
	}
}

// TestAuthorizeCodeFlow_ResourceIndicatorSubset verifies the RFC 8707 Section 2.2 constraint
// for the Authorization Code Grant: when the 'resource' parameter is present in both the
// Authorization Request and Access (token) Request, the resources requested at the token
// endpoint MUST be a subset of those granted at the authorize endpoint. Requesting a resource
// at the token endpoint that was not granted at the authorize endpoint returns an error;
// requesting a proper subset narrows the access token's audience accordingly.
func TestAuthorizeCodeFlow_ResourceIndicatorSubset(t *testing.T) {
	const (
		resourceUsers   = "https://api.example.com/users"
		resourceTenants = "https://api.example.com/tenants"
	)

	newHandlerAndAuthCode := func(t *testing.T, grantedAudience oauth2.Arguments) (AuthorizeExplicitGrantHandler, string) {
		t.Helper()

		store := storage.NewMemoryStore()
		strategy := &hmacshaStrategy
		config := &oauth2.Config{
			ScopeStrategy:         oauth2.HierarchicScopeStrategy,
			AudienceStrategy:      oauth2.DefaultAudienceStrategy,
			AccessTokenLifespan:   time.Minute,
			AuthorizeCodeLifespan: time.Minute,
		}

		handler := AuthorizeExplicitGrantHandler{
			CoreStorage:           store,
			AuthorizeCodeStrategy: strategy,
			AccessTokenStrategy:   strategy,
			RefreshTokenStrategy:  strategy,
			Config:                config,
		}

		code, sig, err := strategy.GenerateAuthorizeCode(t.Context(), nil)
		require.NoError(t, err)

		require.NoError(t, store.CreateAuthorizeCodeSession(t.Context(), sig, &oauth2.AuthorizeRequest{
			Request: oauth2.Request{
				Client: &oauth2.DefaultClient{
					ID:         "foo",
					GrantTypes: oauth2.Arguments{consts.GrantTypeAuthorizationCode},
					Audience:   []string{resourceUsers, resourceTenants},
				},
				Form: url.Values{
					consts.FormParameterRedirectURI: []string{"https://client.example.com/cb"},
					consts.FormParameterResource:    grantedAudience,
				},
				RequestedScope:    oauth2.Arguments{"foo"},
				GrantedScope:      oauth2.Arguments{"foo"},
				RequestedAudience: grantedAudience,
				GrantedAudience:   grantedAudience,
				Session:           &oauth2.DefaultSession{},
				RequestedAt:       time.Now().UTC(),
			},
		}))

		return handler, code
	}

	newAccessRequest := func(code string, resources []string) *oauth2.AccessRequest {
		return &oauth2.AccessRequest{
			GrantTypes: oauth2.Arguments{consts.GrantTypeAuthorizationCode},
			Request: oauth2.Request{
				Client: &oauth2.DefaultClient{
					ID:         "foo",
					GrantTypes: oauth2.Arguments{consts.GrantTypeAuthorizationCode},
					Audience:   []string{resourceUsers, resourceTenants},
				},
				Form: url.Values{
					consts.FormParameterAuthorizationCode: []string{code},
					consts.FormParameterRedirectURI:       []string{"https://client.example.com/cb"},
					consts.FormParameterResource:          resources,
				},
				RequestedAudience: oauth2.Arguments(resources),
				Session:           &oauth2.DefaultSession{},
				RequestedAt:       time.Now().UTC(),
			},
		}
	}

	t.Run("ShouldFailWhenAccessRequestResourceExceedsAuthorizeGranted", func(t *testing.T) {
		handler, code := newHandlerAndAuthCode(t, oauth2.Arguments{resourceUsers})
		accessRequest := newAccessRequest(code, []string{resourceUsers, resourceTenants})

		err := handler.HandleTokenEndpointRequest(t.Context(), accessRequest)
		require.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err),
			"The requested resource is invalid, missing, unknown, or malformed. Ensure the requested resource is an absolute URI without a fragment component that identifies a resource server known to the authorization server and that it is permitted for this client. Requested audience 'https://api.example.com/tenants' has not been whitelisted by the OAuth 2.0 Client.")
	})

	t.Run("ShouldPreserveAccessRequestResourceWhenSubsetOfAuthorizeGranted", func(t *testing.T) {
		handler, code := newHandlerAndAuthCode(t, oauth2.Arguments{resourceUsers, resourceTenants})
		accessRequest := newAccessRequest(code, []string{resourceUsers})

		require.NoError(t, handler.HandleTokenEndpointRequest(t.Context(), accessRequest))
		assert.Equal(t, oauth2.Arguments{resourceUsers}, accessRequest.GetRequestedAudience(),
			"requested audience at token endpoint must be preserved when it is a subset of the authorize request's granted audience")
		assert.NotContains(t, accessRequest.GetRequestedAudience(), resourceTenants)

		response := oauth2.NewAccessResponse()
		require.NoError(t, handler.PopulateTokenEndpointResponse(t.Context(), accessRequest, response))
		assert.Equal(t, oauth2.Arguments{resourceUsers}, accessRequest.GetGrantedAudience(),
			"granted audience on the access token must be narrowed to the resources requested at the token endpoint")
		assert.NotContains(t, accessRequest.GetGrantedAudience(), resourceTenants,
			"narrowed resources must not include audiences the client did not request at the token endpoint")
	})

	t.Run("ShouldFallBackToAuthorizeGrantedAudienceWhenAccessRequestHasNone", func(t *testing.T) {
		handler, code := newHandlerAndAuthCode(t, oauth2.Arguments{resourceUsers, resourceTenants})
		accessRequest := newAccessRequest(code, nil)
		// Simulate the access request not including the resource parameter.
		accessRequest.Form.Del(consts.FormParameterResource)
		accessRequest.RequestedAudience = nil

		require.NoError(t, handler.HandleTokenEndpointRequest(t.Context(), accessRequest))
		assert.Equal(t, oauth2.Arguments{resourceUsers, resourceTenants}, accessRequest.GetRequestedAudience(),
			"requested audience must fall back to the authorize request's granted audience when omitted at the token endpoint")

		response := oauth2.NewAccessResponse()
		require.NoError(t, handler.PopulateTokenEndpointResponse(t.Context(), accessRequest, response))
		assert.Equal(t, oauth2.Arguments{resourceUsers, resourceTenants}, accessRequest.GetGrantedAudience(),
			"granted audience must equal the authorize request's granted audience when the token endpoint omits the resource parameter")
	})
}

// TestAuthorizeCodeFlow_ResourceParameterSubset exercises the per-request 'resource' (RFC 8707) handling at the
// token endpoint, separate from the 'audience' check covered by TestAuthorizeCodeFlow_ResourceIndicatorSubset.
//
// Per RFC 8707 §2.2 and the new check in flow_authorize_code_token.go HandleTokenEndpointRequest:
//
//   - When the token request omits 'resource', it inherits the resources granted at the authorize endpoint.
//   - When the token request includes 'resource', the supplied values MUST be a subset of those granted at the
//     authorize endpoint; a superset is rejected with invalid_target.
func TestAuthorizeCodeFlow_ResourceParameterSubset(t *testing.T) {
	const (
		resourceUsers   = "https://api.example.com/users"
		resourceTenants = "https://api.example.com/tenants"
	)

	newHandlerAndAuthCode := func(t *testing.T, grantedResource oauth2.Arguments) (AuthorizeExplicitGrantHandler, string) {
		t.Helper()

		store := storage.NewMemoryStore()
		strategy := &hmacshaStrategy
		config := &oauth2.Config{
			ScopeStrategy:         oauth2.HierarchicScopeStrategy,
			AudienceStrategy:      oauth2.DefaultAudienceStrategy,
			ResourceStrategy:      oauth2.DefaultResourceStrategy,
			AccessTokenLifespan:   time.Minute,
			AuthorizeCodeLifespan: time.Minute,
		}

		handler := AuthorizeExplicitGrantHandler{
			CoreStorage:           store,
			AuthorizeCodeStrategy: strategy,
			AccessTokenStrategy:   strategy,
			RefreshTokenStrategy:  strategy,
			Config:                config,
		}

		code, sig, err := strategy.GenerateAuthorizeCode(t.Context(), nil)
		require.NoError(t, err)

		require.NoError(t, store.CreateAuthorizeCodeSession(t.Context(), sig, &oauth2.AuthorizeRequest{
			Request: oauth2.Request{
				Client: &oauth2.DefaultClient{
					ID:         "foo",
					GrantTypes: oauth2.Arguments{consts.GrantTypeAuthorizationCode},
					Audience:   []string{resourceUsers, resourceTenants},
				},
				Form: url.Values{
					consts.FormParameterRedirectURI: []string{"https://client.example.com/cb"},
					consts.FormParameterResource:    grantedResource,
				},
				RequestedScope:    oauth2.Arguments{"foo"},
				GrantedScope:      oauth2.Arguments{"foo"},
				RequestedResource: grantedResource,
				GrantedResource:   grantedResource,
				Session:           &oauth2.DefaultSession{},
				RequestedAt:       time.Now().UTC(),
			},
		}))

		return handler, code
	}

	newAccessRequest := func(code string, resources []string) *oauth2.AccessRequest {
		req := &oauth2.AccessRequest{
			GrantTypes: oauth2.Arguments{consts.GrantTypeAuthorizationCode},
			Request: oauth2.Request{
				Client: &oauth2.DefaultClient{
					ID:         "foo",
					GrantTypes: oauth2.Arguments{consts.GrantTypeAuthorizationCode},
					Audience:   []string{resourceUsers, resourceTenants},
				},
				Form: url.Values{
					consts.FormParameterAuthorizationCode: []string{code},
					consts.FormParameterRedirectURI:       []string{"https://client.example.com/cb"},
				},
				Session:     &oauth2.DefaultSession{},
				RequestedAt: time.Now().UTC(),
			},
		}

		if resources != nil {
			req.Form[consts.FormParameterResource] = resources
			req.RequestedResource = oauth2.Arguments(resources)
		}

		return req
	}

	t.Run("ShouldFailWhenAccessRequestResourceExceedsAuthorizeGranted", func(t *testing.T) {
		handler, code := newHandlerAndAuthCode(t, oauth2.Arguments{resourceUsers})
		accessRequest := newAccessRequest(code, []string{resourceUsers, resourceTenants})

		err := handler.HandleTokenEndpointRequest(t.Context(), accessRequest)
		require.Error(t, err)
		require.ErrorIs(t, err, oauth2.ErrInvalidTarget,
			"RFC 8707 §2.2: token-endpoint resource MUST be a subset of authorize-endpoint granted resources")
	})

	t.Run("ShouldPreserveAccessRequestResourceWhenSubsetOfAuthorizeGranted", func(t *testing.T) {
		handler, code := newHandlerAndAuthCode(t, oauth2.Arguments{resourceUsers, resourceTenants})
		accessRequest := newAccessRequest(code, []string{resourceUsers})

		require.NoError(t, handler.HandleTokenEndpointRequest(t.Context(), accessRequest))
		assert.Equal(t, oauth2.Arguments{resourceUsers}, accessRequest.GetRequestedResource(),
			"requested resource at token endpoint must be preserved when it is a subset of the authorize request's granted resources")
		assert.NotContains(t, accessRequest.GetRequestedResource(), resourceTenants)

		response := oauth2.NewAccessResponse()
		require.NoError(t, handler.PopulateTokenEndpointResponse(t.Context(), accessRequest, response))
		assert.Equal(t, oauth2.Arguments{resourceUsers}, accessRequest.GetGrantedResource(),
			"granted resource on the access token must be narrowed to the resources requested at the token endpoint")
		assert.NotContains(t, accessRequest.GetGrantedResource(), resourceTenants,
			"narrowed resources must not include those the client did not request at the token endpoint")
	})

	t.Run("ShouldFallBackToAuthorizeGrantedResourceWhenAccessRequestHasNone", func(t *testing.T) {
		handler, code := newHandlerAndAuthCode(t, oauth2.Arguments{resourceUsers, resourceTenants})
		accessRequest := newAccessRequest(code, nil)

		require.NoError(t, handler.HandleTokenEndpointRequest(t.Context(), accessRequest))
		assert.Equal(t, oauth2.Arguments{resourceUsers, resourceTenants}, accessRequest.GetRequestedResource(),
			"RFC 8707 §2.2: when 'resource' is omitted at the token endpoint, fall back to the authorize request's granted resources")

		response := oauth2.NewAccessResponse()
		require.NoError(t, handler.PopulateTokenEndpointResponse(t.Context(), accessRequest, response))
		assert.Equal(t, oauth2.Arguments{resourceUsers, resourceTenants}, accessRequest.GetGrantedResource(),
			"granted resource must equal the authorize request's granted resource when the token endpoint omits the resource parameter")
	})

	t.Run("ShouldAcceptExactMatch", func(t *testing.T) {
		handler, code := newHandlerAndAuthCode(t, oauth2.Arguments{resourceUsers, resourceTenants})
		accessRequest := newAccessRequest(code, []string{resourceUsers, resourceTenants})

		require.NoError(t, handler.HandleTokenEndpointRequest(t.Context(), accessRequest),
			"a token-endpoint resource that exactly matches the authorize-granted set must be accepted")

		response := oauth2.NewAccessResponse()
		require.NoError(t, handler.PopulateTokenEndpointResponse(t.Context(), accessRequest, response))
		assert.Equal(t, oauth2.Arguments{resourceUsers, resourceTenants}, accessRequest.GetGrantedResource())
	})
}

func TestAuthorizeCodeTransactional_HandleTokenEndpointRequest(t *testing.T) {
	strategy := hmacshaStrategy
	request := &oauth2.AccessRequest{
		GrantTypes: oauth2.Arguments{"authorization_code"},
		Request: oauth2.Request{
			Client: &oauth2.DefaultClient{
				GrantTypes: oauth2.Arguments{"authorization_code", "refresh_token"},
			},
			GrantedScope: oauth2.Arguments{consts.ScopeOffline},
			Session:      &oauth2.DefaultSession{},
			RequestedAt:  time.Now().UTC(),
		},
	}
	token, _, err := strategy.GenerateAuthorizeCode(t.Context(), nil)
	require.NoError(t, err)
	request.Form = url.Values{consts.FormParameterAuthorizationCode: {token}}
	propagatedContext := context.Background()

	// some storage implementation that has support for transactions, notice the embedded type `storage.Transactional`
	type transactionalStore struct {
		storage.Transactional
		CoreStorage
	}

	testCases := []struct {
		name  string
		setup func(mockTransactional *mock.MockTransactional, mockCoreStore *mock.MockCoreStorage)
		err   string
	}{
		{
			name: "ShouldCommitTransactionWhenNoErrors",
			setup: func(mockTransactional *mock.MockTransactional, mockCoreStore *mock.MockCoreStorage) {
				mockCoreStore.
					EXPECT().
					GetAuthorizeCodeSession(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(request, nil).
					Times(1)
				mockTransactional.
					EXPECT().
					BeginTX(propagatedContext).
					Return(propagatedContext, nil)
				mockCoreStore.
					EXPECT().
					InvalidateAuthorizeCodeSession(gomock.Any(), gomock.Any()).
					Return(nil).
					Times(1)
				mockCoreStore.
					EXPECT().
					CreateAccessTokenSession(propagatedContext, gomock.Any(), gomock.Any()).
					Return(nil).
					Times(1)
				mockCoreStore.
					EXPECT().
					CreateRefreshTokenSession(propagatedContext, gomock.Any(), gomock.Any()).
					Return(nil).
					Times(1)
				mockTransactional.
					EXPECT().
					Commit(propagatedContext).
					Return(nil).
					Times(1)
			},
		},
		{
			name: "ShouldRollbackTransactionWhenInvalidateAuthorizeCodeSessionReturnsError",
			setup: func(mockTransactional *mock.MockTransactional, mockCoreStore *mock.MockCoreStorage) {
				mockCoreStore.
					EXPECT().
					GetAuthorizeCodeSession(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(request, nil).
					Times(1)
				mockTransactional.
					EXPECT().
					BeginTX(propagatedContext).
					Return(propagatedContext, nil)
				mockCoreStore.
					EXPECT().
					InvalidateAuthorizeCodeSession(gomock.Any(), gomock.Any()).
					Return(errors.New("Whoops, a nasty database error occurred!")).
					Times(1)
				mockTransactional.
					EXPECT().
					Rollback(propagatedContext).
					Return(nil).
					Times(1)
			},
			err: "The authorization server encountered an unexpected condition that prevented it from fulfilling the request. Whoops, a nasty database error occurred!",
		},
		{
			name: "ShouldRollbackTransactionWhenCreateAccessTokenSessionReturnsError",
			setup: func(mockTransactional *mock.MockTransactional, mockCoreStore *mock.MockCoreStorage) {
				mockCoreStore.
					EXPECT().
					GetAuthorizeCodeSession(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(request, nil).
					Times(1)
				mockTransactional.
					EXPECT().
					BeginTX(propagatedContext).
					Return(propagatedContext, nil)
				mockCoreStore.
					EXPECT().
					InvalidateAuthorizeCodeSession(gomock.Any(), gomock.Any()).
					Return(nil).
					Times(1)
				mockCoreStore.
					EXPECT().
					CreateAccessTokenSession(propagatedContext, gomock.Any(), gomock.Any()).
					Return(errors.New("Whoops, a nasty database error occurred!")).
					Times(1)
				mockTransactional.
					EXPECT().
					Rollback(propagatedContext).
					Return(nil).
					Times(1)
			},
			err: "The authorization server encountered an unexpected condition that prevented it from fulfilling the request. Whoops, a nasty database error occurred!",
		},
		{
			name: "ShouldFailWhenTransactionCannotBeCreated",
			setup: func(mockTransactional *mock.MockTransactional, mockCoreStore *mock.MockCoreStorage) {
				mockCoreStore.
					EXPECT().
					GetAuthorizeCodeSession(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(request, nil).
					Times(1)
				mockTransactional.
					EXPECT().
					BeginTX(propagatedContext).
					Return(nil, errors.New("Whoops, unable to create transaction!"))
			},
			err: "The authorization server encountered an unexpected condition that prevented it from fulfilling the request. Whoops, unable to create transaction!",
		},
		{
			name: "ShouldFailWhenTransactionCannotBeRolledBack",
			setup: func(mockTransactional *mock.MockTransactional, mockCoreStore *mock.MockCoreStorage) {
				mockCoreStore.
					EXPECT().
					GetAuthorizeCodeSession(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(request, nil).
					Times(1)
				mockTransactional.
					EXPECT().
					BeginTX(propagatedContext).
					Return(propagatedContext, nil)
				mockCoreStore.
					EXPECT().
					InvalidateAuthorizeCodeSession(gomock.Any(), gomock.Any()).
					Return(errors.New("Whoops, a nasty database error occurred!")).
					Times(1)
				mockTransactional.
					EXPECT().
					Rollback(propagatedContext).
					Return(errors.New("Whoops, unable to rollback transaction!")).
					Times(1)
			},
			err: "The authorization server encountered an unexpected condition that prevented it from fulfilling the request. error: server_error; rollback error: Whoops, unable to rollback transaction!",
		},
		{
			name: "ShouldFailWhenTransactionCannotBeCommitted",
			setup: func(mockTransactional *mock.MockTransactional, mockCoreStore *mock.MockCoreStorage) {
				mockCoreStore.
					EXPECT().
					GetAuthorizeCodeSession(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(request, nil).
					Times(1)
				mockTransactional.
					EXPECT().
					BeginTX(propagatedContext).
					Return(propagatedContext, nil)
				mockCoreStore.
					EXPECT().
					InvalidateAuthorizeCodeSession(gomock.Any(), gomock.Any()).
					Return(nil).
					Times(1)
				mockCoreStore.
					EXPECT().
					CreateAccessTokenSession(propagatedContext, gomock.Any(), gomock.Any()).
					Return(nil).
					Times(1)
				mockCoreStore.
					EXPECT().
					CreateRefreshTokenSession(propagatedContext, gomock.Any(), gomock.Any()).
					Return(nil).
					Times(1)
				mockTransactional.
					EXPECT().
					Commit(propagatedContext).
					Return(errors.New("Whoops, unable to commit transaction!")).
					Times(1)
				mockTransactional.
					EXPECT().
					Rollback(propagatedContext).
					Return(nil).
					Times(1)
			},
			err: "The authorization server encountered an unexpected condition that prevented it from fulfilling the request. Whoops, unable to commit transaction!",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockTransactional := mock.NewMockTransactional(ctrl)
			mockCoreStore := mock.NewMockCoreStorage(ctrl)
			tc.setup(mockTransactional, mockCoreStore)

			handler := AuthorizeExplicitGrantHandler{
				CoreStorage: transactionalStore{
					mockTransactional,
					mockCoreStore,
				},
				AccessTokenStrategy:   &strategy,
				RefreshTokenStrategy:  &strategy,
				AuthorizeCodeStrategy: &strategy,
				Config: &oauth2.Config{
					ScopeStrategy:         oauth2.HierarchicScopeStrategy,
					AudienceStrategy:      oauth2.DefaultAudienceStrategy,
					AuthorizeCodeLifespan: time.Minute,
				},
			}

			response := oauth2.NewAccessResponse()
			err := handler.PopulateTokenEndpointResponse(propagatedContext, request, response)
			if tc.err != "" {
				assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), tc.err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
