// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"fmt"
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
			err:    oauth2.ErrInvalidRequest,
			errStr: "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Make sure that the various parameters are correct, be aware of case sensitivity and trim your parameters. Make sure that the client you are using has exactly whitelisted the redirect_uri you specified. Token signature mismatch. Check that you provided a valid token in the right format.",
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
				ScopeStrategy:            oauth2.HierarchicScopeStrategy,
				AudienceMatchingStrategy: oauth2.DefaultAudienceMatchingStrategy,
				AccessTokenLifespan:      time.Minute,
				RefreshTokenScopes:       []string{consts.ScopeOffline},
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
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			s := storage.NewMemoryStore()

			handle := AuthorizeExplicitGrantHandler{
				CoreStorage:            s,
				AuthorizeCodeStrategy:  strategy,
				TokenRevocationStorage: s,
				Config: &oauth2.Config{
					ScopeStrategy:            oauth2.HierarchicScopeStrategy,
					AudienceMatchingStrategy: oauth2.DefaultAudienceMatchingStrategy,
					AuthorizeCodeLifespan:    time.Minute,
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

func TestAuthorizeCodeTransactional_HandleTokenEndpointRequest(t *testing.T) {
	var (
		mockTransactional *mock.MockTransactional
		mockCoreStore     *mock.MockCoreStorage
	)

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
	response := oauth2.NewAccessResponse()
	propagatedContext := context.Background()

	// some storage implementation that has support for transactions, notice the embedded type `storage.Transactional`
	type transactionalStore struct {
		storage.Transactional
		CoreStorage
	}

	for _, testCase := range []struct {
		description string
		setup       func()
		expectError error
	}{
		{
			description: "transaction should be committed successfully if no errors occur",
			setup: func() {
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
			description: "transaction should be rolled back if `InvalidateAuthorizeCodeSession` returns an error",
			setup: func() {
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
			expectError: oauth2.ErrServerError,
		},
		{
			description: "transaction should be rolled back if `CreateAccessTokenSession` returns an error",
			setup: func() {
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
			expectError: oauth2.ErrServerError,
		},
		{
			description: "should result in a server error if transaction cannot be created",
			setup: func() {
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
			expectError: oauth2.ErrServerError,
		},
		{
			description: "should result in a server error if transaction cannot be rolled back",
			setup: func() {
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
			expectError: oauth2.ErrServerError,
		},
		{
			description: "should result in a server error if transaction cannot be committed",
			setup: func() {
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
			expectError: oauth2.ErrServerError,
		},
	} {
		t.Run(fmt.Sprintf("scenario=%s", testCase.description), func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockTransactional = mock.NewMockTransactional(ctrl)
			mockCoreStore = mock.NewMockCoreStorage(ctrl)
			testCase.setup()

			handler := AuthorizeExplicitGrantHandler{
				CoreStorage: transactionalStore{
					mockTransactional,
					mockCoreStore,
				},
				AccessTokenStrategy:   &strategy,
				RefreshTokenStrategy:  &strategy,
				AuthorizeCodeStrategy: &strategy,
				Config: &oauth2.Config{
					ScopeStrategy:            oauth2.HierarchicScopeStrategy,
					AudienceMatchingStrategy: oauth2.DefaultAudienceMatchingStrategy,
					AuthorizeCodeLifespan:    time.Minute,
				},
			}

			if err := handler.PopulateTokenEndpointResponse(propagatedContext, request, response); testCase.expectError != nil {
				assert.EqualError(t, err, testCase.expectError.Error())
			}
		})
	}
}
