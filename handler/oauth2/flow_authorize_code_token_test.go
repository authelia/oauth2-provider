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

func TestAuthorizeCode_PopulateTokenEndpointResponse(t *testing.T) {
	for k, strategy := range map[string]CoreStrategy{
		"hmac": &hmacshaStrategy,
	} {
		t.Run("strategy="+k, func(t *testing.T) {
			store := storage.NewMemoryStore()

			var h AuthorizeExplicitGrantHandler
			for _, c := range []struct {
				areq        *oauth2.AccessRequest
				description string
				setup       func(t *testing.T, areq *oauth2.AccessRequest, config *oauth2.Config)
				check       func(t *testing.T, aresp *oauth2.AccessResponse)
				expectErr   error
			}{
				{
					areq: &oauth2.AccessRequest{
						GrantTypes: oauth2.Arguments{"123"},
					},
					description: "should fail because not responsible",
					expectErr:   oauth2.ErrUnknownRequest,
				},
				{
					areq: &oauth2.AccessRequest{
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
					description: "should fail because authcode not found",
					setup: func(t *testing.T, areq *oauth2.AccessRequest, config *oauth2.Config) {
						code, _, err := strategy.GenerateAuthorizeCode(context.TODO(), nil)
						require.NoError(t, err)
						areq.Form.Set("code", code)
					},
					expectErr: oauth2.ErrServerError,
				},
				{
					areq: &oauth2.AccessRequest{
						GrantTypes: oauth2.Arguments{consts.GrantTypeAuthorizationCode},
						Request: oauth2.Request{
							Form: url.Values{consts.FormParameterAuthorizationCode: []string{"foo.bar"}},
							Client: &oauth2.DefaultClient{
								GrantTypes: oauth2.Arguments{consts.GrantTypeAuthorizationCode},
							},
							Session:     &oauth2.DefaultSession{},
							RequestedAt: time.Now().UTC(),
						},
					},
					description: "should fail because validation failed",
					setup: func(t *testing.T, areq *oauth2.AccessRequest, config *oauth2.Config) {
						require.NoError(t, store.CreateAuthorizeCodeSession(context.TODO(), "bar", areq))
					},
					expectErr: oauth2.ErrInvalidRequest,
				},
				{
					areq: &oauth2.AccessRequest{
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
					setup: func(t *testing.T, areq *oauth2.AccessRequest, config *oauth2.Config) {
						code, sig, err := strategy.GenerateAuthorizeCode(context.TODO(), nil)
						require.NoError(t, err)
						areq.Form.Add(consts.FormParameterAuthorizationCode, code)

						require.NoError(t, store.CreateAuthorizeCodeSession(context.TODO(), sig, areq))
					},
					description: "should pass with offline scope and refresh token",
					check: func(t *testing.T, aresp *oauth2.AccessResponse) {
						assert.NotEmpty(t, aresp.AccessToken)
						assert.Equal(t, oauth2.BearerAccessToken, aresp.TokenType)
						assert.NotEmpty(t, aresp.GetExtra(consts.AccessResponseRefreshToken))
						assert.NotEmpty(t, aresp.GetExtra(consts.AccessResponseExpiresIn))
						assert.Equal(t, "foo offline", aresp.GetExtra(consts.AccessResponseScope))
					},
				},
				{
					areq: &oauth2.AccessRequest{
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
					setup: func(t *testing.T, areq *oauth2.AccessRequest, config *oauth2.Config) {
						config.RefreshTokenScopes = []string{}
						code, sig, err := strategy.GenerateAuthorizeCode(context.TODO(), nil)
						require.NoError(t, err)
						areq.Form.Add(consts.FormParameterAuthorizationCode, code)

						require.NoError(t, store.CreateAuthorizeCodeSession(context.TODO(), sig, areq))
					},
					description: "should pass with refresh token always provided",
					check: func(t *testing.T, aresp *oauth2.AccessResponse) {
						assert.NotEmpty(t, aresp.AccessToken)
						assert.Equal(t, oauth2.BearerAccessToken, aresp.TokenType)
						assert.NotEmpty(t, aresp.GetExtra(consts.AccessResponseRefreshToken))
						assert.NotEmpty(t, aresp.GetExtra(consts.AccessResponseExpiresIn))
						assert.Equal(t, "foo", aresp.GetExtra(consts.AccessResponseScope))
					},
				},
				{
					areq: &oauth2.AccessRequest{
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
					setup: func(t *testing.T, areq *oauth2.AccessRequest, config *oauth2.Config) {
						config.RefreshTokenScopes = []string{}
						code, sig, err := strategy.GenerateAuthorizeCode(context.TODO(), nil)
						require.NoError(t, err)
						areq.Form.Add(consts.FormParameterAuthorizationCode, code)

						require.NoError(t, store.CreateAuthorizeCodeSession(context.TODO(), sig, areq))
					},
					description: "should pass with no refresh token",
					check: func(t *testing.T, aresp *oauth2.AccessResponse) {
						assert.NotEmpty(t, aresp.AccessToken)
						assert.Equal(t, oauth2.BearerAccessToken, aresp.TokenType)
						assert.Empty(t, aresp.GetExtra(consts.AccessResponseRefreshToken))
						assert.NotEmpty(t, aresp.GetExtra(consts.AccessResponseExpiresIn))
						assert.Empty(t, aresp.GetExtra(consts.AccessResponseScope))
					},
				},
				{
					areq: &oauth2.AccessRequest{
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
					setup: func(t *testing.T, areq *oauth2.AccessRequest, config *oauth2.Config) {
						code, sig, err := strategy.GenerateAuthorizeCode(context.TODO(), nil)
						require.NoError(t, err)
						areq.Form.Add(consts.FormParameterAuthorizationCode, code)

						require.NoError(t, store.CreateAuthorizeCodeSession(context.TODO(), sig, areq))
					},
					description: "should not have refresh token",
					check: func(t *testing.T, aresp *oauth2.AccessResponse) {
						assert.NotEmpty(t, aresp.AccessToken)
						assert.Equal(t, oauth2.BearerAccessToken, aresp.TokenType)
						assert.Empty(t, aresp.GetExtra(consts.AccessResponseRefreshToken))
						assert.NotEmpty(t, aresp.GetExtra(consts.AccessResponseExpiresIn))
						assert.Equal(t, "foo", aresp.GetExtra(consts.AccessResponseScope))
					},
				},
			} {
				t.Run("case="+c.description, func(t *testing.T) {
					config := &oauth2.Config{
						ScopeStrategy:            oauth2.HierarchicScopeStrategy,
						AudienceMatchingStrategy: oauth2.DefaultAudienceMatchingStrategy,
						AccessTokenLifespan:      time.Minute,
						RefreshTokenScopes:       []string{consts.ScopeOffline},
					}
					h = AuthorizeExplicitGrantHandler{
						CoreStorage:           store,
						AuthorizeCodeStrategy: strategy,
						AccessTokenStrategy:   strategy,
						RefreshTokenStrategy:  strategy,
						Config:                config,
					}

					if c.setup != nil {
						c.setup(t, c.areq, config)
					}

					aresp := oauth2.NewAccessResponse()
					err := h.PopulateTokenEndpointResponse(context.TODO(), c.areq, aresp)

					if c.expectErr != nil {
						require.EqualError(t, err, c.expectErr.Error(), "%+v", err)
					} else {
						require.NoError(t, err, "%+v", err)
					}

					if c.check != nil {
						c.check(t, aresp)
					}
				})
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
				token, signature, err := strategy.GenerateAuthorizeCode(context.TODO(), nil)
				require.NoError(t, err)

				areq.Form = url.Values{consts.FormParameterAuthorizationCode: {token}}
				require.NoError(t, s.CreateAuthorizeCodeSession(context.TODO(), signature, authreq))
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
				token, _, err := strategy.GenerateAuthorizeCode(context.TODO(), nil)
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
				token, signature, err := strategy.GenerateAuthorizeCode(context.TODO(), nil)
				require.NoError(t, err)
				r.Form = url.Values{consts.FormParameterAuthorizationCode: {token}}

				require.NoError(t, s.CreateAuthorizeCodeSession(context.TODO(), signature, ar))
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
				token, signature, err := strategy.GenerateAuthorizeCode(context.TODO(), nil)
				require.NoError(t, err)
				r.Form = url.Values{consts.FormParameterAuthorizationCode: {token}}

				require.NoError(t, s.CreateAuthorizeCodeSession(context.TODO(), signature, ar))
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
				code, sig, err := strategy.GenerateAuthorizeCode(context.TODO(), nil)
				require.NoError(t, err)
				r.Form.Add("code", code)

				require.NoError(t, s.CreateAuthorizeCodeSession(context.TODO(), sig, r))
				require.NoError(t, s.InvalidateAuthorizeCodeSession(context.TODO(), sig))
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
				code, sig, err := strategy.GenerateAuthorizeCode(context.TODO(), nil)
				require.NoError(t, err)

				if tc.r != nil {
					if tc.r.Form == nil {
						tc.r.Form = url.Values{}
					}

					tc.r.Form.Add("code", code)
				}

				require.NoError(t, s.CreateAuthorizeCodeSession(context.TODO(), sig, tc.ar))
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
	token, _, err := strategy.GenerateAuthorizeCode(context.TODO(), nil)
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
