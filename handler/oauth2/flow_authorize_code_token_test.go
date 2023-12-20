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
	"authelia.com/provider/oauth2/internal"
	"authelia.com/provider/oauth2/storage"
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
						GrantTypes: oauth2.Arguments{"authorization_code"},
						Request: oauth2.Request{
							Form: url.Values{},
							Client: &oauth2.DefaultClient{
								GrantTypes: oauth2.Arguments{"authorization_code"},
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
						GrantTypes: oauth2.Arguments{"authorization_code"},
						Request: oauth2.Request{
							Form: url.Values{"code": []string{"foo.bar"}},
							Client: &oauth2.DefaultClient{
								GrantTypes: oauth2.Arguments{"authorization_code"},
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
						GrantTypes: oauth2.Arguments{"authorization_code"},
						Request: oauth2.Request{
							Form: url.Values{},
							Client: &oauth2.DefaultClient{
								GrantTypes: oauth2.Arguments{"authorization_code", "refresh_token"},
							},
							GrantedScope: oauth2.Arguments{"foo", "offline"},
							Session:      &oauth2.DefaultSession{},
							RequestedAt:  time.Now().UTC(),
						},
					},
					setup: func(t *testing.T, areq *oauth2.AccessRequest, config *oauth2.Config) {
						code, sig, err := strategy.GenerateAuthorizeCode(context.TODO(), nil)
						require.NoError(t, err)
						areq.Form.Add("code", code)

						require.NoError(t, store.CreateAuthorizeCodeSession(context.TODO(), sig, areq))
					},
					description: "should pass with offline scope and refresh token",
					check: func(t *testing.T, aresp *oauth2.AccessResponse) {
						assert.NotEmpty(t, aresp.AccessToken)
						assert.Equal(t, "bearer", aresp.TokenType)
						assert.NotEmpty(t, aresp.GetExtra("refresh_token"))
						assert.NotEmpty(t, aresp.GetExtra("expires_in"))
						assert.Equal(t, "foo offline", aresp.GetExtra("scope"))
					},
				},
				{
					areq: &oauth2.AccessRequest{
						GrantTypes: oauth2.Arguments{"authorization_code"},
						Request: oauth2.Request{
							Form: url.Values{},
							Client: &oauth2.DefaultClient{
								GrantTypes: oauth2.Arguments{"authorization_code", "refresh_token"},
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
						areq.Form.Add("code", code)

						require.NoError(t, store.CreateAuthorizeCodeSession(context.TODO(), sig, areq))
					},
					description: "should pass with refresh token always provided",
					check: func(t *testing.T, aresp *oauth2.AccessResponse) {
						assert.NotEmpty(t, aresp.AccessToken)
						assert.Equal(t, "bearer", aresp.TokenType)
						assert.NotEmpty(t, aresp.GetExtra("refresh_token"))
						assert.NotEmpty(t, aresp.GetExtra("expires_in"))
						assert.Equal(t, "foo", aresp.GetExtra("scope"))
					},
				},
				{
					areq: &oauth2.AccessRequest{
						GrantTypes: oauth2.Arguments{"authorization_code"},
						Request: oauth2.Request{
							Form: url.Values{},
							Client: &oauth2.DefaultClient{
								GrantTypes: oauth2.Arguments{"authorization_code"},
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
						areq.Form.Add("code", code)

						require.NoError(t, store.CreateAuthorizeCodeSession(context.TODO(), sig, areq))
					},
					description: "should pass with no refresh token",
					check: func(t *testing.T, aresp *oauth2.AccessResponse) {
						assert.NotEmpty(t, aresp.AccessToken)
						assert.Equal(t, "bearer", aresp.TokenType)
						assert.Empty(t, aresp.GetExtra("refresh_token"))
						assert.NotEmpty(t, aresp.GetExtra("expires_in"))
						assert.Empty(t, aresp.GetExtra("scope"))
					},
				},
				{
					areq: &oauth2.AccessRequest{
						GrantTypes: oauth2.Arguments{"authorization_code"},
						Request: oauth2.Request{
							Form: url.Values{},
							Client: &oauth2.DefaultClient{
								GrantTypes: oauth2.Arguments{"authorization_code"},
							},
							GrantedScope: oauth2.Arguments{"foo"},
							Session:      &oauth2.DefaultSession{},
							RequestedAt:  time.Now().UTC(),
						},
					},
					setup: func(t *testing.T, areq *oauth2.AccessRequest, config *oauth2.Config) {
						code, sig, err := strategy.GenerateAuthorizeCode(context.TODO(), nil)
						require.NoError(t, err)
						areq.Form.Add("code", code)

						require.NoError(t, store.CreateAuthorizeCodeSession(context.TODO(), sig, areq))
					},
					description: "should not have refresh token",
					check: func(t *testing.T, aresp *oauth2.AccessResponse) {
						assert.NotEmpty(t, aresp.AccessToken)
						assert.Equal(t, "bearer", aresp.TokenType)
						assert.Empty(t, aresp.GetExtra("refresh_token"))
						assert.NotEmpty(t, aresp.GetExtra("expires_in"))
						assert.Equal(t, "foo", aresp.GetExtra("scope"))
					},
				},
			} {
				t.Run("case="+c.description, func(t *testing.T) {
					config := &oauth2.Config{
						ScopeStrategy:            oauth2.HierarchicScopeStrategy,
						AudienceMatchingStrategy: oauth2.DefaultAudienceMatchingStrategy,
						AccessTokenLifespan:      time.Minute,
						RefreshTokenScopes:       []string{"offline"},
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

func TestAuthorizeCode_HandleTokenEndpointRequest(t *testing.T) {
	for k, strategy := range map[string]CoreStrategy{
		"hmac": &hmacshaStrategy,
	} {
		t.Run("strategy="+k, func(t *testing.T) {
			store := storage.NewMemoryStore()

			h := AuthorizeExplicitGrantHandler{
				CoreStorage:            store,
				AuthorizeCodeStrategy:  &hmacshaStrategy,
				TokenRevocationStorage: store,
				Config: &oauth2.Config{
					ScopeStrategy:            oauth2.HierarchicScopeStrategy,
					AudienceMatchingStrategy: oauth2.DefaultAudienceMatchingStrategy,
					AuthorizeCodeLifespan:    time.Minute,
				},
			}
			for i, c := range []struct {
				areq        *oauth2.AccessRequest
				authreq     *oauth2.AuthorizeRequest
				description string
				setup       func(t *testing.T, areq *oauth2.AccessRequest, authreq *oauth2.AuthorizeRequest)
				check       func(t *testing.T, areq *oauth2.AccessRequest, authreq *oauth2.AuthorizeRequest)
				expectErr   error
			}{
				{
					areq: &oauth2.AccessRequest{
						GrantTypes: oauth2.Arguments{"12345678"},
					},
					description: "should fail because not responsible",
					expectErr:   oauth2.ErrUnknownRequest,
				},
				{
					areq: &oauth2.AccessRequest{
						GrantTypes: oauth2.Arguments{"authorization_code"},
						Request: oauth2.Request{
							Client:      &oauth2.DefaultClient{ID: "foo", GrantTypes: []string{""}},
							Session:     &oauth2.DefaultSession{},
							RequestedAt: time.Now().UTC(),
						},
					},
					description: "should fail because client is not granted this grant type",
					expectErr:   oauth2.ErrUnauthorizedClient,
				},
				{
					areq: &oauth2.AccessRequest{
						GrantTypes: oauth2.Arguments{"authorization_code"},
						Request: oauth2.Request{
							Client:      &oauth2.DefaultClient{GrantTypes: []string{"authorization_code"}},
							Session:     &oauth2.DefaultSession{},
							RequestedAt: time.Now().UTC(),
						},
					},
					description: "should fail because authcode could not be retrieved (1)",
					setup: func(t *testing.T, areq *oauth2.AccessRequest, authreq *oauth2.AuthorizeRequest) {
						token, _, err := strategy.GenerateAuthorizeCode(context.TODO(), nil)
						require.NoError(t, err)
						areq.Form = url.Values{"code": {token}}
					},
					expectErr: oauth2.ErrInvalidGrant,
				},
				{
					areq: &oauth2.AccessRequest{
						GrantTypes: oauth2.Arguments{"authorization_code"},
						Request: oauth2.Request{
							Form:        url.Values{"code": {"foo.bar"}},
							Client:      &oauth2.DefaultClient{GrantTypes: []string{"authorization_code"}},
							Session:     &oauth2.DefaultSession{},
							RequestedAt: time.Now().UTC(),
						},
					},
					description: "should fail because authcode validation failed",
					expectErr:   oauth2.ErrInvalidGrant,
				},
				{
					areq: &oauth2.AccessRequest{
						GrantTypes: oauth2.Arguments{"authorization_code"},
						Request: oauth2.Request{
							Client:      &oauth2.DefaultClient{ID: "foo", GrantTypes: []string{"authorization_code"}},
							Session:     &oauth2.DefaultSession{},
							RequestedAt: time.Now().UTC(),
						},
					},
					authreq: &oauth2.AuthorizeRequest{
						Request: oauth2.Request{
							Client:         &oauth2.DefaultClient{ID: "bar"},
							RequestedScope: oauth2.Arguments{"a", "b"},
						},
					},
					description: "should fail because client mismatch",
					setup: func(t *testing.T, areq *oauth2.AccessRequest, authreq *oauth2.AuthorizeRequest) {
						token, signature, err := strategy.GenerateAuthorizeCode(context.TODO(), nil)
						require.NoError(t, err)
						areq.Form = url.Values{"code": {token}}

						require.NoError(t, store.CreateAuthorizeCodeSession(context.TODO(), signature, authreq))
					},
					expectErr: oauth2.ErrInvalidGrant,
				},
				{
					areq: &oauth2.AccessRequest{
						GrantTypes: oauth2.Arguments{"authorization_code"},
						Request: oauth2.Request{
							Client:      &oauth2.DefaultClient{ID: "foo", GrantTypes: []string{"authorization_code"}},
							Session:     &oauth2.DefaultSession{},
							RequestedAt: time.Now().UTC(),
						},
					},
					authreq: &oauth2.AuthorizeRequest{
						Request: oauth2.Request{
							Client:  &oauth2.DefaultClient{ID: "foo", GrantTypes: []string{"authorization_code"}},
							Form:    url.Values{"redirect_uri": []string{"request-redir"}},
							Session: &oauth2.DefaultSession{},
						},
					},
					description: "should fail because redirect uri was set during /authorize call, but not in /token call",
					setup: func(t *testing.T, areq *oauth2.AccessRequest, authreq *oauth2.AuthorizeRequest) {
						token, signature, err := strategy.GenerateAuthorizeCode(context.TODO(), nil)
						require.NoError(t, err)
						areq.Form = url.Values{"code": {token}}

						require.NoError(t, store.CreateAuthorizeCodeSession(context.TODO(), signature, authreq))
					},
					expectErr: oauth2.ErrInvalidGrant,
				},
				{
					areq: &oauth2.AccessRequest{
						GrantTypes: oauth2.Arguments{"authorization_code"},
						Request: oauth2.Request{
							Client:      &oauth2.DefaultClient{ID: "foo", GrantTypes: []string{"authorization_code"}},
							Form:        url.Values{"redirect_uri": []string{"request-redir"}},
							Session:     &oauth2.DefaultSession{},
							RequestedAt: time.Now().UTC(),
						},
					},
					authreq: &oauth2.AuthorizeRequest{
						Request: oauth2.Request{
							Client:         &oauth2.DefaultClient{ID: "foo", GrantTypes: []string{"authorization_code"}},
							Session:        &oauth2.DefaultSession{},
							RequestedScope: oauth2.Arguments{"a", "b"},
							RequestedAt:    time.Now().UTC(),
						},
					},
					description: "should pass",
					setup: func(t *testing.T, areq *oauth2.AccessRequest, authreq *oauth2.AuthorizeRequest) {
						token, signature, err := strategy.GenerateAuthorizeCode(context.TODO(), nil)
						require.NoError(t, err)

						areq.Form = url.Values{"code": {token}}
						require.NoError(t, store.CreateAuthorizeCodeSession(context.TODO(), signature, authreq))
					},
				},
				{
					areq: &oauth2.AccessRequest{
						GrantTypes: oauth2.Arguments{"authorization_code"},
						Request: oauth2.Request{
							Form: url.Values{},
							Client: &oauth2.DefaultClient{
								GrantTypes: oauth2.Arguments{"authorization_code"},
							},
							GrantedScope: oauth2.Arguments{"foo", "offline"},
							Session:      &oauth2.DefaultSession{},
							RequestedAt:  time.Now().UTC(),
						},
					},
					check: func(t *testing.T, areq *oauth2.AccessRequest, authreq *oauth2.AuthorizeRequest) {
						assert.Equal(t, time.Now().Add(time.Minute).UTC().Round(time.Second), areq.GetSession().GetExpiresAt(oauth2.AccessToken))
						assert.Equal(t, time.Now().Add(time.Minute).UTC().Round(time.Second), areq.GetSession().GetExpiresAt(oauth2.RefreshToken))
					},
					setup: func(t *testing.T, areq *oauth2.AccessRequest, authreq *oauth2.AuthorizeRequest) {
						code, sig, err := strategy.GenerateAuthorizeCode(context.TODO(), nil)
						require.NoError(t, err)
						areq.Form.Add("code", code)

						require.NoError(t, store.CreateAuthorizeCodeSession(context.TODO(), sig, areq))
						require.NoError(t, store.InvalidateAuthorizeCodeSession(context.TODO(), sig))
					},
					description: "should fail because code has been used already",
					expectErr:   oauth2.ErrInvalidGrant,
				},
			} {
				t.Run(fmt.Sprintf("case=%d/description=%s", i, c.description), func(t *testing.T) {
					if c.setup != nil {
						c.setup(t, c.areq, c.authreq)
					}

					t.Logf("Processing %+v", c.areq.Client)

					err := h.HandleTokenEndpointRequest(context.Background(), c.areq)
					if c.expectErr != nil {
						require.EqualError(t, err, c.expectErr.Error(), "%+v", err)
					} else {
						require.NoError(t, err, "%+v", err)
						if c.check != nil {
							c.check(t, c.areq, c.authreq)
						}
					}
				})
			}
		})
	}
}

func TestAuthorizeCodeTransactional_HandleTokenEndpointRequest(t *testing.T) {
	var mockTransactional *internal.MockTransactional
	var mockCoreStore *internal.MockCoreStorage
	strategy := hmacshaStrategy
	request := &oauth2.AccessRequest{
		GrantTypes: oauth2.Arguments{"authorization_code"},
		Request: oauth2.Request{
			Client: &oauth2.DefaultClient{
				GrantTypes: oauth2.Arguments{"authorization_code", "refresh_token"},
			},
			GrantedScope: oauth2.Arguments{"offline"},
			Session:      &oauth2.DefaultSession{},
			RequestedAt:  time.Now().UTC(),
		},
	}
	token, _, err := strategy.GenerateAuthorizeCode(context.TODO(), nil)
	require.NoError(t, err)
	request.Form = url.Values{"code": {token}}
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

			mockTransactional = internal.NewMockTransactional(ctrl)
			mockCoreStore = internal.NewMockCoreStorage(ctrl)
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
