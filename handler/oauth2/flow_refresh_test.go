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
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/testing/mock"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestRefreshFlow_HandleTokenEndpointRequest(t *testing.T) {
	var requester *oauth2.AccessRequest
	session := &oauth2.DefaultSession{Subject: "othersub"}
	expSession := &oauth2.DefaultSession{
		ExpiresAt: map[oauth2.TokenType]time.Time{
			oauth2.RefreshToken: time.Now().UTC().Add(-time.Hour),
		},
	}

	for k, strategy := range map[string]RefreshTokenStrategy{
		"hmac": &hmacshaStrategy,
	} {
		t.Run("strategy="+k, func(t *testing.T) {
			store := storage.NewMemoryStore()
			var handler *RefreshTokenGrantHandler
			for _, c := range []struct {
				description string
				setup       func(config *oauth2.Config)
				expectErr   error
				expect      func(t *testing.T)
			}{
				{
					description: "should fail because not responsible",
					expectErr:   oauth2.ErrUnknownRequest,
					setup: func(config *oauth2.Config) {
						requester.GrantTypes = oauth2.Arguments{"123"}
					},
				},
				{
					description: "should fail because token invalid",
					setup: func(config *oauth2.Config) {
						requester.GrantTypes = oauth2.Arguments{consts.GrantTypeRefreshToken}
						requester.Client = &oauth2.DefaultClient{GrantTypes: oauth2.Arguments{consts.GrantTypeRefreshToken}}

						requester.Form.Add(consts.FormParameterRefreshToken, "some.refreshtokensig")
					},
					expectErr: oauth2.ErrInvalidGrant,
				},
				{
					description: "should fail because token is valid but does not exist",
					setup: func(config *oauth2.Config) {
						requester.GrantTypes = oauth2.Arguments{consts.GrantTypeRefreshToken}
						requester.Client = &oauth2.DefaultClient{GrantTypes: oauth2.Arguments{consts.GrantTypeRefreshToken}}

						token, _, err := strategy.GenerateRefreshToken(t.Context(), nil)
						require.NoError(t, err)
						requester.Form.Add(consts.FormParameterRefreshToken, token)
					},
					expectErr: oauth2.ErrInvalidGrant,
				},
				{
					description: "should fail because client mismatches",
					setup: func(config *oauth2.Config) {
						requester.GrantTypes = oauth2.Arguments{consts.GrantTypeRefreshToken}
						requester.Client = &oauth2.DefaultClient{
							ID:         "foo",
							GrantTypes: oauth2.Arguments{consts.GrantTypeRefreshToken},
						}

						token, sig, err := strategy.GenerateRefreshToken(t.Context(), nil)
						require.NoError(t, err)

						requester.Form.Add(consts.FormParameterRefreshToken, token)
						err = store.CreateRefreshTokenSession(t.Context(), sig, &oauth2.Request{
							Client:       &oauth2.DefaultClient{ID: ""},
							GrantedScope: []string{consts.ScopeOffline},
							Session:      session,
						})
						require.NoError(t, err)
					},
					expectErr: oauth2.ErrInvalidGrant,
				},
				{
					description: "should fail because token is expired",
					setup: func(config *oauth2.Config) {
						requester.GrantTypes = oauth2.Arguments{consts.GrantTypeRefreshToken}
						requester.Client = &oauth2.DefaultClient{
							ID:         "foo",
							GrantTypes: oauth2.Arguments{consts.GrantTypeRefreshToken},
							Scopes:     []string{"foo", "bar", consts.ScopeOffline},
						}

						token, sig, err := strategy.GenerateRefreshToken(t.Context(), nil)
						require.NoError(t, err)

						requester.Form.Add(consts.FormParameterRefreshToken, token)
						err = store.CreateRefreshTokenSession(t.Context(), sig, &oauth2.Request{
							Client:         requester.Client,
							GrantedScope:   oauth2.Arguments{"foo", consts.ScopeOffline},
							RequestedScope: oauth2.Arguments{"foo", "bar", consts.ScopeOffline},
							Session:        expSession,
							Form:           url.Values{"foo": []string{"bar"}},
							RequestedAt:    time.Now().UTC().Add(-time.Hour).Truncate(time.Hour),
						})
						require.NoError(t, err)
					},
					expectErr: oauth2.ErrInvalidGrant,
				},
				{
					description: "should fail because offline scope has been granted but client no longer allowed to request it",
					setup: func(config *oauth2.Config) {
						requester.GrantTypes = oauth2.Arguments{consts.GrantTypeRefreshToken}
						requester.Client = &oauth2.DefaultClient{
							ID:         "foo",
							GrantTypes: oauth2.Arguments{consts.GrantTypeRefreshToken},
						}

						token, sig, err := strategy.GenerateRefreshToken(t.Context(), nil)
						require.NoError(t, err)

						requester.Form.Add(consts.FormParameterRefreshToken, token)
						err = store.CreateRefreshTokenSession(t.Context(), sig, &oauth2.Request{
							Client:         requester.Client,
							GrantedScope:   oauth2.Arguments{"foo", consts.ScopeOffline},
							RequestedScope: oauth2.Arguments{"foo", consts.ScopeOffline},
							Session:        session,
							Form:           url.Values{"foo": []string{"bar"}},
							RequestedAt:    time.Now().UTC().Add(-time.Hour).Truncate(time.Hour),
						})
						require.NoError(t, err)
					},
					expectErr: oauth2.ErrInvalidScope,
				},
				{
					description: "should pass",
					setup: func(config *oauth2.Config) {
						requester.GrantTypes = oauth2.Arguments{consts.GrantTypeRefreshToken}
						requester.Client = &oauth2.DefaultClient{
							ID:         "foo",
							GrantTypes: oauth2.Arguments{consts.GrantTypeRefreshToken},
							Scopes:     []string{"foo", "bar", consts.ScopeOffline},
						}

						token, sig, err := strategy.GenerateRefreshToken(t.Context(), nil)
						require.NoError(t, err)

						requester.Form.Add(consts.FormParameterRefreshToken, token)
						err = store.CreateRefreshTokenSession(t.Context(), sig, &oauth2.Request{
							Client:         requester.Client,
							GrantedScope:   oauth2.Arguments{"foo", consts.ScopeOffline},
							RequestedScope: oauth2.Arguments{"foo", "bar", consts.ScopeOffline},
							Session:        session,
							Form:           url.Values{"foo": []string{"bar"}},
							RequestedAt:    time.Now().UTC().Add(-time.Hour).Truncate(time.Hour),
						})
						require.NoError(t, err)
					},
					expect: func(t *testing.T) {
						assert.NotEqual(t, session, requester.Session)
						assert.NotEqual(t, time.Now().UTC().Add(-time.Hour).Truncate(time.Hour), requester.RequestedAt)
						assert.Equal(t, oauth2.Arguments{"foo", consts.ScopeOffline}, requester.GrantedScope)
						assert.Equal(t, oauth2.Arguments{"foo", consts.ScopeOffline}, requester.RequestedScope)
						assert.NotEqual(t, url.Values{"foo": []string{"bar"}}, requester.Form)
						assert.Equal(t, time.Now().Add(time.Hour).UTC().Truncate(jwt.TimePrecision), requester.GetSession().GetExpiresAt(oauth2.AccessToken))
						assert.Equal(t, time.Now().Add(time.Hour).UTC().Truncate(jwt.TimePrecision), requester.GetSession().GetExpiresAt(oauth2.RefreshToken))
					},
				},
				{
					description: "should pass with scope in form",
					setup: func(config *oauth2.Config) {
						requester.GrantTypes = oauth2.Arguments{"refresh_token"}
						requester.Client = &oauth2.DefaultClient{
							ID:         "foo",
							GrantTypes: oauth2.Arguments{"refresh_token"},
							Scopes:     []string{"foo", "bar", "baz", consts.ScopeOffline},
						}

						token, sig, err := strategy.GenerateRefreshToken(t.Context(), nil)
						require.NoError(t, err)

						requester.Form.Add("refresh_token", token)
						requester.Form.Add("scope", "foo bar baz offline")
						err = store.CreateRefreshTokenSession(t.Context(), sig, &oauth2.Request{
							Client:         requester.Client,
							GrantedScope:   oauth2.Arguments{"foo", "bar", "baz", consts.ScopeOffline},
							RequestedScope: oauth2.Arguments{"foo", "bar", "baz", consts.ScopeOffline},
							Session:        session,
							Form:           url.Values{"foo": []string{"bar"}},
							RequestedAt:    time.Now().UTC().Add(-time.Hour).Truncate(time.Hour),
						})
						require.NoError(t, err)
					},
					expect: func(t *testing.T) {
						assert.Equal(t, oauth2.Arguments{"foo", "bar", "baz", consts.ScopeOffline}, requester.GrantedScope)
						assert.Equal(t, oauth2.Arguments{"foo", "bar", "baz", consts.ScopeOffline}, requester.RequestedScope)
					},
				},
				{
					description: "should pass with scope in form and should narrow scopes",
					setup: func(config *oauth2.Config) {
						requester.GrantTypes = oauth2.Arguments{"refresh_token"}
						requester.Client = &oauth2.DefaultClient{
							ID:         "foo",
							GrantTypes: oauth2.Arguments{"refresh_token"},
							Scopes:     []string{"foo", "bar", "baz", consts.ScopeOffline},
						}

						token, sig, err := strategy.GenerateRefreshToken(t.Context(), nil)
						require.NoError(t, err)

						requester.Form.Add("refresh_token", token)
						requester.Form.Add("scope", "foo bar offline")
						requester.SetRequestedScopes(oauth2.Arguments{"foo", "bar", consts.ScopeOffline})

						err = store.CreateRefreshTokenSession(t.Context(), sig, &oauth2.Request{
							Client:         requester.Client,
							GrantedScope:   oauth2.Arguments{"foo", "bar", "baz", consts.ScopeOffline},
							RequestedScope: oauth2.Arguments{"foo", "bar", "baz", consts.ScopeOffline},
							Session:        session,
							Form:           url.Values{"foo": []string{"bar"}},
							RequestedAt:    time.Now().UTC().Add(-time.Hour).Truncate(time.Hour),
						})
						require.NoError(t, err)
					},
					expect: func(t *testing.T) {
						assert.Equal(t, oauth2.Arguments{"foo", "bar", consts.ScopeOffline}, requester.GrantedScope)
						assert.Equal(t, oauth2.Arguments{"foo", "bar", consts.ScopeOffline}, requester.RequestedScope)
					},
				},
				{
					description: "should fail with broadened scopes even if the client can request it",
					setup: func(config *oauth2.Config) {
						requester.GrantTypes = oauth2.Arguments{"refresh_token"}
						requester.Client = &oauth2.DefaultClient{
							ID:         "foo",
							GrantTypes: oauth2.Arguments{"refresh_token"},
							Scopes:     []string{"foo", "bar", "baz", consts.ScopeOffline},
						}

						token, sig, err := strategy.GenerateRefreshToken(t.Context(), nil)
						require.NoError(t, err)

						requester.Form.Add("refresh_token", token)
						requester.Form.Add("scope", "foo bar offline")
						requester.SetRequestedScopes(oauth2.Arguments{"foo", "bar", consts.ScopeOffline})

						err = store.CreateRefreshTokenSession(t.Context(), sig, &oauth2.Request{
							Client:         requester.Client,
							GrantedScope:   oauth2.Arguments{"foo", "baz", consts.ScopeOffline},
							RequestedScope: oauth2.Arguments{"foo", "baz", consts.ScopeOffline},
							Session:        session,
							Form:           url.Values{"foo": []string{"bar"}},
							RequestedAt:    time.Now().UTC().Add(-time.Hour).Truncate(time.Hour),
						})
						require.NoError(t, err)
					},
					expectErr: oauth2.ErrInvalidScope,
				},
				{
					description: "should pass with custom client lifespans",
					setup: func(config *oauth2.Config) {
						requester.GrantTypes = oauth2.Arguments{consts.GrantTypeRefreshToken}
						requester.Client = &oauth2.DefaultClientWithCustomTokenLifespans{
							DefaultClient: &oauth2.DefaultClient{
								ID:         "foo",
								GrantTypes: oauth2.Arguments{consts.GrantTypeRefreshToken},
								Scopes:     []string{"foo", "bar", consts.ScopeOffline},
							},
						}

						requester.Client.(*oauth2.DefaultClientWithCustomTokenLifespans).SetTokenLifespans(&internal.TestLifespans)

						token, sig, err := strategy.GenerateRefreshToken(t.Context(), nil)
						require.NoError(t, err)

						requester.Form.Add(consts.FormParameterRefreshToken, token)
						err = store.CreateRefreshTokenSession(t.Context(), sig, &oauth2.Request{
							Client:         requester.Client,
							GrantedScope:   oauth2.Arguments{"foo", consts.ScopeOffline},
							RequestedScope: oauth2.Arguments{"foo", "bar", consts.ScopeOffline},
							Session:        session,
							Form:           url.Values{"foo": []string{"bar"}},
							RequestedAt:    time.Now().UTC().Add(-time.Hour).Truncate(time.Hour),
						})
						require.NoError(t, err)
					},
					expect: func(t *testing.T) {
						assert.NotEqual(t, session, requester.Session)
						assert.NotEqual(t, time.Now().UTC().Add(-time.Hour).Truncate(time.Hour), requester.RequestedAt)
						assert.Equal(t, oauth2.Arguments{"foo", consts.ScopeOffline}, requester.GrantedScope)
						assert.Equal(t, oauth2.Arguments{"foo", consts.ScopeOffline}, requester.RequestedScope)
						assert.NotEqual(t, url.Values{"foo": []string{"bar"}}, requester.Form)
						internal.RequireEqualTime(t, time.Now().Add(*internal.TestLifespans.RefreshTokenGrantAccessTokenLifespan).UTC(), requester.GetSession().GetExpiresAt(oauth2.AccessToken), time.Minute)
						internal.RequireEqualTime(t, time.Now().Add(*internal.TestLifespans.RefreshTokenGrantRefreshTokenLifespan).UTC(), requester.GetSession().GetExpiresAt(oauth2.RefreshToken), time.Minute)
					},
				},
				{
					description: "should fail without offline scope",
					setup: func(config *oauth2.Config) {
						requester.GrantTypes = oauth2.Arguments{consts.GrantTypeRefreshToken}
						requester.Client = &oauth2.DefaultClient{
							ID:         "foo",
							GrantTypes: oauth2.Arguments{consts.GrantTypeRefreshToken},
							Scopes:     []string{"foo", "bar"},
						}

						token, sig, err := strategy.GenerateRefreshToken(t.Context(), nil)
						require.NoError(t, err)

						requester.Form.Add(consts.FormParameterRefreshToken, token)
						err = store.CreateRefreshTokenSession(t.Context(), sig, &oauth2.Request{
							Client:         requester.Client,
							GrantedScope:   oauth2.Arguments{"foo"},
							RequestedScope: oauth2.Arguments{"foo", "bar"},
							Session:        session,
							Form:           url.Values{"foo": []string{"bar"}},
							RequestedAt:    time.Now().UTC().Add(-time.Hour).Truncate(time.Hour),
						})
						require.NoError(t, err)
					},
					expectErr: oauth2.ErrScopeNotGranted,
				},
				{
					description: "should pass without offline scope when configured to allow refresh tokens",
					setup: func(config *oauth2.Config) {
						config.RefreshTokenScopes = []string{}
						requester.GrantTypes = oauth2.Arguments{consts.GrantTypeRefreshToken}
						requester.Client = &oauth2.DefaultClient{
							ID:         "foo",
							GrantTypes: oauth2.Arguments{consts.GrantTypeRefreshToken},
							Scopes:     []string{"foo", "bar"},
						}

						token, sig, err := strategy.GenerateRefreshToken(t.Context(), nil)
						require.NoError(t, err)

						requester.Form.Add(consts.FormParameterRefreshToken, token)
						err = store.CreateRefreshTokenSession(t.Context(), sig, &oauth2.Request{
							Client:         requester.Client,
							GrantedScope:   oauth2.Arguments{"foo"},
							RequestedScope: oauth2.Arguments{"foo", "bar"},
							Session:        session,
							Form:           url.Values{"foo": []string{"bar"}},
							RequestedAt:    time.Now().UTC().Add(-time.Hour).Truncate(time.Hour),
						})
						require.NoError(t, err)
					},
					expect: func(t *testing.T) {
						assert.NotEqual(t, session, requester.Session)
						assert.NotEqual(t, time.Now().UTC().Add(-time.Hour).Truncate(time.Hour), requester.RequestedAt)
						assert.Equal(t, oauth2.Arguments{"foo"}, requester.GrantedScope)
						assert.Equal(t, oauth2.Arguments{"foo"}, requester.RequestedScope)
						assert.NotEqual(t, url.Values{"foo": []string{"bar"}}, requester.Form)
						assert.Equal(t, time.Now().Add(time.Hour).UTC().Truncate(jwt.TimePrecision), requester.GetSession().GetExpiresAt(oauth2.AccessToken))
						assert.Equal(t, time.Now().Add(time.Hour).UTC().Truncate(jwt.TimePrecision), requester.GetSession().GetExpiresAt(oauth2.RefreshToken))
					},
				},
				{
					description: "should deny access on token reuse",
					setup: func(config *oauth2.Config) {
						requester.GrantTypes = oauth2.Arguments{consts.GrantTypeRefreshToken}
						requester.Client = &oauth2.DefaultClient{
							ID:         "foo",
							GrantTypes: oauth2.Arguments{consts.GrantTypeRefreshToken},
							Scopes:     []string{"foo", "bar", consts.ScopeOffline},
						}

						token, sig, err := strategy.GenerateRefreshToken(t.Context(), nil)
						require.NoError(t, err)

						requester.Form.Add(consts.FormParameterRefreshToken, token)
						req := &oauth2.Request{
							Client:         requester.Client,
							GrantedScope:   oauth2.Arguments{"foo", consts.ScopeOffline},
							RequestedScope: oauth2.Arguments{"foo", "bar", consts.ScopeOffline},
							Session:        session,
							Form:           url.Values{"foo": []string{"bar"}},
							RequestedAt:    time.Now().UTC().Add(-time.Hour).Truncate(time.Hour),
						}
						err = store.CreateRefreshTokenSession(t.Context(), sig, req)
						require.NoError(t, err)

						err = store.RevokeRefreshToken(t.Context(), req.ID)
						require.NoError(t, err)
					},
					expectErr: oauth2.ErrInvalidGrant,
				},
			} {
				t.Run("case="+c.description, func(t *testing.T) {
					config := &oauth2.Config{
						AccessTokenLifespan:      time.Hour,
						RefreshTokenLifespan:     time.Hour,
						ScopeStrategy:            oauth2.HierarchicScopeStrategy,
						AudienceMatchingStrategy: oauth2.DefaultAudienceMatchingStrategy,
						RefreshTokenScopes:       []string{consts.ScopeOffline},
					}
					handler = &RefreshTokenGrantHandler{
						TokenRevocationStorage: store,
						RefreshTokenStrategy:   strategy,
						Config:                 config,
					}

					requester = oauth2.NewAccessRequest(&oauth2.DefaultSession{})
					requester.Form = url.Values{}
					c.setup(config)

					err := handler.HandleTokenEndpointRequest(t.Context(), requester)
					if c.expectErr != nil {
						require.EqualError(t, err, c.expectErr.Error())
					} else {
						require.NoError(t, err)
					}

					if c.expect != nil {
						c.expect(t)
					}
				})
			}
		})
	}
}

func TestRefreshFlowTransactional_HandleTokenEndpointRequest(t *testing.T) {
	var mockTransactional *mock.MockTransactional
	var mockRevocationStore *mock.MockTokenRevocationStorage
	request := oauth2.NewAccessRequest(&oauth2.DefaultSession{})
	propagatedContext := context.Background()

	type transactionalStore struct {
		storage.Transactional
		TokenRevocationStorage
	}

	for _, testCase := range []struct {
		description string
		setup       func()
		expectError error
	}{
		{
			description: "should revoke session on token reuse",
			setup: func() {
				request.GrantTypes = oauth2.Arguments{consts.GrantTypeRefreshToken}
				request.Client = &oauth2.DefaultClient{
					ID:         "foo",
					GrantTypes: oauth2.Arguments{consts.GrantTypeRefreshToken},
				}
				mockRevocationStore.
					EXPECT().
					GetRefreshTokenSession(propagatedContext, gomock.Any(), gomock.Any()).
					Return(request, oauth2.ErrInactiveToken).
					Times(1)
				mockTransactional.
					EXPECT().
					BeginTX(propagatedContext).
					Return(propagatedContext, nil).
					Times(1)
				mockRevocationStore.
					EXPECT().
					DeleteRefreshTokenSession(propagatedContext, gomock.Any()).
					Return(nil).
					Times(1)
				mockRevocationStore.
					EXPECT().
					RevokeRefreshToken(propagatedContext, gomock.Any()).
					Return(nil).
					Times(1)
				mockRevocationStore.
					EXPECT().
					RevokeAccessToken(propagatedContext, gomock.Any()).
					Return(nil).
					Times(1)
				mockTransactional.
					EXPECT().
					Commit(propagatedContext).
					Return(nil).
					Times(1)
			},
			expectError: oauth2.ErrInvalidGrant,
		},
	} {
		t.Run(fmt.Sprintf("scenario=%s", testCase.description), func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockTransactional = mock.NewMockTransactional(ctrl)
			mockRevocationStore = mock.NewMockTokenRevocationStorage(ctrl)
			testCase.setup()

			handler := RefreshTokenGrantHandler{
				TokenRevocationStorage: transactionalStore{
					mockTransactional,
					mockRevocationStore,
				},
				AccessTokenStrategy:  &hmacshaStrategy,
				RefreshTokenStrategy: &hmacshaStrategy,
				Config: &oauth2.Config{
					AccessTokenLifespan:      time.Hour,
					ScopeStrategy:            oauth2.HierarchicScopeStrategy,
					AudienceMatchingStrategy: oauth2.DefaultAudienceMatchingStrategy,
				},
			}

			if err := handler.HandleTokenEndpointRequest(propagatedContext, request); testCase.expectError != nil {
				assert.EqualError(t, err, testCase.expectError.Error())
			}
		})
	}
}

func TestRefreshFlow_PopulateTokenEndpointResponse(t *testing.T) {
	var areq *oauth2.AccessRequest
	var aresp *oauth2.AccessResponse

	for k, strategy := range map[string]CoreStrategy{
		"hmac": &hmacshaStrategy,
	} {
		t.Run("strategy="+k, func(t *testing.T) {
			store := storage.NewMemoryStore()

			for _, c := range []struct {
				description string
				setup       func(config *oauth2.Config)
				check       func(t *testing.T)
				expectErr   error
			}{
				{
					description: "should fail because not responsible",
					expectErr:   oauth2.ErrUnknownRequest,
					setup: func(config *oauth2.Config) {
						areq.GrantTypes = oauth2.Arguments{"313"}
					},
				},
				{
					description: "should pass",
					setup: func(config *oauth2.Config) {
						areq.ID = "req-id"
						areq.GrantTypes = oauth2.Arguments{consts.GrantTypeRefreshToken}
						areq.RequestedScope = oauth2.Arguments{"foo", "bar"}
						areq.GrantedScope = oauth2.Arguments{"foo", "bar"}

						token, signature, err := strategy.GenerateRefreshToken(t.Context(), nil)
						require.NoError(t, err)
						require.NoError(t, store.CreateRefreshTokenSession(t.Context(), signature, areq))
						areq.Form.Add(consts.FormParameterRefreshToken, token)
					},
					check: func(t *testing.T) {
						signature := strategy.RefreshTokenSignature(context.Background(), areq.Form.Get(consts.FormParameterRefreshToken))

						// The old refresh token should be deleted
						_, err := store.GetRefreshTokenSession(t.Context(), signature, nil)
						require.Error(t, err)

						assert.Equal(t, "req-id", areq.ID)
						require.NoError(t, strategy.ValidateAccessToken(t.Context(), areq, aresp.GetAccessToken()))
						require.NoError(t, strategy.ValidateRefreshToken(t.Context(), areq, aresp.ToMap()[consts.AccessResponseRefreshToken].(string)))
						assert.Equal(t, oauth2.BearerAccessToken, aresp.GetTokenType())
						assert.NotEmpty(t, aresp.ToMap()[consts.AccessResponseExpiresIn])
						assert.Equal(t, "foo bar", aresp.ToMap()[consts.AccessResponseScope])
					},
				},
			} {
				t.Run("case="+c.description, func(t *testing.T) {
					config := &oauth2.Config{
						AccessTokenLifespan:      time.Hour,
						ScopeStrategy:            oauth2.HierarchicScopeStrategy,
						AudienceMatchingStrategy: oauth2.DefaultAudienceMatchingStrategy,
					}
					h := RefreshTokenGrantHandler{
						TokenRevocationStorage: store,
						RefreshTokenStrategy:   strategy,
						AccessTokenStrategy:    strategy,
						Config:                 config,
					}
					areq = oauth2.NewAccessRequest(&oauth2.DefaultSession{})
					aresp = oauth2.NewAccessResponse()
					areq.Client = &oauth2.DefaultClient{}
					areq.Form = url.Values{}

					c.setup(config)

					err := h.PopulateTokenEndpointResponse(t.Context(), areq, aresp)
					if c.expectErr != nil {
						assert.EqualError(t, err, c.expectErr.Error())
					} else {
						assert.NoError(t, err)
					}

					if c.check != nil {
						c.check(t)
					}
				})
			}
		})
	}
}

func TestRefreshFlowTransactional_PopulateTokenEndpointResponse(t *testing.T) {
	var (
		mockTransactional   *mock.MockTransactional
		mockRevocationStore *mock.MockTokenRevocationStorage
	)

	request := oauth2.NewAccessRequest(&oauth2.DefaultSession{})
	response := oauth2.NewAccessResponse()
	propagatedContext := context.Background()

	// some storage implementation that has support for transactions, notice the embedded type `storage.Transactional`
	type transactionalStore struct {
		storage.Transactional
		TokenRevocationStorage
	}

	for _, testCase := range []struct {
		description string
		setup       func()
		expectError error
	}{
		{
			description: "transaction should be committed successfully if no errors occur",
			setup: func() {
				request.GrantTypes = oauth2.Arguments{consts.GrantTypeRefreshToken}
				mockTransactional.
					EXPECT().
					BeginTX(propagatedContext).
					Return(propagatedContext, nil).
					Times(1)
				mockRevocationStore.
					EXPECT().
					GetRefreshTokenSession(propagatedContext, gomock.Any(), nil).
					Return(request, nil).
					Times(1)
				mockRevocationStore.
					EXPECT().
					RevokeAccessToken(propagatedContext, gomock.Any()).
					Return(nil).
					Times(1)
				mockRevocationStore.
					EXPECT().
					RevokeRefreshTokenMaybeGracePeriod(propagatedContext, gomock.Any(), gomock.Any()).
					Return(nil).
					Times(1)
				mockRevocationStore.
					EXPECT().
					CreateAccessTokenSession(propagatedContext, gomock.Any(), gomock.Any()).
					Return(nil).
					Times(1)
				mockRevocationStore.
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
			description: "transaction should be rolled back if call to `GetRefreshTokenSession` results in an error",
			setup: func() {
				request.GrantTypes = oauth2.Arguments{consts.GrantTypeRefreshToken}
				mockTransactional.
					EXPECT().
					BeginTX(propagatedContext).
					Return(propagatedContext, nil).
					Times(1)
				mockRevocationStore.
					EXPECT().
					GetRefreshTokenSession(propagatedContext, gomock.Any(), nil).
					Return(nil, errors.New("Whoops, a nasty database error occurred!")).
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
			description: "should result in a oauth2.ErrInvalidRequest if `GetRefreshTokenSession` results in a " +
				"oauth2.ErrNotFound error",
			setup: func() {
				request.GrantTypes = oauth2.Arguments{consts.GrantTypeRefreshToken}
				mockTransactional.
					EXPECT().
					BeginTX(propagatedContext).
					Return(propagatedContext, nil).
					Times(1)
				mockRevocationStore.
					EXPECT().
					GetRefreshTokenSession(propagatedContext, gomock.Any(), nil).
					Return(nil, oauth2.ErrNotFound).
					Times(1)
				mockTransactional.
					EXPECT().
					Rollback(propagatedContext).
					Return(nil).
					Times(1)
			},
			expectError: oauth2.ErrInvalidRequest,
		},
		{
			description: "transaction should be rolled back if call to `RevokeAccessToken` results in an error",
			setup: func() {
				request.GrantTypes = oauth2.Arguments{consts.GrantTypeRefreshToken}
				mockTransactional.
					EXPECT().
					BeginTX(propagatedContext).
					Return(propagatedContext, nil).
					Times(1)
				mockRevocationStore.
					EXPECT().
					GetRefreshTokenSession(propagatedContext, gomock.Any(), nil).
					Return(request, nil).
					Times(1)
				mockRevocationStore.
					EXPECT().
					RevokeAccessToken(propagatedContext, gomock.Any()).
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
			description: "should result in a oauth2.ErrInvalidRequest if call to `RevokeAccessToken` results in a " +
				"oauth2.ErrSerializationFailure error",
			setup: func() {
				request.GrantTypes = oauth2.Arguments{consts.GrantTypeRefreshToken}
				mockTransactional.
					EXPECT().
					BeginTX(propagatedContext).
					Return(propagatedContext, nil).
					Times(1)
				mockRevocationStore.
					EXPECT().
					GetRefreshTokenSession(propagatedContext, gomock.Any(), nil).
					Return(request, nil).
					Times(1)
				mockRevocationStore.
					EXPECT().
					RevokeAccessToken(propagatedContext, gomock.Any()).
					Return(oauth2.ErrSerializationFailure).
					Times(1)
				mockTransactional.
					EXPECT().
					Rollback(propagatedContext).
					Return(nil).
					Times(1)
			},
			expectError: oauth2.ErrInvalidRequest,
		},
		{
			description: "should result in a oauth2.ErrInactiveToken if call to `RevokeAccessToken` results in a " +
				"oauth2.ErrInvalidRequest error",
			setup: func() {
				request.GrantTypes = oauth2.Arguments{consts.GrantTypeRefreshToken}
				mockTransactional.
					EXPECT().
					BeginTX(propagatedContext).
					Return(propagatedContext, nil).
					Times(1)
				mockRevocationStore.
					EXPECT().
					GetRefreshTokenSession(propagatedContext, gomock.Any(), nil).
					Return(nil, oauth2.ErrInactiveToken).
					Times(1)
				mockTransactional.
					EXPECT().
					Rollback(propagatedContext).
					Return(nil).
					Times(1)
			},
			expectError: oauth2.ErrInvalidRequest,
		},
		{
			description: "transaction should be rolled back if call to `RevokeRefreshTokenMaybeGracePeriod` results in an error",
			setup: func() {
				request.GrantTypes = oauth2.Arguments{consts.GrantTypeRefreshToken}
				mockTransactional.
					EXPECT().
					BeginTX(propagatedContext).
					Return(propagatedContext, nil).
					Times(1)
				mockRevocationStore.
					EXPECT().
					GetRefreshTokenSession(propagatedContext, gomock.Any(), nil).
					Return(request, nil).
					Times(1)
				mockRevocationStore.
					EXPECT().
					RevokeAccessToken(propagatedContext, gomock.Any()).
					Return(nil).
					Times(1)
				mockRevocationStore.
					EXPECT().
					RevokeRefreshTokenMaybeGracePeriod(propagatedContext, gomock.Any(), gomock.Any()).
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
			description: "should result in a oauth2.ErrInvalidRequest if call to `RevokeRefreshTokenMaybeGracePeriod` results in a " +
				"oauth2.ErrSerializationFailure error",
			setup: func() {
				request.GrantTypes = oauth2.Arguments{consts.GrantTypeRefreshToken}
				mockTransactional.
					EXPECT().
					BeginTX(propagatedContext).
					Return(propagatedContext, nil).
					Times(1)
				mockRevocationStore.
					EXPECT().
					GetRefreshTokenSession(propagatedContext, gomock.Any(), nil).
					Return(request, nil).
					Times(1)
				mockRevocationStore.
					EXPECT().
					RevokeAccessToken(propagatedContext, gomock.Any()).
					Return(nil).
					Times(1)
				mockRevocationStore.
					EXPECT().
					RevokeRefreshTokenMaybeGracePeriod(propagatedContext, gomock.Any(), gomock.Any()).
					Return(oauth2.ErrSerializationFailure).
					Times(1)
				mockTransactional.
					EXPECT().
					Rollback(propagatedContext).
					Return(nil).
					Times(1)
			},
			expectError: oauth2.ErrInvalidRequest,
		},
		{
			description: "should result in a oauth2.ErrInvalidRequest if call to `CreateAccessTokenSession` results in " +
				"a oauth2.ErrSerializationFailure error",
			setup: func() {
				mockTransactional.
					EXPECT().
					BeginTX(propagatedContext).
					Return(propagatedContext, nil).
					Times(1)
				mockRevocationStore.
					EXPECT().
					GetRefreshTokenSession(propagatedContext, gomock.Any(), nil).
					Return(request, nil).
					Times(1)
				mockRevocationStore.
					EXPECT().
					RevokeAccessToken(propagatedContext, gomock.Any()).
					Return(nil).
					Times(1)
				mockRevocationStore.
					EXPECT().
					RevokeRefreshTokenMaybeGracePeriod(propagatedContext, gomock.Any(), gomock.Any()).
					Return(nil).
					Times(1)
				mockRevocationStore.
					EXPECT().
					CreateAccessTokenSession(propagatedContext, gomock.Any(), gomock.Any()).
					Return(oauth2.ErrSerializationFailure).
					Times(1)
				mockTransactional.
					EXPECT().
					Rollback(propagatedContext).
					Return(nil).
					Times(1)
			},
			expectError: oauth2.ErrInvalidRequest,
		},
		{
			description: "transaction should be rolled back if call to `CreateAccessTokenSession` results in an error",
			setup: func() {
				mockTransactional.
					EXPECT().
					BeginTX(propagatedContext).
					Return(propagatedContext, nil).
					Times(1)
				mockRevocationStore.
					EXPECT().
					GetRefreshTokenSession(propagatedContext, gomock.Any(), nil).
					Return(request, nil).
					Times(1)
				mockRevocationStore.
					EXPECT().
					RevokeAccessToken(propagatedContext, gomock.Any()).
					Return(nil).
					Times(1)
				mockRevocationStore.
					EXPECT().
					RevokeRefreshTokenMaybeGracePeriod(propagatedContext, gomock.Any(), gomock.Any()).
					Return(nil).
					Times(1)
				mockRevocationStore.
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
			description: "transaction should be rolled back if call to `CreateRefreshTokenSession` results in an error",
			setup: func() {
				request.GrantTypes = oauth2.Arguments{consts.GrantTypeRefreshToken}
				mockTransactional.
					EXPECT().
					BeginTX(propagatedContext).
					Return(propagatedContext, nil).
					Times(1)
				mockRevocationStore.
					EXPECT().
					GetRefreshTokenSession(propagatedContext, gomock.Any(), nil).
					Return(request, nil).
					Times(1)
				mockRevocationStore.
					EXPECT().
					RevokeAccessToken(propagatedContext, gomock.Any()).
					Return(nil).
					Times(1)
				mockRevocationStore.
					EXPECT().
					RevokeRefreshTokenMaybeGracePeriod(propagatedContext, gomock.Any(), gomock.Any()).
					Return(nil).
					Times(1)
				mockRevocationStore.
					EXPECT().
					CreateAccessTokenSession(propagatedContext, gomock.Any(), gomock.Any()).
					Return(nil).
					Times(1)
				mockRevocationStore.
					EXPECT().
					CreateRefreshTokenSession(propagatedContext, gomock.Any(), gomock.Any()).
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
			description: "should result in a oauth2.ErrInvalidRequest if call to `CreateRefreshTokenSession` results in " +
				"a oauth2.ErrSerializationFailure error",
			setup: func() {
				request.GrantTypes = oauth2.Arguments{consts.GrantTypeRefreshToken}
				mockTransactional.
					EXPECT().
					BeginTX(propagatedContext).
					Return(propagatedContext, nil).
					Times(1)
				mockRevocationStore.
					EXPECT().
					GetRefreshTokenSession(propagatedContext, gomock.Any(), nil).
					Return(request, nil).
					Times(1)
				mockRevocationStore.
					EXPECT().
					RevokeAccessToken(propagatedContext, gomock.Any()).
					Return(nil).
					Times(1)
				mockRevocationStore.
					EXPECT().
					RevokeRefreshTokenMaybeGracePeriod(propagatedContext, gomock.Any(), gomock.Any()).
					Return(nil).
					Times(1)
				mockRevocationStore.
					EXPECT().
					CreateAccessTokenSession(propagatedContext, gomock.Any(), gomock.Any()).
					Return(nil).
					Times(1)
				mockRevocationStore.
					EXPECT().
					CreateRefreshTokenSession(propagatedContext, gomock.Any(), gomock.Any()).
					Return(oauth2.ErrSerializationFailure).
					Times(1)
				mockTransactional.
					EXPECT().
					Rollback(propagatedContext).
					Return(nil).
					Times(1)
			},
			expectError: oauth2.ErrInvalidRequest,
		},
		{
			description: "should result in a server error if transaction cannot be created",
			setup: func() {
				request.GrantTypes = oauth2.Arguments{consts.GrantTypeRefreshToken}
				mockTransactional.
					EXPECT().
					BeginTX(propagatedContext).
					Return(nil, errors.New("Could not create transaction!")).
					Times(1)
			},
			expectError: oauth2.ErrServerError,
		},
		{
			description: "should result in a server error if transaction cannot be rolled back",
			setup: func() {
				request.GrantTypes = oauth2.Arguments{consts.GrantTypeRefreshToken}
				mockTransactional.
					EXPECT().
					BeginTX(propagatedContext).
					Return(propagatedContext, nil).
					Times(1)
				mockRevocationStore.
					EXPECT().
					GetRefreshTokenSession(propagatedContext, gomock.Any(), nil).
					Return(nil, oauth2.ErrNotFound).
					Times(1)
				mockTransactional.
					EXPECT().
					Rollback(propagatedContext).
					Return(errors.New("Could not rollback transaction!")).
					Times(1)
			},
			expectError: oauth2.ErrServerError,
		},
		{
			description: "should result in a server error if transaction cannot be committed",
			setup: func() {
				request.GrantTypes = oauth2.Arguments{consts.GrantTypeRefreshToken}
				mockTransactional.
					EXPECT().
					BeginTX(propagatedContext).
					Return(propagatedContext, nil).
					Times(1)
				mockRevocationStore.
					EXPECT().
					GetRefreshTokenSession(propagatedContext, gomock.Any(), nil).
					Return(request, nil).
					Times(1)
				mockRevocationStore.
					EXPECT().
					RevokeAccessToken(propagatedContext, gomock.Any()).
					Return(nil).
					Times(1)
				mockRevocationStore.
					EXPECT().
					RevokeRefreshTokenMaybeGracePeriod(propagatedContext, gomock.Any(), gomock.Any()).
					Return(nil).
					Times(1)
				mockRevocationStore.
					EXPECT().
					CreateAccessTokenSession(propagatedContext, gomock.Any(), gomock.Any()).
					Return(nil).
					Times(1)
				mockRevocationStore.
					EXPECT().
					CreateRefreshTokenSession(propagatedContext, gomock.Any(), gomock.Any()).
					Return(nil).
					Times(1)
				mockTransactional.
					EXPECT().
					Commit(propagatedContext).
					Return(errors.New("Could not commit transaction!")).
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
			description: "should result in a `oauth2.ErrInvalidRequest` if transaction fails to commit due to a " +
				"`oauth2.ErrSerializationFailure` error",
			setup: func() {
				request.GrantTypes = oauth2.Arguments{consts.GrantTypeRefreshToken}
				mockTransactional.
					EXPECT().
					BeginTX(propagatedContext).
					Return(propagatedContext, nil).
					Times(1)
				mockRevocationStore.
					EXPECT().
					GetRefreshTokenSession(propagatedContext, gomock.Any(), nil).
					Return(request, nil).
					Times(1)
				mockRevocationStore.
					EXPECT().
					RevokeAccessToken(propagatedContext, gomock.Any()).
					Return(nil).
					Times(1)
				mockRevocationStore.
					EXPECT().
					RevokeRefreshTokenMaybeGracePeriod(propagatedContext, gomock.Any(), gomock.Any()).
					Return(nil).
					Times(1)
				mockRevocationStore.
					EXPECT().
					CreateAccessTokenSession(propagatedContext, gomock.Any(), gomock.Any()).
					Return(nil).
					Times(1)
				mockRevocationStore.
					EXPECT().
					CreateRefreshTokenSession(propagatedContext, gomock.Any(), gomock.Any()).
					Return(nil).
					Times(1)
				mockTransactional.
					EXPECT().
					Commit(propagatedContext).
					Return(oauth2.ErrSerializationFailure).
					Times(1)
				mockTransactional.
					EXPECT().
					Rollback(propagatedContext).
					Return(nil).
					Times(1)
			},
			expectError: oauth2.ErrInvalidRequest,
		},
	} {
		t.Run(fmt.Sprintf("scenario=%s", testCase.description), func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockTransactional = mock.NewMockTransactional(ctrl)
			mockRevocationStore = mock.NewMockTokenRevocationStorage(ctrl)
			testCase.setup()

			handler := RefreshTokenGrantHandler{
				// Notice how we are passing in a store that has support for transactions!
				TokenRevocationStorage: transactionalStore{
					mockTransactional,
					mockRevocationStore,
				},
				AccessTokenStrategy:  &hmacshaStrategy,
				RefreshTokenStrategy: &hmacshaStrategy,
				Config: &oauth2.Config{
					AccessTokenLifespan:      time.Hour,
					ScopeStrategy:            oauth2.HierarchicScopeStrategy,
					AudienceMatchingStrategy: oauth2.DefaultAudienceMatchingStrategy,
				},
			}

			if err := handler.PopulateTokenEndpointResponse(propagatedContext, request, response); testCase.expectError != nil {
				assert.EqualError(t, err, testCase.expectError.Error())
			}
		})
	}
}
