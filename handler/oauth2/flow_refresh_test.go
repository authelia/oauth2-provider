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

func TestRefreshFlow_HandleTokenEndpointRequestHMAC(t *testing.T) {
	strategy := &hmacshaStrategy
	session := &oauth2.DefaultSession{Subject: "othersub"}
	expSession := &oauth2.DefaultSession{
		ExpiresAt: map[oauth2.TokenType]time.Time{
			oauth2.RefreshToken: time.Now().UTC().Add(-time.Hour),
		},
	}

	store := storage.NewMemoryStore()

	testCases := []struct {
		name   string
		setup  func(requester *oauth2.AccessRequest, store *storage.MemoryStore, config *oauth2.Config)
		err    string
		expect func(t *testing.T, requester *oauth2.AccessRequest)
	}{
		{
			name: "ShouldFailNotResponsible",
			err:  "The handler is not responsible for this request.",
			setup: func(requester *oauth2.AccessRequest, store *storage.MemoryStore, config *oauth2.Config) {
				requester.GrantTypes = oauth2.Arguments{"123"}
			},
		},
		{
			name: "ShouldFailTokenInvalid",
			setup: func(requester *oauth2.AccessRequest, store *storage.MemoryStore, config *oauth2.Config) {
				requester.GrantTypes = oauth2.Arguments{consts.GrantTypeRefreshToken}
				requester.Client = &oauth2.DefaultClient{GrantTypes: oauth2.Arguments{consts.GrantTypeRefreshToken}}

				requester.Form.Add(consts.FormParameterRefreshToken, "some.refreshtokensig")
			},
			err: "The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client. The refresh token has not been found: Could not find the requested resource(s).",
		},
		{
			name: "ShouldFailTokenValidButDoesNotExist",
			setup: func(requester *oauth2.AccessRequest, store *storage.MemoryStore, config *oauth2.Config) {
				requester.GrantTypes = oauth2.Arguments{consts.GrantTypeRefreshToken}
				requester.Client = &oauth2.DefaultClient{GrantTypes: oauth2.Arguments{consts.GrantTypeRefreshToken}}

				token, _, err := strategy.GenerateRefreshToken(t.Context(), nil)
				require.NoError(t, err)
				requester.Form.Add(consts.FormParameterRefreshToken, token)
			},
			err: "The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client. The refresh token has not been found: Could not find the requested resource(s).",
		},
		{
			name: "ShouldFailClientMismatches",
			setup: func(requester *oauth2.AccessRequest, store *storage.MemoryStore, config *oauth2.Config) {
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
			err: "The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client. The OAuth 2.0 Client ID from this request does not match the ID during the initial token issuance.",
		},
		{
			name: "ShouldFailTokenExpired",
			setup: func(requester *oauth2.AccessRequest, store *storage.MemoryStore, config *oauth2.Config) {
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
			err: fmt.Sprintf("The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client. Token expired. Refresh Token expired at '%s'.", expSession.ExpiresAt[oauth2.RefreshToken]),
		},
		{
			name: "ShouldFailOfflineScopeNoLongerAllowed",
			setup: func(requester *oauth2.AccessRequest, store *storage.MemoryStore, config *oauth2.Config) {
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
			err: "The requested scope is invalid, unknown, or malformed. The OAuth 2.0 Client is not allowed to request scope 'foo'.",
		},
		{
			name: "ShouldPass",
			setup: func(requester *oauth2.AccessRequest, store *storage.MemoryStore, config *oauth2.Config) {
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
			expect: func(t *testing.T, requester *oauth2.AccessRequest) {
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
			name: "ShouldPassWithScopeInForm",
			setup: func(requester *oauth2.AccessRequest, store *storage.MemoryStore, config *oauth2.Config) {
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
			expect: func(t *testing.T, requester *oauth2.AccessRequest) {
				assert.Equal(t, oauth2.Arguments{"foo", "bar", "baz", consts.ScopeOffline}, requester.GrantedScope)
				assert.Equal(t, oauth2.Arguments{"foo", "bar", "baz", consts.ScopeOffline}, requester.RequestedScope)
			},
		},
		{
			name: "ShouldPassWithScopeInFormAndNarrowScopes",
			setup: func(requester *oauth2.AccessRequest, store *storage.MemoryStore, config *oauth2.Config) {
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
			expect: func(t *testing.T, requester *oauth2.AccessRequest) {
				assert.Equal(t, oauth2.Arguments{"foo", "bar", consts.ScopeOffline}, requester.GrantedScope)
				assert.Equal(t, oauth2.Arguments{"foo", "bar", consts.ScopeOffline}, requester.RequestedScope)
			},
		},
		{
			name: "ShouldFailBroadenedScopes",
			setup: func(requester *oauth2.AccessRequest, store *storage.MemoryStore, config *oauth2.Config) {
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
			err: "The requested scope is invalid, unknown, or malformed. The requested scope 'bar' was not originally granted by the resource owner.",
		},
		{
			name: "ShouldPassWithCustomClientLifespans",
			setup: func(requester *oauth2.AccessRequest, store *storage.MemoryStore, config *oauth2.Config) {
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
			expect: func(t *testing.T, requester *oauth2.AccessRequest) {
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
			name: "ShouldFailWithoutOfflineScope",
			setup: func(requester *oauth2.AccessRequest, store *storage.MemoryStore, config *oauth2.Config) {
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
			err: "The token was not granted the requested scope. The OAuth 2.0 Client was not granted scope offline and may thus not perform the 'refresh_token' authorization grant.",
		},
		{
			name: "ShouldPassWithoutOfflineScopeWhenConfigured",
			setup: func(requester *oauth2.AccessRequest, store *storage.MemoryStore, config *oauth2.Config) {
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
			expect: func(t *testing.T, requester *oauth2.AccessRequest) {
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
			name: "ShouldDenyAccessOnTokenReuse",
			setup: func(requester *oauth2.AccessRequest, store *storage.MemoryStore, config *oauth2.Config) {
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
			err: "The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client. Token is inactive because it is malformed, expired or otherwise invalid. Token validation failed.",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := &oauth2.Config{
				AccessTokenLifespan:      time.Hour,
				RefreshTokenLifespan:     time.Hour,
				ScopeStrategy:            oauth2.HierarchicScopeStrategy,
				AudienceMatchingStrategy: oauth2.DefaultAudienceMatchingStrategy,
				RefreshTokenScopes:       []string{consts.ScopeOffline},
			}
			handler := &RefreshTokenGrantHandler{
				TokenRevocationStorage: store,
				RefreshTokenStrategy:   strategy,
				Config:                 config,
			}

			requester := oauth2.NewAccessRequest(&oauth2.DefaultSession{})
			requester.Form = url.Values{}
			tc.setup(requester, store, config)

			err := handler.HandleTokenEndpointRequest(t.Context(), requester)
			if tc.err != "" {
				require.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), tc.err)
			} else {
				require.NoError(t, err)
			}

			if tc.expect != nil {
				tc.expect(t, requester)
			}
		})
	}
}

func TestRefreshFlowTransactional_HandleTokenEndpointRequest(t *testing.T) {
	type transactionalStore struct {
		storage.Transactional
		TokenRevocationStorage
	}

	testCases := []struct {
		name  string
		setup func(ctx context.Context, request *oauth2.AccessRequest, mockTransactional *mock.MockTransactional, mockRevocationStore *mock.MockTokenRevocationStorage)
		err   string
	}{
		{
			name: "ShouldRevokeSessionOnTokenReuse",
			setup: func(ctx context.Context, request *oauth2.AccessRequest, mockTransactional *mock.MockTransactional, mockRevocationStore *mock.MockTokenRevocationStorage) {
				request.GrantTypes = oauth2.Arguments{consts.GrantTypeRefreshToken}
				request.Client = &oauth2.DefaultClient{
					ID:         "foo",
					GrantTypes: oauth2.Arguments{consts.GrantTypeRefreshToken},
				}
				mockRevocationStore.
					EXPECT().
					GetRefreshTokenSession(ctx, gomock.Any(), gomock.Any()).
					Return(request, oauth2.ErrInactiveToken).
					Times(1)
				mockTransactional.
					EXPECT().
					BeginTX(ctx).
					Return(ctx, nil).
					Times(1)
				mockRevocationStore.
					EXPECT().
					DeleteRefreshTokenSession(ctx, gomock.Any()).
					Return(nil).
					Times(1)
				mockRevocationStore.
					EXPECT().
					RevokeRefreshToken(ctx, gomock.Any()).
					Return(nil).
					Times(1)
				mockRevocationStore.
					EXPECT().
					RevokeAccessToken(ctx, gomock.Any()).
					Return(nil).
					Times(1)
				mockTransactional.
					EXPECT().
					Commit(ctx).
					Return(nil).
					Times(1)
			},
			err: "The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client. Token is inactive because it is malformed, expired or otherwise invalid. Token validation failed.",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			ctx := context.Background()
			mockTransactional := mock.NewMockTransactional(ctrl)
			mockRevocationStore := mock.NewMockTokenRevocationStorage(ctrl)
			request := oauth2.NewAccessRequest(&oauth2.DefaultSession{})
			tc.setup(ctx, request, mockTransactional, mockRevocationStore)

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

			err := handler.HandleTokenEndpointRequest(ctx, request)
			if tc.err != "" {
				assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), tc.err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestRefreshFlow_PopulateTokenEndpointResponse(t *testing.T) {
	strategy := &hmacshaStrategy
	store := storage.NewMemoryStore()

	testCases := []struct {
		name  string
		setup func(areq *oauth2.AccessRequest, store *storage.MemoryStore, config *oauth2.Config)
		check func(t *testing.T, areq *oauth2.AccessRequest, aresp *oauth2.AccessResponse)
		err   string
	}{
		{
			name: "ShouldFailNotResponsible",
			err:  "The handler is not responsible for this request.",
			setup: func(areq *oauth2.AccessRequest, store *storage.MemoryStore, config *oauth2.Config) {
				areq.GrantTypes = oauth2.Arguments{"313"}
			},
		},
		{
			name: "ShouldPass",
			setup: func(areq *oauth2.AccessRequest, store *storage.MemoryStore, config *oauth2.Config) {
				areq.ID = "req-id"
				areq.GrantTypes = oauth2.Arguments{consts.GrantTypeRefreshToken}
				areq.RequestedScope = oauth2.Arguments{"foo", "bar"}
				areq.GrantedScope = oauth2.Arguments{"foo", "bar"}

				token, signature, err := strategy.GenerateRefreshToken(t.Context(), nil)
				require.NoError(t, err)
				require.NoError(t, store.CreateRefreshTokenSession(t.Context(), signature, areq))
				areq.Form.Add(consts.FormParameterRefreshToken, token)
			},
			check: func(t *testing.T, areq *oauth2.AccessRequest, aresp *oauth2.AccessResponse) {
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
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
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
			areq := oauth2.NewAccessRequest(&oauth2.DefaultSession{})
			aresp := oauth2.NewAccessResponse()
			areq.Client = &oauth2.DefaultClient{}
			areq.Form = url.Values{}

			tc.setup(areq, store, config)

			err := h.PopulateTokenEndpointResponse(t.Context(), areq, aresp)
			if tc.err != "" {
				assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), tc.err)
			} else {
				assert.NoError(t, err)
			}

			if tc.check != nil {
				tc.check(t, areq, aresp)
			}
		})
	}
}

func TestRefreshFlowTransactional_PopulateTokenEndpointResponse(t *testing.T) {
	propagatedContext := context.Background()

	type transactionalStore struct {
		storage.Transactional
		TokenRevocationStorage
	}

	testCases := []struct {
		name  string
		setup func(request *oauth2.AccessRequest, mockTransactional *mock.MockTransactional, mockRevocationStore *mock.MockTokenRevocationStorage)
		err   string
	}{
		{
			name: "ShouldCommitTransactionWhenNoErrors",
			setup: func(request *oauth2.AccessRequest, mockTransactional *mock.MockTransactional, mockRevocationStore *mock.MockTokenRevocationStorage) {
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
			name: "ShouldRollbackWhenGetRefreshTokenSessionReturnsError",
			err:  "The authorization server encountered an unexpected condition that prevented it from fulfilling the request. Whoops, a nasty database error occurred!",
			setup: func(request *oauth2.AccessRequest, mockTransactional *mock.MockTransactional, mockRevocationStore *mock.MockTokenRevocationStorage) {
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
		},
		{
			name: "ShouldFailWithInvalidRequestWhenGetRefreshTokenSessionReturnsErrNotFound",
			err:  "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Failed to refresh token because of multiple concurrent requests using the same token which is not allowed. not_found",
			setup: func(request *oauth2.AccessRequest, mockTransactional *mock.MockTransactional, mockRevocationStore *mock.MockTokenRevocationStorage) {
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
		},
		{
			name: "ShouldRollbackWhenRevokeAccessTokenReturnsError",
			err:  "The authorization server encountered an unexpected condition that prevented it from fulfilling the request. Whoops, a nasty database error occurred!",
			setup: func(request *oauth2.AccessRequest, mockTransactional *mock.MockTransactional, mockRevocationStore *mock.MockTokenRevocationStorage) {
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
		},
		{
			name: "ShouldFailWithInvalidRequestWhenRevokeAccessTokenReturnsErrSerializationFailure",
			err:  "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Failed to refresh token because of multiple concurrent requests using the same token which is not allowed. The request could not be completed due to concurrent access",
			setup: func(request *oauth2.AccessRequest, mockTransactional *mock.MockTransactional, mockRevocationStore *mock.MockTokenRevocationStorage) {
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
		},
		{
			name: "ShouldFailWithInvalidRequestWhenGetRefreshTokenSessionReturnsErrInactiveToken",
			err:  "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Failed to refresh token because of multiple concurrent requests using the same token which is not allowed. token_inactive",
			setup: func(request *oauth2.AccessRequest, mockTransactional *mock.MockTransactional, mockRevocationStore *mock.MockTokenRevocationStorage) {
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
		},
		{
			name: "ShouldRollbackWhenRevokeRefreshTokenMaybeGracePeriodReturnsError",
			err:  "The authorization server encountered an unexpected condition that prevented it from fulfilling the request. Whoops, a nasty database error occurred!",
			setup: func(request *oauth2.AccessRequest, mockTransactional *mock.MockTransactional, mockRevocationStore *mock.MockTokenRevocationStorage) {
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
		},
		{
			name: "ShouldFailWithInvalidRequestWhenRevokeRefreshTokenMaybeGracePeriodReturnsErrSerializationFailure",
			err:  "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Failed to refresh token because of multiple concurrent requests using the same token which is not allowed. The request could not be completed due to concurrent access",
			setup: func(request *oauth2.AccessRequest, mockTransactional *mock.MockTransactional, mockRevocationStore *mock.MockTokenRevocationStorage) {
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
		},
		{
			name: "ShouldFailWithInvalidRequestWhenCreateAccessTokenSessionReturnsErrSerializationFailure",
			err:  "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Failed to refresh token because of multiple concurrent requests using the same token which is not allowed. The request could not be completed due to concurrent access",
			setup: func(request *oauth2.AccessRequest, mockTransactional *mock.MockTransactional, mockRevocationStore *mock.MockTokenRevocationStorage) {
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
					Return(oauth2.ErrSerializationFailure).
					Times(1)
				mockTransactional.
					EXPECT().
					Rollback(propagatedContext).
					Return(nil).
					Times(1)
			},
		},
		{
			name: "ShouldRollbackWhenCreateAccessTokenSessionReturnsError",
			err:  "The authorization server encountered an unexpected condition that prevented it from fulfilling the request. Whoops, a nasty database error occurred!",
			setup: func(request *oauth2.AccessRequest, mockTransactional *mock.MockTransactional, mockRevocationStore *mock.MockTokenRevocationStorage) {
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
					Return(errors.New("Whoops, a nasty database error occurred!")).
					Times(1)
				mockTransactional.
					EXPECT().
					Rollback(propagatedContext).
					Return(nil).
					Times(1)
			},
		},
		{
			name: "ShouldRollbackWhenCreateRefreshTokenSessionReturnsError",
			err:  "The authorization server encountered an unexpected condition that prevented it from fulfilling the request. Whoops, a nasty database error occurred!",
			setup: func(request *oauth2.AccessRequest, mockTransactional *mock.MockTransactional, mockRevocationStore *mock.MockTokenRevocationStorage) {
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
		},
		{
			name: "ShouldFailWithInvalidRequestWhenCreateRefreshTokenSessionReturnsErrSerializationFailure",
			err:  "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Failed to refresh token because of multiple concurrent requests using the same token which is not allowed. The request could not be completed due to concurrent access",
			setup: func(request *oauth2.AccessRequest, mockTransactional *mock.MockTransactional, mockRevocationStore *mock.MockTokenRevocationStorage) {
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
		},
		{
			name: "ShouldFailWhenTransactionCannotBeCreated",
			err:  "The authorization server encountered an unexpected condition that prevented it from fulfilling the request. Could not create transaction!",
			setup: func(request *oauth2.AccessRequest, mockTransactional *mock.MockTransactional, mockRevocationStore *mock.MockTokenRevocationStorage) {
				request.GrantTypes = oauth2.Arguments{consts.GrantTypeRefreshToken}
				mockTransactional.
					EXPECT().
					BeginTX(propagatedContext).
					Return(nil, errors.New("Could not create transaction!")).
					Times(1)
			},
		},
		{
			name: "ShouldFailWhenTransactionCannotBeRolledBack",
			err:  "The authorization server encountered an unexpected condition that prevented it from fulfilling the request. error: invalid_request; rollback error: Could not rollback transaction!",
			setup: func(request *oauth2.AccessRequest, mockTransactional *mock.MockTransactional, mockRevocationStore *mock.MockTokenRevocationStorage) {
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
		},
		{
			name: "ShouldFailWhenTransactionCannotBeCommitted",
			err:  "The authorization server encountered an unexpected condition that prevented it from fulfilling the request. Could not commit transaction!",
			setup: func(request *oauth2.AccessRequest, mockTransactional *mock.MockTransactional, mockRevocationStore *mock.MockTokenRevocationStorage) {
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
		},
		{
			name: "ShouldFailWithInvalidRequestWhenCommitReturnsErrSerializationFailure",
			err:  "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Failed to refresh token because of multiple concurrent requests using the same token which is not allowed. The request could not be completed due to concurrent access",
			setup: func(request *oauth2.AccessRequest, mockTransactional *mock.MockTransactional, mockRevocationStore *mock.MockTokenRevocationStorage) {
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
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockTransactional := mock.NewMockTransactional(ctrl)
			mockRevocationStore := mock.NewMockTokenRevocationStorage(ctrl)
			request := oauth2.NewAccessRequest(&oauth2.DefaultSession{})
			response := oauth2.NewAccessResponse()
			tc.setup(request, mockTransactional, mockRevocationStore)

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

			err := handler.PopulateTokenEndpointResponse(propagatedContext, request, response)
			if tc.err != "" {
				assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), tc.err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
