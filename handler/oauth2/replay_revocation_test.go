// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
)

func TestReplayWhileTheWinnerWritesItsTokens(t *testing.T) {
	testCases := []struct {
		name          string
		transactional bool
	}{
		{name: "ShouldRevokeTheTokensOfTheWinnerOnATransactionalStore", transactional: true},
		{name: "ShouldLeaveTheTokensOfTheWinnerLiveOnAStoreWithoutTransactions"},
	}

	for _, s := range serializationFailureStores() {
		for _, tc := range testCases {
			t.Run(s.name+"/AuthorizeCode/"+tc.name, func(t *testing.T) {
				backing := s.new()

				if tc.transactional {
					backing = &transactionalFailureStore{serializationStorage: backing}
				}

				hooked := &replayDuringWriteStore{serializationStorage: backing}

				var store serializationStorage = hooked

				if tc.transactional {
					store = &transactionalReplayStore{replayDuringWriteStore: hooked, transaction: backing.(*transactionalFailureStore)}
				}

				strategy := &hmacshaStrategy
				client := &oauth2.DefaultClient{ID: "foo", GrantTypes: oauth2.Arguments{consts.GrantTypeAuthorizationCode}}

				handler := AuthorizeExplicitGrantHandler{
					CoreStorage:            store,
					TokenRevocationStorage: store,
					AuthorizeCodeStrategy:  strategy,
					AccessTokenStrategy:    strategy,
					RefreshTokenStrategy:   strategy,
					Config: &oauth2.Config{
						ScopeStrategy:         oauth2.HierarchicScopeStrategy,
						AudienceStrategy:      oauth2.DefaultAudienceStrategy,
						AccessTokenLifespan:   time.Minute,
						AuthorizeCodeLifespan: time.Minute,
					},
				}

				code, signature, err := strategy.GenerateAuthorizeCode(t.Context(), nil)
				require.NoError(t, err)

				require.NoError(t, backing.CreateAuthorizeCodeSession(t.Context(), signature, &oauth2.AuthorizeRequest{
					Request: oauth2.Request{
						ID:           "req-id",
						Client:       client,
						Form:         url.Values{consts.FormParameterRedirectURI: {"https://client.example.com/cb"}},
						GrantedScope: oauth2.Arguments{"foo"},
						Session:      &oauth2.DefaultSession{},
						RequestedAt:  time.Now().UTC(),
					},
				}))

				newRequest := func() *oauth2.AccessRequest {
					return &oauth2.AccessRequest{
						GrantTypes: oauth2.Arguments{consts.GrantTypeAuthorizationCode},
						Request: oauth2.Request{
							Client: client,
							Form: url.Values{
								consts.FormParameterAuthorizationCode: {code},
								consts.FormParameterRedirectURI:       {"https://client.example.com/cb"},
							},
							Session:     &oauth2.DefaultSession{},
							RequestedAt: time.Now().UTC(),
						},
					}
				}

				replay := func(ctx context.Context) error {
					return handler.HandleTokenEndpointRequest(ctx, newRequest())
				}

				request := newRequest()

				require.NoError(t, handler.HandleTokenEndpointRequest(t.Context(), request))

				hooked.replay = func(ctx context.Context) {
					err := replay(ctx)

					if tc.transactional {
						require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err), "an invalidation which has not been committed must not be visible")
					} else {
						require.ErrorIs(t, err, oauth2.ErrInvalidGrant)
					}
				}

				response := oauth2.NewAccessResponse()

				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(handler.PopulateTokenEndpointResponse(t.Context(), request, response)))
				require.True(t, hooked.replayed)

				if tc.transactional {
					require.ErrorIs(t, replay(t.Context()), oauth2.ErrInvalidGrant)
				}

				_, err = backing.GetAccessTokenSession(t.Context(), strategy.AccessTokenSignature(t.Context(), response.GetAccessToken()), nil)

				if tc.transactional {
					assert.ErrorIs(t, err, oauth2.ErrNotFound)
				} else {
					assert.NoError(t, err)
				}
			})

			t.Run(s.name+"/RefreshToken/"+tc.name, func(t *testing.T) {
				backing := s.new()

				if tc.transactional {
					backing = &transactionalFailureStore{serializationStorage: backing}
				}

				hooked := &replayDuringWriteStore{serializationStorage: backing}

				var store serializationStorage = hooked

				if tc.transactional {
					store = &transactionalReplayStore{replayDuringWriteStore: hooked, transaction: backing.(*transactionalFailureStore)}
				}

				strategy := &hmacshaStrategy
				client := &oauth2.DefaultClient{ID: "foo", GrantTypes: oauth2.Arguments{consts.GrantTypeRefreshToken}, Scopes: []string{consts.ScopeOffline}}

				token, signature, err := strategy.GenerateRefreshToken(t.Context(), nil)
				require.NoError(t, err)

				require.NoError(t, backing.CreateRefreshTokenSession(t.Context(), signature, "", &oauth2.Request{
					ID:           "grant",
					Client:       client,
					GrantedScope: oauth2.Arguments{consts.ScopeOffline},
					Session:      &oauth2.DefaultSession{ExpiresAt: map[oauth2.TokenType]time.Time{oauth2.RefreshToken: time.Now().UTC().Add(time.Hour)}},
					RequestedAt:  time.Now().UTC(),
				}))

				handler := &RefreshTokenGrantHandler{
					TokenRevocationStorage: store,
					AccessTokenStrategy:    strategy,
					RefreshTokenStrategy:   strategy,
					Config: &oauth2.Config{
						AccessTokenLifespan:  time.Hour,
						RefreshTokenLifespan: time.Hour,
						ScopeStrategy:        oauth2.HierarchicScopeStrategy,
						AudienceStrategy:     oauth2.DefaultAudienceStrategy,
						RefreshTokenScopes:   []string{consts.ScopeOffline},
					},
				}

				newRequest := func() *oauth2.AccessRequest {
					request := oauth2.NewAccessRequest(&oauth2.DefaultSession{})
					request.Client = client
					request.GrantTypes = oauth2.Arguments{consts.GrantTypeRefreshToken}
					request.Form = url.Values{consts.FormParameterRefreshToken: {token}}

					return request
				}

				replay := func(ctx context.Context) error {
					return handler.HandleTokenEndpointRequest(ctx, newRequest())
				}

				request := newRequest()

				require.NoError(t, handler.HandleTokenEndpointRequest(t.Context(), request))

				hooked.replay = func(ctx context.Context) {
					err := replay(ctx)

					if tc.transactional {
						require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err), "a rotation which has not been committed must not be visible")
					} else {
						require.ErrorIs(t, err, oauth2.ErrInvalidGrant)
					}
				}

				response := oauth2.NewAccessResponse()

				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(handler.PopulateTokenEndpointResponse(t.Context(), request, response)))
				require.True(t, hooked.replayed)

				if tc.transactional {
					require.ErrorIs(t, replay(t.Context()), oauth2.ErrInvalidGrant)
				}

				_, err = backing.GetAccessTokenSession(t.Context(), strategy.AccessTokenSignature(t.Context(), response.GetAccessToken()), nil)

				if tc.transactional {
					assert.ErrorIs(t, err, oauth2.ErrNotFound)
				} else {
					assert.NoError(t, err)
				}
			})
		}
	}
}

type replayDuringWriteStore struct {
	serializationStorage

	replay   func(ctx context.Context)
	replayed bool
}

func (s *replayDuringWriteStore) CreateAccessTokenSession(ctx context.Context, signature string, request oauth2.Requester) error {
	if s.replay != nil && !s.replayed {
		s.replayed = true

		s.replay(context.Background())
	}

	return s.serializationStorage.CreateAccessTokenSession(ctx, signature, request)
}

type transactionalReplayStore struct {
	*replayDuringWriteStore

	transaction *transactionalFailureStore
}

func (s *transactionalReplayStore) BeginTX(ctx context.Context) (context.Context, error) {
	return s.transaction.BeginTX(ctx)
}

func (s *transactionalReplayStore) Commit(ctx context.Context) error {
	return s.transaction.Commit(ctx)
}

func (s *transactionalReplayStore) Rollback(ctx context.Context) error {
	return s.transaction.Rollback(ctx)
}
