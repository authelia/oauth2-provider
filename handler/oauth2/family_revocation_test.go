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
	"authelia.com/provider/oauth2/storage"
)

func TestRefreshTokenPastItsReadCannotRotateAfterTheGrantIsRevoked(t *testing.T) {
	stores := []struct {
		name string
		new  func() TokenRevocationStorage
	}{
		{"MemoryStore", func() TokenRevocationStorage { return storage.NewMemoryStore() }},
		{"HydratingMemoryStore", func() TokenRevocationStorage { return storage.NewHydratingMemoryStore() }},
	}

	for _, s := range stores {
		t.Run(s.name, func(t *testing.T) {
			store := s.new()
			strategy := &hmacshaStrategy

			client := &oauth2.DefaultClient{ID: "foo", GrantTypes: oauth2.Arguments{consts.GrantTypeRefreshToken}, Scopes: []string{consts.ScopeOffline}}

			original := &oauth2.Request{
				ID:           "grant",
				Client:       client,
				GrantedScope: oauth2.Arguments{consts.ScopeOffline},
				Session:      &oauth2.DefaultSession{ExpiresAt: map[oauth2.TokenType]time.Time{oauth2.RefreshToken: time.Now().UTC().Add(time.Hour)}},
				RequestedAt:  time.Now().UTC(),
			}

			token, signature, err := strategy.GenerateRefreshToken(t.Context(), nil)
			require.NoError(t, err)
			require.NoError(t, store.CreateRefreshTokenSession(t.Context(), signature, "", original))

			newHandler := func(store TokenRevocationStorage) *RefreshTokenGrantHandler {
				return &RefreshTokenGrantHandler{
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
			}

			newRequest := func() *oauth2.AccessRequest {
				request := oauth2.NewAccessRequest(&oauth2.DefaultSession{})
				request.Client = client
				request.GrantTypes = oauth2.Arguments{consts.GrantTypeRefreshToken}
				request.Form = url.Values{consts.FormParameterRefreshToken: {token}}

				return request
			}

			var winner *oauth2.AccessResponse

			paused := &pausedRotationStore{
				TokenRevocationStorage: store,
				pause: func(ctx context.Context) {
					request := newRequest()

					handler := newHandler(store)

					require.NoError(t, handler.HandleTokenEndpointRequest(ctx, request))

					winner = oauth2.NewAccessResponse()

					require.NoError(t, oauth2.ErrorToDebugRFC6749Error(handler.PopulateTokenEndpointResponse(ctx, request, winner)))

					require.ErrorIs(t, handler.HandleTokenEndpointRequest(ctx, newRequest()), oauth2.ErrInvalidGrant)
				},
			}

			handler := newHandler(paused)
			request := newRequest()

			require.NoError(t, handler.HandleTokenEndpointRequest(t.Context(), request))

			response := oauth2.NewAccessResponse()

			err = handler.PopulateTokenEndpointResponse(t.Context(), request, response)
			require.ErrorIs(t, err, oauth2.ErrInvalidGrant)
			assert.Empty(t, response.GetAccessToken())

			_, err = store.GetAccessTokenSession(t.Context(), strategy.AccessTokenSignature(t.Context(), winner.GetAccessToken()), nil)
			assert.ErrorIs(t, err, oauth2.ErrNotFound)

			refresh, _ := winner.GetExtra(consts.AccessResponseRefreshToken).(string)

			_, err = store.GetRefreshTokenSession(t.Context(), strategy.RefreshTokenSignature(t.Context(), refresh), nil)
			assert.ErrorIs(t, err, oauth2.ErrInactiveToken)

			_, err = store.GetRefreshTokenSession(t.Context(), signature, nil)
			assert.ErrorIs(t, err, oauth2.ErrInactiveToken)
		})
	}
}

type pausedRotationStore struct {
	TokenRevocationStorage

	pause func(ctx context.Context)
}

func (s *pausedRotationStore) RotateRefreshToken(ctx context.Context, requestID, signature string) error {
	s.pause(ctx)

	return s.TokenRevocationStorage.RotateRefreshToken(ctx, requestID, signature)
}
