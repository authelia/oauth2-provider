// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/storage"
)

func TestAuthorizeCodeRefreshTokenKeepsTheFullGrant(t *testing.T) {
	const (
		calendar = "https://calendar.example.com/"
		contacts = "https://contacts.example.com/"
		cal      = "https://cal-aud.example.com"
		con      = "https://con-aud.example.com"
	)

	client := &oauth2.DefaultClient{
		ID:         "foo",
		GrantTypes: oauth2.Arguments{consts.GrantTypeAuthorizationCode, consts.GrantTypeRefreshToken},
		Scopes:     []string{"foo", consts.ScopeOfflineAccess},
		Audience:   []string{cal, con},
		Resource:   []string{calendar, contacts},
	}

	type grantStore interface {
		CoreStorage
		TokenRevocationStorage
	}

	stores := map[string]func() grantStore{
		"MemoryStore":          func() grantStore { return storage.NewMemoryStore() },
		"HydratingMemoryStore": func() grantStore { return storage.NewHydratingMemoryStore() },
	}

	for name, newStore := range stores {
		t.Run(name, func(t *testing.T) {
			setup := func(t *testing.T) (string, *RefreshTokenGrantHandler) {
				t.Helper()

				store := newStore()
				strategy := &hmacshaStrategy

				config := &oauth2.Config{
					ScopeStrategy:         oauth2.ExactScopeStrategy,
					AudienceStrategy:      oauth2.DefaultAudienceStrategy,
					ResourceStrategy:      oauth2.DefaultResourceStrategy,
					AccessTokenLifespan:   time.Minute,
					RefreshTokenLifespan:  time.Hour,
					AuthorizeCodeLifespan: time.Minute,
					RefreshTokenScopes:    []string{},
				}

				handler := AuthorizeExplicitGrantHandler{
					CoreStorage:           store,
					AuthorizeCodeStrategy: strategy,
					AccessTokenStrategy:   strategy,
					RefreshTokenStrategy:  strategy,
					Config:                config,
				}

				code, signature, err := strategy.GenerateAuthorizeCode(t.Context(), nil)
				require.NoError(t, err)

				session := &oauth2.DefaultSession{ExpiresAt: map[oauth2.TokenType]time.Time{oauth2.AuthorizeCode: time.Now().UTC().Add(time.Minute)}}

				require.NoError(t, store.CreateAuthorizeCodeSession(t.Context(), signature, &oauth2.AuthorizeRequest{
					Request: oauth2.Request{
						ID:                "grant",
						Client:            client,
						Form:              url.Values{consts.FormParameterRedirectURI: {"https://client.example.com/cb"}},
						RequestedScope:    oauth2.Arguments{"foo", consts.ScopeOfflineAccess},
						GrantedScope:      oauth2.Arguments{"foo", consts.ScopeOfflineAccess},
						RequestedAudience: oauth2.Arguments{cal, con},
						GrantedAudience:   oauth2.Arguments{cal, con},
						RequestedResource: oauth2.Arguments{calendar, contacts},
						GrantedResource:   oauth2.Arguments{calendar, contacts},
						Session:           session,
						RequestedAt:       time.Now().UTC(),
					},
				}))

				request := &oauth2.AccessRequest{
					GrantTypes: oauth2.Arguments{consts.GrantTypeAuthorizationCode},
					Request: oauth2.Request{
						Client:            client,
						Form:              url.Values{consts.FormParameterAuthorizationCode: {code}, consts.FormParameterRedirectURI: {"https://client.example.com/cb"}},
						RequestedAudience: oauth2.Arguments{cal},
						RequestedResource: oauth2.Arguments{calendar},
						Session:           &oauth2.DefaultSession{},
						RequestedAt:       time.Now().UTC(),
					},
				}

				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(handler.HandleTokenEndpointRequest(t.Context(), request)))

				response := oauth2.NewAccessResponse()

				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(handler.PopulateTokenEndpointResponse(t.Context(), request, response)))

				// RFC 8707 Section 2.2: the access token is limited to the subset.
				assert.Equal(t, oauth2.Arguments{cal}, request.GetGrantedAudience())
				assert.Equal(t, oauth2.Arguments{calendar}, request.GetGrantedResource())

				refresh, _ := response.GetExtra(consts.AccessResponseRefreshToken).(string)
				require.NotEmpty(t, refresh)

				return refresh, &RefreshTokenGrantHandler{
					AccessTokenStrategy:    strategy,
					RefreshTokenStrategy:   strategy,
					TokenRevocationStorage: store,
					Config:                 config,
				}
			}

			exchange := func(t *testing.T, handler *RefreshTokenGrantHandler, refresh string, audience, resource oauth2.Arguments) (*oauth2.AccessRequest, error) {
				t.Helper()

				request := &oauth2.AccessRequest{
					GrantTypes: oauth2.Arguments{consts.GrantTypeRefreshToken},
					Request: oauth2.Request{
						Client:            client,
						Form:              url.Values{consts.FormParameterRefreshToken: {refresh}},
						RequestedAudience: audience,
						RequestedResource: resource,
						Session:           &oauth2.DefaultSession{},
						RequestedAt:       time.Now().UTC(),
					},
				}

				return request, handler.HandleTokenEndpointRequest(t.Context(), request)
			}

			t.Run("ShouldRefreshForTheOtherGrantedResource", func(t *testing.T) {
				refresh, handler := setup(t)

				request, err := exchange(t, handler, refresh, nil, oauth2.Arguments{contacts})

				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
				assert.Equal(t, oauth2.Arguments{contacts}, request.GetGrantedResource())
			})

			t.Run("ShouldRefreshForTheOtherGrantedAudience", func(t *testing.T) {
				refresh, handler := setup(t)

				request, err := exchange(t, handler, refresh, oauth2.Arguments{con}, nil)

				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
				assert.Equal(t, oauth2.Arguments{con}, request.GetGrantedAudience())
			})

			t.Run("ShouldRefreshForTheFullGrantWithoutANarrowing", func(t *testing.T) {
				refresh, handler := setup(t)

				request, err := exchange(t, handler, refresh, nil, nil)

				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
				assert.ElementsMatch(t, oauth2.Arguments{calendar, contacts}, request.GetGrantedResource())
				assert.ElementsMatch(t, oauth2.Arguments{cal, con}, request.GetGrantedAudience())
			})

			t.Run("ShouldRefuseAResourceOutsideTheGrant", func(t *testing.T) {
				refresh, handler := setup(t)

				_, err := exchange(t, handler, refresh, nil, oauth2.Arguments{"https://never.example.com/"})

				assert.ErrorIs(t, err, oauth2.ErrInvalidTarget)
			})
		})
	}
}
