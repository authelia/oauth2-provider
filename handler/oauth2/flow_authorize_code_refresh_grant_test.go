// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/gen"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/token/jwt"
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

func TestTokenRequestRestrictsTheAudienceToTheNamedTargets(t *testing.T) {
	const (
		audience = "https://a.example.com"
		first    = "https://r1.example.com/"
		second   = "https://r2.example.com/"
	)

	client := &oauth2.DefaultClient{
		ID:         "foo",
		GrantTypes: oauth2.Arguments{consts.GrantTypeAuthorizationCode, consts.GrantTypeRefreshToken},
		Scopes:     []string{"foo", consts.ScopeOfflineAccess},
		Audience:   []string{audience},
		Resource:   []string{first, second},
	}

	type grantStore interface {
		CoreStorage
		TokenRevocationStorage
	}

	stores := map[string]func() grantStore{
		"MemoryStore":          func() grantStore { return storage.NewMemoryStore() },
		"HydratingMemoryStore": func() grantStore { return storage.NewHydratingMemoryStore() },
	}

	// RFC 8707 Section 2.
	testCases := []struct {
		name     string
		audience oauth2.Arguments
		resource oauth2.Arguments
		expected []string
	}{
		{
			name:     "ShouldRestrictToTheNamedResource",
			resource: oauth2.Arguments{first},
			expected: []string{first},
		},
		{
			name:     "ShouldRestrictToTheNamedAudience",
			audience: oauth2.Arguments{audience},
			expected: []string{audience},
		},
		{
			name:     "ShouldRestrictToTheNamedAudienceAndResource",
			audience: oauth2.Arguments{audience},
			resource: oauth2.Arguments{second},
			expected: []string{audience, second},
		},
		{
			name:     "ShouldKeepTheFullGrantWhenNeitherIsNamed",
			expected: []string{audience, first, second},
		},
	}

	for name, newStore := range stores {
		t.Run(name, func(t *testing.T) {
			for _, tc := range testCases {
				t.Run(tc.name, func(t *testing.T) {
					store := newStore()

					config := &oauth2.Config{
						EnforceJWTProfileAccessTokens: true,
						Issuer:                        "https://as.example.com",
						GlobalSecret:                  []byte("foofoofoofoofoofoofoofoofoofoofoo"),
						ScopeStrategy:                 oauth2.ExactScopeStrategy,
						AudienceStrategy:              oauth2.DefaultAudienceStrategy,
						ResourceStrategy:              oauth2.DefaultResourceStrategy,
						AccessTokenLifespan:           time.Minute,
						RefreshTokenLifespan:          time.Hour,
						AuthorizeCodeLifespan:         time.Minute,
						RefreshTokenScopes:            []string{},
					}

					strategy := &JWTProfileCoreStrategy{
						HMACCoreStrategy: NewHMACCoreStrategy(config, "authelia_%s_"),
						Strategy:         &jwt.DefaultStrategy{Config: config, Issuer: jwt.NewDefaultIssuerRS256Unverified(gen.MustRSAKey())},
						Config:           config,
					}

					code, signature, err := strategy.GenerateAuthorizeCode(t.Context(), nil)
					require.NoError(t, err)

					session := &JWTSession{JWTClaims: &jwt.JWTClaims{Subject: "alice"}, Subject: "alice"}
					session.SetExpiresAt(oauth2.AuthorizeCode, time.Now().UTC().Add(time.Minute))

					require.NoError(t, store.CreateAuthorizeCodeSession(t.Context(), signature, &oauth2.AuthorizeRequest{
						Request: oauth2.Request{
							ID:                "grant",
							Client:            client,
							Form:              url.Values{consts.FormParameterRedirectURI: {"https://client.example.com/cb"}},
							RequestedScope:    oauth2.Arguments{"foo", consts.ScopeOfflineAccess},
							GrantedScope:      oauth2.Arguments{"foo", consts.ScopeOfflineAccess},
							RequestedAudience: oauth2.Arguments{audience},
							GrantedAudience:   oauth2.Arguments{audience},
							RequestedResource: oauth2.Arguments{first, second},
							GrantedResource:   oauth2.Arguments{first, second},
							Session:           session,
							RequestedAt:       time.Now().UTC(),
						},
					}))

					request := &oauth2.AccessRequest{
						GrantTypes: oauth2.Arguments{consts.GrantTypeAuthorizationCode},
						Request: oauth2.Request{
							Client:            client,
							Form:              url.Values{consts.FormParameterAuthorizationCode: {code}, consts.FormParameterRedirectURI: {"https://client.example.com/cb"}},
							RequestedAudience: tc.audience,
							RequestedResource: tc.resource,
							Session:           &JWTSession{},
							RequestedAt:       time.Now().UTC(),
						},
					}

					explicit := &AuthorizeExplicitGrantHandler{
						CoreStorage:           store,
						AuthorizeCodeStrategy: strategy,
						AccessTokenStrategy:   strategy,
						RefreshTokenStrategy:  strategy,
						Config:                config,
					}

					require.NoError(t, oauth2.ErrorToDebugRFC6749Error(explicit.HandleTokenEndpointRequest(t.Context(), request)))

					response := oauth2.NewAccessResponse()

					require.NoError(t, oauth2.ErrorToDebugRFC6749Error(explicit.PopulateTokenEndpointResponse(t.Context(), request, response)))

					refresh := assertIssuedTokenAudience(t, strategy, store, response, tc.expected)

					request = &oauth2.AccessRequest{
						GrantTypes: oauth2.Arguments{consts.GrantTypeRefreshToken},
						Request: oauth2.Request{
							Client:            client,
							Form:              url.Values{consts.FormParameterRefreshToken: {refresh}},
							RequestedAudience: tc.audience,
							RequestedResource: tc.resource,
							Session:           &JWTSession{},
							RequestedAt:       time.Now().UTC(),
						},
					}

					handler := &RefreshTokenGrantHandler{
						AccessTokenStrategy:    strategy,
						RefreshTokenStrategy:   strategy,
						TokenRevocationStorage: store,
						Config:                 config,
					}

					require.NoError(t, oauth2.ErrorToDebugRFC6749Error(handler.HandleTokenEndpointRequest(t.Context(), request)))

					response = oauth2.NewAccessResponse()

					require.NoError(t, oauth2.ErrorToDebugRFC6749Error(handler.PopulateTokenEndpointResponse(t.Context(), request, response)))

					assertIssuedTokenAudience(t, strategy, store, response, tc.expected)
				})
			}
		})
	}
}

func assertIssuedTokenAudience(t *testing.T, strategy *JWTProfileCoreStrategy, store CoreStorage, response *oauth2.AccessResponse, expected []string) (refresh string) {
	t.Helper()

	token := response.GetAccessToken()

	payload, err := base64.RawURLEncoding.DecodeString(strings.Split(token, ".")[1])
	require.NoError(t, err)

	var claims struct {
		Audience jwt.ClaimStrings `json:"aud"`
	}

	require.NoError(t, json.Unmarshal(payload, &claims))

	assert.ElementsMatch(t, expected, []string(claims.Audience))

	stored, err := store.GetAccessTokenSession(t.Context(), strategy.AccessTokenSignature(t.Context(), token), &JWTSession{})
	require.NoError(t, err)

	assert.ElementsMatch(t, expected, oauth2.JoinGrantedAudienceAndResource(stored.GetGrantedAudience(), stored.GetGrantedResource()))

	refresh, _ = response.GetExtra(consts.AccessResponseRefreshToken).(string)
	require.NotEmpty(t, refresh)

	grant, err := store.GetRefreshTokenSession(t.Context(), strategy.RefreshTokenSignature(t.Context(), refresh), &JWTSession{})
	require.NoError(t, err)

	// RFC 8707 Section 2.2: the refresh token keeps the full original grant.
	assert.ElementsMatch(t, []string{"https://a.example.com"}, grant.GetGrantedAudience())
	assert.ElementsMatch(t, []string{"https://r1.example.com/", "https://r2.example.com/"}, grant.GetGrantedResource())

	return refresh
}
