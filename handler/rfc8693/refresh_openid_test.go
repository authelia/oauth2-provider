// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc8693_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/jose"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/compose"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	. "authelia.com/provider/oauth2/handler/rfc8693"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/gen"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/token/jwt"
)

const (
	refreshOpenIDExchanger = "refresh-openid-exchanger"
	refreshOpenIDSecret    = "foobarfoobarfoobarfoobarfoobar12"
)

func TestRefreshTokenFromAnExchangeRefreshesTheIDToken(t *testing.T) {
	authTime := time.Now().Add(-time.Hour).Truncate(time.Second)

	stores := map[string]func() (any, *storage.MemoryStore){
		"MemoryStore": func() (any, *storage.MemoryStore) {
			store := storage.NewMemoryStore()

			return store, store
		},
		"HydratingMemoryStore": func() (any, *storage.MemoryStore) {
			store := storage.NewHydratingMemoryStore()

			return store, store.MemoryStore
		},
	}

	for name, newStore := range stores {
		t.Run(name, func(t *testing.T) {
			setup := func(t *testing.T, granted oauth2.Arguments) (oauth2.Provider, string) {
				t.Helper()

				store, memory := newStore()

				memory.Clients[refreshOpenIDExchanger] = &oauth2.DefaultClient{
					ID:           refreshOpenIDExchanger,
					ClientSecret: oauth2.NewPlainTextClientSecret(refreshOpenIDSecret),
					GrantTypes:   []string{consts.GrantTypeOAuthTokenExchange, consts.GrantTypeRefreshToken},
					Scopes:       granted,
				}

				config := &oauth2.Config{
					GlobalSecret:                          []byte("super-duper-secret-that-is-at-least-32-bytes"),
					RFC7591ClientRegistrationGlobalSecret: []byte("a-completely-different-secret-at-least-32b"),
					IDTokenIssuer:                         "https://as.example.com",
					AccessTokenLifespan:                   time.Hour,
					RefreshTokenLifespan:                  time.Hour,
					TokenEntropy:                          32,
					DefaultRequestedTokenType:             consts.TokenTypeRFC8693AccessToken,
					RFC8693TokenTypes: map[string]oauth2.RFC8693TokenType{
						consts.TokenTypeRFC8693AccessToken:  &DefaultTokenType{Name: consts.TokenTypeRFC8693AccessToken},
						consts.TokenTypeRFC8693RefreshToken: &DefaultTokenType{Name: consts.TokenTypeRFC8693RefreshToken},
						consts.TokenTypeRFC8693IDToken:      &DefaultTokenType{Name: consts.TokenTypeRFC8693IDToken},
					},
				}

				session := NewDefaultSession()
				session.SetSubject("peter")
				session.SetExpiresAt(oauth2.RefreshToken, time.Now().UTC().Add(time.Hour))

				claims := session.IDTokenClaims()
				claims.Subject = "peter"
				claims.AuthTime = jwt.NewNumericDate(authTime)
				claims.AuthenticationContextClassReference = "gold"
				claims.AuthenticationMethodsReferences = []string{"mfa"}

				request := &oauth2.AccessRequest{
					GrantTypes: oauth2.Arguments{consts.GrantTypeAuthorizationCode},
					Request:    oauth2.Request{ID: uuid.New().String(), RequestedAt: time.Now().UTC(), Client: memory.Clients[refreshOpenIDExchanger], GrantedScope: granted, Session: session},
				}

				ctx := context.Background()
				strategy := compose.NewOAuth2HMACStrategy(config)

				token, signature, err := strategy.GenerateRefreshToken(ctx, request)
				require.NoError(t, err)
				require.NoError(t, store.(hoauth2.TokenRevocationStorage).CreateRefreshTokenSession(ctx, signature, "", request))

				return compose.ComposeAllEnabled(config, store, gen.MustRSAKey()), token
			}

			token := func(t *testing.T, provider oauth2.Provider, form url.Values) oauth2.AccessResponder {
				t.Helper()

				r := httptest.NewRequest(http.MethodPost, "https://as.example.com/token", strings.NewReader(form.Encode()))
				r.Header.Set(consts.HeaderContentType, "application/x-www-form-urlencoded")
				r.SetBasicAuth(refreshOpenIDExchanger, refreshOpenIDSecret)

				ctx := context.Background()

				request, err := provider.NewAccessRequest(ctx, r, NewDefaultSession())
				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

				if form.Get(consts.FormParameterGrantType) == consts.GrantTypeOAuthTokenExchange {
					for _, scope := range request.GetRequestedScopes() {
						request.GrantScope(scope)
					}
				}

				response, err := provider.NewAccessResponse(ctx, request)
				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

				return response
			}

			exchange := func(subject, scope, requested string) url.Values {
				return url.Values{
					consts.FormParameterGrantType:          {consts.GrantTypeOAuthTokenExchange},
					consts.FormParameterSubjectToken:       {subject},
					consts.FormParameterSubjectTokenType:   {consts.TokenTypeRFC8693RefreshToken},
					consts.FormParameterRequestedTokenType: {requested},
					consts.FormParameterScope:              {scope},
				}
			}

			refresh := func(token string) url.Values {
				return url.Values{
					consts.FormParameterGrantType:    {consts.GrantTypeRefreshToken},
					consts.FormParameterRefreshToken: {token},
				}
			}

			assertLogin := func(t *testing.T, raw any) {
				t.Helper()

				claims := parseUnverified(t, raw)

				assert.Equal(t, "peter", claims[consts.ClaimSubject])
				assert.Equal(t, float64(authTime.Unix()), claims[consts.ClaimAuthenticationTime])
				assert.Equal(t, "gold", claims[consts.ClaimAuthenticationContextClassReference])
				assert.Equal(t, []any{"mfa"}, claims[consts.ClaimAuthenticationMethodsReference])
				assert.Contains(t, claims[consts.ClaimAudience], refreshOpenIDExchanger)
			}

			granted := oauth2.Arguments{consts.ScopeOpenID, consts.ScopeOfflineAccess, "read"}

			t.Run("ShouldRefreshAnIDTokenFromAnExchangedAccessToken", func(t *testing.T) {
				provider, subject := setup(t, granted)

				exchanged := token(t, provider, exchange(subject, "openid offline_access read", consts.TokenTypeRFC8693AccessToken))

				issued, _ := exchanged.GetExtra(consts.AccessResponseRefreshToken).(string)
				require.NotEmpty(t, issued)

				assertLogin(t, token(t, provider, refresh(issued)).GetExtra(consts.AccessResponseIDToken))
			})

			t.Run("ShouldRefreshAnIDTokenFromAnExchangedRefreshToken", func(t *testing.T) {
				provider, subject := setup(t, granted)

				issued := token(t, provider, exchange(subject, "openid offline_access read", consts.TokenTypeRFC8693RefreshToken)).GetAccessToken()
				require.NotEmpty(t, issued)

				assertLogin(t, token(t, provider, refresh(issued)).GetExtra(consts.AccessResponseIDToken))
			})

			t.Run("ShouldCarryTheLoginOntoAnExchangedIDToken", func(t *testing.T) {
				provider, subject := setup(t, granted)

				assertLogin(t, token(t, provider, exchange(subject, "", consts.TokenTypeRFC8693IDToken)).GetAccessToken())
			})

			t.Run("ShouldNotIssueAnIDTokenWithoutOpenID", func(t *testing.T) {
				provider, subject := setup(t, oauth2.Arguments{consts.ScopeOfflineAccess, "read"})

				exchanged := token(t, provider, exchange(subject, "offline_access read", consts.TokenTypeRFC8693AccessToken))

				issued, _ := exchanged.GetExtra(consts.AccessResponseRefreshToken).(string)
				require.NotEmpty(t, issued)

				assert.Nil(t, token(t, provider, refresh(issued)).GetExtra(consts.AccessResponseIDToken))
			})
		})
	}
}

func parseUnverified(t *testing.T, raw any) (claims map[string]any) {
	t.Helper()

	value, ok := raw.(string)
	require.True(t, ok, "the response has no ID Token")

	signed, err := jose.ParseSigned(value, []jose.SignatureAlgorithm{jose.RS256})
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(signed.UnsafePayloadWithoutVerification(), &claims))

	return claims
}
