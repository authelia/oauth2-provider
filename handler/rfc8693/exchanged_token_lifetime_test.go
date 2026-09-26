// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc8693_test

import (
	"context"
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/handler/openid"
	. "authelia.com/provider/oauth2/handler/rfc8693"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestExchangedTokenLifetime(t *testing.T) {
	for _, sc := range bindingExchangeStores() {
		t.Run(sc.name, func(t *testing.T) {
			t.Run("ShouldCapTheAccessTokenAtAnAccessTokenSubject", func(t *testing.T) {
				store := sc.newStore()
				config, coreStrategy := newBindingExchangeConfig()

				subject := NewDefaultSession()
				subject.SetSubject("peter")

				request := newLifetimeExchangeRequest(store, consts.TokenTypeRFC8693AccessToken, createSessionAccessToken(t.Context(), coreStrategy, store, store.GetClients()["custom-lifespan-client"], subject), "")
				handler := newLifetimeAccessTokenHandler(config, coreStrategy, store)

				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(handler.HandleTokenEndpointRequest(t.Context(), request)))

				response := oauth2.NewAccessResponse()

				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(handler.PopulateTokenEndpointResponse(t.Context(), request, response)))

				assert.WithinDuration(t, subject.GetExpiresAt(oauth2.AccessToken), request.GetSession().GetExpiresAt(oauth2.AccessToken), time.Second)
				assert.LessOrEqual(t, response.ToMap()[consts.AccessResponseExpiresIn], int64((10 * time.Minute).Seconds()))

				// RFC 8693 Section 2.2.1: a refresh token is typically not issued for a temporary credential.
				assert.Empty(t, response.GetExtra(consts.FormParameterRefreshToken))
			})

			t.Run("ShouldCapTheAccessAndRefreshTokensAtARefreshTokenSubject", func(t *testing.T) {
				store := sc.newStore()
				config, coreStrategy := newBindingExchangeConfig()

				expires := time.Now().UTC().Add(20 * time.Minute).Truncate(time.Second)

				request := newLifetimeExchangeRequest(store, consts.TokenTypeRFC8693RefreshToken, createSessionRefreshToken(t.Context(), coreStrategy, store, store.GetClients()["custom-lifespan-client"], expires), "")

				refreshHandler := newLifetimeRefreshTokenHandler(config, coreStrategy, store)
				handler := newLifetimeAccessTokenHandler(config, coreStrategy, store)

				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(refreshHandler.HandleTokenEndpointRequest(t.Context(), request)))

				response := oauth2.NewAccessResponse()

				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(handler.PopulateTokenEndpointResponse(t.Context(), request, response)))

				assert.WithinDuration(t, expires, request.GetSession().GetExpiresAt(oauth2.AccessToken), time.Second)
				assert.WithinDuration(t, expires, request.GetSession().GetExpiresAt(oauth2.RefreshToken), time.Second)
				assert.NotEmpty(t, response.GetExtra(consts.FormParameterRefreshToken))
			})

			t.Run("ShouldCapAnExplicitRefreshTokenAtARefreshTokenSubject", func(t *testing.T) {
				store := sc.newStore()
				config, coreStrategy := newBindingExchangeConfig()

				expires := time.Now().UTC().Add(20 * time.Minute).Truncate(time.Second)

				request := newLifetimeExchangeRequest(store, consts.TokenTypeRFC8693RefreshToken, createSessionRefreshToken(t.Context(), coreStrategy, store, store.GetClients()["custom-lifespan-client"], expires), consts.TokenTypeRFC8693RefreshToken)
				handler := newLifetimeRefreshTokenHandler(config, coreStrategy, store)

				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(handler.HandleTokenEndpointRequest(t.Context(), request)))

				response := oauth2.NewAccessResponse()

				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(handler.PopulateTokenEndpointResponse(t.Context(), request, response)))

				assert.WithinDuration(t, expires, request.GetSession().GetExpiresAt(oauth2.RefreshToken), time.Second)
			})

			t.Run("ShouldKeepTheSubjectTokenDeadlineWhenTheExchangedRefreshTokenIsRefreshed", func(t *testing.T) {
				testCases := []struct {
					name      string
					requested string
					refresh   func(response *oauth2.AccessResponse) string
				}{
					{
						name:      "AccessTokenType",
						requested: "",
						refresh: func(response *oauth2.AccessResponse) string {
							token, _ := response.GetExtra(consts.FormParameterRefreshToken).(string)

							return token
						},
					},
					{
						name:      "RefreshTokenType",
						requested: consts.TokenTypeRFC8693RefreshToken,
						refresh: func(response *oauth2.AccessResponse) string {
							return response.GetAccessToken()
						},
					},
				}

				for _, tc := range testCases {
					t.Run(tc.name, func(t *testing.T) {
						store := sc.newStore()
						config, coreStrategy := newBindingExchangeConfig()
						config.RefreshTokenScopes = []string{}

						expires := time.Now().UTC().Add(20 * time.Minute).Truncate(time.Second)

						request := newLifetimeExchangeRequest(store, consts.TokenTypeRFC8693RefreshToken, createSessionRefreshToken(t.Context(), coreStrategy, store, store.GetClients()["custom-lifespan-client"], expires), tc.requested)

						refreshHandler := newLifetimeRefreshTokenHandler(config, coreStrategy, store)

						require.NoError(t, oauth2.ErrorToDebugRFC6749Error(refreshHandler.HandleTokenEndpointRequest(t.Context(), request)))

						var issuer oauth2.TokenEndpointHandler = newLifetimeAccessTokenHandler(config, coreStrategy, store)
						if tc.requested == consts.TokenTypeRFC8693RefreshToken {
							issuer = refreshHandler
						}

						response := oauth2.NewAccessResponse()

						require.NoError(t, oauth2.ErrorToDebugRFC6749Error(issuer.PopulateTokenEndpointResponse(t.Context(), request, response)))

						token := tc.refresh(response)
						require.NotEmpty(t, token)

						refreshed := redeemLifetimeRefreshToken(t, config, coreStrategy, store, token)

						assert.False(t, refreshed.GetSession().GetExpiresAt(oauth2.AccessToken).After(expires))
						assert.False(t, refreshed.GetSession().GetExpiresAt(oauth2.RefreshToken).After(expires))
					})
				}
			})

			t.Run("ShouldRejectAnExplicitRefreshTokenForAnAccessTokenSubject", func(t *testing.T) {
				store := sc.newStore()
				config, coreStrategy := newBindingExchangeConfig()

				subject := NewDefaultSession()
				subject.SetSubject("peter")

				request := newLifetimeExchangeRequest(store, consts.TokenTypeRFC8693AccessToken, createSessionAccessToken(t.Context(), coreStrategy, store, store.GetClients()["custom-lifespan-client"], subject), consts.TokenTypeRFC8693RefreshToken)

				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(newLifetimeAccessTokenHandler(config, coreStrategy, store).HandleTokenEndpointRequest(t.Context(), request)))

				err := newLifetimeRefreshTokenHandler(config, coreStrategy, store).PopulateTokenEndpointResponse(t.Context(), request, oauth2.NewAccessResponse())

				require.ErrorIs(t, err, oauth2.ErrInvalidRequest)
				assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. A refresh token can only be issued by a token exchange whose 'subject_token' is a refresh token.")
			})
		})
	}
}

func TestExchangedJWTLifetime(t *testing.T) {
	store := storage.NewExampleStore()
	cfg := newSpecConfig(t)

	jwtStrategy := &jwt.DefaultStrategy{Config: cfg, Issuer: jwt.NewDefaultIssuerRS256Unverified(key)}

	client := store.Clients["my-client"]

	testCases := []struct {
		name    string
		handler oauth2.TokenEndpointHandler
		typ     string
		claims  jwt.MapClaims
	}{
		{
			name: "ShouldCapAnIDTokenAtTheSubjectToken",
			handler: &IDTokenTypeHandler{
				Config:             cfg,
				Strategy:           jwtStrategy,
				IssueStrategy:      &openid.DefaultStrategy{Strategy: jwtStrategy, Config: cfg},
				ValidationStrategy: &openid.DefaultIDTokenValidationStrategy{Strategy: jwtStrategy},
				Storage:            store,
			},
			typ:    consts.TokenTypeRFC8693IDToken,
			claims: jwt.MapClaims{consts.ClaimAudience: []string{client.GetID()}},
		},
		{
			name: "ShouldCapACustomJWTAtTheSubjectToken",
			handler: &CustomJWTTypeHandler{
				Config:   cfg,
				Strategy: jwtStrategy,
				Storage:  store,
			},
			typ:    "urn:spec:jwt",
			claims: jwt.MapClaims{consts.ClaimIssuer: "https://as.example.com", "subject": "peter"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			expires := time.Now().Add(2 * time.Minute).Unix()

			claims := jwt.MapClaims{
				consts.ClaimSubject:        "peter",
				consts.ClaimExpirationTime: expires,
				consts.ClaimIssuedAt:       time.Now().Unix(),
			}

			for k, v := range tc.claims {
				claims[k] = v
			}

			request := &oauth2.AccessRequest{
				GrantTypes: oauth2.Arguments{consts.GrantTypeOAuthTokenExchange},
				Request: oauth2.Request{
					ID:     uuid.New().String(),
					Client: client,
					Form: url.Values{
						consts.FormParameterGrantType:          {consts.GrantTypeOAuthTokenExchange},
						consts.FormParameterSubjectTokenType:   {tc.typ},
						consts.FormParameterSubjectToken:       {createJWT(t.Context(), client, jwtStrategy, claims)},
						consts.FormParameterRequestedTokenType: {tc.typ},
					},
					Session: newSpecSession("peter"),
				},
			}

			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(tc.handler.HandleTokenEndpointRequest(t.Context(), request)))

			response := oauth2.NewAccessResponse()

			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(tc.handler.PopulateTokenEndpointResponse(t.Context(), request, response)))

			issued := map[string]any{}

			_, err := jwt.UnsafeParseSignedAny(response.GetAccessToken(), &issued)
			require.NoError(t, err)

			assert.LessOrEqual(t, int64(issued[consts.ClaimExpirationTime].(float64)), expires)
			assert.LessOrEqual(t, response.ToMap()[consts.AccessResponseExpiresIn], int64((2 * time.Minute).Seconds()))
		})
	}
}

func redeemLifetimeRefreshToken(t *testing.T, config *oauth2.Config, coreStrategy hoauth2.CoreStrategy, store rfc8693ExchangeStore, token string) *oauth2.AccessRequest {
	t.Helper()

	revocation, ok := store.(hoauth2.TokenRevocationStorage)
	require.True(t, ok)

	handler := &hoauth2.RefreshTokenGrantHandler{
		AccessTokenStrategy:    coreStrategy,
		RefreshTokenStrategy:   coreStrategy,
		TokenRevocationStorage: revocation,
		Config:                 config,
	}

	request := oauth2.NewAccessRequest(NewDefaultSession())
	request.Client = store.GetClients()["my-client"]
	request.GrantTypes = oauth2.Arguments{consts.GrantTypeRefreshToken}
	request.Form.Set(consts.FormParameterRefreshToken, token)

	require.NoError(t, oauth2.ErrorToDebugRFC6749Error(handler.HandleTokenEndpointRequest(t.Context(), request)))
	require.NoError(t, oauth2.ErrorToDebugRFC6749Error(handler.PopulateTokenEndpointResponse(t.Context(), request, oauth2.NewAccessResponse())))

	return request
}

func newLifetimeExchangeRequest(store rfc8693ExchangeStore, subjectTokenType, subjectToken, requestedTokenType string) *oauth2.AccessRequest {
	form := url.Values{
		consts.FormParameterGrantType:        {consts.GrantTypeOAuthTokenExchange},
		consts.FormParameterSubjectTokenType: {subjectTokenType},
		consts.FormParameterSubjectToken:     {subjectToken},
	}

	if requestedTokenType != "" {
		form.Set(consts.FormParameterRequestedTokenType, requestedTokenType)
	}

	return &oauth2.AccessRequest{
		GrantTypes: oauth2.Arguments{consts.GrantTypeOAuthTokenExchange},
		Request: oauth2.Request{
			ID:      uuid.New().String(),
			Client:  store.GetClients()["my-client"],
			Form:    form,
			Session: NewDefaultSession(),
		},
	}
}

func newLifetimeAccessTokenHandler(config *oauth2.Config, coreStrategy hoauth2.CoreStrategy, store rfc8693ExchangeStore) *AccessTokenTypeHandler {
	return &AccessTokenTypeHandler{
		Config:               config,
		AccessTokenLifespan:  time.Hour,
		RefreshTokenLifespan: 24 * time.Hour,
		CoreStrategy:         coreStrategy,
		ScopeStrategy:        config.ScopeStrategy,
		Storage:              store,
	}
}

func newLifetimeRefreshTokenHandler(config *oauth2.Config, coreStrategy hoauth2.CoreStrategy, store rfc8693ExchangeStore) *RefreshTokenTypeHandler {
	return &RefreshTokenTypeHandler{
		Config:               config,
		RefreshTokenLifespan: 24 * time.Hour,
		CoreStrategy:         coreStrategy,
		ScopeStrategy:        config.ScopeStrategy,
		Storage:              store,
	}
}

func createSessionRefreshToken(ctx context.Context, coreStrategy hoauth2.CoreStrategy, store rfc8693ExchangeStore, client oauth2.Client, expires time.Time) string {
	session := NewDefaultSession()
	session.SetSubject("peter")
	session.SetExpiresAt(oauth2.RefreshToken, expires)

	request := &oauth2.AccessRequest{
		GrantTypes: oauth2.Arguments{"password"},
		Request: oauth2.Request{
			ID:      uuid.New().String(),
			Session: session,
			Client:  client,
		},
	}

	token, signature, err := coreStrategy.GenerateRefreshToken(ctx, request)
	if err != nil {
		panic(err.Error())
	}

	if err = store.(hoauth2.TokenRevocationStorage).CreateRefreshTokenSession(ctx, signature, "", request.Sanitize([]string{})); err != nil {
		panic(err.Error())
	}

	return token
}
