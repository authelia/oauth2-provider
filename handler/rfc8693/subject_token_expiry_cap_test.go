// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc8693_test

import (
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

// RFC 8693 Section 2.1: the expiration of the output token may be influenced by that of the input token.
func TestSubjectTokenExpiryCapPolicy(t *testing.T) {
	testCases := []struct {
		name     string
		disable  bool
		override bool
		capped   bool
		expected bool
	}{
		{name: "ShouldCapByDefault", expected: true},
		{name: "ShouldNotCapWhenDisabledByConfig", disable: true},
		{name: "ShouldNotCapWhenTheClientOptsOut", override: true},
		{name: "ShouldCapWhenTheClientOptsInOverConfig", disable: true, override: true, capped: true, expected: true},
		{name: "ShouldIgnoreTheClientValueWithoutTheOverride", disable: true, capped: true},
	}

	requested := []string{"", consts.TokenTypeRFC8693RefreshToken}

	for _, sc := range bindingExchangeStores() {
		for _, tokenType := range requested {
			for _, tc := range testCases {
				t.Run(sc.name+"/"+requestedName(tokenType)+"/"+tc.name, func(t *testing.T) {
					store := sc.newStore()
					config, coreStrategy := newBindingExchangeConfig()
					config.RFC8693DisableSubjectTokenExpiryCap = tc.disable

					expires := time.Now().UTC().Add(20 * time.Minute).Truncate(time.Second)

					request := newLifetimeExchangeRequest(store, consts.TokenTypeRFC8693RefreshToken, createSessionRefreshToken(t.Context(), coreStrategy, store, store.GetClients()["my-client"], expires), tokenType)
					request.Client = &expiryCapOverrideClient{permittingOwnerClient: request.Client.(*permittingOwnerClient), override: tc.override, capped: tc.capped}

					populateLifetimeExchange(t, config, coreStrategy, store, request, tokenType, 24*time.Hour)

					now := time.Now().UTC()

					if tc.expected {
						assert.WithinDuration(t, expires, request.GetSession().GetExpiresAt(oauth2.RefreshToken), time.Second)

						if tokenType == "" {
							assert.WithinDuration(t, expires, request.GetSession().GetExpiresAt(oauth2.AccessToken), time.Second)
						}

						return
					}

					assert.WithinDuration(t, now.Add(24*time.Hour), request.GetSession().GetExpiresAt(oauth2.RefreshToken), 5*time.Second)

					if tokenType == "" {
						assert.WithinDuration(t, now.Add(time.Hour), request.GetSession().GetExpiresAt(oauth2.AccessToken), 5*time.Second)
					}
				})
			}
		}
	}
}

func TestSubjectTokenExpiryCapDisabled(t *testing.T) {
	for _, sc := range bindingExchangeStores() {
		t.Run(sc.name, func(t *testing.T) {
			t.Run("ShouldNotCapTheAccessTokenAtAnAccessTokenSubject", func(t *testing.T) {
				store := sc.newStore()
				config, coreStrategy := newBindingExchangeConfig()
				config.RFC8693DisableSubjectTokenExpiryCap = true

				subject := NewDefaultSession()
				subject.SetSubject("peter")

				request := newLifetimeExchangeRequest(store, consts.TokenTypeRFC8693AccessToken, createSessionAccessToken(t.Context(), coreStrategy, store, store.GetClients()["custom-lifespan-client"], subject), "")
				handler := newLifetimeAccessTokenHandler(config, coreStrategy, store)

				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(handler.HandleTokenEndpointRequest(t.Context(), request)))

				response := oauth2.NewAccessResponse()

				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(handler.PopulateTokenEndpointResponse(t.Context(), request, response)))

				assert.WithinDuration(t, time.Now().UTC().Add(time.Hour), request.GetSession().GetExpiresAt(oauth2.AccessToken), 5*time.Second)
				assert.InDelta(t, int64(time.Hour.Seconds()), response.ToMap()[consts.AccessResponseExpiresIn], 5)
			})

			for _, tokenType := range []string{"", consts.TokenTypeRFC8693RefreshToken} {
				t.Run("ShouldNotExpireARefreshTokenWithANegativeLifespan/"+requestedName(tokenType), func(t *testing.T) {
					store := sc.newStore()
					config, coreStrategy := newBindingExchangeConfig()
					config.RFC8693DisableSubjectTokenExpiryCap = true
					config.RefreshTokenScopes = []string{}
					config.RefreshTokenLifespan = -1

					expires := time.Now().UTC().Add(20 * time.Minute).Truncate(time.Second)

					request := newLifetimeExchangeRequest(store, consts.TokenTypeRFC8693RefreshToken, createSessionRefreshToken(t.Context(), coreStrategy, store, store.GetClients()["my-client"], expires), tokenType)

					response := populateLifetimeExchange(t, config, coreStrategy, store, request, tokenType, -1)

					assert.True(t, request.GetSession().GetExpiresAt(oauth2.RefreshToken).IsZero())

					token := response.GetAccessToken()
					if tokenType == "" {
						token, _ = response.GetExtra(consts.FormParameterRefreshToken).(string)
					} else {
						assert.NotContains(t, response.ToMap(), consts.AccessResponseExpiresIn)
					}

					require.NotEmpty(t, token)

					refreshed := redeemLifetimeRefreshToken(t, config, coreStrategy, store, token)

					assert.True(t, refreshed.GetSession().GetExpiresAt(oauth2.RefreshToken).IsZero())
				})

				t.Run("ShouldNotRecordADeadlineWhenTheSubjectRefreshTokenIsNotRotated/"+requestedName(tokenType), func(t *testing.T) {
					store := sc.newStore()
					config, coreStrategy := newBindingExchangeConfig()
					config.RFC8693DisableSubjectTokenExpiryCap = true
					config.RefreshTokenScopes = []string{}
					config.AccessTokenLifespan = time.Hour
					config.RefreshTokenLifespan = 24 * time.Hour
					config.DisableRefreshTokenRotation = true

					expires := time.Now().UTC().Add(20 * time.Minute).Truncate(time.Second)

					request := newLifetimeExchangeRequest(store, consts.TokenTypeRFC8693RefreshToken, createSessionRefreshToken(t.Context(), coreStrategy, store, store.GetClients()["my-client"], expires), tokenType)

					response := populateLifetimeExchange(t, config, coreStrategy, store, request, tokenType, 24*time.Hour)

					assert.True(t, request.GetSession().(oauth2.ExpiryDeadlineSession).GetExpiryDeadline().IsZero())

					token := response.GetAccessToken()
					if tokenType == "" {
						token, _ = response.GetExtra(consts.FormParameterRefreshToken).(string)
					}

					require.NotEmpty(t, token)

					config.DisableRefreshTokenRotation = false

					refreshed := redeemLifetimeRefreshToken(t, config, coreStrategy, store, token)

					assert.True(t, refreshed.GetSession().(oauth2.ExpiryDeadlineSession).GetExpiryDeadline().IsZero())
					assert.True(t, refreshed.GetSession().GetExpiresAt(oauth2.AccessToken).After(expires))
					assert.True(t, refreshed.GetSession().GetExpiresAt(oauth2.RefreshToken).After(expires))
				})

				for _, unrotated := range []bool{false, true} {
					name := "Rotated"
					if unrotated {
						name = "Unrotated"
					}

					t.Run("ShouldKeepTheExpiryDeadlineOfTheGrant/"+requestedName(tokenType)+"/"+name, func(t *testing.T) {
						store := sc.newStore()
						config, coreStrategy := newBindingExchangeConfig()
						config.RFC8693DisableSubjectTokenExpiryCap = true
						config.DisableRefreshTokenRotation = unrotated

						now := time.Now().UTC().Truncate(time.Second)
						deadline := now.Add(10 * time.Minute)

						session := NewDefaultSession()
						session.SetSubject("peter")
						session.SetExpiresAt(oauth2.RefreshToken, now.Add(5*time.Minute))
						session.SetExpiryDeadline(deadline)

						issued := &oauth2.AccessRequest{
							GrantTypes: oauth2.Arguments{"password"},
							Request: oauth2.Request{
								ID:      uuid.New().String(),
								Session: session,
								Client:  store.GetClients()["my-client"],
							},
						}

						token, signature, err := coreStrategy.GenerateRefreshToken(t.Context(), issued)
						require.NoError(t, err)
						require.NoError(t, store.CreateRefreshTokenSession(t.Context(), signature, "", issued.Sanitize([]string{})))

						request := newLifetimeExchangeRequest(store, consts.TokenTypeRFC8693RefreshToken, token, tokenType)

						populateLifetimeExchange(t, config, coreStrategy, store, request, tokenType, 24*time.Hour)

						assert.Equal(t, deadline, request.GetSession().(oauth2.ExpiryDeadlineSession).GetExpiryDeadline())
						assert.Equal(t, deadline, request.GetSession().GetExpiresAt(oauth2.RefreshToken))

						if tokenType == "" {
							assert.Equal(t, deadline.Unix(), request.GetSession().GetExpiresAt(oauth2.AccessToken).Unix())
						}
					})
				}
			}
		})
	}
}

func TestExchangedJWTLifetimeWithoutTheSubjectTokenExpiryCap(t *testing.T) {
	testCases := []struct {
		name     string
		typ      string
		claims   jwt.MapClaims
		disable  bool
		override bool
		capped   bool
		lifespan time.Duration
	}{
		{name: "ShouldNotCapAnIDTokenWhenDisabledByConfig", typ: consts.TokenTypeRFC8693IDToken, disable: true, lifespan: 10 * time.Minute},
		{name: "ShouldNotCapAnIDTokenWhenTheClientOptsOut", typ: consts.TokenTypeRFC8693IDToken, override: true, lifespan: 10 * time.Minute},
		{name: "ShouldCapAnIDTokenWhenTheClientOptsIn", typ: consts.TokenTypeRFC8693IDToken, disable: true, override: true, capped: true},
		{name: "ShouldNotCapACustomJWTWhenDisabledByConfig", typ: "urn:spec:jwt", disable: true, lifespan: 5 * time.Minute},
		{name: "ShouldNotCapACustomJWTWhenTheClientOptsOut", typ: "urn:spec:jwt", override: true, lifespan: 5 * time.Minute},
		{name: "ShouldCapACustomJWTWhenTheClientOptsIn", typ: "urn:spec:jwt", disable: true, override: true, capped: true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			store := storage.NewExampleStore()
			cfg := newSpecConfig(t)
			cfg.RFC8693DisableSubjectTokenExpiryCap = tc.disable

			jwtStrategy := &jwt.DefaultStrategy{Config: cfg, Issuer: jwt.NewDefaultIssuerRS256Unverified(key)}

			client := &expiryCapOverrideIDTokenClient{ownIDTokenExchangeClient: ownIDTokenClient(store.Clients["my-client"]).(*ownIDTokenExchangeClient), override: tc.override, capped: tc.capped}

			var handler oauth2.TokenEndpointHandler

			expires := time.Now().Add(2 * time.Minute).Unix()

			claims := jwt.MapClaims{
				consts.ClaimSubject:        "peter",
				consts.ClaimExpirationTime: expires,
				consts.ClaimIssuedAt:       time.Now().Unix(),
			}

			if tc.typ == consts.TokenTypeRFC8693IDToken {
				claims[consts.ClaimAudience] = []string{client.GetID()}

				handler = &IDTokenTypeHandler{
					Config:             cfg,
					Strategy:           jwtStrategy,
					IssueStrategy:      &openid.DefaultStrategy{Strategy: jwtStrategy, Config: cfg},
					ValidationStrategy: &openid.DefaultIDTokenValidationStrategy{Strategy: jwtStrategy},
					Storage:            store,
				}
			} else {
				claims[consts.ClaimIssuer] = "https://as.example.com"

				handler = &CustomJWTTypeHandler{Config: cfg, Strategy: jwtStrategy, Storage: store}
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

			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(handler.HandleTokenEndpointRequest(t.Context(), request)))

			response := oauth2.NewAccessResponse()

			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(handler.PopulateTokenEndpointResponse(t.Context(), request, response)))

			issued := map[string]any{}

			_, err := jwt.UnsafeParseSignedAny(response.GetAccessToken(), &issued)
			require.NoError(t, err)

			if tc.capped {
				assert.LessOrEqual(t, int64(issued[consts.ClaimExpirationTime].(float64)), expires)

				return
			}

			assert.InDelta(t, time.Now().Add(tc.lifespan).Unix(), int64(issued[consts.ClaimExpirationTime].(float64)), 5)
			assert.InDelta(t, int64(tc.lifespan.Seconds()), response.ToMap()[consts.AccessResponseExpiresIn], 5)
		})
	}
}

func TestCapIssuedTokenExpiry(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)

	session := NewDefaultSession()
	session.SetSubjectToken(map[string]any{consts.ClaimExpirationTime: now.Add(time.Minute).Unix()})

	request := &oauth2.Request{Client: &oauth2.DefaultClient{ID: "example"}, Session: session}

	assert.Equal(t, now.Add(time.Minute), CapIssuedTokenExpiry(t.Context(), nil, request, now.Add(time.Hour)))
	assert.Equal(t, now.Add(time.Minute), CapIssuedTokenExpiry(t.Context(), &oauth2.Config{}, request, now.Add(time.Hour)))
	assert.Equal(t, now.Add(time.Second), CapIssuedTokenExpiry(t.Context(), &oauth2.Config{}, request, now.Add(time.Second)))
	assert.Equal(t, now.Add(time.Hour), CapIssuedTokenExpiry(t.Context(), &oauth2.Config{RFC8693DisableSubjectTokenExpiryCap: true}, request, now.Add(time.Hour)))
}

func populateLifetimeExchange(t *testing.T, config *oauth2.Config, coreStrategy hoauth2.CoreStrategy, store rfc8693ExchangeStore, request *oauth2.AccessRequest, tokenType string, refresh time.Duration) *oauth2.AccessResponse {
	t.Helper()

	refreshHandler := newLifetimeRefreshTokenHandler(config, coreStrategy, store)
	refreshHandler.RefreshTokenLifespan = refresh

	require.NoError(t, oauth2.ErrorToDebugRFC6749Error(refreshHandler.HandleTokenEndpointRequest(t.Context(), request)))

	var issuer oauth2.TokenEndpointHandler = refreshHandler

	if tokenType == "" {
		handler := newLifetimeAccessTokenHandler(config, coreStrategy, store)
		handler.RefreshTokenLifespan = refresh
		issuer = handler
	}

	response := oauth2.NewAccessResponse()

	require.NoError(t, oauth2.ErrorToDebugRFC6749Error(issuer.PopulateTokenEndpointResponse(t.Context(), request, response)))

	return response
}

func requestedName(tokenType string) string {
	if tokenType == "" {
		return "AccessTokenType"
	}

	return "RefreshTokenType"
}

type expiryCapOverrideClient struct {
	*permittingOwnerClient

	override bool
	capped   bool
}

func (c *expiryCapOverrideClient) GetOverrideTokenExchangeSubjectTokenExpiryCap() bool {
	return c.override
}

func (c *expiryCapOverrideClient) GetTokenExchangeSubjectTokenExpiryCap() bool { return c.capped }

type expiryCapOverrideIDTokenClient struct {
	*ownIDTokenExchangeClient

	override bool
	capped   bool
}

func (c *expiryCapOverrideIDTokenClient) GetOverrideTokenExchangeSubjectTokenExpiryCap() bool {
	return c.override
}

func (c *expiryCapOverrideIDTokenClient) GetTokenExchangeSubjectTokenExpiryCap() bool {
	return c.capped
}
