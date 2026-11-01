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
	"authelia.com/provider/oauth2/handler/openid"
	. "authelia.com/provider/oauth2/handler/rfc8693"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestTokenExchangeHonoursTheIssuanceDecision(t *testing.T) {
	testCases := []struct {
		name      string
		requested string
		decision  *oauth2.IssuanceDecision
		assert    func(t *testing.T, request *oauth2.AccessRequest, response *oauth2.AccessResponse)
	}{
		{
			name:      "ShouldCapTheAccessToken",
			requested: consts.TokenTypeRFC8693AccessToken,
			decision:  &oauth2.IssuanceDecision{Lifespans: map[oauth2.TokenType]time.Duration{oauth2.AccessToken: time.Minute}},
			assert: func(t *testing.T, request *oauth2.AccessRequest, _ *oauth2.AccessResponse) {
				assert.WithinDuration(t, time.Now().Add(time.Minute), request.GetSession().GetExpiresAt(oauth2.AccessToken), 2*time.Second)
			},
		},
		{
			name:      "ShouldCapARefreshTokenIssuedWithAnAccessToken",
			requested: consts.TokenTypeRFC8693AccessToken,
			decision:  &oauth2.IssuanceDecision{Lifespans: map[oauth2.TokenType]time.Duration{oauth2.RefreshToken: time.Minute}},
			assert: func(t *testing.T, request *oauth2.AccessRequest, response *oauth2.AccessResponse) {
				assert.NotEmpty(t, response.GetExtra(consts.FormParameterRefreshToken))
				assert.WithinDuration(t, time.Now().Add(time.Minute), request.GetSession().GetExpiresAt(oauth2.RefreshToken), 2*time.Second)
			},
		},
		{
			name:      "ShouldOmitADeniedRefreshTokenIssuedWithAnAccessToken",
			requested: consts.TokenTypeRFC8693AccessToken,
			decision:  &oauth2.IssuanceDecision{DeniedTokens: []oauth2.TokenType{oauth2.RefreshToken}},
			assert: func(t *testing.T, _ *oauth2.AccessRequest, response *oauth2.AccessResponse) {
				assert.Empty(t, response.GetExtra(consts.FormParameterRefreshToken))
				assert.NotEmpty(t, response.GetAccessToken())
			},
		},
		{
			name:      "ShouldCapARequestedRefreshToken",
			requested: consts.TokenTypeRFC8693RefreshToken,
			decision:  &oauth2.IssuanceDecision{Lifespans: map[oauth2.TokenType]time.Duration{oauth2.RefreshToken: time.Minute}},
			assert: func(t *testing.T, request *oauth2.AccessRequest, _ *oauth2.AccessResponse) {
				assert.WithinDuration(t, time.Now().Add(time.Minute), request.GetSession().GetExpiresAt(oauth2.RefreshToken), 2*time.Second)
			},
		},
	}

	for _, sc := range bindingExchangeStores() {
		for _, tc := range testCases {
			t.Run(sc.name+"/"+tc.name, func(t *testing.T) {
				store := sc.newStore()
				config, strategy := newBindingExchangeConfig()
				config.RefreshTokenScopes = []string{}
				config.RFC8693TokenTypes[consts.TokenTypeRFC8693RefreshToken] = &DefaultTokenType{Name: consts.TokenTypeRFC8693RefreshToken}

				client := store.GetClients()["my-client"].(*oauth2.DefaultClient)
				token := chainSubjectToken(t, strategy, store, client, newOptInSubject(), true)

				request := newLifetimeExchangeRequest(store, consts.TokenTypeRFC8693RefreshToken, token, tc.requested)
				request.Client = &oauth2.DefaultRegisteredClient{DefaultClient: client, TokenExchangeRefreshToken: true}

				access := newLifetimeAccessTokenHandler(config, strategy, store)
				access.RefreshTokenScopes = []string{}

				refresh := newLifetimeRefreshTokenHandler(config, strategy, store)
				refresh.RefreshTokenScopes = []string{}

				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(refresh.HandleTokenEndpointRequest(t.Context(), request)))

				ctx := context.WithValue(t.Context(), oauth2.IssuanceDecisionContextKey, tc.decision)
				response := oauth2.NewAccessResponse()

				if tc.requested == consts.TokenTypeRFC8693RefreshToken {
					require.NoError(t, oauth2.ErrorToDebugRFC6749Error(refresh.PopulateTokenEndpointResponse(ctx, request, response)))
				} else {
					require.NoError(t, oauth2.ErrorToDebugRFC6749Error(access.PopulateTokenEndpointResponse(ctx, request, response)))
				}

				tc.assert(t, request, response)
			})
		}
	}
}

func TestTokenExchangeCapsSignedTokensToTheIssuanceDecision(t *testing.T) {
	testCases := []struct {
		name  string
		token oauth2.TokenType
		issue func(t *testing.T, ctx context.Context, response *oauth2.AccessResponse)
	}{
		{
			name:  "ShouldCapAnIDToken",
			token: oauth2.IDToken,
			issue: func(t *testing.T, ctx context.Context, response *oauth2.AccessResponse) {
				store := storage.NewExampleStore()
				cfg := newSpecConfig(t)
				strategy := &jwt.DefaultStrategy{Config: cfg, Issuer: jwt.NewDefaultIssuerRS256Unverified(key)}
				client := store.Clients["my-client"]

				handler := &IDTokenTypeHandler{
					Config:             cfg,
					Strategy:           strategy,
					IssueStrategy:      &openid.DefaultStrategy{Strategy: strategy, Config: cfg},
					ValidationStrategy: &openid.DefaultIDTokenValidationStrategy{Strategy: strategy},
					Storage:            store,
				}

				request := &oauth2.AccessRequest{
					GrantTypes: oauth2.Arguments{consts.GrantTypeOAuthTokenExchange},
					Request: oauth2.Request{
						ID:     uuid.New().String(),
						Client: client,
						Form: url.Values{
							consts.FormParameterGrantType:          {consts.GrantTypeOAuthTokenExchange},
							consts.FormParameterRequestedTokenType: {consts.TokenTypeRFC8693IDToken},
							consts.FormParameterSubjectTokenType:   {consts.TokenTypeRFC8693IDToken},
							consts.FormParameterSubjectToken: {createJWT(t.Context(), client, strategy, jwt.MapClaims{
								consts.ClaimSubject:        "peter",
								consts.ClaimAudience:       []string{client.GetID()},
								consts.ClaimExpirationTime: time.Now().Add(time.Hour).Unix(),
								consts.ClaimIssuedAt:       time.Now().Unix(),
							})},
						},
						Session: newSpecSession("peter"),
					},
				}

				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(handler.HandleTokenEndpointRequest(t.Context(), request)))
				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(handler.PopulateTokenEndpointResponse(ctx, request, response)))
			},
		},
		{
			name:  "ShouldCapACustomJWT",
			token: oauth2.ExchangedToken,
			issue: func(t *testing.T, ctx context.Context, response *oauth2.AccessResponse) {
				fixture := newCustomJWTConsumeFixture(t, false)

				request := fixture.request(url.Values{
					consts.FormParameterRequestedTokenType: {"urn:spec:jwt"},
					consts.FormParameterSubjectTokenType:   {"urn:spec:jwt"},
					consts.FormParameterSubjectToken:       {fixture.token(t, uuid.New().String())},
				})

				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(fixture.custom.HandleTokenEndpointRequest(t.Context(), request)))
				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(fixture.custom.PopulateTokenEndpointResponse(ctx, request, response)))
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.WithValue(t.Context(), oauth2.IssuanceDecisionContextKey, &oauth2.IssuanceDecision{Lifespans: map[oauth2.TokenType]time.Duration{tc.token: time.Minute}})
			response := oauth2.NewAccessResponse()

			tc.issue(t, ctx, response)

			assert.LessOrEqual(t, response.ToMap()[consts.AccessResponseExpiresIn], int64(60))
		})
	}
}
