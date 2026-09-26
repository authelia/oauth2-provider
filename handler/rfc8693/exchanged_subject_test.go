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
	"authelia.com/provider/oauth2/handler/openid"
	. "authelia.com/provider/oauth2/handler/rfc8693"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestExchangedTokenSubject(t *testing.T) {
	store := storage.NewExampleStore()
	cfg := newSpecConfig(t)

	jwtStrategy := &jwt.DefaultStrategy{Config: cfg, Issuer: jwt.NewDefaultIssuerRS256Unverified(key)}

	client := store.Clients["my-client"]

	idTokenHandler := &IDTokenTypeHandler{
		Config:             cfg,
		Strategy:           jwtStrategy,
		IssueStrategy:      &openid.DefaultStrategy{Strategy: jwtStrategy, Config: cfg},
		ValidationStrategy: &openid.DefaultIDTokenValidationStrategy{Strategy: jwtStrategy},
		Storage:            store,
	}

	customHandler := &CustomJWTTypeHandler{
		Config:   cfg,
		Strategy: jwtStrategy,
		Storage:  store,
	}

	newSession := func(seeded string) *DefaultSession {
		return &DefaultSession{
			DefaultSession: &openid.DefaultSession{
				Claims:  &jwt.IDTokenClaims{Subject: seeded},
				Headers: &jwt.Headers{},
				Subject: seeded,
			},
			Extra: map[string]any{},
		}
	}

	testCases := []struct {
		name    string
		handler oauth2.TokenEndpointHandler
		typ     string
		claims  jwt.MapClaims
		seeded  string
	}{
		{
			name:    "ShouldIssueAnIDTokenForTheExchangedSubjectWithAFreshSession",
			handler: idTokenHandler,
			typ:     consts.TokenTypeRFC8693IDToken,
			claims:  jwt.MapClaims{consts.ClaimAudience: []string{client.GetID()}},
		},
		{
			name:    "ShouldIssueAnIDTokenForTheExchangedSubjectWithASeededSession",
			handler: idTokenHandler,
			typ:     consts.TokenTypeRFC8693IDToken,
			claims:  jwt.MapClaims{consts.ClaimAudience: []string{client.GetID()}},
			seeded:  "my-client",
		},
		{
			name:    "ShouldIssueACustomJWTForTheExchangedSubjectWithAFreshSession",
			handler: customHandler,
			typ:     "urn:spec:jwt",
			claims:  jwt.MapClaims{consts.ClaimIssuer: "https://as.example.com", "subject": "peter"},
		},
		{
			name:    "ShouldIssueACustomJWTForTheExchangedSubjectWithASeededSession",
			handler: customHandler,
			typ:     "urn:spec:jwt",
			claims:  jwt.MapClaims{consts.ClaimIssuer: "https://as.example.com", "subject": "peter"},
			seeded:  "my-client",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			claims := jwt.MapClaims{
				consts.ClaimSubject:        "peter",
				consts.ClaimExpirationTime: time.Now().Add(10 * time.Minute).Unix(),
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
					Session: newSession(tc.seeded),
				},
			}

			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(tc.handler.HandleTokenEndpointRequest(t.Context(), request)))

			response := oauth2.NewAccessResponse()

			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(tc.handler.PopulateTokenEndpointResponse(t.Context(), request, response)))

			issued := map[string]any{}

			_, err := jwt.UnsafeParseSignedAny(response.GetAccessToken(), &issued)
			require.NoError(t, err)

			assert.Equal(t, "peter", issued[consts.ClaimSubject])
		})
	}
}
