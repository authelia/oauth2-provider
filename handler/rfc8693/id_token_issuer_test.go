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

func TestIDTokenSubjectTokenIssuer(t *testing.T) {
	testCases := []struct {
		name     string
		issuer   string
		allowed  []string
		expected string
	}{
		{
			name:   "ShouldAcceptTheIDTokenIssuer",
			issuer: "https://id.example.com",
		},
		{
			name:     "ShouldRejectTheAccessTokenIssuer",
			issuer:   "https://at.example.com",
			expected: "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Claim 'iss' from token must match the 'https://id.example.com'.",
		},
		{
			name:     "ShouldRejectAnIssuerOnlyTheClientPermits",
			issuer:   "https://jwt.example.com",
			allowed:  []string{"https://jwt.example.com"},
			expected: "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Claim 'iss' from token must match the 'https://id.example.com'.",
		},
		{
			name:    "ShouldAcceptTheIDTokenIssuerTheClientDoesNotPermit",
			issuer:  "https://id.example.com",
			allowed: []string{"https://jwt.example.com"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := newSpecConfig(t)
			config.IDTokenIssuer = "https://id.example.com"
			config.AccessTokenIssuer = "https://at.example.com"

			store := storage.NewExampleStore()
			client := &rfc8693Client{DefaultClient: store.Clients["my-client"].(*oauth2.DefaultClient), subjectTokenIssuers: tc.allowed}
			strategy := &jwt.DefaultStrategy{Config: config, Issuer: jwt.NewDefaultIssuerRS256Unverified(key)}

			token := createJWT(t.Context(), client, strategy, jwt.MapClaims{
				consts.ClaimIssuer:         tc.issuer,
				consts.ClaimSubject:        "peter",
				consts.ClaimAudience:       []string{client.GetID()},
				consts.ClaimExpirationTime: time.Now().Add(10 * time.Minute).Unix(),
				consts.ClaimIssuedAt:       time.Now().Unix(),
			})

			err := newIDTokenSubjectHandler(config, strategy, store).HandleTokenEndpointRequest(t.Context(), newIDTokenSubjectRequest(client, token))

			if tc.expected == "" {
				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
			} else {
				assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), tc.expected)
			}
		})
	}
}

func TestCustomJWTIsNotAcceptedAsIDTokenSubjectToken(t *testing.T) {
	testCases := []struct {
		name     string
		issuer   string
		expected string
	}{
		{
			name:     "ShouldRefuseToIssueWithTheIDTokenIssuer",
			issuer:   "https://as.example.com",
			expected: "The authorization server encountered an unexpected condition that prevented it from fulfilling the request. The JSON Web Token type 'urn:spec:jwt' has the issuer 'https://as.example.com' which is the ID Token issuer, so the issued token would be accepted as an ID Token.",
		},
		{
			name:   "ShouldIssueWithADistinctIssuer",
			issuer: "https://jwt.example.com",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := newSpecConfig(t)
			config.IDTokenIssuer = "https://as.example.com"
			config.RFC8693TokenTypes["urn:spec:jwt"].(*JWTType).Issuer = tc.issuer

			store := storage.NewExampleStore()
			client := store.Clients["my-client"]
			strategy := &jwt.DefaultStrategy{Config: config, Issuer: jwt.NewDefaultIssuerRS256Unverified(key)}

			handler := &CustomJWTTypeHandler{Config: config, Strategy: strategy, Storage: store}

			request := &oauth2.AccessRequest{
				GrantTypes: oauth2.Arguments{consts.GrantTypeOAuthTokenExchange},
				Request: oauth2.Request{
					ID:              uuid.New().String(),
					Client:          client,
					Session:         newValidatedSpecSession("alice"),
					GrantedAudience: oauth2.Arguments{client.GetID()},
					Form: url.Values{
						consts.FormParameterGrantType:          {consts.GrantTypeOAuthTokenExchange},
						consts.FormParameterRequestedTokenType: {"urn:spec:jwt"},
						consts.FormParameterSubjectToken:       {"opaque-subject-token"},
						consts.FormParameterSubjectTokenType:   {consts.TokenTypeRFC8693AccessToken},
					},
				},
			}

			response := oauth2.NewAccessResponse()

			err := handler.PopulateTokenEndpointResponse(t.Context(), request, response)

			if tc.expected != "" {
				assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), tc.expected)

				return
			}

			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

			err = newIDTokenSubjectHandler(config, strategy, store).HandleTokenEndpointRequest(t.Context(), newIDTokenSubjectRequest(client, response.AccessToken))

			assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Claim 'iss' from token must match the 'https://as.example.com'.")
		})
	}
}

func newIDTokenSubjectHandler(config *oauth2.Config, strategy jwt.Strategy, store *storage.MemoryStore) *IDTokenTypeHandler {
	return &IDTokenTypeHandler{
		Config:             config,
		Strategy:           strategy,
		IssueStrategy:      &openid.DefaultStrategy{Strategy: strategy, Config: config},
		ValidationStrategy: &openid.DefaultIDTokenValidationStrategy{Strategy: strategy},
		Storage:            store,
	}
}

func newIDTokenSubjectRequest(client oauth2.Client, token string) *oauth2.AccessRequest {
	return &oauth2.AccessRequest{
		GrantTypes: oauth2.Arguments{consts.GrantTypeOAuthTokenExchange},
		Request: oauth2.Request{
			ID:     uuid.New().String(),
			Client: client,
			Form: url.Values{
				consts.FormParameterGrantType:        {consts.GrantTypeOAuthTokenExchange},
				consts.FormParameterSubjectTokenType: {consts.TokenTypeRFC8693IDToken},
				consts.FormParameterSubjectToken:     {token},
			},
			Session: newSpecSession("peter"),
		},
	}
}
