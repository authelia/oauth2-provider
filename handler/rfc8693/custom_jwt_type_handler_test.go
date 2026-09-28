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

func TestCustomJWTTypeHandler_OmitsIDTokenKeyBindingConfirmation(t *testing.T) {
	config := newSpecConfig(t)
	store := storage.NewExampleStore()

	session := &DefaultSession{
		DefaultSession: &openid.DefaultSession{
			Claims: &jwt.IDTokenClaims{
				Subject: "alice",
				Confirmation: map[string]any{
					consts.ClaimConfirmationJWK: map[string]any{"kty": "EC", "crv": "P-256", "x": "x-value", "y": "y-value"},
				},
			},
			Headers: &jwt.Headers{Extra: map[string]any{
				consts.JSONWebTokenHeaderType: consts.JSONWebTokenTypeDPoPIDToken,
			}},
			Subject: "alice",
		},
		SubjectToken: map[string]any{consts.ClaimSubject: "alice"},
		Extra:        map[string]any{},
	}

	handler := &CustomJWTTypeHandler{
		Config:   config,
		Strategy: &jwt.DefaultStrategy{Config: config, Issuer: jwt.NewDefaultIssuerRS256Unverified(key)},
		Storage:  store,
	}

	request := &oauth2.AccessRequest{
		GrantTypes: oauth2.Arguments{consts.GrantTypeOAuthTokenExchange},
		Request: oauth2.Request{
			ID:      uuid.New().String(),
			Client:  store.Clients["my-client"],
			Session: session,
			Form: url.Values{
				consts.FormParameterGrantType:          {consts.GrantTypeOAuthTokenExchange},
				consts.FormParameterRequestedTokenType: {"urn:spec:jwt"},
				consts.FormParameterSubjectToken:       {"opaque-subject-token"},
				consts.FormParameterSubjectTokenType:   {consts.TokenTypeRFC8693AccessToken},
			},
		},
	}

	response := oauth2.NewAccessResponse()

	require.NoError(t, handler.PopulateTokenEndpointResponse(t.Context(), request, response))
	require.NotEmpty(t, response.AccessToken)

	var claims map[string]any

	token, err := jwt.UnsafeParseSignedAny(response.AccessToken, &claims)
	require.NoError(t, err)
	require.Len(t, token.Headers, 1)

	_, ok := claims[consts.ClaimConfirmation]
	assert.False(t, ok, "the exchanged token carried a 'cnf' claim")

	typ, _ := token.Headers[0].ExtraHeaders[consts.JSONWebTokenHeaderType].(string)
	assert.NotEqual(t, consts.JSONWebTokenTypeDPoPIDToken, typ, "the exchanged token carried a 'dpop+id_token' type")
}

func TestCustomJWTTypeHandlerExpiry(t *testing.T) {
	testCases := []struct {
		name     string
		expiry   time.Duration
		expected time.Duration
	}{
		{
			name:     "ShouldUseTheConfiguredExpiry",
			expiry:   5 * time.Minute,
			expected: 5 * time.Minute,
		},
		{
			name:     "ShouldDefaultAZeroExpiryToTheAccessTokenLifespan",
			expiry:   0,
			expected: 30 * time.Minute,
		},
		{
			name:     "ShouldDefaultANegativeExpiryToTheAccessTokenLifespan",
			expiry:   -1,
			expected: 30 * time.Minute,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := newSpecConfig(t)
			config.AccessTokenLifespan = 30 * time.Minute
			config.RFC8693TokenTypes["urn:spec:jwt"].(*JWTType).Expiry = tc.expiry

			store := storage.NewExampleStore()

			handler := &CustomJWTTypeHandler{
				Config:   config,
				Strategy: &jwt.DefaultStrategy{Config: config, Issuer: jwt.NewDefaultIssuerRS256Unverified(key)},
				Storage:  store,
			}

			request := &oauth2.AccessRequest{
				GrantTypes: oauth2.Arguments{consts.GrantTypeOAuthTokenExchange},
				Request: oauth2.Request{
					ID:      uuid.New().String(),
					Client:  store.Clients["my-client"],
					Session: newValidatedSpecSession("alice"),
					Form: url.Values{
						consts.FormParameterGrantType:          {consts.GrantTypeOAuthTokenExchange},
						consts.FormParameterRequestedTokenType: {"urn:spec:jwt"},
						consts.FormParameterSubjectToken:       {"opaque-subject-token"},
						consts.FormParameterSubjectTokenType:   {consts.TokenTypeRFC8693AccessToken},
					},
				},
			}

			response := oauth2.NewAccessResponse()

			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(handler.PopulateTokenEndpointResponse(t.Context(), request, response)))

			claims := map[string]any{}

			_, err := jwt.UnsafeParseSignedAny(response.AccessToken, &claims)
			require.NoError(t, err)

			assert.WithinDuration(t, time.Now().Add(tc.expected), time.Unix(int64(claims[consts.ClaimExpirationTime].(float64)), 0), 5*time.Second)
			assert.InDelta(t, int64(tc.expected.Seconds()), response.ToMap()[consts.AccessResponseExpiresIn], 5)
		})
	}
}
