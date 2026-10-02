// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc8693_test

import (
	"encoding/json"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/jose"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/handler/openid"
	. "authelia.com/provider/oauth2/handler/rfc8693"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestIDTokenIsOnlyIssuedForAnAuthenticatedSubject(t *testing.T) {
	testCases := []struct {
		name             string
		subjectTokenType string
	}{
		{"ShouldRejectAnAccessToken", consts.TokenTypeRFC8693AccessToken},
		{"ShouldRejectACustomJWT", "urn:spec:jwt"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := newSpecConfig(t)
			store := storage.NewExampleStore()
			strategy := &jwt.DefaultStrategy{Config: config, Issuer: jwt.NewDefaultIssuerRS256Unverified(key)}

			handler := &IDTokenTypeHandler{
				Config:             config,
				Strategy:           strategy,
				IssueStrategy:      &openid.DefaultStrategy{Strategy: strategy, Config: config},
				ValidationStrategy: &openid.DefaultIDTokenValidationStrategy{Strategy: strategy},
				Storage:            store,
			}

			request := newExchangeRequest(t, store.Clients["my-client"], newSpecSession("peter"), url.Values{
				consts.FormParameterSubjectToken:       {"subject-token"},
				consts.FormParameterSubjectTokenType:   {tc.subjectTokenType},
				consts.FormParameterRequestedTokenType: {consts.TokenTypeRFC8693IDToken},
			})

			err := handler.HandleTokenEndpointRequest(t.Context(), request)

			assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. An ID Token can only be issued by a token exchange whose 'subject_token_type' is an ID Token or a refresh token.")
		})
	}
}

func TestCustomJWTSubjectTokenType(t *testing.T) {
	testCases := []struct {
		name     string
		types    []string
		typ      string
		expected string
	}{
		{name: "ShouldAcceptJWT", typ: consts.JSONWebTokenTypeJWT},
		{name: "ShouldAcceptAnAbsentType"},
		{name: "ShouldRejectAnAccessToken", typ: consts.JSONWebTokenTypeAccessToken, expected: "The 'typ' header 'at+jwt' is not permitted for the token type 'urn:spec:jwt'. token was signed with an invalid typ"},
		{name: "ShouldRejectALogoutToken", typ: consts.JSONWebTokenTypeLogoutToken, expected: "The 'typ' header 'logout+jwt' is not permitted for the token type 'urn:spec:jwt'. token was signed with an invalid typ"},
		{name: "ShouldRejectAKeyBoundIDToken", typ: consts.JSONWebTokenTypeDPoPIDToken, expected: "The 'typ' header 'dpop+id_token' is not permitted for the token type 'urn:spec:jwt'. token was signed with an invalid typ"},
		{name: "ShouldAcceptAConfiguredType", types: []string{consts.JSONWebTokenTypeAccessToken}, typ: "application/AT+JWT"},
		{name: "ShouldRejectAnAbsentTypeWhenJWTIsNotConfigured", types: []string{consts.JSONWebTokenTypeAccessToken}, expected: "The 'typ' header '' is not permitted for the token type 'urn:spec:jwt'. token was signed with an invalid typ"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := newSpecConfig(t)
			config.RFC8693TokenTypes["urn:spec:jwt"].(*JWTType).Types = tc.types

			err := runCustomJWTSubjectToken(t, config, "https://as.example.com", tc.typ)

			if tc.expected == "" {
				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
			} else {
				assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. "+tc.expected)
			}
		})
	}
}

func TestCustomJWTSubjectTokenIDTokenIssuer(t *testing.T) {
	testCases := []struct {
		name     string
		issuer   string
		expected string
	}{
		{
			name:     "ShouldRejectTheIDTokenIssuer",
			issuer:   "https://as.example.com",
			expected: "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Claim 'iss' from token is the ID Token issuer, so the token must be exchanged as 'urn:ietf:params:oauth:token-type:id_token'.",
		},
		{
			name:   "ShouldAcceptADistinctIssuer",
			issuer: "https://id.example.com",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := newSpecConfig(t)
			config.IDTokenIssuer = tc.issuer

			err := runCustomJWTSubjectToken(t, config, "https://as.example.com", consts.JSONWebTokenTypeJWT)

			if tc.expected == "" {
				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
			} else {
				assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), tc.expected)
			}
		})
	}
}

func runCustomJWTSubjectToken(t *testing.T, config *oauth2.Config, issuer, typ string) error {
	t.Helper()

	store := storage.NewExampleStore()
	strategy := &jwt.DefaultStrategy{Config: config, Issuer: jwt.NewDefaultIssuerRS256Unverified(key)}

	claims := jwt.MapClaims{
		consts.ClaimIssuer:         issuer,
		consts.ClaimSubject:        "peter",
		"subject":                  "peter",
		consts.ClaimExpirationTime: time.Now().Add(time.Minute).Unix(),
		consts.ClaimIssuedAt:       time.Now().Unix(),
	}

	options := &jose.SignerOptions{}

	if typ != "" {
		options = options.WithType(jose.ContentType(typ))
	}

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, options)
	require.NoError(t, err)

	payload, err := json.Marshal(claims)
	require.NoError(t, err)

	signed, err := signer.Sign(payload)
	require.NoError(t, err)

	token, err := signed.CompactSerialize()
	require.NoError(t, err)

	request := newExchangeRequest(t, store.Clients["my-client"], newSpecSession("peter"), url.Values{
		consts.FormParameterSubjectToken:       {token},
		consts.FormParameterSubjectTokenType:   {"urn:spec:jwt"},
		consts.FormParameterRequestedTokenType: {consts.TokenTypeRFC8693AccessToken},
	})

	return (&CustomJWTTypeHandler{Config: config, Strategy: strategy, Storage: store}).HandleTokenEndpointRequest(t.Context(), request)
}
