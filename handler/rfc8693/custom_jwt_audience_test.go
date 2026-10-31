// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc8693_test

import (
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	. "authelia.com/provider/oauth2/handler/rfc8693"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestCustomJWTAudience(t *testing.T) {
	const expectedAudience = "https://as.example.com/token"

	testCases := []struct {
		name     string
		aud      any
		expected []string
		actor    bool
		valid    bool
	}{
		{name: "ShouldAcceptTheRequestingClient", aud: []string{"my-client"}, valid: true},
		{name: "ShouldAcceptTheRequestingClientAsAString", aud: "my-client", valid: true},
		{name: "ShouldAcceptAnExpectedAudience", aud: []string{expectedAudience}, expected: []string{expectedAudience}, valid: true},
		{name: "ShouldAcceptTheRequestingClientWithAnExpectedAudienceSet", aud: []string{"my-client"}, expected: []string{expectedAudience}, valid: true},
		{name: "ShouldRejectAnAbsentAudience"},
		{name: "ShouldRejectAnotherAudience", aud: []string{"https://other.example.com"}},
		{name: "ShouldRejectAnotherAudienceWithAnExpectedAudienceSet", aud: []string{"https://other.example.com"}, expected: []string{expectedAudience}},
		{name: "ShouldRejectAnAbsentAudienceForAnActor", actor: true},
		{name: "ShouldAcceptTheRequestingClientForAnActor", aud: []string{"my-client"}, actor: true, valid: true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := newSpecConfig(t)
			config.RFC8693TokenTypes["urn:spec:jwt"].(*JWTType).ExpectedAudience = tc.expected

			claims := jwt.MapClaims{
				consts.ClaimIssuer:         "https://as.example.com",
				consts.ClaimSubject:        "peter",
				"subject":                  "peter",
				consts.ClaimExpirationTime: time.Now().Add(time.Minute).Unix(),
			}

			if tc.aud != nil {
				claims[consts.ClaimAudience] = tc.aud
			}

			err := validateCustomJWTToken(t, config, claims, tc.actor)

			if tc.valid {
				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

				return
			}

			// RFC 8693 Section 2.2.2.
			assert.ErrorIs(t, err, oauth2.ErrInvalidRequest)
			assert.ErrorContains(t, oauth2.ErrorToDebugRFC6749Error(err), "Claim 'aud' from token must include")
		})
	}
}

func TestCustomJWTIssuerFailsClosed(t *testing.T) {
	testCases := []struct {
		name  string
		iss   string
		actor bool
	}{
		{name: "ShouldRejectAnyIssuer", iss: "https://anything.example.com"},
		{name: "ShouldRejectAnAbsentIssuer"},
		{name: "ShouldRejectAnyIssuerForAnActor", iss: "https://anything.example.com", actor: true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := newSpecConfig(t)
			config.RFC8693TokenTypes["urn:spec:jwt"].(*JWTType).Issuer = ""

			err := validateCustomJWTToken(t, config, jwt.MapClaims{
				consts.ClaimIssuer:         tc.iss,
				consts.ClaimSubject:        "peter",
				consts.ClaimAudience:       []string{"my-client"},
				consts.ClaimExpirationTime: time.Now().Add(time.Minute).Unix(),
			}, tc.actor)

			assert.ErrorIs(t, err, oauth2.ErrInvalidRequest)
			assert.ErrorContains(t, oauth2.ErrorToDebugRFC6749Error(err), "so no issuer is trusted")
		})
	}
}

func validateCustomJWTToken(t *testing.T, config *oauth2.Config, claims jwt.MapClaims, actor bool) error {
	t.Helper()

	store := storage.NewExampleStore()
	strategy := &jwt.DefaultStrategy{Config: config, Issuer: jwt.NewDefaultIssuerRS256Unverified(key)}

	token, _, err := strategy.Encode(t.Context(), claims)
	require.NoError(t, err)

	form := url.Values{
		consts.FormParameterSubjectTokenType: {"urn:spec:jwt"},
		consts.FormParameterSubjectToken:     {token},
	}

	if actor {
		form = url.Values{
			consts.FormParameterActorTokenType: {"urn:spec:jwt"},
			consts.FormParameterActorToken:     {token},
		}
	}

	request := newExchangeRequest(t, store.Clients["my-client"], newSpecSession("peter"), form)

	return (&CustomJWTTypeHandler{Config: config, Strategy: strategy, Storage: store}).HandleTokenEndpointRequest(t.Context(), request)
}
