// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc8693

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/jose"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/gen"
	"authelia.com/provider/oauth2/token/jwt"
)

// RFC 8725 Section 3.1 and FAPI 2.0 Security Profile Sections 5.3.2.1 and 5.4.1.
func TestCustomJWTTypeHandlerParse(t *testing.T) {
	rsaKey := gen.MustRSAKey()
	secret := []byte("a-shared-secret-of-at-least-32-octets")

	sign := func(t *testing.T, alg jose.SignatureAlgorithm, key any, iat time.Time) string {
		t.Helper()

		token, err := jwt.NewWithClaims(alg, jwt.MapClaims{"iss": "https://issuer.example.com", "iat": iat.Unix(), "exp": iat.Add(time.Minute).Unix()}).CompactSignedString(key)
		require.NoError(t, err)

		return token
	}

	var keyfunc jwt.Keyfunc = func(token *jwt.Token) (any, error) {
		if token.SignatureAlgorithm == jose.HS256 {
			return &jose.JSONWebKey{Key: secret, Algorithm: string(jose.HS256), Use: "sig"}, nil
		}

		return &rsaKey.PublicKey, nil
	}

	fapi2 := &oauth2.DefaultRegisteredClient{DefaultClient: &oauth2.DefaultClient{ID: "client"}, FAPI2SecurityProfile: true}
	other := &oauth2.DefaultClient{ID: "client"}
	now := time.Now()

	testCases := []struct {
		name    string
		alg     jose.SignatureAlgorithm
		key     any
		iat     time.Time
		algs    []string
		profile bool
		skew    time.Duration
		client  oauth2.Client
		err     string
	}{
		{name: "ShouldAcceptRS256ByDefault", alg: jose.RS256, key: rsaKey, iat: now, client: other},
		{name: "ShouldRejectHS256ByDefault", alg: jose.HS256, key: secret, iat: now, client: other, err: "unexpected signature algorithm"},
		{name: "ShouldAcceptHS256WhenConfigured", alg: jose.HS256, key: secret, iat: now, algs: []string{string(jose.HS256)}, client: other},
		{name: "ShouldRejectAnAlgorithmNotConfigured", alg: jose.RS256, key: rsaKey, iat: now, algs: []string{string(jose.PS256)}, client: other, err: "unexpected signature algorithm"},
		{name: "ShouldRejectRS256ForAFAPI2Client", alg: jose.RS256, key: rsaKey, iat: now, client: fapi2, err: "unexpected signature algorithm"},
		{name: "ShouldRejectRS256ForAFAPI2Server", alg: jose.RS256, key: rsaKey, iat: now, profile: true, client: other, err: "unexpected signature algorithm"},
		{name: "ShouldAcceptPS256ForAFAPI2Client", alg: jose.PS256, key: rsaKey, iat: now, client: fapi2},
		{name: "ShouldAcceptAnIssuedAtWithinTheClockSkew", alg: jose.PS256, key: rsaKey, iat: now.Add(5 * time.Second), client: fapi2},
		{name: "ShouldRejectAnIssuedAtBeyondTheClockSkew", alg: jose.PS256, key: rsaKey, iat: now.Add(2 * time.Minute), client: fapi2, err: "used before issued"},
		{name: "ShouldAcceptAnIssuedAtWithinTheClockSkewOfAFAPI2Server", alg: jose.PS256, key: rsaKey, iat: now.Add(5 * time.Second), profile: true, skew: -1, client: other},
		{name: "ShouldRejectAnIssuedAtInTheFutureWithoutAClockSkew", alg: jose.PS256, key: rsaKey, iat: now.Add(5 * time.Second), skew: -1, client: other, err: "used before issued"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			handler := &CustomJWTTypeHandler{Config: &oauth2.Config{FAPI2SecurityProfile: tc.profile, JWTClockSkew: tc.skew}}

			token, err := handler.parse(t.Context(), tc.client, &JWTValidationConfig{ValidateFunc: keyfunc, SigningAlgValues: tc.algs}, sign(t, tc.alg, tc.key, tc.iat))

			if tc.err != "" {
				require.ErrorIs(t, err, oauth2.ErrInvalidRequest)
				assert.Contains(t, oauth2.ErrorToDebugRFC6749Error(err).Error(), tc.err)

				return
			}

			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
			assert.Equal(t, tc.alg, token.SignatureAlgorithm)
			require.NoError(t, validateCustomJWTType(t.Context(), &JWTType{Name: "urn:example:jwt"}, token))
		})
	}
}
