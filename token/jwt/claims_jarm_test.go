// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package jwt_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	. "authelia.com/provider/oauth2/token/jwt"
)

var jarmClaims = &JARMClaims{
	Issuer:         "authelia",
	Audience:       []string{"tests"},
	JTI:            "abcdef",
	IssuedAt:       Now(),
	ExpirationTime: NewNumericDate(time.Now().Add(time.Hour)),
	Extra: map[string]any{
		"foo": "bar",
		"baz": "bar",
	},
}

var jarmClaimsMap = map[string]any{
	ClaimIssuer:         jwtClaims.Issuer,
	ClaimAudience:       jwtClaims.Audience,
	ClaimJWTID:          jwtClaims.JTI,
	ClaimIssuedAt:       jwtClaims.IssuedAt.Unix(),
	ClaimExpirationTime: jwtClaims.ExpiresAt.Unix(),
	"foo":               jwtClaims.Extra["foo"],
	"baz":               jwtClaims.Extra["baz"],
}

func TestJARMClaims_AddGetString(t *testing.T) {
	testCases := []struct {
		name     string
		key      string
		value    string
		expected string
	}{
		{
			name:     "ShouldRoundTripValue",
			key:      "foo",
			value:    "bar",
			expected: "bar",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			jarmClaims.Add(tc.key, tc.value)
			assert.Equal(t, tc.expected, jarmClaims.Get(tc.key))
		})
	}
}

func TestJARMClaims_ToMapSetsID(t *testing.T) {
	assert.NotEmpty(t, (&JARMClaims{}).ToMap()[ClaimJWTID])
}

func TestJARMClaims_Valid(t *testing.T) {
	testCases := []struct {
		name    string
		claims  *JARMClaims
		wantErr bool
	}{
		{
			name:    "ShouldPassWithFutureExpiration",
			claims:  &JARMClaims{ExpirationTime: NewNumericDate(time.Now().Add(time.Hour))},
			wantErr: false,
		},
		{
			name:    "ShouldFailWithPastExpiration",
			claims:  &JARMClaims{ExpirationTime: NewNumericDate(time.Now().Add(-2 * time.Hour))},
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.claims.ToMapClaims().Valid()

			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestJARMClaims_ToMap(t *testing.T) {
	assert.Equal(t, jarmClaimsMap, jarmClaims.ToMap())
}

func TestJARMClaims_FromMap(t *testing.T) {
	var claims JARMClaims

	claims.FromMap(jarmClaimsMap)
	assert.Equal(t, jarmClaims, &claims)
}
