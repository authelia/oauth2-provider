// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package jwt_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"authelia.com/provider/oauth2/internal/consts"
	. "authelia.com/provider/oauth2/token/jwt"
)

const scopeEmailOffline = "email offline"

var jwtClaims = &JWTClaims{
	Subject:   "peter",
	IssuedAt:  time.Now().UTC().Truncate(TimePrecision),
	Issuer:    "authelia",
	NotBefore: time.Now().UTC().Truncate(TimePrecision),
	Audience:  []string{"tests"},
	ExpiresAt: time.Now().UTC().Add(time.Hour).Truncate(TimePrecision),
	JTI:       "abcdef",
	Scope:     []string{consts.ScopeEmail, consts.ScopeOffline},
	Extra: map[string]any{
		"foo": "bar",
		"baz": "bar",
	},
	ScopeField: JWTScopeFieldList,
}

var jwtClaimsMap = map[string]any{
	ClaimSubject:          jwtClaims.Subject,
	ClaimIssuedAt:         jwtClaims.IssuedAt.Unix(),
	ClaimIssuer:           jwtClaims.Issuer,
	ClaimNotBefore:        jwtClaims.NotBefore.Unix(),
	ClaimAudience:         jwtClaims.Audience,
	ClaimExpirationTime:   jwtClaims.ExpiresAt.Unix(),
	ClaimJWTID:            jwtClaims.JTI,
	ClaimScopeNonStandard: []string{consts.ScopeEmail, consts.ScopeOffline},
	"foo":                 jwtClaims.Extra["foo"],
	"baz":                 jwtClaims.Extra["baz"],
}

func TestJWTClaims_AddGetString(t *testing.T) {
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
			jwtClaims.Add(tc.key, tc.value)
			assert.Equal(t, tc.expected, jwtClaims.Get(tc.key))
		})
	}
}

func TestJWTClaims_ToMapSetsID(t *testing.T) {
	assert.NotEmpty(t, (&JWTClaims{}).ToMap()[ClaimJWTID])
}

func TestJWTClaims_Valid(t *testing.T) {
	testCases := []struct {
		name    string
		claims  *JWTClaims
		wantErr bool
	}{
		{
			name:    "ShouldPassWithFutureExpiration",
			claims:  &JWTClaims{ExpiresAt: time.Now().UTC().Add(time.Hour)},
			wantErr: false,
		},
		{
			name:    "ShouldFailWithPastExpiration",
			claims:  &JWTClaims{ExpiresAt: time.Now().UTC().Add(-2 * time.Hour)},
			wantErr: true,
		},
		{
			name:    "ShouldFailWithFutureNotBefore",
			claims:  &JWTClaims{NotBefore: time.Now().UTC().Add(time.Hour)},
			wantErr: true,
		},
		{
			name:    "ShouldPassWithPastNotBefore",
			claims:  &JWTClaims{NotBefore: time.Now().UTC().Add(-time.Hour)},
			wantErr: false,
		},
		{
			name: "ShouldPassWithExpAndNbf",
			claims: &JWTClaims{
				ExpiresAt: time.Now().UTC().Add(time.Hour),
				NotBefore: time.Now().UTC().Add(-time.Hour),
			},
			wantErr: false,
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

func TestJWTClaims_ToMap(t *testing.T) {
	assert.Equal(t, jwtClaimsMap, jwtClaims.ToMap())
}

func TestJWTClaims_FromMap(t *testing.T) {
	var claims JWTClaims
	claims.FromMap(jwtClaimsMap)
	assert.Equal(t, jwtClaims, &claims)
}

func TestJWTClaims_WithScopeField(t *testing.T) {
	testCases := []struct {
		name     string
		field    JWTScopeFieldEnum
		mutate   func(m map[string]any)
		original *JWTClaims
	}{
		{
			name:  "ShouldEncodeAsString",
			field: JWTScopeFieldString,
			mutate: func(m map[string]any) {
				delete(m, ClaimScopeNonStandard)
				m[ClaimScope] = scopeEmailOffline
			},
			original: jwtClaims,
		},
		{
			name:  "ShouldEncodeAsBoth",
			field: JWTScopeFieldBoth,
			mutate: func(m map[string]any) {
				m[ClaimScope] = scopeEmailOffline
			},
			original: jwtClaims,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			withField := tc.original.WithScopeField(tc.field)
			expected := tc.original.ToMap()
			tc.mutate(expected)

			assert.Equal(t, expected, map[string]any(withField.ToMapClaims()))

			var actual JWTClaims
			actual.FromMap(expected)
			assert.Equal(t, withField, &actual)
		})
	}
}
