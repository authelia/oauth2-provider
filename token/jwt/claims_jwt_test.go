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

func TestJWTClaims_With(t *testing.T) {
	exp := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	scope := []string{"openid", "profile"}
	audience := []string{"client-id"}

	c := &JWTClaims{}
	result := c.With(exp, scope, audience)

	assert.Same(t, c, result)
	assert.Equal(t, exp, c.ExpiresAt)
	assert.Equal(t, scope, c.Scope)
	assert.Equal(t, audience, c.Audience)
}

func TestJWTClaims_Sanitize(t *testing.T) {
	c := &JWTClaims{
		Subject:   "peter",
		IssuedAt:  time.Now().UTC(),
		NotBefore: time.Now().UTC(),
	}

	result := c.Sanitize()

	assert.Same(t, c, result)
	assert.True(t, c.IssuedAt.IsZero())
	assert.True(t, c.NotBefore.IsZero())
	assert.Equal(t, "peter", c.Subject, "Sanitize must not affect unrelated fields")
}

func TestJWTClaims_WithDefaults(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	earlier := now.Add(-time.Hour)

	testCases := []struct {
		name        string
		existing    *JWTClaims
		iat         time.Time
		nbf         time.Time
		issuer      string
		expectedIAT time.Time
		expectedNBF time.Time
		expectedIss string
	}{
		{
			name:        "ShouldApplyDefaultsWhenZero",
			existing:    &JWTClaims{},
			iat:         now,
			nbf:         now,
			issuer:      "authelia",
			expectedIAT: now,
			expectedNBF: now,
			expectedIss: "authelia",
		},
		{
			name: "ShouldPreserveExistingValues",
			existing: &JWTClaims{
				IssuedAt:  earlier,
				NotBefore: earlier,
				Issuer:    "preset",
			},
			iat:         now,
			nbf:         now,
			issuer:      "authelia",
			expectedIAT: earlier,
			expectedNBF: earlier,
			expectedIss: "preset",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := tc.existing.WithDefaults(tc.iat, tc.nbf, tc.issuer)
			assert.Same(t, tc.existing, result)
			assert.Equal(t, tc.expectedIAT, tc.existing.IssuedAt)
			assert.Equal(t, tc.expectedNBF, tc.existing.NotBefore)
			assert.Equal(t, tc.expectedIss, tc.existing.Issuer)
		})
	}
}

func TestJWTClaims_Add(t *testing.T) {
	t.Run("ShouldInitializeExtraWhenNil", func(t *testing.T) {
		c := &JWTClaims{}
		c.Add("foo", "bar")
		assert.Equal(t, "bar", c.Extra["foo"])
	})

	t.Run("ShouldAddToExistingExtra", func(t *testing.T) {
		c := &JWTClaims{Extra: map[string]any{"existing": 1}}
		c.Add("foo", "bar")
		assert.Equal(t, 1, c.Extra["existing"])
		assert.Equal(t, "bar", c.Extra["foo"])
	})
}

func TestJWTClaims_FromMapClaims(t *testing.T) {
	var claims JWTClaims

	claims.FromMapClaims(MapClaims(jwtClaimsMap))
	assert.Equal(t, jwtClaims, &claims)
}

func TestJWTClaims_FromMapScopeFieldTransitions(t *testing.T) {
	testCases := []struct {
		name             string
		existing         JWTScopeFieldEnum
		input            map[string]any
		expectedScope    []string
		expectedScopeFld JWTScopeFieldEnum
	}{
		{
			name:             "ShouldTransitionUnsetToListForScpSlice",
			existing:         JWTScopeFieldUnset,
			input:            map[string]any{ClaimScopeNonStandard: []string{"a", "b"}},
			expectedScope:    []string{"a", "b"},
			expectedScopeFld: JWTScopeFieldList,
		},
		{
			name:             "ShouldTransitionStringToBothForScpSlice",
			existing:         JWTScopeFieldString,
			input:            map[string]any{ClaimScopeNonStandard: []string{"a", "b"}},
			expectedScope:    []string{"a", "b"},
			expectedScopeFld: JWTScopeFieldBoth,
		},
		{
			name:             "ShouldTransitionUnsetToListForScpAnySlice",
			existing:         JWTScopeFieldUnset,
			input:            map[string]any{ClaimScopeNonStandard: []any{"a", "b"}},
			expectedScope:    []string{"a", "b"},
			expectedScopeFld: JWTScopeFieldList,
		},
		{
			name:             "ShouldTransitionStringToBothForScpAnySlice",
			existing:         JWTScopeFieldString,
			input:            map[string]any{ClaimScopeNonStandard: []any{"a", "b"}},
			expectedScope:    []string{"a", "b"},
			expectedScopeFld: JWTScopeFieldBoth,
		},
		{
			name:             "ShouldTransitionListToBothForScopeString",
			existing:         JWTScopeFieldList,
			input:            map[string]any{ClaimScope: "a b"},
			expectedScope:    []string{"a", "b"},
			expectedScopeFld: JWTScopeFieldBoth,
		},
		{
			name:             "ShouldKeepBothForScopeStringWhenAlreadyBoth",
			existing:         JWTScopeFieldBoth,
			input:            map[string]any{ClaimScope: "a b"},
			expectedScope:    []string{"a", "b"},
			expectedScopeFld: JWTScopeFieldBoth,
		},
		{
			name:             "ShouldKeepBothForScpSliceWhenAlreadyBoth",
			existing:         JWTScopeFieldBoth,
			input:            map[string]any{ClaimScopeNonStandard: []string{"a", "b"}},
			expectedScope:    []string{"a", "b"},
			expectedScopeFld: JWTScopeFieldBoth,
		},
		{
			name:             "ShouldKeepBothForScpAnySliceWhenAlreadyBoth",
			existing:         JWTScopeFieldBoth,
			input:            map[string]any{ClaimScopeNonStandard: []any{"a", "b"}},
			expectedScope:    []string{"a", "b"},
			expectedScopeFld: JWTScopeFieldBoth,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			c := &JWTClaims{ScopeField: tc.existing}
			c.FromMap(tc.input)
			assert.Equal(t, tc.expectedScope, c.Scope)
			assert.Equal(t, tc.expectedScopeFld, c.ScopeField)
		})
	}
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
