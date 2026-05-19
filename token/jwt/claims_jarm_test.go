// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package jwt_test

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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

func TestJARMClaims_MapClaimsValid(t *testing.T) {
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

func TestNewJARMClaims(t *testing.T) {
	before := time.Now()
	claims := NewJARMClaims("authelia", ClaimStrings{"a", "b"}, time.Hour)
	after := time.Now()

	require.NotNil(t, claims)
	assert.Equal(t, "authelia", claims.Issuer)
	assert.Equal(t, ClaimStrings{"a", "b"}, claims.Audience)
	assert.NotEmpty(t, claims.JTI)
	require.NotNil(t, claims.IssuedAt)
	require.NotNil(t, claims.ExpirationTime)

	assert.False(t, claims.IssuedAt.Before(before.Truncate(time.Second)))
	assert.False(t, claims.IssuedAt.After(after))

	assert.False(t, claims.ExpirationTime.Before(before.Add(time.Hour).Truncate(time.Second)))
	assert.False(t, claims.ExpirationTime.After(after.Add(time.Hour)))

	assert.Equal(t, map[string]any{}, claims.Extra)
}

func TestJARMClaims_Getters(t *testing.T) {
	exp := NewNumericDate(time.Now().Add(time.Hour))
	iat := NewNumericDate(time.Now())
	nbf := NewNumericDate(time.Now().Add(-time.Minute))

	claims := &JARMClaims{
		Issuer:         "authelia",
		Audience:       ClaimStrings{"tests"},
		ExpirationTime: exp,
		IssuedAt:       iat,
		Extra: map[string]any{
			ClaimNotBefore: nbf.Unix(),
			ClaimSubject:   "peter",
		},
	}

	actualExp, err := claims.GetExpirationTime()
	require.NoError(t, err)
	assert.Equal(t, exp, actualExp)

	actualIat, err := claims.GetIssuedAt()
	require.NoError(t, err)
	assert.Equal(t, iat, actualIat)

	actualNbf, err := claims.GetNotBefore()
	require.NoError(t, err)
	assert.Equal(t, nbf.Unix(), actualNbf.Unix())

	iss, err := claims.GetIssuer()
	require.NoError(t, err)
	assert.Equal(t, "authelia", iss)

	sub, err := claims.GetSubject()
	require.NoError(t, err)
	assert.Equal(t, "peter", sub)

	aud, err := claims.GetAudience()
	require.NoError(t, err)
	assert.Equal(t, ClaimStrings{"tests"}, aud)
}

func TestJARMClaims_GetNotBefore(t *testing.T) {
	testCases := []struct {
		name     string
		claims   *JARMClaims
		expected *NumericDate
		wantErr  bool
	}{
		{
			name:   "ShouldReturnNilWhenMissing",
			claims: &JARMClaims{Extra: map[string]any{}},
		},
		{
			name:     "ShouldReturnNumericDateFromInt64",
			claims:   &JARMClaims{Extra: map[string]any{ClaimNotBefore: int64(1700000000)}},
			expected: NewNumericDate(time.Unix(1700000000, 0)),
		},
		{
			name:    "ShouldErrorOnInvalidType",
			claims:  &JARMClaims{Extra: map[string]any{ClaimNotBefore: "not-a-date"}},
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual, err := tc.claims.GetNotBefore()

			if tc.wantErr {
				require.Error(t, err)

				return
			}

			require.NoError(t, err)

			if tc.expected == nil {
				assert.Nil(t, actual)

				return
			}

			require.NotNil(t, actual)
			assert.Equal(t, tc.expected.Unix(), actual.Unix())
		})
	}
}

func TestJARMClaims_GetSubject(t *testing.T) {
	testCases := []struct {
		name     string
		claims   *JARMClaims
		expected string
		wantErr  string
	}{
		{
			name:   "ShouldReturnEmptyWhenMissing",
			claims: &JARMClaims{Extra: map[string]any{}},
		},
		{
			name:     "ShouldReturnSubjectWhenPresent",
			claims:   &JARMClaims{Extra: map[string]any{ClaimSubject: "peter"}},
			expected: "peter",
		},
		{
			name:    "ShouldErrorOnInvalidType",
			claims:  &JARMClaims{Extra: map[string]any{ClaimSubject: 123}},
			wantErr: "sub is invalid",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual, err := tc.claims.GetSubject()

			if tc.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
				assert.True(t, errors.Is(err, ErrInvalidType))

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.expected, actual)
		})
	}
}

func TestJARMClaims_Valid(t *testing.T) {
	claims := &JARMClaims{ExpirationTime: NewNumericDate(time.Now().Add(-time.Hour))}
	assert.NoError(t, claims.Valid())
}

func TestJARMClaims_FromMapClaims(t *testing.T) {
	var claims JARMClaims

	claims.FromMapClaims(MapClaims(jarmClaimsMap))
	assert.Equal(t, jarmClaims, &claims)
}

func TestJARMClaims_Add(t *testing.T) {
	t.Run("ShouldInitializeExtraWhenNil", func(t *testing.T) {
		c := &JARMClaims{}
		c.Add("foo", "bar")
		assert.Equal(t, "bar", c.Extra["foo"])
	})

	t.Run("ShouldAddToExistingExtra", func(t *testing.T) {
		c := &JARMClaims{Extra: map[string]any{"existing": 1}}
		c.Add("foo", "bar")
		assert.Equal(t, 1, c.Extra["existing"])
		assert.Equal(t, "bar", c.Extra["foo"])
	})
}

func TestJARMClaims_ToMapEdgeCases(t *testing.T) {
	t.Run("ShouldOmitEmptyIssuer", func(t *testing.T) {
		c := &JARMClaims{
			JTI:   "id-1",
			Extra: map[string]any{ClaimIssuer: "stale"},
		}
		out := c.ToMap()
		_, ok := out[ClaimIssuer]
		assert.False(t, ok)
	})

	t.Run("ShouldGenerateJTIWhenEmpty", func(t *testing.T) {
		c := &JARMClaims{}
		assert.NotEmpty(t, c.ToMap()[ClaimJWTID])
	})

	t.Run("ShouldReturnEmptyAudienceSlice", func(t *testing.T) {
		c := &JARMClaims{JTI: "id-1"}
		assert.Equal(t, []string{}, c.ToMap()[ClaimAudience])
	})

	t.Run("ShouldDeleteStaleIssuedAtAndExp", func(t *testing.T) {
		c := &JARMClaims{
			JTI: "id-1",
			Extra: map[string]any{
				ClaimIssuedAt:       int64(1),
				ClaimExpirationTime: int64(2),
			},
		}
		out := c.ToMap()
		_, ok := out[ClaimIssuedAt]
		assert.False(t, ok)
		_, ok = out[ClaimExpirationTime]
		assert.False(t, ok)
	})
}
