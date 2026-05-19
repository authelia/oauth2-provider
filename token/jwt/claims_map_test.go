// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package jwt

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2/internal/consts"
)

func TestMapClaims_VerifyAudience(t *testing.T) {
	testCases := []struct {
		name     string
		have     MapClaims
		cmp      string
		required bool
		expected bool
	}{
		{
			name:     "ShouldPass",
			have:     MapClaims{ClaimAudience: []string{"foo"}},
			cmp:      "foo",
			required: true,
			expected: true,
		},
		{
			name:     "ShouldPassMultiple",
			have:     MapClaims{ClaimAudience: []string{"foo", "bar"}},
			cmp:      "foo",
			required: true,
			expected: true,
		},
		{
			name:     "ShouldFailNoClaim",
			have:     MapClaims{},
			cmp:      "foo",
			required: true,
			expected: false,
		},
		{
			name:     "ShouldFailNoMatch",
			have:     MapClaims{ClaimAudience: []string{"bar"}},
			cmp:      "foo",
			required: true,
			expected: false,
		},
		{
			name:     "ShouldPassNoClaim",
			have:     MapClaims{},
			cmp:      "foo",
			required: false,
			expected: true,
		},
		{
			name:     "ShouldPassTypeAny",
			have:     MapClaims{ClaimAudience: []any{"foo"}},
			cmp:      "foo",
			required: true,
			expected: true,
		},
		{
			name:     "ShouldPassTypeString",
			have:     MapClaims{ClaimAudience: "foo"},
			cmp:      "foo",
			required: true,
			expected: true,
		},
		{
			name:     "ShouldFailTypeString",
			have:     MapClaims{consts.ClaimAudience: "bar"},
			cmp:      "foo",
			required: true,
			expected: false,
		},
		{
			name:     "ShouldFailTypeNil",
			have:     MapClaims{consts.ClaimAudience: nil},
			cmp:      "foo",
			required: true,
			expected: false,
		},
		{
			name:     "ShouldFailTypeSliceAnyInt",
			have:     MapClaims{consts.ClaimAudience: []any{1, 2, 3}},
			cmp:      "foo",
			required: true,
			expected: false,
		},
		{
			name:     "ShouldFailTypeInt",
			have:     MapClaims{consts.ClaimAudience: 1},
			cmp:      "foo",
			required: true,
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.have.VerifyAudience(tc.cmp, tc.required))
		})
	}
}

func TestMapClaims_VerifyAudienceAll(t *testing.T) {
	testCases := []struct {
		name     string
		have     MapClaims
		cmp      []string
		required bool
		expected bool
	}{
		{
			name:     "ShouldPass",
			have:     MapClaims{consts.ClaimAudience: []string{"foo"}},
			cmp:      []string{"foo"},
			required: true,
			expected: true,
		},
		{
			name:     "ShouldFailMultipleAll",
			have:     MapClaims{consts.ClaimAudience: []string{"foo"}},
			cmp:      []string{"foo", "bar"},
			required: true,
			expected: false,
		},
		{
			name:     "ShouldPassMultiple",
			have:     MapClaims{consts.ClaimAudience: []string{"foo", "bar"}},
			cmp:      []string{"foo"},
			required: true,
			expected: true,
		},
		{
			name:     "ShouldPassMultipleAll",
			have:     MapClaims{consts.ClaimAudience: []string{"foo", "bar"}},
			cmp:      []string{"foo", "bar"},
			required: true,
			expected: true,
		},
		{
			name:     "ShouldFailNoClaim",
			have:     MapClaims{},
			cmp:      []string{"foo"},
			required: true,
			expected: false,
		},
		{
			name:     "ShouldFailNoMatch",
			have:     MapClaims{consts.ClaimAudience: []string{"bar"}},
			cmp:      []string{"foo"},
			required: true,
			expected: false,
		},
		{
			name:     "ShouldPassNoClaim",
			have:     MapClaims{},
			cmp:      []string{"foo"},
			required: false,
			expected: true,
		},
		{
			name:     "ShouldPassTypeAny",
			have:     MapClaims{consts.ClaimAudience: []any{"foo"}},
			cmp:      []string{"foo"},
			required: true,
			expected: true,
		},
		{
			name:     "ShouldPassTypeString",
			have:     MapClaims{consts.ClaimAudience: "foo"},
			cmp:      []string{"foo"},
			required: true,
			expected: true,
		},
		{
			name:     "ShouldFailTypeString",
			have:     MapClaims{consts.ClaimAudience: "bar"},
			cmp:      []string{"foo"},
			required: true,
			expected: false,
		},
		{
			name:     "ShouldFailTypeNil",
			have:     MapClaims{consts.ClaimAudience: nil},
			cmp:      []string{"foo"},
			required: true,
			expected: false,
		},
		{
			name:     "ShouldFailTypeSliceAnyInt",
			have:     MapClaims{consts.ClaimAudience: []any{1, 2, 3}},
			cmp:      []string{"foo"},
			required: true,
			expected: false,
		},
		{
			name:     "ShouldFailTypeInt",
			have:     MapClaims{consts.ClaimAudience: 1},
			cmp:      []string{"foo"},
			required: true,
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.have.VerifyAudienceAll(tc.cmp, tc.required))
		})
	}
}

func TestMapClaims_VerifyAudienceAny(t *testing.T) {
	testCases := []struct {
		name     string
		have     MapClaims
		cmp      []string
		required bool
		expected bool
	}{
		{
			name:     "ShouldPass",
			have:     MapClaims{consts.ClaimAudience: []string{"foo"}},
			cmp:      []string{"foo"},
			required: true,
			expected: true,
		},
		{
			name:     "ShouldPassMultipleAny",
			have:     MapClaims{consts.ClaimAudience: []string{"foo", "baz"}},
			cmp:      []string{"bar", "baz"},
			required: true,
			expected: true,
		},
		{
			name:     "ShouldPassMultiple",
			have:     MapClaims{consts.ClaimAudience: []string{"foo", "bar"}},
			cmp:      []string{"foo"},
			required: true,
			expected: true,
		},
		{
			name:     "ShouldPassMultipleAll",
			have:     MapClaims{consts.ClaimAudience: []string{"foo", "bar"}},
			cmp:      []string{"foo", "bar"},
			required: true,
			expected: true,
		},
		{
			name:     "ShouldFailNoClaim",
			have:     MapClaims{},
			cmp:      []string{"foo"},
			required: true,
			expected: false,
		},
		{
			name:     "ShouldFailNoMatch",
			have:     MapClaims{consts.ClaimAudience: []string{"bar"}},
			cmp:      []string{"foo"},
			required: true,
			expected: false,
		},
		{
			name:     "ShouldPassNoClaim",
			have:     MapClaims{},
			cmp:      []string{"foo"},
			required: false,
			expected: true,
		},
		{
			name:     "ShouldPassTypeAny",
			have:     MapClaims{consts.ClaimAudience: []any{"foo"}},
			cmp:      []string{"foo"},
			required: true,
			expected: true,
		},
		{
			name:     "ShouldPassTypeString",
			have:     MapClaims{consts.ClaimAudience: "foo"},
			cmp:      []string{"foo"},
			required: true,
			expected: true,
		},
		{
			name:     "ShouldFailTypeString",
			have:     MapClaims{consts.ClaimAudience: "bar"},
			cmp:      []string{"foo"},
			required: true,
			expected: false,
		},
		{
			name:     "ShouldFailTypeNil",
			have:     MapClaims{consts.ClaimAudience: nil},
			cmp:      []string{"foo"},
			required: true,
			expected: false,
		},
		{
			name:     "ShouldFailTypeSliceAnyInt",
			have:     MapClaims{consts.ClaimAudience: []any{1, 2, 3}},
			cmp:      []string{"foo"},
			required: true,
			expected: false,
		},
		{
			name:     "ShouldFailTypeInt",
			have:     MapClaims{consts.ClaimAudience: 1},
			cmp:      []string{"foo"},
			required: true,
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.have.VerifyAudienceAny(tc.cmp, tc.required))
		})
	}
}

func TestMapClaims_VerifyIssuer(t *testing.T) {
	testCases := []struct {
		name     string
		have     MapClaims
		cmp      string
		required bool
		expected bool
	}{
		{
			name:     "ShouldPass",
			have:     MapClaims{consts.ClaimIssuer: "foo"},
			cmp:      "foo",
			required: true,
			expected: true,
		},
		{
			name:     "ShouldFailEmptyString",
			have:     MapClaims{consts.ClaimIssuer: ""},
			cmp:      "foo",
			required: true,
			expected: false,
		},
		{
			name:     "ShouldFailNoClaim",
			have:     MapClaims{},
			cmp:      "foo",
			required: true,
			expected: false,
		},
		{
			name:     "ShouldPassNoClaim",
			have:     MapClaims{},
			cmp:      "foo",
			required: false,
			expected: true,
		},
		{
			name:     "ShouldFailNoMatch",
			have:     MapClaims{consts.ClaimIssuer: "bar"},
			cmp:      "foo",
			required: true,
			expected: false,
		},
		{
			name:     "ShouldFailWrongType",
			have:     MapClaims{consts.ClaimIssuer: 5},
			cmp:      "5",
			required: true,
			expected: false,
		},
		{
			name:     "ShouldFailNil",
			have:     MapClaims{consts.ClaimIssuer: nil},
			cmp:      "foo",
			required: true,
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.have.VerifyIssuer(tc.cmp, tc.required))
		})
	}
}

func TestMapClaims_VerifySubject(t *testing.T) {
	testCases := []struct {
		name     string
		have     MapClaims
		cmp      string
		required bool
		expected bool
	}{
		{
			name:     "ShouldPass",
			have:     MapClaims{consts.ClaimSubject: "foo"},
			cmp:      "foo",
			required: true,
			expected: true,
		},
		{
			name:     "ShouldFailNoClaim",
			have:     MapClaims{},
			cmp:      "foo",
			required: true,
			expected: false,
		},
		{
			name:     "ShouldPassNoClaim",
			have:     MapClaims{},
			cmp:      "foo",
			required: false,
			expected: true,
		},
		{
			name:     "ShouldFailNoMatch",
			have:     MapClaims{consts.ClaimSubject: "bar"},
			cmp:      "foo",
			required: true,
			expected: false,
		},
		{
			name:     "ShouldFailWrongType",
			have:     MapClaims{consts.ClaimSubject: 5},
			cmp:      "5",
			required: true,
			expected: false,
		},
		{
			name:     "ShouldFailNil",
			have:     MapClaims{consts.ClaimSubject: nil},
			cmp:      "foo",
			required: true,
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.have.VerifySubject(tc.cmp, tc.required))
		})
	}
}

func TestMapClaims_VerifyExpiresAt(t *testing.T) {
	testCases := []struct {
		name     string
		have     MapClaims
		cmp      int64
		required bool
		expected bool
	}{
		{
			name:     "ShouldPass",
			have:     MapClaims{consts.ClaimExpirationTime: int64(123)},
			cmp:      int64(123),
			required: true,
			expected: true,
		},
		{
			name:     "ShouldPassStandardInt",
			have:     MapClaims{consts.ClaimExpirationTime: 123},
			cmp:      int64(123),
			required: true,
			expected: true,
		},
		{
			name:     "ShouldPassStandardInt32",
			have:     MapClaims{consts.ClaimExpirationTime: int32(123)},
			cmp:      int64(123),
			required: true,
			expected: true,
		},
		{
			name:     "ShouldFailNoClaim",
			have:     MapClaims{},
			cmp:      int64(123),
			required: true,
			expected: false,
		},
		{
			name:     "ShouldPassNoClaim",
			have:     MapClaims{},
			cmp:      int64(123),
			required: false,
			expected: true,
		},
		{
			name:     "ShouldFailNoMatch",
			have:     MapClaims{consts.ClaimExpirationTime: 4},
			cmp:      int64(123),
			required: true,
			expected: false,
		},
		{
			name:     "ShouldFailWrongType",
			have:     MapClaims{consts.ClaimExpirationTime: true},
			cmp:      int64(123),
			required: true,
			expected: false,
		},
		{
			name:     "ShouldFailNil",
			have:     MapClaims{consts.ClaimExpirationTime: nil},
			cmp:      int64(123),
			required: true,
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.have.VerifyExpirationTime(tc.cmp, tc.required))
		})
	}
}

func TestMapClaims_VerifyIssuedAt(t *testing.T) {
	testCases := []struct {
		name     string
		have     MapClaims
		cmp      int64
		required bool
		expected bool
	}{
		{
			name:     "ShouldPass",
			have:     MapClaims{consts.ClaimIssuedAt: int64(123)},
			cmp:      int64(123),
			required: true,
			expected: true,
		},
		{
			name:     "ShouldPassStandardInt",
			have:     MapClaims{consts.ClaimIssuedAt: 123},
			cmp:      int64(123),
			required: true,
			expected: true,
		},
		{
			name:     "ShouldPassStandardInt32",
			have:     MapClaims{consts.ClaimIssuedAt: int32(123)},
			cmp:      int64(123),
			required: true,
			expected: true,
		},
		{
			name:     "ShouldFailNoClaim",
			have:     MapClaims{},
			cmp:      int64(123),
			required: true,
			expected: false,
		},
		{
			name:     "ShouldPassNoClaim",
			have:     MapClaims{},
			cmp:      int64(123),
			required: false,
			expected: true,
		},
		{
			name:     "ShouldFailFuture",
			have:     MapClaims{consts.ClaimIssuedAt: 9000},
			cmp:      int64(123),
			required: true,
			expected: false,
		},
		{
			name:     "ShouldPassPast",
			have:     MapClaims{consts.ClaimIssuedAt: 4},
			cmp:      int64(123),
			required: true,
			expected: true,
		},
		{
			name:     "ShouldFailWrongType",
			have:     MapClaims{consts.ClaimIssuedAt: true},
			cmp:      int64(123),
			required: true,
			expected: false,
		},
		{
			name:     "ShouldFailNil",
			have:     MapClaims{consts.ClaimIssuedAt: nil},
			cmp:      int64(123),
			required: true,
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.have.VerifyIssuedAt(tc.cmp, tc.required))
		})
	}
}

func TestMapClaims_VerifyNotBefore(t *testing.T) {
	testCases := []struct {
		name     string
		have     MapClaims
		cmp      int64
		required bool
		expected bool
	}{
		{
			name:     "ShouldPass",
			have:     MapClaims{consts.ClaimNotBefore: int64(123)},
			cmp:      int64(123),
			required: true,
			expected: true,
		},
		{
			name:     "ShouldPassStandardInt",
			have:     MapClaims{consts.ClaimNotBefore: 123},
			cmp:      int64(123),
			required: true,
			expected: true,
		},
		{
			name:     "ShouldPassStandardInt32",
			have:     MapClaims{consts.ClaimNotBefore: int32(123)},
			cmp:      int64(123),
			required: true,
			expected: true,
		},
		{
			name:     "ShouldFailNoClaim",
			have:     MapClaims{},
			cmp:      int64(123),
			required: true,
			expected: false,
		},
		{
			name:     "ShouldPassNoClaim",
			have:     MapClaims{},
			cmp:      int64(123),
			required: false,
			expected: true,
		},
		{
			name:     "ShouldFailFuture",
			have:     MapClaims{consts.ClaimNotBefore: 9000},
			cmp:      int64(123),
			required: true,
			expected: false,
		},
		{
			name:     "ShouldPassPast",
			have:     MapClaims{consts.ClaimNotBefore: 4},
			cmp:      int64(123),
			required: true,
			expected: true,
		},
		{
			name:     "ShouldFailWrongType",
			have:     MapClaims{consts.ClaimNotBefore: true},
			cmp:      int64(123),
			required: true,
			expected: false,
		},
		{
			name:     "ShouldFailNil",
			have:     MapClaims{consts.ClaimNotBefore: nil},
			cmp:      int64(123),
			required: true,
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.have.VerifyNotBefore(tc.cmp, tc.required))
		})
	}
}

func TestMapClaims_Valid(t *testing.T) {
	testCases := []struct {
		name string
		have MapClaims
		opts []ClaimValidationOption
		errs []uint32
		err  string
	}{
		{
			name: "ShouldPass",
			have: MapClaims{},
		},
		{
			name: "ShouldFailEXPNotPresent",
			have: MapClaims{},
			opts: []ClaimValidationOption{ValidateRequireExpiresAt(), ValidateTimeFunc(func() time.Time { return time.Unix(0, 0) })},
			errs: []uint32{ValidationErrorExpired},
			err:  "Token is expired",
		},
		{
			name: "ShouldFailIATNotPresent",
			have: MapClaims{},
			opts: []ClaimValidationOption{ValidateRequireIssuedAt()},
			errs: []uint32{ValidationErrorIssuedAt},
			err:  "Token used before issued",
		},
		{
			name: "ShouldFailNBFNotPresent",
			have: MapClaims{},
			opts: []ClaimValidationOption{ValidateRequireNotBefore()},
			errs: []uint32{ValidationErrorNotValidYet},
			err:  "Token is not valid yet",
		},
		{
			name: "ShouldFailExpPast",
			have: MapClaims{consts.ClaimExpirationTime: 1},
			errs: []uint32{ValidationErrorExpired},
			err:  "Token is expired",
		},
		{
			name: "ShouldFailIssuedFuture",
			have: MapClaims{consts.ClaimIssuedAt: 999999999999999},
			errs: []uint32{ValidationErrorIssuedAt},
			err:  "Token used before issued",
		},
		{
			name: "ShouldFailMultiple",
			have: MapClaims{
				consts.ClaimExpirationTime: 1,
				consts.ClaimIssuedAt:       999999999999999,
			},
			errs: []uint32{ValidationErrorIssuedAt, ValidationErrorExpired},
			err:  "Token used before issued",
		},
		{
			name: "ShouldPassIssuer",
			have: MapClaims{consts.ClaimIssuer: "abc"},
			opts: []ClaimValidationOption{ValidateIssuer("abc")},
		},
		{
			name: "ShouldFailIssuer",
			have: MapClaims{consts.ClaimIssuer: "abc"},
			opts: []ClaimValidationOption{ValidateIssuer("abc2"), ValidateTimeFunc(time.Now)},
			errs: []uint32{ValidationErrorIssuer},
			err:  "Token has invalid issuer",
		},
		{
			name: "ShouldFailIssuerAbsent",
			have: MapClaims{},
			opts: []ClaimValidationOption{ValidateIssuer("abc2")},
			errs: []uint32{ValidationErrorIssuer},
			err:  "Token has invalid issuer",
		},
		{
			name: "ShouldPassSubject",
			have: MapClaims{consts.ClaimSubject: "abc"},
			opts: []ClaimValidationOption{ValidateSubject("abc")},
		},
		{
			name: "ShouldFailSubject",
			have: MapClaims{consts.ClaimSubject: "abc"},
			opts: []ClaimValidationOption{ValidateSubject("abc2")},
			errs: []uint32{ValidationErrorSubject},
			err:  "Token has invalid subject",
		},
		{
			name: "ShouldFailSubjectAbsent",
			have: MapClaims{},
			opts: []ClaimValidationOption{ValidateSubject("abc2")},
			errs: []uint32{ValidationErrorSubject},
			err:  "Token has invalid subject",
		},
		{
			name: "ShouldPassAudienceAll",
			have: MapClaims{consts.ClaimAudience: []any{"abc", "123"}},
			opts: []ClaimValidationOption{ValidateAudienceAll("abc", "123")},
		},
		{
			name: "ShouldFailAudienceAll",
			have: MapClaims{consts.ClaimAudience: []any{"abc", "123"}},
			opts: []ClaimValidationOption{ValidateAudienceAll("abc", "123", "456")},
			errs: []uint32{ValidationErrorAudience},
			err:  "Token has invalid audience",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := tc.have.Valid(tc.opts...)

			if tc.err == "" {
				assert.NoError(t, actual)
				return
			}

			assert.EqualError(t, actual, tc.err)

			var e *ValidationError

			errors.As(actual, &e)

			require.NotNil(t, e)

			var errs uint32

			for _, err := range tc.errs {
				errs |= err

				assert.True(t, e.Has(err))
				assert.Equal(t, len(tc.errs) == 1, e.Is(err))
			}

			assert.Equal(t, errs, e.Errors)
			assert.True(t, e.Is(errs))
		})
	}
}
