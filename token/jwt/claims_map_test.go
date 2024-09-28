// Copyright © 2023 Ory Corp
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
			"ShouldPass",
			MapClaims{
				consts.ClaimAudience: []string{"foo"},
			},
			"foo",
			true,
			true,
		},
		{
			"ShouldPassMultiple",
			MapClaims{
				consts.ClaimAudience: []string{"foo", "bar"},
			},
			"foo",
			true,
			true,
		},
		{
			"ShouldFailNoClaim",
			MapClaims{},
			"foo",
			true,
			false,
		},
		{
			"ShouldFailNoMatch",
			MapClaims{
				consts.ClaimAudience: []string{"bar"},
			},
			"foo",
			true,
			false,
		},
		{
			"ShouldPassNoClaim",
			MapClaims{},
			"foo",
			false,
			true,
		},
		{
			"ShouldPassTypeAny",
			MapClaims{
				consts.ClaimAudience: []any{"foo"},
			},
			"foo",
			true,
			true,
		},
		{
			"ShouldPassTypeString",
			MapClaims{
				consts.ClaimAudience: "foo",
			},
			"foo",
			true,
			true,
		},
		{
			"ShouldFailTypeString",
			MapClaims{
				consts.ClaimAudience: "bar",
			},
			"foo",
			true,
			false,
		},
		{
			"ShouldFailTypeNil",
			MapClaims{
				consts.ClaimAudience: nil,
			},
			"foo",
			true,
			false,
		},
		{
			"ShouldFailTypeSliceAnyInt",
			MapClaims{
				consts.ClaimAudience: []any{1, 2, 3},
			},
			"foo",
			true,
			false,
		},
		{
			"ShouldFailTypeInt",
			MapClaims{
				consts.ClaimAudience: 1,
			},
			"foo",
			true,
			false,
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
			"ShouldPass",
			MapClaims{
				consts.ClaimAudience: []string{"foo"},
			},
			[]string{"foo"},
			true,
			true,
		},
		{
			"ShouldFailMultipleAll",
			MapClaims{
				consts.ClaimAudience: []string{"foo"},
			},
			[]string{"foo", "bar"},
			true,
			false,
		},
		{
			"ShouldPassMultiple",
			MapClaims{
				consts.ClaimAudience: []string{"foo", "bar"},
			},
			[]string{"foo"},
			true,
			true,
		},
		{
			"ShouldPassMultipleAll",
			MapClaims{
				consts.ClaimAudience: []string{"foo", "bar"},
			},
			[]string{"foo", "bar"},
			true,
			true,
		},
		{
			"ShouldFailNoClaim",
			MapClaims{},
			[]string{"foo"},
			true,
			false,
		},
		{
			"ShouldFailNoMatch",
			MapClaims{
				consts.ClaimAudience: []string{"bar"},
			},
			[]string{"foo"},
			true,
			false,
		},
		{
			"ShouldPassNoClaim",
			MapClaims{},
			[]string{"foo"},
			false,
			true,
		},
		{
			"ShouldPassTypeAny",
			MapClaims{
				consts.ClaimAudience: []any{"foo"},
			},
			[]string{"foo"},
			true,
			true,
		},
		{
			"ShouldPassTypeString",
			MapClaims{
				consts.ClaimAudience: "foo",
			},
			[]string{"foo"},
			true,
			true,
		},
		{
			"ShouldFailTypeString",
			MapClaims{
				consts.ClaimAudience: "bar",
			},
			[]string{"foo"},
			true,
			false,
		},
		{
			"ShouldFailTypeNil",
			MapClaims{
				consts.ClaimAudience: nil,
			},
			[]string{"foo"},
			true,
			false,
		},
		{
			"ShouldFailTypeSliceAnyInt",
			MapClaims{
				consts.ClaimAudience: []any{1, 2, 3},
			},
			[]string{"foo"},
			true,
			false,
		},
		{
			"ShouldFailTypeInt",
			MapClaims{
				consts.ClaimAudience: 1,
			},
			[]string{"foo"},
			true,
			false,
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
			"ShouldPass",
			MapClaims{
				consts.ClaimAudience: []string{"foo"},
			},
			[]string{"foo"},
			true,
			true,
		},
		{
			"ShouldPassMultipleAny",
			MapClaims{
				consts.ClaimAudience: []string{"foo", "baz"},
			},
			[]string{"bar", "baz"},
			true,
			true,
		},
		{
			"ShouldPassMultiple",
			MapClaims{
				consts.ClaimAudience: []string{"foo", "bar"},
			},
			[]string{"foo"},
			true,
			true,
		},
		{
			"ShouldPassMultipleAll",
			MapClaims{
				consts.ClaimAudience: []string{"foo", "bar"},
			},
			[]string{"foo", "bar"},
			true,
			true,
		},
		{
			"ShouldFailNoClaim",
			MapClaims{},
			[]string{"foo"},
			true,
			false,
		},
		{
			"ShouldFailNoMatch",
			MapClaims{
				consts.ClaimAudience: []string{"bar"},
			},
			[]string{"foo"},
			true,
			false,
		},
		{
			"ShouldPassNoClaim",
			MapClaims{},
			[]string{"foo"},
			false,
			true,
		},
		{
			"ShouldPassTypeAny",
			MapClaims{
				consts.ClaimAudience: []any{"foo"},
			},
			[]string{"foo"},
			true,
			true,
		},
		{
			"ShouldPassTypeString",
			MapClaims{
				consts.ClaimAudience: "foo",
			},
			[]string{"foo"},
			true,
			true,
		},
		{
			"ShouldFailTypeString",
			MapClaims{
				consts.ClaimAudience: "bar",
			},
			[]string{"foo"},
			true,
			false,
		},
		{
			"ShouldFailTypeNil",
			MapClaims{
				consts.ClaimAudience: nil,
			},
			[]string{"foo"},
			true,
			false,
		},
		{
			"ShouldFailTypeSliceAnyInt",
			MapClaims{
				consts.ClaimAudience: []any{1, 2, 3},
			},
			[]string{"foo"},
			true,
			false,
		},
		{
			"ShouldFailTypeInt",
			MapClaims{
				consts.ClaimAudience: 1,
			},
			[]string{"foo"},
			true,
			false,
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
			"ShouldPass",
			MapClaims{
				consts.ClaimIssuer: "foo",
			},
			"foo",
			true,
			true,
		},
		{
			"ShouldFailEmptyString",
			MapClaims{
				consts.ClaimIssuer: "",
			},
			"foo",
			true,
			false,
		},
		{
			"ShouldFailNoClaim",
			MapClaims{},
			"foo",
			true,
			false,
		},
		{
			"ShouldPassNoClaim",
			MapClaims{},
			"foo",
			false,
			true,
		},
		{
			"ShouldFailNoMatch",
			MapClaims{
				consts.ClaimIssuer: "bar",
			},
			"foo",
			true,
			false,
		},
		{
			"ShouldFailWrongType",
			MapClaims{
				consts.ClaimIssuer: 5,
			},
			"5",
			true,
			false,
		},
		{
			"ShouldFailNil",
			MapClaims{
				consts.ClaimIssuer: nil,
			},
			"foo",
			true,
			false,
		},
		{
			"ShouldPassNil",
			MapClaims{
				consts.ClaimIssuer: nil,
			},
			"foo",
			false,
			true,
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
			"ShouldPass",
			MapClaims{
				consts.ClaimSubject: "foo",
			},
			"foo",
			true,
			true,
		},
		{
			"ShouldFailNoClaim",
			MapClaims{},
			"foo",
			true,
			false,
		},
		{
			"ShouldPassNoClaim",
			MapClaims{},
			"foo",
			false,
			true,
		},
		{
			"ShouldFailNoMatch",
			MapClaims{
				consts.ClaimSubject: "bar",
			},
			"foo",
			true,
			false,
		},
		{
			"ShouldFailWrongType",
			MapClaims{
				consts.ClaimSubject: 5,
			},
			"5",
			true,
			false,
		},
		{
			"ShouldFailNil",
			MapClaims{
				consts.ClaimSubject: nil,
			},
			"foo",
			true,
			false,
		},
		{
			"ShouldPassNil",
			MapClaims{
				consts.ClaimSubject: nil,
			},
			"foo",
			false,
			true,
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
			"ShouldPass",
			MapClaims{
				consts.ClaimExpirationTime: int64(123),
			},
			int64(123),
			true,
			true,
		},
		{
			"ShouldPassStandardInt",
			MapClaims{
				consts.ClaimExpirationTime: 123,
			},
			int64(123),
			true,
			true,
		},
		{
			"ShouldPassStandardInt32",
			MapClaims{
				consts.ClaimExpirationTime: int32(123),
			},
			int64(123),
			true,
			true,
		},
		{
			"ShouldFailNoClaim",
			MapClaims{},
			int64(123),
			true,
			false,
		},
		{
			"ShouldPassNoClaim",
			MapClaims{},
			int64(123),
			false,
			true,
		},
		{
			"ShouldFailNoMatch",
			MapClaims{
				consts.ClaimExpirationTime: 4,
			},
			int64(123),
			true,
			false,
		},
		{
			"ShouldFailWrongType",
			MapClaims{
				consts.ClaimExpirationTime: true,
			},
			int64(123),
			true,
			false,
		},
		{
			"ShouldFailNil",
			MapClaims{
				consts.ClaimExpirationTime: nil,
			},
			int64(123),
			true,
			false,
		},
		{
			"ShouldPassNil",
			MapClaims{
				consts.ClaimExpirationTime: nil,
			},
			int64(123),
			false,
			true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.have.VerifyExpiresAt(tc.cmp, tc.required))
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
			"ShouldPass",
			MapClaims{
				consts.ClaimIssuedAt: int64(123),
			},
			int64(123),
			true,
			true,
		},
		{
			"ShouldPassStandardInt",
			MapClaims{
				consts.ClaimIssuedAt: 123,
			},
			int64(123),
			true,
			true,
		},
		{
			"ShouldPassStandardInt32",
			MapClaims{
				consts.ClaimIssuedAt: int32(123),
			},
			int64(123),
			true,
			true,
		},
		{
			"ShouldFailNoClaim",
			MapClaims{},
			int64(123),
			true,
			false,
		},
		{
			"ShouldPassNoClaim",
			MapClaims{},
			int64(123),
			false,
			true,
		},
		{
			"ShouldFailFuture",
			MapClaims{
				consts.ClaimIssuedAt: 9000,
			},
			int64(123),
			true,
			false,
		},
		{
			"ShouldPassPast",
			MapClaims{
				consts.ClaimIssuedAt: 4,
			},
			int64(123),
			true,
			true,
		},
		{
			"ShouldFailWrongType",
			MapClaims{
				consts.ClaimIssuedAt: true,
			},
			int64(123),
			true,
			false,
		},
		{
			"ShouldFailNil",
			MapClaims{
				consts.ClaimIssuedAt: nil,
			},
			int64(123),
			true,
			false,
		},
		{
			"ShouldPassNil",
			MapClaims{
				consts.ClaimIssuedAt: nil,
			},
			int64(123),
			false,
			true,
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
			"ShouldPass",
			MapClaims{
				consts.ClaimNotBefore: int64(123),
			},
			int64(123),
			true,
			true,
		},
		{
			"ShouldPassStandardInt",
			MapClaims{
				consts.ClaimNotBefore: 123,
			},
			int64(123),
			true,
			true,
		},
		{
			"ShouldPassStandardInt32",
			MapClaims{
				consts.ClaimNotBefore: int32(123),
			},
			int64(123),
			true,
			true,
		},
		{
			"ShouldFailNoClaim",
			MapClaims{},
			int64(123),
			true,
			false,
		},
		{
			"ShouldPassNoClaim",
			MapClaims{},
			int64(123),
			false,
			true,
		},
		{
			"ShouldFailFuture",
			MapClaims{
				consts.ClaimNotBefore: 9000,
			},
			int64(123),
			true,
			false,
		},
		{
			"ShouldPassPast",
			MapClaims{
				consts.ClaimNotBefore: 4,
			},
			int64(123),
			true,
			true,
		},
		{
			"ShouldFailWrongType",
			MapClaims{
				consts.ClaimNotBefore: true,
			},
			int64(123),
			true,
			false,
		},
		{
			"ShouldFailNil",
			MapClaims{
				consts.ClaimNotBefore: nil,
			},
			int64(123),
			true,
			false,
		},
		{
			"ShouldPassNil",
			MapClaims{
				consts.ClaimNotBefore: nil,
			},
			int64(123),
			false,
			true,
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
			"ShouldPass",
			MapClaims{},
			nil,
			nil,
			"",
		},
		{
			"ShouldFailEXPNotPresent",
			MapClaims{},
			[]ClaimValidationOption{ValidateRequireExpiresAt(), ValidateTimeFunc(func() time.Time { return time.Unix(0, 0) })},
			[]uint32{ValidationErrorExpired},
			"Token is expired",
		},
		{
			"ShouldFailIATNotPresent",
			MapClaims{},
			[]ClaimValidationOption{ValidateRequireIssuedAt()},
			[]uint32{ValidationErrorIssuedAt},
			"Token used before issued",
		},
		{
			"ShouldFailNBFNotPresent",
			MapClaims{},
			[]ClaimValidationOption{ValidateRequireNotBefore()},
			[]uint32{ValidationErrorNotValidYet},
			"Token is not valid yet",
		},
		{
			"ShouldFailExpPast",
			MapClaims{
				consts.ClaimExpirationTime: 1,
			},
			nil,
			[]uint32{ValidationErrorExpired},
			"Token is expired",
		},
		{
			"ShouldFailIssuedFuture",
			MapClaims{
				consts.ClaimIssuedAt: 999999999999999,
			},
			nil,
			[]uint32{ValidationErrorIssuedAt},
			"Token used before issued",
		},
		{
			"ShouldFailMultiple",
			MapClaims{
				consts.ClaimExpirationTime: 1,
				consts.ClaimIssuedAt:       999999999999999,
			},
			nil,
			[]uint32{ValidationErrorIssuedAt, ValidationErrorExpired},
			"Token used before issued",
		},
		{
			"ShouldPassIssuer",
			MapClaims{
				consts.ClaimIssuer: "abc",
			},
			[]ClaimValidationOption{ValidateIssuer("abc")},
			nil,
			"",
		},
		{
			"ShouldFailIssuer",
			MapClaims{
				consts.ClaimIssuer: "abc",
			},
			[]ClaimValidationOption{ValidateIssuer("abc2"), ValidateTimeFunc(time.Now)},
			[]uint32{ValidationErrorIssuer},
			"Token has invalid issuer",
		},
		{
			"ShouldFailIssuerAbsent",
			MapClaims{},
			[]ClaimValidationOption{ValidateIssuer("abc2")},
			[]uint32{ValidationErrorIssuer},
			"Token has invalid issuer",
		},
		{
			"ShouldPassSubject",
			MapClaims{
				consts.ClaimSubject: "abc",
			},
			[]ClaimValidationOption{ValidateSubject("abc")},
			nil,
			"",
		},
		{
			"ShouldFailSubject",
			MapClaims{
				consts.ClaimSubject: "abc",
			},
			[]ClaimValidationOption{ValidateSubject("abc2")},
			[]uint32{ValidationErrorSubject},
			"Token has invalid subject",
		},
		{
			"ShouldFailSubjectAbsent",
			MapClaims{},
			[]ClaimValidationOption{ValidateSubject("abc2")},
			[]uint32{ValidationErrorSubject},
			"Token has invalid subject",
		},
		{
			"ShouldPassAudienceAll",
			MapClaims{
				consts.ClaimAudience: []any{"abc", "123"},
			},
			[]ClaimValidationOption{ValidateAudienceAll("abc", "123")},
			nil,
			"",
		},
		{
			"ShouldFailAudienceAll",
			MapClaims{
				consts.ClaimAudience: []any{"abc", "123"},
			},
			[]ClaimValidationOption{ValidateAudienceAll("abc", "123", "456")},
			[]uint32{ValidationErrorAudience},
			"Token has invalid audience",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := tc.have.Valid(tc.opts...)

			if len(tc.err) == 0 && tc.err == "" {
				assert.NoError(t, actual)
			} else {
				if tc.err != "" {
					assert.EqualError(t, actual, tc.err)
				}

				var e *ValidationError

				errors.As(actual, &e)

				require.NotNil(t, e)

				var errs uint32

				for _, err := range tc.errs {
					errs |= err

					assert.True(t, e.Has(err))
				}

				assert.Equal(t, errs, e.Errors)
			}
		})
	}
}
