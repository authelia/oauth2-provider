// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package jwt

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidationErrorHasAndIsExactly(t *testing.T) {
	testCases := []struct {
		name      string
		errors    uint32
		check     uint32
		isExactly bool
		has       bool
	}{
		{
			name:      "ShouldMatchSingleFlag",
			errors:    ValidationErrorExpired,
			check:     ValidationErrorExpired,
			isExactly: true,
			has:       true,
		},
		{
			name:      "ShouldNotMatchExactlyWhenOtherFlagsAreSet",
			errors:    ValidationErrorExpired | ValidationErrorSignatureInvalid,
			check:     ValidationErrorExpired,
			isExactly: false,
			has:       true,
		},
		{
			name:      "ShouldNotMatchDifferentFlag",
			errors:    ValidationErrorIssuer,
			check:     ValidationErrorExpired,
			isExactly: false,
			has:       false,
		},
		{
			name:      "ShouldNotMatchWhenNoFlagsAreSet",
			errors:    0,
			check:     ValidationErrorExpired,
			isExactly: false,
			has:       false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ve := &ValidationError{Errors: tc.errors}

			assert.Equal(t, tc.isExactly, ve.IsExactly(tc.check))
			assert.Equal(t, tc.has, ve.Has(tc.check))
		})
	}
}
