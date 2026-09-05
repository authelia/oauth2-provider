// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oidckb

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestCodeHash pins the encoding with the non-normative examples from OpenID Connect Key Binding 1.0. The expected
// values are the 'c_s256' claims of the example DPoP proofs in those sections, over the codes in the same examples.
func TestCodeHash(t *testing.T) {
	testCases := []struct {
		name     string
		have     string
		expected string
	}{
		{
			name:     "ShouldMatchSection2Point3AuthorizationCode",
			have:     "SplxlOBeZQQYbYS6WxSbIA",
			expected: "o1uBp9eSe3DsmScN0jYriFgKKFdK-BLywC9WRpV5GG8",
		},
		{
			name:     "ShouldMatchSection3Point3DeviceCode",
			have:     "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS",
			expected: "z-6KJMF671PQKXSuIHAVQfnEVR2x1AUsfHlvC50va38",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, CodeHash(tc.have))
		})
	}
}
