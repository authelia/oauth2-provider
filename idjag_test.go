// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"authelia.com/provider/oauth2"
)

func TestIsIDJAGTokenType(t *testing.T) {
	testCases := []struct {
		name     string
		typ      string
		expected bool
	}{
		{"ShouldMatchExact", "oauth-id-jag+jwt", true},
		{"ShouldMatchCaseInsensitive", "OAUTH-ID-JAG+JWT", true},
		{"ShouldMatchMediaType", "application/oauth-id-jag+jwt", true},
		{"ShouldNotMatchJWT", "JWT", false},
		{"ShouldNotMatchEmpty", "", false},
		{"ShouldNotMatchSuffix", "x-oauth-id-jag+jwt", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, oauth2.IsIDJAGTokenType(tc.typ))
		})
	}
}
