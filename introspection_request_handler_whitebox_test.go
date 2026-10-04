// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2/internal/consts"
)

func TestIntrospectionCredentialFromRequest(t *testing.T) {
	testCases := []struct {
		name     string
		header   string
		expected string
	}{
		{
			name:     "ShouldReturnTheDPoPSchemeToken",
			header:   "DPoP some-token",
			expected: "some-token",
		},
		{
			name:     "ShouldMatchTheDPoPSchemeWithoutRegardToCase",
			header:   "dpop some-token",
			expected: "some-token",
		},
		{
			name:     "ShouldTrimRepeatedSpacesAfterTheDPoPScheme",
			header:   "DPoP   some-token",
			expected: "some-token",
		},
		{
			name:     "ShouldReturnNothingForTheDPoPSchemeWithoutAToken",
			header:   "DPoP  ",
			expected: "",
		},
		{
			name:     "ShouldReturnTheBearerSchemeToken",
			header:   "Bearer some-token",
			expected: "some-token",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "https://as.example.com/introspect", nil)
			r.Header.Set(consts.HeaderAuthorization, tc.header)

			token, err := introspectionCredentialFromRequest(r)

			require.NoError(t, err)
			assert.Equal(t, tc.expected, token)
		})
	}
}
