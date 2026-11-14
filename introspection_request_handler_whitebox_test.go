// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2/internal/consts"
)

func TestIntrospectionCredentialFromRequest(t *testing.T) {
	const errMultiple = "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Multiple methods used to include access token."

	testCases := []struct {
		name     string
		target   string
		header   string
		body     string
		query    bool
		expected string
		err      string
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
		{
			name:     "ShouldReturnTheFormBodyToken",
			body:     "access_token=some-token",
			expected: "some-token",
		},
		{
			name:     "ShouldReturnTheFormBodyTokenAlongsideABasicHeader",
			header:   "Basic abc",
			body:     "access_token=some-token",
			expected: "some-token",
		},
		{
			name:     "ShouldIgnoreTheQueryParameterToken",
			target:   "?access_token=some-token",
			body:     "token=other-token",
			expected: "",
		},
		{
			name:     "ShouldIgnoreTheQueryParameterTokenAlongsideABasicHeader",
			target:   "?access_token=some-token",
			header:   "Basic abc",
			body:     "token=other-token",
			expected: "",
		},
		{
			name:     "ShouldReturnTheQueryParameterTokenWhenEnabled",
			target:   "?access_token=some-token",
			body:     "token=other-token",
			query:    true,
			expected: "some-token",
		},
		{
			name:   "ShouldRejectTheBearerSchemeTokenAlongsideTheFormBodyToken",
			header: "Bearer some-token",
			body:   "access_token=some-token",
			err:    errMultiple,
		},
		{
			name:   "ShouldRejectTheBearerSchemeTokenAlongsideTheQueryParameterToken",
			target: "?access_token=some-token",
			header: "Bearer some-token",
			body:   "token=other-token",
			err:    errMultiple,
		},
		{
			name:   "ShouldRejectTheDPoPSchemeTokenAlongsideTheQueryParameterTokenWhenEnabled",
			target: "?access_token=some-token",
			header: "DPoP some-token",
			body:   "token=other-token",
			query:  true,
			err:    errMultiple,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "https://as.example.com/introspect"+tc.target, strings.NewReader(tc.body))
			r.Header.Set(consts.HeaderContentType, "application/x-www-form-urlencoded")

			if tc.header != "" {
				r.Header.Set(consts.HeaderAuthorization, tc.header)
			}

			require.NoError(t, r.ParseForm())

			token, err := introspectionCredentialFromRequest(r, tc.query)

			if tc.err != "" {
				assert.EqualError(t, ErrorToDebugRFC6749Error(err), tc.err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expected, token)
			}
		})
	}
}
