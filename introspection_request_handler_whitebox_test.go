// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2/internal/consts"
)

func TestIntrospectionCredentialFromRequest(t *testing.T) {
	testCases := []struct {
		name     string
		headers  []string
		query    string
		body     string
		expected string
		err      string
	}{
		{
			name:     "ShouldReturnEmptyWithoutCredential",
			body:     "token=abc",
			expected: "",
		},
		{
			name:     "ShouldExtractBearerHeader",
			headers:  []string{"Bearer header-token"},
			body:     "token=abc",
			expected: "header-token",
		},
		{
			name:     "ShouldExtractDPoPHeader",
			headers:  []string{"DPoP header-token"},
			body:     "token=abc",
			expected: "header-token",
		},
		{
			name:     "ShouldExtractFormParameter",
			body:     "token=abc&access_token=form-token",
			expected: "form-token",
		},
		{
			name:     "ShouldExtractQueryParameter",
			query:    "access_token=query-token",
			body:     "token=abc",
			expected: "query-token",
		},
		{
			name:    "ShouldRejectDuplicateHeaders",
			headers: []string{"Bearer one", "Bearer two"},
			body:    "token=abc",
			err:     "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Multiple methods used to include access token.",
		},
		{
			name:    "ShouldRejectBearerHeaderWithFormParameter",
			headers: []string{"Bearer header-token"},
			body:    "token=abc&access_token=form-token",
			err:     "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Multiple methods used to include access token.",
		},
		{
			name:    "ShouldRejectDPoPHeaderWithFormParameter",
			headers: []string{"DPoP header-token"},
			body:    "token=abc&access_token=form-token",
			err:     "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Multiple methods used to include access token.",
		},
		{
			name:    "ShouldRejectBearerHeaderWithQueryParameter",
			headers: []string{"Bearer header-token"},
			query:   "access_token=query-token",
			body:    "token=abc",
			err:     "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Multiple methods used to include access token.",
		},
		{
			name:     "ShouldAllowBasicHeaderWithFormParameter",
			headers:  []string{"Basic Y2xpZW50OnNlY3JldA=="},
			body:     "token=abc&access_token=form-token",
			expected: "form-token",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			target := "https://auth.example.com/introspect"

			if tc.query != "" {
				target += "?" + tc.query
			}

			r, err := http.NewRequest(http.MethodPost, target, strings.NewReader(tc.body))
			require.NoError(t, err)

			r.Header.Set(consts.HeaderContentType, consts.ContentTypeApplicationURLEncodedForm)

			for i, value := range tc.headers {
				if i == 0 {
					r.Header.Set(consts.HeaderAuthorization, value)
				} else {
					r.Header.Add(consts.HeaderAuthorization, value)
				}
			}

			require.NoError(t, r.ParseForm())

			token, err := introspectionCredentialFromRequest(r)

			if tc.err != "" {
				require.Error(t, err)
				assert.Equal(t, tc.err, ErrorToRFC6749Error(err).WithExposeDebug(true).GetDescription())
				assert.Equal(t, "", token)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expected, token)
			}
		})
	}
}
