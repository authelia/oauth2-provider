// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateResponseTypes(t *testing.T) {
	testCases := []struct {
		name           string
		rt             string
		art            []string
		omitResponseTy bool
		expected       string
	}{
		{
			name:     "ShouldFailClientNotAllowedCode",
			rt:       "code",
			art:      []string{"token"},
			expected: "The authorization server does not support obtaining a token using this method. The client is not allowed to request response_type 'code'.",
		},
		{
			name: "ShouldPassToken",
			rt:   "token",
			art:  []string{"token"},
		},
		{
			name:     "ShouldFailMissingResponseType",
			rt:       "",
			art:      []string{"token"},
			expected: "The authorization server does not support obtaining a token using this method. The request is missing the 'response_type' parameter.",
		},
		{
			name:     "ShouldFailWhitespaceResponseType",
			rt:       "  ",
			art:      []string{"token"},
			expected: "The authorization server does not support obtaining a token using this method. The request is missing the 'response_type' parameter.",
		},
		{
			name:           "ShouldFailWhenResponseTypeFormKeyMissing",
			omitResponseTy: true,
			art:            []string{"token"},
			expected:       "The authorization server does not support obtaining a token using this method. The request is missing the 'response_type' parameter.",
		},
		{
			name:     "ShouldFailClientNotAllowedCodeToken",
			rt:       "code token",
			art:      []string{"token", "code"},
			expected: "The authorization server does not support obtaining a token using this method. The client is not allowed to request response_type 'code token'.",
		},
		{
			name: "ShouldPassCodeTokenWithTokenCode",
			rt:   "code token",
			art:  []string{"token", "token code"},
		},
		{
			name: "ShouldPassCodeTokenWithCodeToken",
			rt:   "code token",
			art:  []string{"token", "code token"},
		},
		{
			name:     "ShouldFailClientNotAllowedCodeTokenIDToken",
			rt:       "code token",
			art:      []string{"token", "code token id_token"},
			expected: "The authorization server does not support obtaining a token using this method. The client is not allowed to request response_type 'code token'.",
		},
		{
			name:     "ShouldFailWhenClientResponseTypesUnsetAndRequestIsNotCode",
			rt:       "token",
			art:      nil,
			expected: "The authorization server does not support obtaining a token using this method. The client is not allowed to request response_type 'token'.",
		},
		{
			name: "ShouldPassWhenClientHasMultipleResponseTypesAndOneMatches",
			rt:   "code",
			art:  []string{"token", "code", "id_token"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			provider := &Fosite{Config: new(Config)}

			form := url.Values{}
			if !tc.omitResponseTy {
				form.Set("response_type", tc.rt)
			}

			r := &http.Request{Form: form}
			ar := NewAuthorizeRequest()
			ar.Client = &DefaultClient{ResponseTypes: tc.art}

			actual := provider.validateResponseTypes(t.Context(), r, ar)

			if tc.expected != "" {
				require.EqualError(t, ErrorToDebugRFC6749Error(actual), tc.expected)

				return
			}

			require.NoError(t, ErrorToDebugRFC6749Error(actual))
			assert.EqualValues(t, RemoveEmpty(strings.Split(tc.rt, " ")), ar.GetResponseTypes())
		})
	}
}
