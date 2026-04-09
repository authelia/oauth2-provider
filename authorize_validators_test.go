// Copyright © 2023 Ory Corp
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
		name string
		rt   string
		art  []string
		err  string
	}{
		{
			name: "ShouldFailClientNotAllowedCode",
			rt:   "code",
			art:  []string{"token"},
			err:  "The authorization server does not support obtaining a token using this method. The client is not allowed to request response_type 'code'.",
		},
		{
			name: "ShouldPassToken",
			rt:   "token",
			art:  []string{"token"},
		},
		{
			name: "ShouldFailMissingResponseType",
			rt:   "",
			art:  []string{"token"},
			err:  "The authorization server does not support obtaining a token using this method. The request is missing the 'response_type' parameter.",
		},
		{
			name: "ShouldFailWhitespaceResponseType",
			rt:   "  ",
			art:  []string{"token"},
			err:  "The authorization server does not support obtaining a token using this method. The request is missing the 'response_type' parameter.",
		},
		{
			name: "ShouldFailDisabledResponseType",
			rt:   "disable",
			art:  []string{"token"},
			err:  "The authorization server does not support obtaining a token using this method. The request is missing the 'response_type' parameter.",
		},
		{
			name: "ShouldFailClientNotAllowedCodeToken",
			rt:   "code token",
			art:  []string{"token", "code"},
			err:  "The authorization server does not support obtaining a token using this method. The client is not allowed to request response_type 'code token'.",
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
			name: "ShouldFailClientNotAllowedCodeTokenIDToken",
			rt:   "code token",
			art:  []string{"token", "code token id_token"},
			err:  "The authorization server does not support obtaining a token using this method. The client is not allowed to request response_type 'code token'.",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			provider := &Fosite{Config: new(Config)}

			r := &http.Request{Form: url.Values{"response_type": {tc.rt}}}
			if tc.rt == "disable" {
				r = &http.Request{Form: url.Values{}}
			}
			ar := NewAuthorizeRequest()
			ar.Client = &DefaultClient{ResponseTypes: tc.art}

			err := provider.validateResponseTypes(r, ar)
			if tc.err != "" {
				require.EqualError(t, ErrorToDebugRFC6749Error(err), tc.err)
			} else {
				require.NoError(t, err)
				assert.EqualValues(t, RemoveEmpty(strings.Split(tc.rt, " ")), ar.GetResponseTypes())
			}
		})
	}
}
