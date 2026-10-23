// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateClientIdentifierURL(t *testing.T) {
	testCases := []struct {
		name  string
		id    string
		valid bool
	}{
		{"ShouldAcceptPath", "https://client.example.com/metadata.json", true},
		{"ShouldAcceptRootPath", "https://client.example.com/", true},
		{"ShouldAcceptPort", "https://client.example.com:8443/client", true},
		{"ShouldAcceptQuery", "https://client.example.com/client?v=1", true},
		{"ShouldAcceptDotInsideSegment", "https://client.example.com/a.b/..c", true},
		{"ShouldAcceptUppercaseHost", "https://Client.Example.COM/client", true},
		{"ShouldAcceptTrailingDotHost", "https://client.example.com./client", true},
		{"ShouldAcceptIPv6Host", "https://[2001:db8::1]:8443/client", true},
		{"ShouldAcceptEmptySegment", "https://client.example.com//client", true},
		{"ShouldAcceptEmptyQuery", "https://client.example.com/client?", true},
		{"ShouldAcceptEncodedSlash", "https://client.example.com/a%2Fb", true},
		{"ShouldAcceptEncodedSpace", "https://client.example.com/a%20b", true},
		{"ShouldRejectSpaceInPath", "https://client.example.com/a b", false},
		{"ShouldRejectSpaceInQuery", "https://client.example.com/client?a b", false},
		{"ShouldRejectNonASCIIPath", "https://client.example.com/p\u00e9", false},
		{"ShouldRejectNonASCIIHost", "https://ex\u00e4mple.com/client", false},
		{"ShouldRejectControlCharacter", "https://client.example.com/client\t", false},
		{"ShouldRejectEmptyPort", "https://client.example.com:/client", false},
		{"ShouldRejectEmptyPortOnIPv6Host", "https://[2001:db8::1]:/client", false},
		{"ShouldRejectEmpty", "", false},
		{"ShouldRejectOpaqueIdentifier", "my-client", false},
		{"ShouldRejectHTTP", "http://client.example.com/client", false},
		{"ShouldRejectUppercaseScheme", "HTTPS://client.example.com/client", false},
		{"ShouldRejectUserinfo", "https://user@client.example.com/client", false},
		{"ShouldRejectUserinfoWithPassword", "https://user:pass@client.example.com/client", false},
		{"ShouldRejectMissingHost", "https:///client", false},
		{"ShouldRejectMissingPath", "https://client.example.com", false},
		{"ShouldRejectMissingPathWithQuery", "https://client.example.com?v=1", false},
		{"ShouldRejectSingleDotSegment", "https://client.example.com/./client", false},
		{"ShouldRejectDoubleDotSegment", "https://client.example.com/a/../client", false},
		{"ShouldRejectTrailingDoubleDotSegment", "https://client.example.com/a/..", false},
		{"ShouldRejectEncodedDotSegment", "https://client.example.com/%2e/client", false},
		{"ShouldRejectEncodedDoubleDotSegment", "https://client.example.com/%2E%2e/client", false},
		{"ShouldRejectFragment", "https://client.example.com/client#frag", false},
		{"ShouldRejectEmptyFragment", "https://client.example.com/client#", false},
		{"ShouldRejectInvalidEscape", "https://client.example.com/%zz", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateClientIdentifierURL(tc.id)

			if tc.valid {
				assert.NoError(t, err)

				request, rerr := http.NewRequest(http.MethodGet, tc.id, nil)

				require.NoError(t, rerr)
				assert.Equal(t, tc.id, request.URL.String())
			} else {
				assert.ErrorIs(t, err, ErrInvalidClient)
			}

			assert.Equal(t, tc.valid, IsClientIdentifierURL(tc.id))
		})
	}
}
