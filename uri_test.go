package oauth2

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsMatchingNativeAppLoopbackURI(t *testing.T) {
	testCases := []struct {
		name            string
		uri, registered *url.URL
		expected        bool
	}{
		{
			"ShouldHandleHTTPSRequested",
			MustParseURI(t, "https://127.0.0.1"),
			MustParseURI(t, "http://127.0.0.1"),
			false,
		},
		{
			"ShouldHandleHTTPSRegistered",
			MustParseURI(t, "http://127.0.0.1"),
			MustParseURI(t, "https://127.0.0.1"),
			false,
		},
		{
			"ShouldHandleNonLoopbackRequested",
			MustParseURI(t, "http://google.com"),
			MustParseURI(t, "http://127.0.0.1"),
			false,
		},
		{
			"ShouldHandleNonLoopbackRegistered",
			MustParseURI(t, "http://127.0.0.1"),
			MustParseURI(t, "http://google.com"),
			false,
		},
		{
			"ShouldHandleDifferentLoopbacks",
			MustParseURI(t, "http://127.0.0.1"),
			MustParseURI(t, "http://127.0.0.2"),
			false,
		},
		{
			"ShouldHandleDifferentPaths",
			MustParseURI(t, "http://127.0.0.1/1234"),
			MustParseURI(t, "http://127.0.0.1/abc"),
			false,
		},
		{
			"ShouldHandleDifferentPorts",
			MustParseURI(t, "http://127.0.0.1:1234"),
			MustParseURI(t, "http://127.0.0.1"),
			true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, isMatchingLoopbackURI(tc.uri, tc.registered))
		})
	}
}

func MustParseURI(t *testing.T, uri string) *url.URL {
	t.Helper()

	u, err := url.Parse(uri)
	require.NoError(t, err)

	return u
}
