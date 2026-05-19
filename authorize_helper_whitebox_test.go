// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsLoopbackAddress(t *testing.T) {
	testCases := []struct {
		name     string
		have     string
		expected bool
	}{
		{
			name:     "ShouldReturnTrueForIPv4LoopbackWithPort",
			have:     "http://127.0.0.1:1235",
			expected: true,
		},
		{
			name:     "ShouldReturnTrueForIPv6LoopbackWithPort",
			have:     "http://[::1]:1234",
			expected: true,
		},
		{
			name:     "ShouldReturnTrueFor127DotZeroDotZeroDot255",
			have:     "https://127.0.0.255",
			expected: true,
		},
		{
			name:     "ShouldReturnFalseForInvalidFourthOctet",
			have:     "https://127.0.0.11230",
			expected: false,
		},
		{
			name:     "ShouldReturnFalseForNonDotSeparatedIPv4",
			have:     "https://127x0x0x11230",
			expected: false,
		},
		{
			name:     "ShouldReturnFalseForHostname",
			have:     "https://example.com",
			expected: false,
		},
		{
			name:     "ShouldReturnFalseForNonLoopbackIPv4",
			have:     "https://192.168.1.1",
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			have, err := url.Parse(tc.have)
			require.NoError(t, err)

			actual := isLoopbackAddress(have)
			assert.Equal(t, tc.expected, actual)
		})
	}
}

func TestIsLoopbackAddressNilURL(t *testing.T) {
	testCases := []struct {
		name string
	}{
		{
			name: "ShouldReturnFalseForNilURL",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := isLoopbackAddress(nil)
			assert.False(t, actual)
		})
	}
}
