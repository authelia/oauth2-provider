// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsLookbackAddress(t *testing.T) {
	testCases := []struct {
		name     string
		have     string
		expected bool
	}{
		{
			"ShouldReturnTrueIPv4Loopback",
			"http://127.0.0.1:1235",
			true,
		},
		{
			"ShouldReturnTrueIPv6Loopback",
			"http://[::1]:1234",
			true,
		},
		{
			"ShouldReturnFalse12700255",
			"https://127.0.0.255",
			true,
		},
		{
			"ShouldReturnTrue127.0.0.255",
			"https://127.0.0.255",
			true,
		},
		{
			"ShouldReturnFalseInvalidFourthOctet",
			"https://127.0.0.11230",
			false,
		},
		{
			"ShouldReturnFalseInvalidIPv4",
			"https://127x0x0x11230",
			false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			have, err := url.Parse(tc.have)

			require.NoError(t, err)
			assert.Equal(t, tc.expected, isLoopbackAddress(have))
		})
	}
}
