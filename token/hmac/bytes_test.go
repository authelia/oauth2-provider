// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package hmac

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRandomBytes(t *testing.T) {
	testCases := []struct {
		name string
		size int
	}{
		{
			name: "ShouldReturn128Bytes",
			size: 128,
		},
		{
			name: "ShouldReturn32Bytes",
			size: 32,
		},
		{
			name: "ShouldReturnZeroBytesForZeroSize",
			size: 0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual, err := RandomBytes(tc.size)
			require.NoError(t, err)
			assert.Len(t, actual, tc.size)
		})
	}
}

func TestRandomBytesPseudoRandomness(t *testing.T) {
	testCases := []struct {
		name string
		runs int
		size int
	}{
		{
			name: "ShouldNotRepeatAcross65536Runs",
			runs: 65536,
			size: 128,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			results := make(map[string]bool, tc.runs)
			for i := 0; i < tc.runs; i++ {
				bytes, err := RandomBytes(tc.size)
				require.NoError(t, err)

				_, ok := results[string(bytes)]
				assert.Falsef(t, ok, "duplicate random output at iteration %d", i)
				results[string(bytes)] = true
			}
		})
	}
}
