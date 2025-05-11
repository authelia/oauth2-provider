// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCompare(t *testing.T) {
	secret, err := NewBCryptClientSecretPlain("hello world", DefaultBCryptWorkFactor)
	require.NoError(t, err)

	testCases := []struct {
		name        string
		have        string
		shouldError bool
	}{
		{
			name:        "should not return an error if hash of provided password matches hash of expected password",
			have:        "hello world",
			shouldError: false,
		},
		{
			name:        "should return an error if hash of provided password does not match hash of expected password",
			have:        "some invalid password",
			shouldError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.shouldError {
				assert.Error(t, secret.Compare(t.Context(), []byte(tc.have)))
			} else {
				assert.NoError(t, secret.Compare(t.Context(), []byte(tc.have)))
			}
		})
	}
}
