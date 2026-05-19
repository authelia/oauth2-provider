// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

func TestNewBCryptClientSecret(t *testing.T) {
	testCases := []struct {
		name  string
		hash  string
		valid bool
	}{
		{
			name:  "ShouldReturnValidSecretForHash",
			hash:  "$2a$12$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZabcd",
			valid: true,
		},
		{
			name:  "ShouldReturnInvalidSecretForEmptyHash",
			hash:  "",
			valid: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := NewBCryptClientSecret(tc.hash)
			require.NotNil(t, actual)
			assert.Equal(t, tc.valid, actual.Valid())
			assert.Equal(t, []byte(tc.hash), actual.value)
		})
	}
}

func TestNewBCryptClientSecretPlain(t *testing.T) {
	testCases := []struct {
		name  string
		raw   string
		cost  int
		err   bool
		check func(t *testing.T, secret *BCryptClientSecret)
	}{
		{
			name: "ShouldHashWithDefaultWorkFactor",
			raw:  "hello world",
			cost: DefaultBCryptWorkFactor,
			check: func(t *testing.T, secret *BCryptClientSecret) {
				require.NotNil(t, secret)
				assert.True(t, secret.Valid())
				require.NoError(t, secret.Compare(t.Context(), []byte("hello world")))
			},
		},
		{
			name: "ShouldHashWithMinCost",
			raw:  "hello world",
			cost: bcrypt.MinCost,
			check: func(t *testing.T, secret *BCryptClientSecret) {
				require.NotNil(t, secret)
				assert.True(t, secret.Valid())
				require.NoError(t, secret.Compare(t.Context(), []byte("hello world")))
			},
		},
		{
			name: "ShouldFailWhenCostExceedsMax",
			raw:  "hello world",
			cost: bcrypt.MaxCost + 1,
			err:  true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual, err := NewBCryptClientSecretPlain(tc.raw, tc.cost)
			if tc.err {
				require.Error(t, err)
				assert.Nil(t, actual)
				return
			}

			require.NoError(t, err)
			tc.check(t, actual)
		})
	}
}

func TestBCryptClientSecretCompare(t *testing.T) {
	secret, err := NewBCryptClientSecretPlain("hello world", DefaultBCryptWorkFactor)
	require.NoError(t, err)

	testCases := []struct {
		name  string
		input string
		err   bool
	}{
		{
			name:  "ShouldNotErrorWhenSecretMatches",
			input: "hello world",
		},
		{
			name:  "ShouldErrorWhenSecretMismatch",
			input: "some invalid password",
			err:   true,
		},
		{
			name:  "ShouldErrorWhenSecretEmpty",
			input: "",
			err:   true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := secret.Compare(t.Context(), []byte(tc.input))
			if tc.err {
				assert.Error(t, actual)
				return
			}
			assert.NoError(t, actual)
		})
	}
}

func TestBCryptClientSecretIsPlainText(t *testing.T) {
	testCases := []struct {
		name     string
		secret   *BCryptClientSecret
		expected bool
	}{
		{
			name:     "ShouldNotBePlainTextForHash",
			secret:   NewBCryptClientSecret("hash"),
			expected: false,
		},
		{
			name:     "ShouldNotBePlainTextForEmpty",
			secret:   NewBCryptClientSecret(""),
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := tc.secret.IsPlainText()
			assert.Equal(t, tc.expected, actual)
		})
	}
}

func TestBCryptClientSecretGetPlainTextValue(t *testing.T) {
	testCases := []struct {
		name string
	}{
		{
			name: "ShouldReturnUnsupportedError",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			secret := NewBCryptClientSecret("hash")
			value, err := secret.GetPlainTextValue()

			assert.Nil(t, value)
			require.Error(t, err)
			assert.EqualError(t, err, "this secret doesn't support plaintext")
		})
	}
}

func TestBCryptClientSecretValid(t *testing.T) {
	testCases := []struct {
		name     string
		secret   *BCryptClientSecret
		expected bool
	}{
		{
			name:     "ShouldNotBeValidWhenNil",
			secret:   nil,
			expected: false,
		},
		{
			name:     "ShouldNotBeValidWhenEmpty",
			secret:   NewBCryptClientSecret(""),
			expected: false,
		},
		{
			name:     "ShouldBeValidWhenHashSet",
			secret:   NewBCryptClientSecret("hash"),
			expected: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := tc.secret.Valid()
			assert.Equal(t, tc.expected, actual)
		})
	}
}
