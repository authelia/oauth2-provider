// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package hmac

import (
	"context"
	"crypto/sha512"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
)

const (
	validSecret   = "1234567890123456789012345678901234567890"
	otherSecret   = "abcdefgh90123456789012345678901234567890"
	rotatedSecret = "0000000090123456789012345678901234567890"
	shortSecret   = "abcdefgh90123456789012345678901"
)

func TestHMACStrategyGenerate(t *testing.T) {
	testCases := []struct {
		name         string
		globalSecret []byte
		entropy      int
		err          string
	}{
		{
			name:         "ShouldFailWhenSecretTooShort",
			globalSecret: []byte("foo"),
			entropy:      32,
			err:          "secret for signing HMAC-SHA512/256 is expected to be 32 byte long, got 3 byte",
		},
		{
			name:         "ShouldGenerateWith32ByteEntropy",
			globalSecret: []byte(validSecret),
			entropy:      32,
		},
		{
			name:         "ShouldGenerateWith64ByteEntropy",
			globalSecret: []byte(validSecret),
			entropy:      64,
		},
		{
			name:         "ShouldGenerateUsingDefaultEntropyWhenBelowMinimum",
			globalSecret: []byte(validSecret),
			entropy:      0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cg := HMACStrategy{Config: &oauth2.Config{
				GlobalSecret: tc.globalSecret,
				TokenEntropy: tc.entropy,
			}}

			token, signature, err := cg.Generate(context.Background())

			if tc.err != "" {
				assert.EqualError(t, err, tc.err)
				assert.Empty(t, token)
				assert.Empty(t, signature)

				return
			}

			require.NoError(t, err)
			assert.NotEmpty(t, token)
			assert.NotEmpty(t, signature)
			assert.Equal(t, signature, cg.Signature(token), "Signature() must extract the same signature")

			require.NoError(t, cg.Validate(context.Background(), token))
		})
	}
}

func TestHMACStrategyValidate(t *testing.T) {
	testCases := []struct {
		name   string
		token  string
		config *oauth2.Config
		err    string
	}{
		{
			name:   "ShouldFailEmptyToken",
			token:  "",
			config: &oauth2.Config{GlobalSecret: []byte(validSecret)},
			err:    oauth2.ErrInvalidTokenFormat.Error(),
		},
		{
			name:   "ShouldFailWhitespaceToken",
			token:  " ",
			config: &oauth2.Config{GlobalSecret: []byte(validSecret)},
			err:    oauth2.ErrInvalidTokenFormat.Error(),
		},
		{
			name:   "ShouldFailWhenSignatureDoesNotMatch",
			token:  "foo.bar",
			config: &oauth2.Config{GlobalSecret: []byte(validSecret)},
			err:    oauth2.ErrTokenSignatureMismatch.Error(),
		},
		{
			name:   "ShouldFailWhenTokenKeyIsInvalidBase64",
			token:  "!!.MTIzNA",
			config: &oauth2.Config{GlobalSecret: []byte(validSecret)},
			err:    "illegal base64 data at input byte 0",
		},
		{
			name:   "ShouldFailWhenTokenSignatureIsInvalidBase64",
			token:  "MTIzNA.!!",
			config: &oauth2.Config{GlobalSecret: []byte(validSecret)},
			err:    "illegal base64 data at input byte 0",
		},
		{
			name:   "ShouldFailTokenMissingSignature",
			token:  "foo.",
			config: &oauth2.Config{GlobalSecret: []byte(validSecret)},
			err:    oauth2.ErrInvalidTokenFormat.Error(),
		},
		{
			name:   "ShouldFailTokenMissingKey",
			token:  ".foo",
			config: &oauth2.Config{GlobalSecret: []byte(validSecret)},
			err:    oauth2.ErrInvalidTokenFormat.Error(),
		},
		{
			name:   "ShouldFailWhenAllConfiguredSecretsTooShort",
			token:  "MTIzNA.NQQ",
			config: &oauth2.Config{GlobalSecret: []byte("short")},
			err:    "secret for signing HMAC-SHA512/256 is expected to be 32 byte long, got 5 byte",
		},
		{
			name:   "ShouldFailWhenNoSecretConfigured",
			token:  "MTIzNA.NQQ",
			config: &oauth2.Config{},
			err:    "a secret for signing HMAC-SHA512/256 is expected to be defined, but none were",
		},
		{
			name:   "ShouldFailMismatchedSignatureWithValidSecret",
			token:  "thisisatoken.withaninvalidsignature",
			config: &oauth2.Config{GlobalSecret: []byte(validSecret)},
			err:    oauth2.ErrTokenSignatureMismatch.Error(),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cg := HMACStrategy{Config: tc.config}
			actual := cg.Validate(context.Background(), tc.token)
			require.Error(t, actual)
			assert.EqualError(t, actual, tc.err)
		})
	}
}

func TestHMACStrategyValidateRotatedSecrets(t *testing.T) {
	testCases := []struct {
		name   string
		config *oauth2.Config
		check  func(t *testing.T, current, signer *HMACStrategy)
	}{
		{
			name: "ShouldValidateTokenFromRotatedSecret",
			config: &oauth2.Config{
				GlobalSecret: []byte(rotatedSecret),
				RotatedGlobalSecrets: [][]byte{
					[]byte(otherSecret),
					[]byte(validSecret),
				},
			},
			check: func(t *testing.T, current, signer *HMACStrategy) {
				token, _, err := signer.Generate(context.Background())
				require.NoError(t, err)
				require.NoError(t, current.Validate(context.Background(), token))
			},
		},
		{
			name: "ShouldFailMismatchedSignatureWithRotatedKeys",
			config: &oauth2.Config{
				GlobalSecret: []byte(rotatedSecret),
				RotatedGlobalSecrets: [][]byte{
					[]byte(otherSecret),
					[]byte(validSecret),
				},
			},
			check: func(t *testing.T, current, _ *HMACStrategy) {
				assert.EqualError(t,
					current.Validate(context.Background(), "thisisatoken.withaninvalidsignature"),
					oauth2.ErrTokenSignatureMismatch.Error(),
				)
			},
		},
		{
			name: "ShouldFailWhenARotatedSecretIsTooShort",
			config: &oauth2.Config{
				GlobalSecret: []byte(rotatedSecret),
				RotatedGlobalSecrets: [][]byte{
					[]byte(shortSecret),
					[]byte(validSecret),
				},
			},
			check: func(t *testing.T, current, signer *HMACStrategy) {
				token, _, err := signer.Generate(context.Background())
				require.NoError(t, err)
				assert.EqualError(t, current.Validate(context.Background(), token),
					"secret for signing HMAC-SHA512/256 is expected to be 32 byte long, got 31 byte")
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			current := &HMACStrategy{Config: tc.config}
			signer := &HMACStrategy{Config: &oauth2.Config{GlobalSecret: []byte(validSecret)}}
			tc.check(t, current, signer)
		})
	}
}

func TestHMACStrategyCustomHMAC(t *testing.T) {
	testCases := []struct {
		name  string
		check func(t *testing.T, def, sha *HMACStrategy)
	}{
		{
			name: "ShouldFailValidatingDefaultTokenWithCustomHasher",
			check: func(t *testing.T, def, sha *HMACStrategy) {
				token, _, err := def.Generate(context.Background())
				require.NoError(t, err)
				assert.EqualError(t, sha.Validate(context.Background(), token), oauth2.ErrTokenSignatureMismatch.Error())
			},
		},
		{
			name: "ShouldValidateCustomHashedTokenWithSameHasher",
			check: func(t *testing.T, def, sha *HMACStrategy) {
				token, _, err := sha.Generate(context.Background())
				require.NoError(t, err)
				require.NoError(t, sha.Validate(context.Background(), token))
			},
		},
		{
			name: "ShouldFailValidatingCustomTokenWithDefaultHasher",
			check: func(t *testing.T, def, sha *HMACStrategy) {
				token, _, err := sha.Generate(context.Background())
				require.NoError(t, err)
				assert.EqualError(t, def.Validate(context.Background(), token), oauth2.ErrTokenSignatureMismatch.Error())
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			def := &HMACStrategy{Config: &oauth2.Config{GlobalSecret: []byte(validSecret)}}
			sha := &HMACStrategy{Config: &oauth2.Config{
				GlobalSecret: []byte(validSecret),
				HMACHasher:   sha512.New,
			}}
			tc.check(t, def, sha)
		})
	}
}

func TestHMACStrategyGenerateHMACForString(t *testing.T) {
	testCases := []struct {
		name   string
		config *oauth2.Config
		text   string
		err    string
	}{
		{
			name:   "ShouldFailWhenSecretTooShort",
			config: &oauth2.Config{GlobalSecret: []byte("foo")},
			text:   "hello",
			err:    "secret for signing HMAC-SHA512/256 is expected to be 32 byte long, got 3 byte",
		},
		{
			name:   "ShouldHashShortText",
			config: &oauth2.Config{GlobalSecret: []byte(validSecret)},
			text:   "hello",
		},
		{
			name:   "ShouldHashEmptyText",
			config: &oauth2.Config{GlobalSecret: []byte(validSecret)},
			text:   "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cg := HMACStrategy{Config: tc.config}
			actual, err := cg.GenerateHMACForString(context.Background(), tc.text)

			if tc.err != "" {
				assert.EqualError(t, err, tc.err)
				assert.Empty(t, actual)

				return
			}

			require.NoError(t, err)
			assert.NotEmpty(t, actual)

			// Same input + secret must be deterministic.
			again, err := cg.GenerateHMACForString(context.Background(), tc.text)
			require.NoError(t, err)
			assert.Equal(t, actual, again)
		})
	}
}

func TestHMACStrategySignature(t *testing.T) {
	testCases := []struct {
		name     string
		token    string
		expected string
	}{
		{
			name:     "ShouldReturnSignaturePart",
			token:    "key.signature",
			expected: "signature",
		},
		{
			name:     "ShouldReturnEmptyForUnformattedToken",
			token:    "no-dot-here",
			expected: "",
		},
		{
			name:     "ShouldReturnEmptyForMultipleDots",
			token:    "a.b.c",
			expected: "",
		},
		{
			name:     "ShouldReturnEmptyForEmptyToken",
			token:    "",
			expected: "",
		},
	}

	cg := HMACStrategy{Config: &oauth2.Config{GlobalSecret: []byte(validSecret)}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, cg.Signature(tc.token))
		})
	}
}
