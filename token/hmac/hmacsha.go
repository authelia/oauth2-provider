// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

// Package hmac is the default implementation for generating and validating challenges. It uses SHA-512/256 to
// generate and validate challenges.

package hmac

import (
	"context"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"strings"
	"sync"

	"github.com/pkg/errors"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/x/errorsx"
)

type HMACStrategyConfigurator interface {
	oauth2.TokenEntropyProvider
	oauth2.GlobalSecretProvider
	oauth2.RotatedGlobalSecretsProvider
	oauth2.HMACHashingProvider
}

// HMACStrategy is responsible for generating and validating challenges.
type HMACStrategy struct {
	sync.Mutex
	Config HMACStrategyConfigurator
}

const (
	minimumEntropy int = 32

	minimumSecretLength = 32
)

var b64 = base64.URLEncoding.WithPadding(base64.NoPadding)

// Generate generates a token and a matching signature or returns an error.
// This method implements rfc6819 Section 5.1.4.2.2: Use High Entropy for Secrets.
func (c *HMACStrategy) Generate(ctx context.Context) (string, string, error) {
	c.Lock()
	defer c.Unlock()

	secret, err := c.Config.GetGlobalSecret(ctx)
	if err != nil {
		return "", "", err
	}

	if len(secret) < minimumSecretLength {
		return "", "", errors.Errorf("secret for signing HMAC-SHA512/256 is expected to be 32 byte long, got %d byte", len(secret))
	}

	var signingKey [32]byte
	copy(signingKey[:], secret)

	entropy := c.Config.GetTokenEntropy(ctx)
	if entropy < minimumEntropy {
		entropy = minimumEntropy
	}

	// The token value should be at least 128 bits long and constructed from a cryptographically strong random
	// sequence.
	//
	// See: https://www.rfc-editor.org/rfc/rfc6749#section-10.10
	tokenKey, err := RandomBytes(entropy)
	if err != nil {
		return "", "", errorsx.WithStack(err)
	}

	signature := c.generateHMAC(ctx, tokenKey, &signingKey)

	encodedSignature := b64.EncodeToString(signature)
	encodedToken := fmt.Sprintf("%s.%s", b64.EncodeToString(tokenKey), encodedSignature)

	return encodedToken, encodedSignature, nil
}

// GenerateHMACForString returns the base64url encoded (no padding) HMAC of text, computed with the global secret.
func (c *HMACStrategy) GenerateHMACForString(ctx context.Context, text string) (string, error) {
	var signingKey [32]byte

	secrets, err := c.Config.GetGlobalSecret(ctx)
	if err != nil {
		return "", err
	}

	if len(secrets) < minimumSecretLength {
		return "", errors.Errorf("secret for signing HMAC-SHA512/256 is expected to be 32 byte long, got %d byte", len(secrets))
	}
	copy(signingKey[:], secrets)

	bytes := []byte(text)
	hashBytes := c.generateHMAC(ctx, bytes, &signingKey)

	b64 := base64.RawURLEncoding.EncodeToString(hashBytes)
	return b64, nil
}

// Validate validates a token and returns its signature or an error if the token is not valid.
func (c *HMACStrategy) Validate(ctx context.Context, token string) (err error) {
	var keys [][]byte

	secrets, err := c.Config.GetGlobalSecret(ctx)
	if err != nil {
		return err
	}

	rotatedSecrets, err := c.Config.GetRotatedGlobalSecrets(ctx)
	if err != nil {
		return err
	}

	if len(secrets) > 0 {
		keys = append(keys, secrets)
	}

	keys = append(keys, rotatedSecrets...)
	for _, key := range keys {
		if err = c.validate(ctx, key, token); err == nil {
			return nil
		} else if errors.Is(err, oauth2.ErrTokenSignatureMismatch) {
		} else {
			return err
		}
	}

	if err == nil {
		return errors.New("a secret for signing HMAC-SHA512/256 is expected to be defined, but none were")
	}

	return err
}

func (c *HMACStrategy) validate(ctx context.Context, secret []byte, token string) error {
	if len(secret) < minimumSecretLength {
		return errors.Errorf("secret for signing HMAC-SHA512/256 is expected to be 32 byte long, got %d byte", len(secret))
	}

	var signingKey [32]byte
	copy(signingKey[:], secret)

	split := strings.SplitN(token, ".", 3)
	if len(split) != 2 {
		return errorsx.WithStack(oauth2.ErrInvalidTokenFormat)
	}

	tokenKey := split[0]
	tokenSignature := split[1]
	if tokenKey == "" || tokenSignature == "" {
		return errorsx.WithStack(oauth2.ErrInvalidTokenFormat)
	}

	decodedTokenSignature, err := b64.DecodeString(tokenSignature)
	if err != nil {
		return errorsx.WithStack(err)
	}

	decodedTokenKey, err := b64.DecodeString(tokenKey)
	if err != nil {
		return errorsx.WithStack(err)
	}

	expectedMAC := c.generateHMAC(ctx, decodedTokenKey, &signingKey)
	if !hmac.Equal(expectedMAC, decodedTokenSignature) {
		// Hash is invalid
		return errorsx.WithStack(oauth2.ErrTokenSignatureMismatch)
	}

	return nil
}

// Signature returns the signature part of a token, or an empty string if the token does not consist of exactly two
// parts separated by a period.
func (c *HMACStrategy) Signature(token string) string {
	split := strings.SplitN(token, ".", 3)

	if len(split) != 2 {
		return ""
	}

	return split[1]
}

func (c *HMACStrategy) generateHMAC(ctx context.Context, data []byte, key *[32]byte) []byte {
	hasher := c.Config.GetHMACHasher(ctx)
	if hasher == nil {
		hasher = sha512.New512_256
	}
	h := hmac.New(hasher, key[:])
	// sha512.digest.Write() always returns nil for err, the panic should never happen
	_, err := h.Write(data)
	if err != nil {
		panic(err)
	}
	return h.Sum(nil)
}
