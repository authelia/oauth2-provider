// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc9449

import (
	"context"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"time"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/x/errorsx"
)

const (
	// StatelessNonceSecretMinLength is the minimum length of the global secret the stateless nonce key is derived from.
	StatelessNonceSecretMinLength = 32

	statelessNonceVersion    byte = 1
	statelessNonceKeyInfo         = "authelia.com/provider/oauth2/rfc9449/nonce/v1"
	statelessNonceKeyLength       = 32
	statelessNonceTimeLength      = 8
	statelessNonceLength          = 1 + statelessNonceTimeLength + sha256.Size
)

func (s *DefaultStrategy) newStatelessNonce(ctx context.Context, now time.Time) (nonce string, err error) {
	var secret []byte

	if secret, err = s.Config.GetGlobalSecret(ctx); err != nil {
		return "", errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}

	var key []byte

	if key, err = statelessNonceKey(secret); err != nil {
		return "", errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}

	raw := make([]byte, 1+statelessNonceTimeLength, statelessNonceLength)
	raw[0] = statelessNonceVersion
	binary.BigEndian.PutUint64(raw[1:], uint64(now.UnixNano()))

	return base64.RawURLEncoding.EncodeToString(append(raw, statelessNonceMAC(key, raw)...)), nil
}

func (s *DefaultStrategy) validateStatelessNonce(ctx context.Context, nonce string, now time.Time) (err error) {
	raw, err := base64.RawURLEncoding.DecodeString(nonce)
	if err != nil || len(raw) != statelessNonceLength || raw[0] != statelessNonceVersion {
		return errorsx.WithStack(oauth2.ErrUseDPoPNonce.WithHint("The DPoP proof 'nonce' claim is invalid or expired."))
	}

	var (
		secret  []byte
		rotated [][]byte
	)

	if secret, err = s.Config.GetGlobalSecret(ctx); err != nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}

	if rotated, err = s.Config.GetRotatedGlobalSecrets(ctx); err != nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}

	payload, tag := raw[:1+statelessNonceTimeLength], raw[1+statelessNonceTimeLength:]

	if !statelessNonceAuthentic(payload, tag, append([][]byte{secret}, rotated...)) {
		return errorsx.WithStack(oauth2.ErrUseDPoPNonce.WithHint("The DPoP proof 'nonce' claim is invalid or expired."))
	}

	issued := time.Unix(0, int64(binary.BigEndian.Uint64(payload[1:]))) //nolint:gosec // Authenticated above.

	// The nonce was issued by this or a sibling server, so the skew allowed is between server clocks.
	if issued.After(now.Add(s.Config.GetDPoPClockSkew(ctx))) || now.After(issued.Add(s.Config.GetDPoPNonceLifespan(ctx))) {
		return errorsx.WithStack(oauth2.ErrUseDPoPNonce.WithHint("The DPoP proof 'nonce' claim is invalid or expired."))
	}

	return nil
}

func statelessNonceAuthentic(payload, tag []byte, secrets [][]byte) bool {
	for _, secret := range secrets {
		key, err := statelessNonceKey(secret)
		if err != nil {
			continue
		}

		if hmac.Equal(tag, statelessNonceMAC(key, payload)) {
			return true
		}
	}

	return false
}

func statelessNonceKey(secret []byte) (key []byte, err error) {
	if len(secret) < StatelessNonceSecretMinLength {
		return nil, fmt.Errorf("the global secret must be at least %d bytes to derive the stateless DPoP nonce key but it is %d bytes", StatelessNonceSecretMinLength, len(secret))
	}

	return hkdf.Key(sha256.New, secret, nil, statelessNonceKeyInfo, statelessNonceKeyLength)
}

func statelessNonceMAC(key, payload []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(payload)

	return mac.Sum(nil)
}
