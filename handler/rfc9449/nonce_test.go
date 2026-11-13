// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc9449

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestStrategyStatelessNonce(t *testing.T) {
	ctx := context.Background()
	secret := []byte("0123456789abcdef0123456789abcdef")
	other := []byte("fedcba9876543210fedcba9876543210")

	newStrategy := func(secret []byte, rotated ...[]byte) *DefaultStrategy {
		cfg := &testStrategyConfig{algs: []string{"ES256"}, skew: 10 * time.Second, lifespan: time.Minute, nonceExp: time.Minute, stateless: true, secret: secret, rotated: rotated}

		return NewDefaultStrategy(cfg, &nonceStorageForbidden{MemoryStore: storage.NewMemoryStore()})
	}

	t.Run("ShouldValidateIssuedNonceWithoutStorage", func(t *testing.T) {
		s := newStrategy(secret)

		nonce, err := s.NewDPoPNonce(ctx)
		require.NoError(t, err)
		assert.Len(t, nonce, base64.RawURLEncoding.EncodedLen(statelessNonceLength))
		assert.NoError(t, s.ValidateDPoPNonce(ctx, nonce))
	})

	t.Run("ShouldValidateNonceFromRotatedSecret", func(t *testing.T) {
		nonce, err := newStrategy(other).NewDPoPNonce(ctx)
		require.NoError(t, err)

		assert.NoError(t, newStrategy(secret, other).ValidateDPoPNonce(ctx, nonce))
	})

	t.Run("ShouldRejectNonceFromUnknownSecret", func(t *testing.T) {
		nonce, err := newStrategy(other).NewDPoPNonce(ctx)
		require.NoError(t, err)

		assert.ErrorIs(t, newStrategy(secret).ValidateDPoPNonce(ctx, nonce), oauth2.ErrUseDPoPNonce)
	})

	t.Run("ShouldBoundNonceAge", func(t *testing.T) {
		s := newStrategy(secret)
		now := time.Unix(1_700_000_000, 900_000_000)

		nonce, err := s.newStatelessNonce(ctx, now)
		require.NoError(t, err)

		assert.NoError(t, s.validateStatelessNonce(ctx, nonce, now.Add(time.Minute)))
		assert.ErrorIs(t, s.validateStatelessNonce(ctx, nonce, now.Add(time.Minute+time.Second)), oauth2.ErrUseDPoPNonce)
		assert.NoError(t, s.validateStatelessNonce(ctx, nonce, now.Add(-10*time.Second)))
		assert.ErrorIs(t, s.validateStatelessNonce(ctx, nonce, now.Add(-11*time.Second)), oauth2.ErrUseDPoPNonce)
	})

	t.Run("ShouldBoundSubsecondNonceAge", func(t *testing.T) {
		s := NewDefaultStrategy(&testStrategyConfig{algs: []string{"ES256"}, nonceExp: 500 * time.Millisecond, stateless: true, secret: secret}, &nonceStorageForbidden{MemoryStore: storage.NewMemoryStore()})
		now := time.Unix(1_700_000_000, 900_000_000)

		nonce, err := s.newStatelessNonce(ctx, now)
		require.NoError(t, err)

		assert.NoError(t, s.validateStatelessNonce(ctx, nonce, now))
		assert.NoError(t, s.validateStatelessNonce(ctx, nonce, now.Add(500*time.Millisecond)))
		assert.ErrorIs(t, s.validateStatelessNonce(ctx, nonce, now.Add(501*time.Millisecond)), oauth2.ErrUseDPoPNonce)
	})

	t.Run("ShouldRejectAlteredNonce", func(t *testing.T) {
		s := newStrategy(secret)

		nonce, err := s.NewDPoPNonce(ctx)
		require.NoError(t, err)

		raw, err := base64.RawURLEncoding.DecodeString(nonce)
		require.NoError(t, err)

		for _, i := range []int{0, 1, len(raw) - 1} {
			altered := append([]byte(nil), raw...)
			altered[i] ^= 0x01

			assert.ErrorIs(t, s.ValidateDPoPNonce(ctx, base64.RawURLEncoding.EncodeToString(altered)), oauth2.ErrUseDPoPNonce, i)
		}
	})

	t.Run("ShouldRejectUnknownVersion", func(t *testing.T) {
		s := newStrategy(secret)

		nonce, err := s.NewDPoPNonce(ctx)
		require.NoError(t, err)

		raw, err := base64.RawURLEncoding.DecodeString(nonce)
		require.NoError(t, err)

		key, err := statelessNonceKey(secret)
		require.NoError(t, err)

		payload := append([]byte{statelessNonceVersion + 1}, raw[1:1+statelessNonceTimeLength]...)

		assert.ErrorIs(t, s.ValidateDPoPNonce(ctx, base64.RawURLEncoding.EncodeToString(append(payload, statelessNonceMAC(key, payload)...))), oauth2.ErrUseDPoPNonce)
	})

	t.Run("ShouldRejectMalformedNonce", func(t *testing.T) {
		s := newStrategy(secret)

		for _, nonce := range []string{"", "not-a-nonce!", base64.RawURLEncoding.EncodeToString(make([]byte, statelessNonceLength-1))} {
			assert.ErrorIs(t, s.ValidateDPoPNonce(ctx, nonce), oauth2.ErrUseDPoPNonce, nonce)
		}
	})

	t.Run("ShouldFailWithShortSecret", func(t *testing.T) {
		_, err := newStrategy(secret[:31]).NewDPoPNonce(ctx)
		assert.ErrorIs(t, err, oauth2.ErrServerError)
	})

	t.Run("ShouldAcceptProofCarryingNonce", func(t *testing.T) {
		s := newStrategy(secret)

		nonce, err := s.NewDPoPNonce(ctx)
		require.NoError(t, err)

		raw := signProof(t, newTestProofKey(t), jwt.JSONWebTokenTypeDPoP, map[string]any{
			jwt.ClaimJWTID: "stateless-1", jwt.ClaimHTTPMethod: http.MethodPost, jwt.ClaimHTTPURI: "https://op/token", jwt.ClaimIssuedAt: time.Now().Unix(), jwt.ClaimNonce: nonce,
		})

		_, err = s.ValidateDPoPProof(ctx, http.MethodPost, "https://op/token", raw, true)
		assert.NoError(t, err)
	})
}

type nonceStorageForbidden struct {
	*storage.MemoryStore
}

func (s *nonceStorageForbidden) CreateDPoPNonce(context.Context, string, time.Time) error {
	return errors.New("stateless nonces must not be stored")
}

func (s *nonceStorageForbidden) IsDPoPNonceValid(context.Context, string) (bool, error) {
	return false, errors.New("stateless nonces must not be looked up")
}
