// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package ssfreceiver

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/jose"
	josejwt "authelia.com/provider/jose/jwt"

	"authelia.com/provider/oauth2"
)

type testKeyServer struct {
	*httptest.Server

	metadataHits, keysHits atomic.Int32

	keys     atomic.Pointer[jose.JSONWebKeySet]
	critical atomic.Pointer[[]string]
	extra    atomic.Pointer[map[string]any]
	status   atomic.Int32
}

func newTestKeyServer(t *testing.T, keys ...jose.JSONWebKey) *testKeyServer {
	s := &testKeyServer{}

	s.setKeys(keys...)

	s.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case testWellKnown:
			s.metadataHits.Add(1)

			var extra map[string]any

			if members := s.extra.Load(); members != nil {
				extra = maps.Clone(*members)
			}

			if critical := s.critical.Load(); critical != nil {
				if extra == nil {
					extra = map[string]any{}
				}

				extra["critical_subject_members"] = *critical
			}

			writeTestJSON(w, testMetadata(s.URL, extra))
		case "/jwks.json":
			s.keysHits.Add(1)

			if status := s.status.Load(); status != 0 {
				w.WriteHeader(int(status))

				return
			}

			data, _ := json.Marshal(s.keys.Load())

			writeTestJSON(w, data)
		default:
			http.NotFound(w, r)
		}
	}))

	t.Cleanup(s.Close)

	return s
}

func (s *testKeyServer) setKeys(keys ...jose.JSONWebKey) {
	s.keys.Store(&jose.JSONWebKeySet{Keys: keys})
}

// receiver returns a Receiver with a JSON Web Key Set fetcher whose cache the returned function settles.
func (s *testKeyServer) receiver() (receiver *Receiver, wait func()) {
	fetcher := oauth2.NewDefaultJWKSFetcherStrategy(oauth2.JWKSFetcherWithHTTPClient(testHTTPClient(s.Server)))

	receiver = testReceiver(s.Server)
	receiver.Config.JWKSFetcher = fetcher

	return receiver, fetcher.(*oauth2.DefaultJWKSFetcherStrategy).WaitForCache
}

func testSigningKey(t *testing.T, kid, use, alg string) (key jose.JSONWebKey, public *ecdsa.PublicKey) {
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	return jose.JSONWebKey{Key: &private.PublicKey, KeyID: kid, Use: use, Algorithm: alg}, &private.PublicKey
}

func testToken(kid, alg string) *josejwt.JSONWebToken {
	return &josejwt.JSONWebToken{Headers: []jose.Header{{KeyID: kid, Algorithm: alg}}}
}

func TestReceiverKeyFunc(t *testing.T) {
	const es256 = string(jose.ES256)

	t.Run("ShouldSelectKeyByKID", func(t *testing.T) {
		k1, _ := testSigningKey(t, "k1", "sig", es256)
		k2, public := testSigningKey(t, "k2", "sig", es256)
		k3, _ := testSigningKey(t, "k3", "", "")

		server := newTestKeyServer(t, k1, k2, k3)
		receiver, wait := server.receiver()

		keyFunc := receiver.keyFunc(&StreamRecord{Issuer: server.URL, StreamID: "s1"})

		for range 2 {
			key, err := keyFunc(t.Context(), testToken("k2", es256), nil)
			require.NoError(t, err)

			assert.Equal(t, "k2", key.KeyID)
			assert.Equal(t, public, key.Key)

			wait()
		}

		key, err := keyFunc(t.Context(), testToken("k3", es256), nil)
		require.NoError(t, err)

		assert.Equal(t, "k3", key.KeyID)

		assert.Equal(t, int32(1), server.metadataHits.Load())
		assert.Equal(t, int32(1), server.keysHits.Load())
	})

	t.Run("ShouldSelectSoleKeyWithoutKID", func(t *testing.T) {
		k1, public := testSigningKey(t, "", "", "")

		server := newTestKeyServer(t, k1)
		receiver, _ := server.receiver()

		key, err := receiver.keyFunc(&StreamRecord{Issuer: server.URL})(t.Context(), testToken("", es256), nil)
		require.NoError(t, err)

		assert.Equal(t, public, key.Key)
		assert.Equal(t, int32(1), server.keysHits.Load())
	})

	t.Run("ShouldRejectAmbiguousKeysWithoutKID", func(t *testing.T) {
		k1, _ := testSigningKey(t, "k1", "sig", es256)
		k2, _ := testSigningKey(t, "k2", "sig", es256)

		server := newTestKeyServer(t, k1, k2)
		receiver, _ := server.receiver()

		key, err := receiver.keyFunc(&StreamRecord{Issuer: server.URL})(t.Context(), testToken("", es256), nil)

		assert.Nil(t, key)
		assert.ErrorIs(t, err, ErrSigningKey)
	})

	t.Run("ShouldRefreshOnceOnUnknownKID", func(t *testing.T) {
		k1, _ := testSigningKey(t, "k1", "sig", es256)
		k2, public := testSigningKey(t, "k2", "sig", es256)

		server := newTestKeyServer(t, k1)
		receiver, wait := server.receiver()

		keyFunc := receiver.keyFunc(&StreamRecord{Issuer: server.URL})

		_, err := keyFunc(t.Context(), testToken("k1", es256), nil)
		require.NoError(t, err)

		wait()

		assert.Equal(t, int32(1), server.keysHits.Load())

		// The Transmitter rotates its key.
		server.setKeys(k2)

		key, err := keyFunc(t.Context(), testToken("k2", es256), nil)
		require.NoError(t, err)

		wait()

		assert.Equal(t, "k2", key.KeyID)
		assert.Equal(t, public, key.Key)
		assert.Equal(t, int32(2), server.keysHits.Load())

		key, err = keyFunc(t.Context(), testToken("k2", es256), nil)
		require.NoError(t, err)

		assert.Equal(t, "k2", key.KeyID)
		assert.Equal(t, int32(2), server.keysHits.Load())
		assert.Equal(t, int32(1), server.metadataHits.Load())
	})

	t.Run("ShouldNotRefreshAgainWithinInterval", func(t *testing.T) {
		k1, _ := testSigningKey(t, "k1", "sig", es256)

		server := newTestKeyServer(t, k1)
		receiver, wait := server.receiver()

		keyFunc := receiver.keyFunc(&StreamRecord{Issuer: server.URL})

		_, err := keyFunc(t.Context(), testToken("k1", es256), nil)
		require.NoError(t, err)

		wait()

		require.Equal(t, int32(1), server.keysHits.Load())

		// Two unknown 'kid' values cause one fetch.
		for _, kid := range []string{"unknown1", "unknown2", "unknown1"} {
			key, err := keyFunc(t.Context(), testToken(kid, es256), nil)

			wait()

			assert.Nil(t, key)
			assert.ErrorIs(t, err, ErrSigningKey)
			assert.Equal(t, int32(2), server.keysHits.Load())
		}

		// The known key is still served from the cache.
		_, err = keyFunc(t.Context(), testToken("k1", es256), nil)
		require.NoError(t, err)

		assert.Equal(t, int32(2), server.keysHits.Load())
	})

	t.Run("ShouldRejectSymmetricKey", func(t *testing.T) {
		secret := jose.JSONWebKey{Key: []byte("0123456789abcdef0123456789abcdef"), KeyID: "k1", Use: "sig", Algorithm: es256}
		hmac := jose.JSONWebKey{Key: []byte("0123456789abcdef0123456789abcdef"), KeyID: "k2", Use: "sig", Algorithm: string(jose.HS256)}

		server := newTestKeyServer(t, secret, hmac)
		receiver, _ := server.receiver()

		keyFunc := receiver.keyFunc(&StreamRecord{Issuer: server.URL})

		// A symmetric key labeled with an asymmetric algorithm.
		key, err := keyFunc(t.Context(), testToken("k1", es256), nil)

		assert.Nil(t, key)
		assert.ErrorIs(t, err, ErrSigningKey)

		hits := server.keysHits.Load()

		// A symmetric or absent algorithm is refused before any key is looked up.
		for _, alg := range []string{"HS256", "HS384", "HS512", "none", ""} {
			key, err = keyFunc(t.Context(), testToken("k2", alg), nil)

			assert.Nil(t, key)
			assert.ErrorIs(t, err, ErrSigningKey)
		}

		assert.Equal(t, hits, server.keysHits.Load())
	})

	t.Run("ShouldRejectEncryptionOnlyKey", func(t *testing.T) {
		k1, _ := testSigningKey(t, "k1", "enc", "")
		k2, _ := testSigningKey(t, "k2", "enc", string(jose.ECDH_ES))
		k3, _ := testSigningKey(t, "k3", "", "")
		k3.KeyOps = []string{"encrypt"}
		k4, _ := testSigningKey(t, "k4", "", "")
		k4.KeyOps = []string{"sign"}

		server := newTestKeyServer(t, k1, k2, k3, k4)
		receiver, wait := server.receiver()

		keyFunc := receiver.keyFunc(&StreamRecord{Issuer: server.URL})

		for _, kid := range []string{"k1", "k2", "k3", "k4"} {
			key, err := keyFunc(t.Context(), testToken(kid, es256), nil)

			wait()

			assert.Nil(t, key, kid)
			assert.ErrorIs(t, err, ErrSigningKey, kid)
		}
	})

	t.Run("ShouldAcceptKeyWhoseOperationsIncludeVerify", func(t *testing.T) {
		k1, _ := testSigningKey(t, "k1", "", "")
		k1.KeyOps = []string{"sign", "verify"}

		server := newTestKeyServer(t, k1)
		receiver, wait := server.receiver()

		key, err := receiver.keyFunc(&StreamRecord{Issuer: server.URL})(t.Context(), testToken("k1", es256), nil)

		wait()

		require.NoError(t, err)
		assert.NotNil(t, key)
	})

	t.Run("ShouldRejectKeyOfAnotherType", func(t *testing.T) {
		k1, _ := testSigningKey(t, "k1", "sig", string(jose.RS256))

		server := newTestKeyServer(t, k1)
		receiver, _ := server.receiver()

		key, err := receiver.keyFunc(&StreamRecord{Issuer: server.URL})(t.Context(), testToken("k1", string(jose.RS256)), nil)

		assert.Nil(t, key)
		assert.ErrorIs(t, err, ErrSigningKey)
	})

	t.Run("ShouldRejectMalformedHeader", func(t *testing.T) {
		k1, _ := testSigningKey(t, "k1", "sig", es256)

		server := newTestKeyServer(t, k1)
		receiver, _ := server.receiver()

		keyFunc := receiver.keyFunc(&StreamRecord{Issuer: server.URL})

		for _, token := range []*josejwt.JSONWebToken{nil, {}, {Headers: []jose.Header{{KeyID: "k1", Algorithm: es256}, {KeyID: "k1", Algorithm: es256}}}} {
			key, err := keyFunc(t.Context(), token, nil)

			assert.Nil(t, key)
			assert.ErrorIs(t, err, ErrSigningKey)
		}

		assert.Equal(t, int32(0), server.keysHits.Load())
	})

	t.Run("ShouldNotMatchSigningKeyErrorWhenKeysAreUnavailable", func(t *testing.T) {
		k1, _ := testSigningKey(t, "k1", "sig", es256)

		server := newTestKeyServer(t, k1)
		server.status.Store(http.StatusServiceUnavailable)

		receiver, _ := server.receiver()

		key, err := receiver.keyFunc(&StreamRecord{Issuer: server.URL})(t.Context(), testToken("k1", es256), nil)

		assert.Nil(t, key)
		require.Error(t, err)
		assert.False(t, errors.Is(err, ErrSigningKey))
	})

	t.Run("ShouldNotMatchSigningKeyErrorWhenMetadataIsRefused", func(t *testing.T) {
		k1, _ := testSigningKey(t, "k1", "sig", es256)

		server := newTestKeyServer(t, k1)
		receiver, _ := server.receiver()

		key, err := receiver.keyFunc(&StreamRecord{Issuer: server.URL + "/other"})(t.Context(), testToken("k1", es256), nil)

		assert.Nil(t, key)
		assert.ErrorContains(t, err, "the transmitter configuration metadata could not be fetched")
		assert.False(t, errors.Is(err, ErrSigningKey))
		assert.Equal(t, int32(0), server.keysHits.Load())
	})

	t.Run("ShouldRefuseSpecialUseAddressOfKeys", func(t *testing.T) {
		k1, _ := testSigningKey(t, "k1", "sig", es256)

		server := newTestKeyServer(t, k1)

		receiver := testReceiver(server.Server)

		// The metadata is known, and the default fetcher of the keys is guarded with the same configuration.
		_, err := receiver.Discover(t.Context(), server.URL)
		require.NoError(t, err)

		receiver.Config.SpecialUseAddressGuard = nil

		key, err := receiver.keyFunc(&StreamRecord{Issuer: server.URL})(t.Context(), testToken("k1", es256), nil)

		assert.Nil(t, key)
		assert.ErrorIs(t, err, oauth2.ErrSpecialUseAddress)
		assert.Equal(t, int32(0), server.keysHits.Load())
	})

	t.Run("ShouldUseDefaultFetcher", func(t *testing.T) {
		k1, public := testSigningKey(t, "k1", "sig", es256)

		server := newTestKeyServer(t, k1)

		receiver := testReceiver(server.Server)

		key, err := receiver.keyFunc(&StreamRecord{Issuer: server.URL})(context.Background(), testToken("k1", es256), nil)
		require.NoError(t, err)

		assert.Equal(t, public, key.Key)
		assert.Same(t, receiver.jwksFetcher(), receiver.jwksFetcher())
	})

	t.Run("ShouldRejectNilRecord", func(t *testing.T) {
		key, err := (&Receiver{}).keyFunc(nil)(t.Context(), testToken("k1", es256), nil)

		assert.Nil(t, key)
		assert.Error(t, err)
	})
}
