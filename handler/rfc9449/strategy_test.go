package rfc9449

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/token/jwt"
)

type testStrategyConfig struct {
	algs     []string
	skew     time.Duration
	nonceExp time.Duration
}

func (c *testStrategyConfig) GetDPoPAllowedJWSAlgorithms(context.Context) []string { return c.algs }
func (c *testStrategyConfig) GetDPoPClockSkew(context.Context) time.Duration       { return c.skew }
func (c *testStrategyConfig) GetDPoPNonceLifespan(context.Context) time.Duration   { return c.nonceExp }

func newTestStrategy() (*DefaultStrategy, *storage.MemoryStore) {
	store := storage.NewMemoryStore()
	cfg := &testStrategyConfig{algs: []string{"ES256"}, skew: time.Minute, nonceExp: time.Minute}

	return NewDefaultStrategy(cfg, store), store
}

func TestStrategyValidateProofAcceptsMatchingMethodURL(t *testing.T) {
	s, _ := newTestStrategy()
	key := newTestProofKey(t)

	raw := signProof(t, key, jwt.JSONWebTokenTypeDPoP, map[string]any{
		jwt.ClaimJWTID: "j1", jwt.ClaimHTTPMethod: http.MethodPost, jwt.ClaimHTTPURI: "https://as.example.com/token", jwt.ClaimIssuedAt: time.Now().Unix(),
	})

	_, err := s.ValidateDPoPProof(context.Background(), http.MethodPost, "https://as.example.com/token", raw, false)
	require.NoError(t, err)
}

func TestStrategyValidateProofReplay(t *testing.T) {
	s, _ := newTestStrategy()
	key := newTestProofKey(t)
	raw := signProof(t, key, jwt.JSONWebTokenTypeDPoP, map[string]any{
		jwt.ClaimJWTID: "replay-1", jwt.ClaimHTTPMethod: http.MethodPost, jwt.ClaimHTTPURI: "https://as.example.com/token", jwt.ClaimIssuedAt: time.Now().Unix(),
	})

	_, err := s.ValidateDPoPProof(context.Background(), http.MethodPost, "https://as.example.com/token", raw, false)
	require.NoError(t, err)

	_, err = s.ValidateDPoPProof(context.Background(), http.MethodPost, "https://as.example.com/token", raw, false)
	assert.ErrorIs(t, err, oauth2.ErrInvalidDPoPProof)
}

func TestStrategyReplayMarkerCoversFullIATWindow(t *testing.T) {
	s, store := newTestStrategy()
	key := newTestProofKey(t)

	iat := time.Now().Add(30 * time.Second)
	raw := signProof(t, key, jwt.JSONWebTokenTypeDPoP, map[string]any{
		jwt.ClaimJWTID: "future-iat", jwt.ClaimHTTPMethod: http.MethodPost, jwt.ClaimHTTPURI: "https://as.example.com/token", jwt.ClaimIssuedAt: iat.Unix(),
	})

	_, err := s.ValidateDPoPProof(context.Background(), http.MethodPost, "https://as.example.com/token", raw, false)
	require.NoError(t, err)

	exp, ok := store.DPoPProofJTIs["future-iat"]
	require.True(t, ok, "expected the proof jti to be recorded as used")

	wantMin := time.Unix(iat.Unix(), 0).Add(time.Minute)
	assert.Falsef(t, exp.Before(wantMin), "replay marker expiry %s is before the end of the iat acceptance window %s", exp, wantMin)
}

func TestStrategyNonceLifecycle(t *testing.T) {
	s, _ := newTestStrategy()

	nonce, err := s.NewDPoPNonce(context.Background())
	require.NoError(t, err)
	assert.NotEmpty(t, nonce)

	require.NoError(t, s.ValidateDPoPNonce(context.Background(), nonce))
	assert.ErrorIs(t, s.ValidateDPoPNonce(context.Background(), "not-a-nonce"), oauth2.ErrUseDPoPNonce)
}

func TestStrategyRequireNonce(t *testing.T) {
	s, _ := newTestStrategy()
	key := newTestProofKey(t)
	raw := signProof(t, key, jwt.JSONWebTokenTypeDPoP, map[string]any{
		jwt.ClaimJWTID: "nn-1", jwt.ClaimHTTPMethod: http.MethodPost, jwt.ClaimHTTPURI: "https://as.example.com/token", jwt.ClaimIssuedAt: time.Now().Unix(),
	})

	_, err := s.ValidateDPoPProof(context.Background(), http.MethodPost, "https://as.example.com/token", raw, true)
	assert.ErrorIs(t, err, oauth2.ErrUseDPoPNonce)
}

func TestStrategyValidateProofRejects(t *testing.T) {
	testCases := []struct {
		name   string
		method string
		url    string
		htm    string
		htu    string
		iat    int64
	}{
		{
			name:   "MethodMismatch",
			method: http.MethodGet,
			url:    "https://as.example.com/token",
			htm:    http.MethodPost,
			htu:    "https://as.example.com/token",
			iat:    time.Now().Unix(),
		},
		{
			name:   "HTUMismatch",
			method: http.MethodPost,
			url:    "https://as.example.com/token",
			htm:    http.MethodPost,
			htu:    "https://as.example.com/other",
			iat:    time.Now().Unix(),
		},
		{
			name:   "IATInPast",
			method: http.MethodPost,
			url:    "https://as.example.com/token",
			htm:    http.MethodPost,
			htu:    "https://as.example.com/token",
			iat:    time.Now().Add(-time.Hour).Unix(),
		},
		{
			name:   "IATInFuture",
			method: http.MethodPost,
			url:    "https://as.example.com/token",
			htm:    http.MethodPost,
			htu:    "https://as.example.com/token",
			iat:    time.Now().Add(time.Hour).Unix(),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			s, _ := newTestStrategy()
			key := newTestProofKey(t)

			raw := signProof(t, key, jwt.JSONWebTokenTypeDPoP, map[string]any{
				jwt.ClaimJWTID: tc.name, jwt.ClaimHTTPMethod: tc.htm, jwt.ClaimHTTPURI: tc.htu, jwt.ClaimIssuedAt: tc.iat,
			})

			_, err := s.ValidateDPoPProof(context.Background(), tc.method, tc.url, raw, false)
			assert.ErrorIs(t, err, oauth2.ErrInvalidDPoPProof)
		})
	}
}

func TestStrategyValidateProofAcceptsDefaultPortEquivalence(t *testing.T) {
	s, _ := newTestStrategy()
	key := newTestProofKey(t)

	raw := signProof(t, key, jwt.JSONWebTokenTypeDPoP, map[string]any{
		jwt.ClaimJWTID: "port-1", jwt.ClaimHTTPMethod: http.MethodPost, jwt.ClaimHTTPURI: "https://as.example.com:443/token", jwt.ClaimIssuedAt: time.Now().Unix(),
	})

	_, err := s.ValidateDPoPProof(context.Background(), http.MethodPost, "https://as.example.com/token", raw, false)
	assert.NoError(t, err)
}

var _ = jose.ES256
