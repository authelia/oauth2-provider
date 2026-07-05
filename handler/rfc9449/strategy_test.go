package rfc9449

import (
	"context"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/storage"
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

func TestStrategyValidateProofChecksMethodURL(t *testing.T) {
	s, _ := newTestStrategy()
	key := newTestProofKey(t)

	raw := signProof(t, key, "dpop+jwt", map[string]any{
		"jti": "j1", "htm": "POST", "htu": "https://as.example.com/token", "iat": time.Now().Unix(),
	})

	_, err := s.ValidateDPoPProof(context.Background(), "POST", "https://as.example.com/token", raw, false)
	require.NoError(t, err)

	// Method mismatch.
	_, err = s.ValidateDPoPProof(context.Background(), "GET", "https://as.example.com/token", raw, false)
	assert.ErrorIs(t, err, oauth2.ErrInvalidDPoPProof)
}

func TestStrategyValidateProofReplay(t *testing.T) {
	s, _ := newTestStrategy()
	key := newTestProofKey(t)
	raw := signProof(t, key, "dpop+jwt", map[string]any{
		"jti": "replay-1", "htm": "POST", "htu": "https://as.example.com/token", "iat": time.Now().Unix(),
	})

	_, err := s.ValidateDPoPProof(context.Background(), "POST", "https://as.example.com/token", raw, false)
	require.NoError(t, err)

	_, err = s.ValidateDPoPProof(context.Background(), "POST", "https://as.example.com/token", raw, false)
	assert.ErrorIs(t, err, oauth2.ErrInvalidDPoPProof)
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
	raw := signProof(t, key, "dpop+jwt", map[string]any{
		"jti": "nn-1", "htm": "POST", "htu": "https://as.example.com/token", "iat": time.Now().Unix(),
	})

	_, err := s.ValidateDPoPProof(context.Background(), "POST", "https://as.example.com/token", raw, true)
	assert.ErrorIs(t, err, oauth2.ErrUseDPoPNonce)
}

func TestStrategyValidateProofRejectsHTUMismatch(t *testing.T) {
	s, _ := newTestStrategy()
	key := newTestProofKey(t)

	raw := signProof(t, key, "dpop+jwt", map[string]any{
		"jti": "htu-1", "htm": "POST", "htu": "https://as.example.com/other", "iat": time.Now().Unix(),
	})

	_, err := s.ValidateDPoPProof(context.Background(), "POST", "https://as.example.com/token", raw, false)
	assert.ErrorIs(t, err, oauth2.ErrInvalidDPoPProof)
}

func TestStrategyValidateProofRejectsIATOutsideWindow(t *testing.T) {
	s, _ := newTestStrategy()
	key := newTestProofKey(t)

	rawPast := signProof(t, key, "dpop+jwt", map[string]any{
		"jti": "iat-past", "htm": "POST", "htu": "https://as.example.com/token", "iat": time.Now().Add(-time.Hour).Unix(),
	})
	_, err := s.ValidateDPoPProof(context.Background(), "POST", "https://as.example.com/token", rawPast, false)
	assert.ErrorIs(t, err, oauth2.ErrInvalidDPoPProof)

	rawFuture := signProof(t, key, "dpop+jwt", map[string]any{
		"jti": "iat-future", "htm": "POST", "htu": "https://as.example.com/token", "iat": time.Now().Add(time.Hour).Unix(),
	})
	_, err = s.ValidateDPoPProof(context.Background(), "POST", "https://as.example.com/token", rawFuture, false)
	assert.ErrorIs(t, err, oauth2.ErrInvalidDPoPProof)
}

func TestStrategyValidateProofAcceptsDefaultPortEquivalence(t *testing.T) {
	s, _ := newTestStrategy()
	key := newTestProofKey(t)

	raw := signProof(t, key, "dpop+jwt", map[string]any{
		"jti": "port-1", "htm": "POST", "htu": "https://as.example.com:443/token", "iat": time.Now().Unix(),
	})

	_, err := s.ValidateDPoPProof(context.Background(), "POST", "https://as.example.com/token", raw, false)
	assert.NoError(t, err)
}

var _ = jose.ES256
