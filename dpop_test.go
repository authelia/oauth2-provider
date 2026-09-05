package oauth2

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDefaultSessionDPoPBinding(t *testing.T) {
	var s DPoPBoundSession = &DefaultSession{}

	assert.Equal(t, "", s.GetDPoPJWKThumbprint())

	s.SetDPoPJWKThumbprint("abc")
	assert.Equal(t, "abc", s.GetDPoPJWKThumbprint())
}

func TestDPoPBoundSessionImplementations(t *testing.T) {
	var _ DPoPBoundSession = &DefaultSession{}
}

func TestDPoPProofHolder(t *testing.T) {
	t.Run("ShouldRoundTripThroughTheContext", func(t *testing.T) {
		ctx := context.WithValue(t.Context(), DPoPProofContextKey, &DPoPProofHolder{})

		assert.Nil(t, GetDPoPProof(ctx))

		proof := &DPoPProof{Thumbprint: "jkt", CodeHash: "c_s256"}

		PublishDPoPProof(ctx, proof)

		assert.Same(t, proof, GetDPoPProof(ctx))
	})

	t.Run("ShouldNoOpWithoutAHolder", func(t *testing.T) {
		ctx := t.Context()

		assert.NotPanics(t, func() { PublishDPoPProof(ctx, &DPoPProof{}) })
		assert.Nil(t, GetDPoPProof(ctx))
	})

	t.Run("ShouldNoOpWithAWrongTypedValue", func(t *testing.T) {
		ctx := context.WithValue(t.Context(), DPoPProofContextKey, "not a holder")

		assert.NotPanics(t, func() { PublishDPoPProof(ctx, &DPoPProof{}) })
		assert.Nil(t, GetDPoPProof(ctx))
	})
}
