package oauth2

import (
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
