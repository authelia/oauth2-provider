// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package openid

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestDefaultSessionMTLSBinding(t *testing.T) {
	var session *DefaultSession

	assert.Empty(t, session.GetClientCertificateSHA256Thumbprint())

	session = NewDefaultSession()

	session.SetClientCertificateSHA256Thumbprint("test-x5t")

	assert.Equal(t, "test-x5t", session.GetClientCertificateSHA256Thumbprint())
}

func TestDefaultSessionConfirmationRoundTrip(t *testing.T) {
	var source oauth2.MTLSBoundSession = NewDefaultSession()

	source.SetClientCertificateSHA256Thumbprint("round-trip-value")

	claims := map[string]any{}

	oauth2.ApplyConfirmation(claims, source.(oauth2.Session))

	cnf, ok := claims[jwt.ClaimConfirmation].(map[string]any)
	require.True(t, ok, "expected cnf to be present and a map, got %#v", claims[jwt.ClaimConfirmation])
	assert.Equal(t, "round-trip-value", cnf[jwt.ClaimConfirmationX509SHA256Thumbprint])

	restored := NewDefaultSession()

	oauth2.RestoreConfirmation(claims, restored)

	assert.Equal(t, "round-trip-value", restored.GetClientCertificateSHA256Thumbprint())
}
