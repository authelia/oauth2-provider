// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestJWTSessionMTLSBinding(t *testing.T) {
	var session *JWTSession

	assert.Empty(t, session.GetClientCertificateSHA256Thumbprint())

	session = &JWTSession{}

	session.SetClientCertificateSHA256Thumbprint("test-x5t")

	assert.Equal(t, "test-x5t", session.GetClientCertificateSHA256Thumbprint())
}

func TestJWTSessionConfirmationRoundTrip(t *testing.T) {
	var source oauth2.MTLSBoundSession = &JWTSession{}

	source.SetClientCertificateSHA256Thumbprint("round-trip-value")

	claims := map[string]any{}

	oauth2.ApplyConfirmation(context.Background(), &oauth2.Config{DPoPEnabled: true, MTLSEnabled: true}, claims, source.(oauth2.Session))

	cnf, ok := claims[jwt.ClaimConfirmation].(map[string]any)
	require.True(t, ok, "expected cnf to be present and a map, got %#v", claims[jwt.ClaimConfirmation])
	assert.Equal(t, "round-trip-value", cnf[jwt.ClaimConfirmationX509SHA256Thumbprint])

	restored := &JWTSession{}

	oauth2.RestoreConfirmation(claims, restored)

	assert.Equal(t, "round-trip-value", restored.GetClientCertificateSHA256Thumbprint())
}
