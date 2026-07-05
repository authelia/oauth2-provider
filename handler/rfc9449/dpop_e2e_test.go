// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc9449

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
)

// TestDPoPEndToEndBindingAndRefresh drives the handler exactly as the token endpoint would: it binds a DPoP proof's
// key thumbprint on a fresh authorization_code exchange, confirms a refresh presenting a proof from the same key
// (with a fresh 'jti') succeeds and keeps the binding, and confirms a refresh presenting a proof from a different
// key is rejected with oauth2.ErrInvalidDPoPProof.
//
// Note: the brief for this test references oauth2.JWTSession, but no such type exists in the root oauth2 package
// (JWTSession lives in handler/oauth2, a different package). oauth2.DefaultSession implements DPoPBoundSession
// (GetDPoPJWKThumbprint/SetDPoPJWKThumbprint) exactly as the brief's session needs, and is what the rest of this
// package's tests (handler_test.go) already use, so it is used here instead.
func TestDPoPEndToEndBindingAndRefresh(t *testing.T) {
	h, _, _ := newTestHandler(false)
	key := newTestProofKey(t)

	// 1. Fresh authorization_code exchange with a DPoP proof binds the session.
	session := &oauth2.DefaultSession{}
	request := oauth2.NewAccessRequest(session)
	request.Client = &oauth2.DefaultClient{DPoPBoundAccessTokens: true}

	raw1 := signProof(t, key, "dpop+jwt", map[string]any{
		"jti": "e2e-1", "htm": "POST", "htu": "https://as.example.com/token", "iat": time.Now().Unix(),
	})
	ctx1 := ctxWithDPoP("POST", "https://as.example.com/token", raw1)

	require.NoError(t, h.HandleTokenEndpointRequest(ctx1, request))
	jkt := session.GetDPoPJWKThumbprint()
	require.NotEmpty(t, jkt)

	// 2. Refresh with a proof from the same key (fresh jti) succeeds and keeps the binding.
	refreshSession := &oauth2.DefaultSession{}
	refreshSession.SetDPoPJWKThumbprint(jkt)
	refreshRequest := oauth2.NewAccessRequest(refreshSession)
	refreshRequest.Client = &oauth2.DefaultClient{DPoPBoundAccessTokens: true}

	raw2 := signProof(t, key, "dpop+jwt", map[string]any{
		"jti": "e2e-2", "htm": "POST", "htu": "https://as.example.com/token", "iat": time.Now().Unix(),
	})
	ctx2 := ctxWithDPoP("POST", "https://as.example.com/token", raw2)

	require.NoError(t, h.HandleTokenEndpointRequest(ctx2, refreshRequest))
	assert.Equal(t, jkt, refreshSession.GetDPoPJWKThumbprint())

	// 3. Refresh with a proof from a DIFFERENT key is rejected.
	otherKey := newTestProofKey(t)
	otherSession := &oauth2.DefaultSession{}
	otherSession.SetDPoPJWKThumbprint(jkt)
	otherRequest := oauth2.NewAccessRequest(otherSession)
	otherRequest.Client = &oauth2.DefaultClient{DPoPBoundAccessTokens: true}

	raw3 := signProof(t, otherKey, "dpop+jwt", map[string]any{
		"jti": "e2e-3", "htm": "POST", "htu": "https://as.example.com/token", "iat": time.Now().Unix(),
	})
	ctx3 := ctxWithDPoP("POST", "https://as.example.com/token", raw3)

	err := h.HandleTokenEndpointRequest(ctx3, otherRequest)
	assert.ErrorIs(t, err, oauth2.ErrInvalidDPoPProof)
}
