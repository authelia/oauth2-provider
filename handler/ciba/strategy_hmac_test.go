// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package ciba_test

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	. "authelia.com/provider/oauth2/handler/ciba"
	"authelia.com/provider/oauth2/handler/openid"
)

func newHMACTestStrategy(t *testing.T, prefix string) *HMACAuthRequestIDStrategy {
	t.Helper()

	return NewHMACAuthRequestIDStrategy(&oauth2.Config{
		GlobalSecret:       []byte("some-cool-secret-thats-long-enough-for-the-hmac-strategy"),
		OpenIDCIBALifespan: time.Minute * 10,
	}, prefix)
}

func TestHMACAuthRequestIDStrategy_GenerateAndValidate(t *testing.T) {
	s := newHMACTestStrategy(t, "")

	id, sig, err := s.GenerateAuthRequestID(t.Context())
	require.NoError(t, err)
	assert.NotEmpty(t, id)
	assert.NotEmpty(t, sig)

	got, err := s.AuthRequestIDSignature(t.Context(), id)
	require.NoError(t, err)
	assert.Equal(t, sig, got, "AuthRequestIDSignature must round-trip the signature returned by Generate")

	request := oauth2.NewCIBARequest()
	request.SetSession(openid.NewDefaultSession())
	assert.NoError(t, s.ValidateAuthRequestID(t.Context(), request, id))
}

func TestHMACAuthRequestIDStrategy_Prefix(t *testing.T) {
	s := newHMACTestStrategy(t, "authelia_%s_")

	id, _, err := s.GenerateAuthRequestID(t.Context())
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(id, "authelia_bc_"), "id %q must use the configured prefix", id)
	assert.True(t, s.IsOpaqueAuthRequestID(t.Context(), id))
	assert.False(t, s.IsOpaqueAuthRequestID(t.Context(), "not-an-bc"))
}

func TestHMACAuthRequestIDStrategy_AuthRequestIDSignature_RejectsForeignToken(t *testing.T) {
	s := newHMACTestStrategy(t, "authelia_%s_")

	_, err := s.AuthRequestIDSignature(t.Context(), "authelia_dc_some-device-code.sig")
	require.Error(t, err)
	assert.ErrorIs(t, err, oauth2.ErrInvalidTokenFormat)
}

func TestHMACAuthRequestIDStrategy_ValidateAuthRequestID_RejectsForeignToken(t *testing.T) {
	s := newHMACTestStrategy(t, "authelia_%s_")

	request := oauth2.NewCIBARequest()
	request.SetSession(openid.NewDefaultSession())

	err := s.ValidateAuthRequestID(t.Context(), request, "authelia_dc_some-device-code.sig")
	require.Error(t, err)
	assert.ErrorIs(t, err, oauth2.ErrInvalidTokenFormat)
}

func TestHMACAuthRequestIDStrategy_ValidateAuthRequestID_ExpiredBySession(t *testing.T) {
	s := newHMACTestStrategy(t, "")

	id, _, err := s.GenerateAuthRequestID(t.Context())
	require.NoError(t, err)

	request := oauth2.NewCIBARequest()
	session := openid.NewDefaultSession()
	session.SetExpiresAt(oauth2.CIBAAuthRequestID, time.Now().UTC().Add(-time.Minute))
	request.SetSession(session)

	err = s.ValidateAuthRequestID(t.Context(), request, id)
	require.Error(t, err)
	assert.ErrorIs(t, err, oauth2.ErrDeviceExpiredToken)
}

func TestHMACAuthRequestIDStrategy_ValidateAuthRequestID_ExpiredByConfig(t *testing.T) {
	s := newHMACTestStrategy(t, "")

	id, _, err := s.GenerateAuthRequestID(t.Context())
	require.NoError(t, err)

	// No expiry recorded in the session; the request was placed far enough in the past that the configured lifespan
	// has already elapsed.
	request := oauth2.NewCIBARequest()
	request.SetRequestedAt(time.Now().UTC().Add(-time.Hour))
	request.SetSession(openid.NewDefaultSession())

	err = s.ValidateAuthRequestID(t.Context(), request, id)
	require.Error(t, err)
	assert.ErrorIs(t, err, oauth2.ErrDeviceExpiredToken)
}

func TestHMACAuthRequestIDStrategy_ValidateAuthRequestID_TamperedSignature(t *testing.T) {
	s := newHMACTestStrategy(t, "")

	id, _, err := s.GenerateAuthRequestID(t.Context())
	require.NoError(t, err)

	// Mutate the signature segment (everything after the dot) so HMAC validation fails.
	parts := strings.SplitN(id, ".", 2)
	require.Len(t, parts, 2, "HMAC token must contain a '.' separator")
	tampered := parts[0] + ".AAAAAAAA"

	request := oauth2.NewCIBARequest()
	request.SetSession(openid.NewDefaultSession())

	require.Error(t, s.ValidateAuthRequestID(t.Context(), request, tampered))
}

func TestHMACAuthRequestIDStrategy_GeneratedSignaturesAreUnique(t *testing.T) {
	s := newHMACTestStrategy(t, "")

	seen := map[string]bool{}
	for range 32 {
		_, sig, err := s.GenerateAuthRequestID(t.Context())
		require.NoError(t, err)
		assert.False(t, seen[sig], "duplicate signature returned by GenerateAuthRequestID: %q", sig)
		seen[sig] = true
	}
}
