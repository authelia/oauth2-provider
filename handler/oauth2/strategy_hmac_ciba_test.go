// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"encoding/base64"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
)

func TestGenerateCIBAAuthRequestID(t *testing.T) {
	charset := regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

	testCases := []struct {
		name   string
		prefix string
		have   string
	}{
		{"ShouldGenerateWithoutPrefix", "", ""},
		{"ShouldGenerateWithPrefix", "authelia_%s_", "authelia_ar_"},
		{"ShouldGenerateWithADottedPrefix", "authelia.%s.", "authelia.ar."},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			strategy := NewHMACCoreStrategy(&oauth2.Config{
				GlobalSecret: []byte("foobarfoobarfoobarfoobarfoobarfoobarfoobarfoobar"),
			}, tc.prefix)

			seen := map[string]struct{}{}

			for range 100 {
				id, signature, err := strategy.GenerateCIBAAuthRequestID(t.Context())
				require.NoError(t, err)

				assert.Regexp(t, charset, id)
				assert.NotEmpty(t, signature)
				assert.Contains(t, id, tc.have)

				if tc.have != "" {
					assert.Equal(t, tc.have, id[:len(tc.have)])
				}

				random := id[len(tc.have):]
				raw, _, found := strings.Cut(random, ".")
				require.True(t, found)

				decoded, err := base64.RawURLEncoding.DecodeString(raw)
				require.NoError(t, err)
				assert.GreaterOrEqual(t, len(decoded), 20)

				_, dup := seen[id]
				assert.False(t, dup)

				seen[id] = struct{}{}

				actual, err := strategy.CIBAAuthRequestIDSignature(t.Context(), id)
				require.NoError(t, err)
				assert.Equal(t, signature, actual)

				r := oauth2.NewBackChannelAuthenticationRequest()
				r.SetRequestedAt(time.Now())
				r.Session = &oauth2.DefaultSession{}

				assert.NoError(t, strategy.ValidateCIBAAuthRequestID(t.Context(), r, id))
			}
		})
	}
}

func TestCIBAAuthRequestIDRejectsOtherTokens(t *testing.T) {
	strategy := NewHMACCoreStrategy(&oauth2.Config{
		GlobalSecret: []byte("foobarfoobarfoobarfoobarfoobarfoobarfoobarfoobar"),
	}, "authelia_%s_")

	dc, _, err := strategy.GenerateRFC8628DeviceCode(t.Context())
	require.NoError(t, err)

	_, err = strategy.CIBAAuthRequestIDSignature(t.Context(), dc)
	assert.Error(t, err)

	assert.Error(t, strategy.ValidateCIBAAuthRequestID(t.Context(), &oauth2.BackChannelAuthenticationRequest{Request: oauth2.Request{Session: &oauth2.DefaultSession{}}}, dc))
}

func TestValidateCIBAAuthRequestIDExpired(t *testing.T) {
	strategy := NewHMACCoreStrategy(&oauth2.Config{
		GlobalSecret: []byte("foobarfoobarfoobarfoobarfoobarfoobarfoobarfoobar"),
	}, "")

	id, _, err := strategy.GenerateCIBAAuthRequestID(t.Context())
	require.NoError(t, err)

	testCases := []struct {
		name     string
		setup    func(r *oauth2.BackChannelAuthenticationRequest)
		expected error
	}{
		{"ShouldAcceptFreshWithoutExpiry", func(r *oauth2.BackChannelAuthenticationRequest) { r.SetRequestedAt(time.Now()) }, nil},
		{"ShouldRejectPastDefaultLifespan", func(r *oauth2.BackChannelAuthenticationRequest) { r.SetRequestedAt(time.Now().Add(-10 * time.Minute)) }, oauth2.ErrDeviceExpiredToken},
		{"ShouldRejectPastSessionExpiry", func(r *oauth2.BackChannelAuthenticationRequest) {
			r.SetRequestedAt(time.Now())
			r.Session.SetExpiresAt(oauth2.CIBAAuthRequestID, time.Now().Add(-time.Second))
		}, oauth2.ErrDeviceExpiredToken},
		{"ShouldAcceptSessionExpiryInFuture", func(r *oauth2.BackChannelAuthenticationRequest) {
			r.SetRequestedAt(time.Now().Add(-time.Hour))
			r.Session.SetExpiresAt(oauth2.CIBAAuthRequestID, time.Now().Add(time.Minute))
		}, nil},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			r := oauth2.NewBackChannelAuthenticationRequest()
			r.Session = &oauth2.DefaultSession{}
			tc.setup(r)

			err := strategy.ValidateCIBAAuthRequestID(t.Context(), r, id)
			if tc.expected == nil {
				assert.NoError(t, err)
			} else {
				assert.ErrorIs(t, err, tc.expected)
			}
		})
	}
}

func TestGenerateCIBAAuthRequestIDRejectsInvalidPrefixCharacters(t *testing.T) {
	strategy := NewHMACCoreStrategy(&oauth2.Config{
		GlobalSecret: []byte("foobarfoobarfoobarfoobarfoobarfoobarfoobarfoobar"),
	}, "ory:%s:")

	id, signature, err := strategy.GenerateCIBAAuthRequestID(t.Context())
	assert.Error(t, err)
	assert.Empty(t, id)
	assert.Empty(t, signature)
}
