// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oidckb

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
)

func TestBackChannelKeyBinding(t *testing.T) {
	const jkt = "dnfb1T9jil_gOhti60baHs_WD_a4D8JN9VDJXbmBmGw"

	jwk := []byte(`{"kty":"EC","crv":"P-256","x":"x","y":"y"}`)

	verified := func() *oauth2.DefaultSession {
		session := &oauth2.DefaultSession{}
		session.SetDPoPJWKThumbprint(jkt)
		session.SetRequestedDPoPJWKThumbprint(jkt)
		session.SetDPoPPublicKeyJWK(jwk)

		return session
	}

	jktOnly := func() *oauth2.DefaultSession {
		session := &oauth2.DefaultSession{}
		session.SetDPoPJWKThumbprint(jkt)
		session.SetRequestedDPoPJWKThumbprint(jkt)

		return session
	}

	testCases := []struct {
		name    string
		enabled bool
		dpop    bool
		scopes  oauth2.Arguments
		session *oauth2.DefaultSession
		granted bool
		err     error
	}{
		{name: "ShouldGrantWithAVerifiedProof", enabled: true, dpop: true, scopes: oauth2.Arguments{consts.ScopeOpenID, consts.ScopeBoundKey}, session: verified(), granted: true},
		{name: "ShouldNotGrantWithoutBoundKey", enabled: true, dpop: true, scopes: oauth2.Arguments{consts.ScopeOpenID}, session: verified()},
		{name: "ShouldNotGrantWhenKeyBindingIsDisabled", enabled: false, dpop: true, scopes: oauth2.Arguments{consts.ScopeOpenID, consts.ScopeBoundKey}, session: verified()},
		{name: "ShouldNotGrantWhenDPoPIsDisabled", enabled: true, dpop: false, scopes: oauth2.Arguments{consts.ScopeOpenID, consts.ScopeBoundKey}, session: verified()},
		{name: "ShouldRejectWithoutKeyMaterial", enabled: true, dpop: true, scopes: oauth2.Arguments{consts.ScopeOpenID, consts.ScopeBoundKey}, session: &oauth2.DefaultSession{}, err: oauth2.ErrInvalidRequest},
		{name: "ShouldRejectADPoPJKTWithoutAProof", enabled: true, dpop: true, scopes: oauth2.Arguments{consts.ScopeOpenID, consts.ScopeBoundKey}, session: jktOnly(), err: oauth2.ErrInvalidRequest},
		{name: "ShouldRejectBoundKeyWithoutTheOpenIDScope", enabled: true, dpop: true, scopes: oauth2.Arguments{consts.ScopeBoundKey}, session: verified(), err: oauth2.ErrInvalidRequest},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			handler := &Handler{Config: &oauth2.Config{OIDCKeyBindingEnabled: tc.enabled, DPoPEnabled: tc.dpop}}

			request := oauth2.NewBackChannelAuthenticationRequest()
			request.Form = url.Values{}
			request.RequestedScope = tc.scopes
			request.SetSession(tc.session)

			err := handler.BindBackChannelAuthenticationRequest(t.Context(), request)

			if tc.err != nil {
				assert.ErrorIs(t, err, tc.err)
				assert.False(t, tc.session.GetOIDCKeyBindingGranted())

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.granted, tc.session.GetOIDCKeyBindingGranted())
		})
	}
}

// TestBackChannelKeyBindingIgnoresAnUnverifiedProof composes the handler without rfc9449.Handler: a DPoP header that
// nothing verified must not satisfy the 'bound_key' scope.
func TestBackChannelKeyBindingIgnoresAnUnverifiedProof(t *testing.T) {
	config := &oauth2.Config{OIDCKeyBindingEnabled: true, DPoPEnabled: true}
	config.BackChannelAuthenticationEndpointBindingHandlers.Append(&Handler{Config: config})

	r := httptest.NewRequest(http.MethodPost, "https://as.example.com/bc-authorize", nil)
	r.Header.Set(consts.HeaderDPoP, "not.a.proof")

	session := &oauth2.DefaultSession{Subject: "alice"}

	request := oauth2.NewBackChannelAuthenticationRequest()
	request.Form = url.Values{}
	request.RequestedScope = oauth2.Arguments{consts.ScopeOpenID, consts.ScopeBoundKey}
	request.SetSession(session)

	_, err := (&oauth2.Fosite{Config: config}).NewBackChannelAuthenticationResponse(context.WithValue(t.Context(), oauth2.RequestContextKey, r), request)

	assert.ErrorIs(t, err, oauth2.ErrInvalidRequest)
	assert.False(t, session.GetOIDCKeyBindingGranted())
}
