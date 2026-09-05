// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oidckb

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
)

func TestDeviceAuthorizeHandler_BindRFC8628DeviceAuthorizeRequest(t *testing.T) {
	const jkt = "dnfb1T9jil_gOhti60baHs_WD_a4D8JN9VDJXbmBmGw"

	testCases := []struct {
		name    string
		enabled bool
		dpop    bool
		scopes  oauth2.Arguments
		jkt     string
		err     bool
	}{
		{name: "ShouldAllowWithThumbprint", enabled: true, dpop: true, scopes: oauth2.Arguments{consts.ScopeOpenID, consts.ScopeBoundKey}, jkt: jkt},
		{name: "ShouldIgnoreWhenBoundKeyNotRequested", enabled: true, dpop: true, scopes: oauth2.Arguments{consts.ScopeOpenID}},
		{name: "ShouldIgnoreWhenDisabled", enabled: false, dpop: true, scopes: oauth2.Arguments{consts.ScopeOpenID, consts.ScopeBoundKey}},
		{name: "ShouldIgnoreWhenDPoPDisabled", enabled: true, dpop: false, scopes: oauth2.Arguments{consts.ScopeOpenID, consts.ScopeBoundKey}},
		{name: "ShouldRejectMissingThumbprint", enabled: true, dpop: true, scopes: oauth2.Arguments{consts.ScopeOpenID, consts.ScopeBoundKey}, err: true},
		{name: "ShouldRejectBoundKeyWithoutOpenID", enabled: true, dpop: true, scopes: oauth2.Arguments{consts.ScopeBoundKey}, jkt: jkt, err: true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			handler := &DeviceAuthorizeHandler{Config: &oauth2.Config{OIDCKeyBindingEnabled: tc.enabled, DPoPEnabled: tc.dpop}}

			request := oauth2.NewDeviceAuthorizeRequest()
			request.Form = url.Values{}
			request.RequestedScope = tc.scopes
			request.SetSession(&oauth2.DefaultSession{})

			if tc.jkt != "" {
				request.Form.Set(consts.FormParameterDPoPJKT, tc.jkt)
			}

			err := handler.BindRFC8628DeviceAuthorizeRequest(t.Context(), request)

			if tc.err {
				assert.ErrorIs(t, err, oauth2.ErrInvalidRequest)

				return
			}

			assert.NoError(t, err)
		})
	}
}
