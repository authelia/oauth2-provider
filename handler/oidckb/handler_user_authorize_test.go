// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oidckb

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
)

// TestUserAuthorizeHandler_RecordsTheGrantedMarker pins the device flow half. Scopes are granted at this endpoint
// rather than at the device authorization endpoint, because the end user approves the request here.
func TestUserAuthorizeHandler_RecordsTheGrantedMarker(t *testing.T) {
	newRequest := func(granted oauth2.Arguments) (*oauth2.DeviceAuthorizeRequest, *oauth2.DefaultSession) {
		session := &oauth2.DefaultSession{}

		request := oauth2.NewDeviceAuthorizeRequest()
		request.GrantedScope = granted
		request.SetSession(session)

		return request, session
	}

	testCases := []struct {
		name     string
		enabled  bool
		dpop     bool
		granted  oauth2.Arguments
		expected bool
	}{
		{name: "ShouldRecordWhenBoundKeyGranted", enabled: true, dpop: true, granted: oauth2.Arguments{consts.ScopeOpenID, consts.ScopeBoundKey}, expected: true},
		{name: "ShouldNotRecordWhenBoundKeyNotGranted", enabled: true, dpop: true, granted: oauth2.Arguments{consts.ScopeOpenID}, expected: false},
		{name: "ShouldNotRecordWhenDisabled", enabled: false, dpop: true, granted: oauth2.Arguments{consts.ScopeOpenID, consts.ScopeBoundKey}, expected: false},
		{name: "ShouldNotRecordWhenDPoPDisabled", enabled: true, dpop: false, granted: oauth2.Arguments{consts.ScopeOpenID, consts.ScopeBoundKey}, expected: false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			handler := &UserAuthorizeHandler{Config: &oauth2.Config{OIDCKeyBindingEnabled: tc.enabled, DPoPEnabled: tc.dpop}}

			request, session := newRequest(tc.granted)

			require.NoError(t, handler.PopulateRFC8628UserAuthorizeEndpointResponse(t.Context(), request, nil))
			assert.Equal(t, tc.expected, session.GetOIDCKeyBindingGranted())
		})
	}
}
