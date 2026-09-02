// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc9449

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
)

func TestDeviceAuthorizeHandler_BindRFC8628DeviceAuthorizeRequest(t *testing.T) {
	const jkt = "dnfb1T9jil_gOhti60baHs_WD_a4D8JN9VDJXbmBmGw"

	testCases := []struct {
		name     string
		enabled  bool
		jkt      string
		session  oauth2.Session
		expected string
		err      string
	}{
		{name: "ShouldRecordThumbprint", enabled: true, jkt: jkt, session: &oauth2.DefaultSession{}, expected: jkt},
		{name: "ShouldSkipWhenDisabled", enabled: false, jkt: jkt, session: &oauth2.DefaultSession{}, expected: ""},
		{name: "ShouldSkipWhenAbsent", enabled: true, jkt: "", session: &oauth2.DefaultSession{}, expected: ""},
		{name: "ShouldRejectMalformed", enabled: true, jkt: "short", session: &oauth2.DefaultSession{}, err: "The request is missing a required parameter"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			handler := &DeviceAuthorizeHandler{Config: &oauth2.Config{DPoPEnabled: tc.enabled}}

			request := oauth2.NewDeviceAuthorizeRequest()
			request.Form = url.Values{}
			request.SetSession(tc.session)

			if tc.jkt != "" {
				request.Form.Set(consts.FormParameterDPoPJKT, tc.jkt)
			}

			err := handler.BindRFC8628DeviceAuthorizeRequest(t.Context(), request)

			if tc.err != "" {
				assert.ErrorIs(t, err, oauth2.ErrInvalidRequest)

				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tc.expected, tc.session.(*oauth2.DefaultSession).GetDPoPJWKThumbprint())
		})
	}
}

func TestDeviceAuthorizeHandler_RecordsTheRequestedThumbprint(t *testing.T) {
	const jkt = "dnfb1T9jil_gOhti60baHs_WD_a4D8JN9VDJXbmBmGw"

	handler := &DeviceAuthorizeHandler{Config: &oauth2.Config{DPoPEnabled: true}}

	session := &oauth2.DefaultSession{}

	request := oauth2.NewDeviceAuthorizeRequest()
	request.Form = url.Values{consts.FormParameterDPoPJKT: []string{jkt}}
	request.SetSession(session)

	require.NoError(t, handler.BindRFC8628DeviceAuthorizeRequest(t.Context(), request))

	assert.Equal(t, jkt, session.GetDPoPJWKThumbprint())
	assert.Equal(t, jkt, session.GetRequestedDPoPJWKThumbprint())
}
