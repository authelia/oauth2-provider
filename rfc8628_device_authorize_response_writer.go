// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
)

// NewRFC862DeviceAuthorizeResponse dispatches the device authorization request to each configured RFC 8628 device
// authorization endpoint handler to populate the device_code, user_code, verification URIs and polling interval.
func (f *Fosite) NewRFC862DeviceAuthorizeResponse(ctx context.Context, r DeviceAuthorizeRequester, session Session) (DeviceAuthorizeResponder, error) {
	r.SetSession(session)

	var resp = NewDeviceAuthorizeResponse()

	for _, h := range f.Config.GetRFC8628DeviceAuthorizeEndpointHandlers(ctx) {
		if err := h.HandleRFC8628DeviceAuthorizeEndpointRequest(ctx, r, resp); err != nil {
			return nil, err
		}
	}

	return resp, nil
}
