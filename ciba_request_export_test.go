// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"net/http"
	"net/url"
)

// DecodeBackChannelSignedRequestForTest exposes decodeBackChannelSignedRequest to the external test package.
func (f *Fosite) DecodeBackChannelSignedRequestForTest(ctx context.Context, client Client, form url.Values) (params url.Values, err error) {
	params, _, err = f.decodeBackChannelSignedRequest(ctx, client, form)

	return params, err
}

// HTTPRequestForTest exposes the unexported HTTP request to the external test package.
func (r *BackChannelAuthenticationRequest) HTTPRequestForTest() *http.Request {
	return r.httpRequest
}

// SetHTTPRequestForTest sets the unexported HTTP request from the external test package.
func (r *BackChannelAuthenticationRequest) SetHTTPRequestForTest(request *http.Request) {
	r.httpRequest = request
}
