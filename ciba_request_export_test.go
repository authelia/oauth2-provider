// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"net/http"
)

// HTTPRequestForTest exposes the unexported HTTP request to the external test package.
func (r *BackChannelAuthenticationRequest) HTTPRequestForTest() *http.Request {
	return r.httpRequest
}

// SetHTTPRequestForTest sets the unexported HTTP request from the external test package.
func (r *BackChannelAuthenticationRequest) SetHTTPRequestForTest(request *http.Request) {
	r.httpRequest = request
}
