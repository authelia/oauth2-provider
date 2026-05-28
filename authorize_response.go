// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"net/http"
	"net/url"

	"authelia.com/provider/oauth2/internal/consts"
)

// AuthorizeResponse is an implementation of AuthorizeResponder
type AuthorizeResponse struct {
	Header     http.Header
	Parameters url.Values
	code       string
}

// NewAuthorizeResponse returns an empty AuthorizeResponse with its Header and Parameters maps initialized.
func NewAuthorizeResponse() *AuthorizeResponse {
	return &AuthorizeResponse{
		Header:     http.Header{},
		Parameters: url.Values{},
	}
}

// GetCode returns the authorization code stored on the response, or the empty string if none has been added via
// AddParameter using the 'code' parameter name.
func (a *AuthorizeResponse) GetCode() string {
	return a.code
}

// GetHeader returns the response HTTP headers that will be written to the client.
func (a *AuthorizeResponse) GetHeader() http.Header {
	return a.Header
}

// AddHeader appends the value to the named response header.
func (a *AuthorizeResponse) AddHeader(key, value string) {
	a.Header.Add(key, value)
}

// GetParameters returns the response parameters that will be encoded in the redirect URI, fragment, or form_post body
// depending on the negotiated response_mode.
func (a *AuthorizeResponse) GetParameters() url.Values {
	return a.Parameters
}

// AddParameter appends a key/value pair to the response parameters. The authorization 'code' parameter is captured
// separately so it can be accessed via GetCode for handler chaining.
func (a *AuthorizeResponse) AddParameter(key, value string) {
	if key == consts.FormParameterAuthorizationCode {
		a.code = value
	}

	a.Parameters.Add(key, value)
}
