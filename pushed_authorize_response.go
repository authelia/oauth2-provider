// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"net/http"

	"authelia.com/provider/oauth2/internal/consts"
)

// PushedAuthorizeResponse is the response object for PAR
type PushedAuthorizeResponse struct {
	RequestURI string `json:"request_uri"`
	ExpiresIn  int    `json:"expires_in"`
	Header     http.Header
	Extra      map[string]any
}

// GetRequestURI gets
func (a *PushedAuthorizeResponse) GetRequestURI() string {
	return a.RequestURI
}

// SetRequestURI sets
func (a *PushedAuthorizeResponse) SetRequestURI(requestURI string) {
	a.RequestURI = requestURI
}

// GetExpiresIn gets
func (a *PushedAuthorizeResponse) GetExpiresIn() int {
	return a.ExpiresIn
}

// SetExpiresIn sets
func (a *PushedAuthorizeResponse) SetExpiresIn(seconds int) {
	a.ExpiresIn = seconds
}

// GetHeader gets
func (a *PushedAuthorizeResponse) GetHeader() http.Header {
	return a.Header
}

// AddHeader adds
func (a *PushedAuthorizeResponse) AddHeader(key, value string) {
	a.Header.Add(key, value)
}

// SetExtra sets
func (a *PushedAuthorizeResponse) SetExtra(key string, value any) {
	a.Extra[key] = value
}

// GetExtra gets
func (a *PushedAuthorizeResponse) GetExtra(key string) any {
	return a.Extra[key]
}

// ToMap converts to a map
func (a *PushedAuthorizeResponse) ToMap() map[string]any {
	a.Extra[consts.FormParameterRequestURI] = a.RequestURI
	a.Extra[consts.AccessResponseExpiresIn] = a.ExpiresIn

	return a.Extra
}
