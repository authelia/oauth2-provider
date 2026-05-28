// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"net/http"

	"authelia.com/provider/oauth2/internal/consts"
)

var (
	_ CIBAResponder = (*CIBAResponse)(nil)
)

// CIBAResponse is an implementation of CIBAResponder used by the OpenID Connect Client Initiated Backchannel
// Authentication (CIBA) backchannel authentication endpoint.
type CIBAResponse struct {
	Header        http.Header    `json:"-"`
	AuthRequestID string         `json:"auth_req_id"`
	ExpiresIn     int64          `json:"expires_in"`
	Interval      int            `json:"interval,omitempty"`
	Extra         map[string]any `json:"-"`
}

// NewCIBAResponse returns an empty CIBAResponse with its header and extras map initialized.
func NewCIBAResponse() *CIBAResponse {
	return &CIBAResponse{
		Header: http.Header{},
		Extra:  map[string]any{},
	}
}

// GetAuthRequestID returns the auth_req_id value issued for this CIBA request.
func (r *CIBAResponse) GetAuthRequestID() string {
	return r.AuthRequestID
}

// SetAuthRequestID records the auth_req_id value issued for this CIBA request.
func (r *CIBAResponse) SetAuthRequestID(id string) {
	r.AuthRequestID = id
}

// GetExpiresIn returns the lifetime, in seconds, of the auth_req_id.
func (r *CIBAResponse) GetExpiresIn() int64 {
	return r.ExpiresIn
}

// SetExpiresIn records the lifetime, in seconds, of the auth_req_id.
func (r *CIBAResponse) SetExpiresIn(seconds int64) {
	r.ExpiresIn = seconds
}

// GetInterval returns the minimum polling interval, in seconds, that the client must observe when polling the token
// endpoint for an access token.
func (r *CIBAResponse) GetInterval() int {
	return r.Interval
}

// SetInterval records the minimum polling interval, in seconds, that the client must observe when polling the token
// endpoint for an access token.
func (r *CIBAResponse) SetInterval(seconds int) {
	r.Interval = seconds
}

// GetHeader returns the response HTTP headers that will be written to the client.
func (r *CIBAResponse) GetHeader() http.Header {
	return r.Header
}

// AddHeader appends the value to the named response header.
func (r *CIBAResponse) AddHeader(key, value string) {
	r.Header.Add(key, value)
}

// SetExtra sets an extension parameter on the response, allowing handlers to inject additional response fields.
func (r *CIBAResponse) SetExtra(key string, value any) {
	r.Extra[key] = value
}

// GetExtra returns the value previously stored under key by SetExtra, or nil if none has been set.
func (r *CIBAResponse) GetExtra(key string) any {
	return r.Extra[key]
}

// ToMap returns the complete CIBA response payload as a map, including the auth_req_id, expires_in, interval and all
// extra parameters.
func (r *CIBAResponse) ToMap() map[string]any {
	r.Extra[consts.CIBAResponseAuthRequestID] = r.AuthRequestID
	r.Extra[consts.CIBAResponseExpiresIn] = r.ExpiresIn

	if r.Interval > 0 {
		r.Extra[consts.CIBAResponseInterval] = r.Interval
	}

	return r.Extra
}
