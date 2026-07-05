// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"

	"authelia.com/provider/oauth2/internal/consts"
)

// RFC8628UserAuthorizeResponse is an implementation of DeviceUserAuthorizeResponder
type RFC8628UserAuthorizeResponse struct {
	Header     http.Header    `json:"-"`
	Parameters url.Values     `json:"-"`
	Status     string         `json:"status"`
	Extra      map[string]any `json:"-"`
}

// NewRFC8628UserAuthorizeResponse returns an empty RFC8628UserAuthorizeResponse with its header, parameter and extras
// maps initialized.
func NewRFC8628UserAuthorizeResponse() *RFC8628UserAuthorizeResponse {
	return &RFC8628UserAuthorizeResponse{
		Header:     http.Header{},
		Parameters: url.Values{},
		Extra:      map[string]any{},
	}
}

// GetHeader returns the response HTTP headers that will be written to the user.
func (d *RFC8628UserAuthorizeResponse) GetHeader() http.Header {
	return d.Header
}

// AddHeader appends the value to the named response header.
func (d *RFC8628UserAuthorizeResponse) AddHeader(key, value string) {
	d.Header.Add(key, value)
}

// GetParameters returns the query/body parameters that will be returned in the response.
func (d *RFC8628UserAuthorizeResponse) GetParameters() url.Values {
	return d.Parameters
}

// AddParameter appends the value to the named response parameter.
func (d *RFC8628UserAuthorizeResponse) AddParameter(key, value string) {
	d.Parameters.Add(key, value)
}

// GetStatus returns the user's authorization decision as a string.
func (d *RFC8628UserAuthorizeResponse) GetStatus() string {
	return d.Status
}

// SetStatus records the user's authorization decision as a string. See DeviceAuthorizeStatusToString for the canonical
// values.
func (d *RFC8628UserAuthorizeResponse) SetStatus(status string) {
	d.Status = status
}

// ToJSON encodes the response as JSON and writes it to rw.
func (d *RFC8628UserAuthorizeResponse) ToJSON(rw io.Writer) error {
	return json.NewEncoder(rw).Encode(&d)
}

// FromJSON decodes a JSON-encoded response from r into the receiver.
func (d *RFC8628UserAuthorizeResponse) FromJSON(r io.Reader) error {
	return json.NewDecoder(r).Decode(&d)
}

// SetExtra sets an extension parameter on the response, allowing handlers to inject additional response fields.
func (d *RFC8628UserAuthorizeResponse) SetExtra(key string, value any) {
	d.Extra[key] = value
}

// GetExtra returns the value previously stored under key by SetExtra, or nil if none has been set.
func (d *RFC8628UserAuthorizeResponse) GetExtra(key string) any {
	return d.Extra[key]
}

// ToMap converts the response to a map.
func (d *RFC8628UserAuthorizeResponse) ToMap() map[string]any {
	d.Extra[consts.DeviceCodeResponseStatus] = d.Status

	return d.Extra
}

var (
	_ DeviceUserAuthorizeResponder = (*RFC8628UserAuthorizeResponse)(nil)
)
