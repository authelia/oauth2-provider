// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"encoding/json"
	"net/http"
	"time"

	"authelia.com/provider/oauth2/internal/consts"
)

// ClientRegistrationResponder is the response object for the RFC 7591 client registration endpoint and the RFC 7592
// client configuration endpoint.
//
// See: https://datatracker.ietf.org/doc/html/rfc7591#section-3.2.1 and
// https://datatracker.ietf.org/doc/html/rfc7592#section-3
type ClientRegistrationResponder interface {
	// SetMetadata sets the client metadata to be returned to the client.
	SetMetadata(metadata *ClientRegistrationMetadata)

	// GetMetadata returns the client metadata to be returned to the client.
	GetMetadata() (metadata *ClientRegistrationMetadata)

	// SetClientID sets the 'client_id' value.
	SetClientID(id string)

	// SetClientSecret sets the 'client_secret' value. An empty value omits both 'client_secret' and
	// 'client_secret_expires_at' from ToMap.
	SetClientSecret(secret string)

	// SetClientIDIssuedAt sets the 'client_id_issued_at' value. A zero value omits 'client_id_issued_at' from ToMap
	// entirely, since RFC 7591 defines no zero sentinel for this OPTIONAL field.
	SetClientIDIssuedAt(issued time.Time)

	// SetClientSecretExpiresAt sets the 'client_secret_expires_at' value. A zero value indicates the secret does not
	// expire and is reported as 0 per RFC 7591 Section 3.2.1.
	SetClientSecretExpiresAt(expires time.Time)

	// SetRegistrationAccessToken sets the 'registration_access_token' value.
	SetRegistrationAccessToken(token string)

	// SetRegistrationClientURI sets the 'registration_client_uri' value.
	SetRegistrationClientURI(uri string)

	// SetStatusCode sets the HTTP status code the response should be written with.
	SetStatusCode(code int)

	// GetStatusCode returns the HTTP status code the response should be written with.
	GetStatusCode() (code int)

	// GetHeader returns the HTTP headers to be written with the response.
	GetHeader() (header http.Header)

	// AddHeader adds an HTTP header to be written with the response.
	AddHeader(key, value string)

	// ToMap marshals the metadata and overlays the registration values, keyed by their wire names. Timestamps are
	// emitted as int64 Unix seconds. 'client_id_issued_at' is omitted entirely when unset, since RFC 7591 defines no
	// zero sentinel for that OPTIONAL field. The 'client_secret' and 'client_secret_expires_at' values are omitted
	// entirely when there is no client secret. Every key ToMap is responsible for is deterministically controlled by
	// the server: it is either always set or explicitly deleted, so an unregistered 'Extra' metadata parameter of the
	// same name submitted by the client can never survive into the response in its place.
	ToMap() (values map[string]any)
}

// ClientConfigurationResponder is the response object for the RFC 7592 client configuration endpoint. It is the same
// shape as ClientRegistrationResponder because both endpoints return the same wire format.
type ClientConfigurationResponder = ClientRegistrationResponder

var (
	_ ClientRegistrationResponder = (*ClientRegistrationResponse)(nil)
)

// ClientRegistrationResponse is an implementation of ClientRegistrationResponder.
type ClientRegistrationResponse struct {
	Metadata                *ClientRegistrationMetadata
	ClientID                string
	ClientSecret            string
	ClientIDIssuedAt        time.Time
	ClientSecretExpiresAt   time.Time
	RegistrationAccessToken string
	RegistrationClientURI   string
	StatusCode              int
	Header                  http.Header
}

// NewClientRegistrationResponse returns an empty ClientRegistrationResponse with its status code set to
// http.StatusOK and its header initialized.
func NewClientRegistrationResponse() *ClientRegistrationResponse {
	return &ClientRegistrationResponse{
		StatusCode: http.StatusOK,
		Header:     http.Header{},
	}
}

// SetMetadata sets the client metadata to be returned to the client.
func (r *ClientRegistrationResponse) SetMetadata(metadata *ClientRegistrationMetadata) {
	r.Metadata = metadata
}

// GetMetadata returns the client metadata to be returned to the client.
func (r *ClientRegistrationResponse) GetMetadata() (metadata *ClientRegistrationMetadata) {
	return r.Metadata
}

// SetClientID sets the 'client_id' value.
func (r *ClientRegistrationResponse) SetClientID(id string) {
	r.ClientID = id
}

// SetClientSecret sets the 'client_secret' value.
func (r *ClientRegistrationResponse) SetClientSecret(secret string) {
	r.ClientSecret = secret
}

// SetClientIDIssuedAt sets the 'client_id_issued_at' value. A zero value omits 'client_id_issued_at' from ToMap
// entirely, since RFC 7591 defines no zero sentinel for this OPTIONAL field.
func (r *ClientRegistrationResponse) SetClientIDIssuedAt(issued time.Time) {
	r.ClientIDIssuedAt = issued
}

// SetClientSecretExpiresAt sets the 'client_secret_expires_at' value.
func (r *ClientRegistrationResponse) SetClientSecretExpiresAt(expires time.Time) {
	r.ClientSecretExpiresAt = expires
}

// SetRegistrationAccessToken sets the 'registration_access_token' value.
func (r *ClientRegistrationResponse) SetRegistrationAccessToken(token string) {
	r.RegistrationAccessToken = token
}

// SetRegistrationClientURI sets the 'registration_client_uri' value.
func (r *ClientRegistrationResponse) SetRegistrationClientURI(uri string) {
	r.RegistrationClientURI = uri
}

// SetStatusCode sets the HTTP status code the response should be written with.
func (r *ClientRegistrationResponse) SetStatusCode(code int) {
	r.StatusCode = code
}

// GetStatusCode returns the HTTP status code the response should be written with.
func (r *ClientRegistrationResponse) GetStatusCode() (code int) {
	return r.StatusCode
}

// GetHeader returns the HTTP headers to be written with the response.
func (r *ClientRegistrationResponse) GetHeader() (header http.Header) {
	return r.Header
}

// AddHeader adds an HTTP header to be written with the response.
func (r *ClientRegistrationResponse) AddHeader(key, value string) {
	r.Header.Add(key, value)
}

// ToMap marshals the metadata through json.Marshal into a map[string]any and overlays the registration values on
// top, keyed by the consts.ClientRegistrationResponse* constants. 'client_secret_expires_at' is emitted as an int64
// Unix seconds value, and a zero ClientSecretExpiresAt emits 0, which per RFC 7591 Section 3.2.1 means the secret
// does not expire. 'client_id_issued_at' is also emitted as an int64 Unix seconds value when set, but is omitted
// entirely when zero since RFC 7591 defines no zero sentinel for that OPTIONAL field. Both 'client_secret' and
// 'client_secret_expires_at' are omitted entirely when there is no client secret.
//
// Every key overlaid here is deterministically controlled by the server: it is either always set unconditionally
// (which is enough to override anything of the same name decoded from Metadata's Extra) or, when it may be omitted,
// explicitly deleted first. This matters because none of these keys are registered ClientRegistrationMetadata
// fields, so a client that submits e.g. 'client_secret' or 'client_id_issued_at' as an unrecognized metadata
// parameter has it land in Extra, which MarshalJSON merges into the map above. Without the delete, an omitted
// server-controlled value would silently let that client-submitted value survive into the response.
func (r *ClientRegistrationResponse) ToMap() (values map[string]any) {
	values = map[string]any{}

	if r.Metadata != nil {
		if data, err := json.Marshal(r.Metadata); err == nil {
			_ = json.Unmarshal(data, &values)
		}
	}

	values[consts.ClientRegistrationResponseClientID] = r.ClientID

	delete(values, consts.ClientRegistrationResponseClientIDIssuedAt)

	if !r.ClientIDIssuedAt.IsZero() {
		values[consts.ClientRegistrationResponseClientIDIssuedAt] = r.ClientIDIssuedAt.Unix()
	}

	delete(values, consts.ClientRegistrationResponseClientSecret)
	delete(values, consts.ClientRegistrationResponseClientSecretExpiresAt)

	if r.ClientSecret != "" {
		values[consts.ClientRegistrationResponseClientSecret] = r.ClientSecret

		var expiresAt int64
		if !r.ClientSecretExpiresAt.IsZero() {
			expiresAt = r.ClientSecretExpiresAt.Unix()
		}

		values[consts.ClientRegistrationResponseClientSecretExpiresAt] = expiresAt
	}

	values[consts.ClientRegistrationResponseRegistrationAccessToken] = r.RegistrationAccessToken
	values[consts.ClientRegistrationResponseRegistrationClientURI] = r.RegistrationClientURI

	return values
}
