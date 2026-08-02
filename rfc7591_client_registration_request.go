// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

// ClientRegistrationRequester is the interface for a client registration endpoint request, extended by the
// RFC 7591 client registration endpoint.
//
// See: https://datatracker.ietf.org/doc/html/rfc7591#section-3
type ClientRegistrationRequester interface {
	// GetMetadata returns the client metadata submitted by the client.
	GetMetadata() (metadata *ClientRegistrationMetadata)

	// GetAuthenticatedRequester returns the requester authenticated by the endpoint's configured
	// ClientRegistrationEndpointAuthStrategy, or nil when the endpoint does not require authentication.
	GetAuthenticatedRequester() (requester Requester)

	Requester
}

// ClientConfigurationRequester is the interface for a client configuration endpoint request, extended by the
// RFC 7592 client configuration endpoint.
//
// See: https://datatracker.ietf.org/doc/html/rfc7592#section-2
type ClientConfigurationRequester interface {
	// GetMethod returns the HTTP method of the request, used to dispatch between read, update, and delete.
	GetMethod() (method string)

	// GetClientID returns the client identifier taken from the request path.
	GetClientID() (id string)

	// GetMetadata returns the client metadata submitted by the client. It is nil for GET and DELETE requests.
	GetMetadata() (metadata *ClientRegistrationMetadata)

	// GetAuthenticatedRequester returns the requester authenticated by the endpoint's configured
	// ClientRegistrationEndpointAuthStrategy.
	GetAuthenticatedRequester() (requester Requester)

	// GetSignature returns the signature of the registration access token presented at the endpoint, taken from the
	// authenticated requester's ID.
	GetSignature() (signature string)

	Requester
}

var (
	_ ClientRegistrationRequester  = (*ClientRegistrationRequest)(nil)
	_ ClientConfigurationRequester = (*ClientConfigurationRequest)(nil)
)

// ClientRegistrationRequest is an implementation of ClientRegistrationRequester.
type ClientRegistrationRequest struct {
	// Metadata is the client metadata submitted by the client.
	Metadata *ClientRegistrationMetadata

	// Authenticated is the requester authenticated by the endpoint's configured
	// ClientRegistrationEndpointAuthStrategy, or nil when the endpoint does not require authentication.
	Authenticated Requester

	*Request
}

// NewClientRegistrationRequest returns an empty ClientRegistrationRequest with its embedded Request initialized.
func NewClientRegistrationRequest() *ClientRegistrationRequest {
	return &ClientRegistrationRequest{
		Request: NewRequest(),
	}
}

// GetMetadata returns the client metadata submitted by the client.
func (r *ClientRegistrationRequest) GetMetadata() (metadata *ClientRegistrationMetadata) {
	return r.Metadata
}

// GetAuthenticatedRequester returns the requester authenticated by the endpoint's configured
// ClientRegistrationEndpointAuthStrategy, or nil when the endpoint does not require authentication.
func (r *ClientRegistrationRequest) GetAuthenticatedRequester() (requester Requester) {
	return r.Authenticated
}

// ClientConfigurationRequest is an implementation of ClientConfigurationRequester.
type ClientConfigurationRequest struct {
	// Method is the HTTP method of the request, used to dispatch between read, update, and delete.
	Method string

	// ClientID is the client identifier taken from the request path.
	ClientID string

	// Metadata is the client metadata submitted by the client. It is nil for GET and DELETE requests.
	Metadata *ClientRegistrationMetadata

	// Authenticated is the requester authenticated by the endpoint's configured
	// ClientRegistrationEndpointAuthStrategy.
	Authenticated Requester

	// Signature is the signature of the registration access token presented at the endpoint, taken from the
	// authenticated requester's ID.
	Signature string

	*Request
}

// NewClientConfigurationRequest returns an empty ClientConfigurationRequest with its embedded Request initialized.
func NewClientConfigurationRequest() *ClientConfigurationRequest {
	return &ClientConfigurationRequest{
		Request: NewRequest(),
	}
}

// GetMethod returns the HTTP method of the request, used to dispatch between read, update, and delete.
func (r *ClientConfigurationRequest) GetMethod() (method string) {
	return r.Method
}

// GetClientID returns the client identifier taken from the request path.
func (r *ClientConfigurationRequest) GetClientID() (id string) {
	return r.ClientID
}

// GetMetadata returns the client metadata submitted by the client. It is nil for GET and DELETE requests.
func (r *ClientConfigurationRequest) GetMetadata() (metadata *ClientRegistrationMetadata) {
	return r.Metadata
}

// GetAuthenticatedRequester returns the requester authenticated by the endpoint's configured
// ClientRegistrationEndpointAuthStrategy.
func (r *ClientConfigurationRequest) GetAuthenticatedRequester() (requester Requester) {
	return r.Authenticated
}

// GetSignature returns the signature of the registration access token presented at the endpoint, taken from the
// authenticated requester's ID.
func (r *ClientConfigurationRequest) GetSignature() (signature string) {
	return r.Signature
}
