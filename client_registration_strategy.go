// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"net/http"
)

// ClientRegistrationStrategy constructs and patches concrete Client values from RFC 7591 / RFC 7592 client
// registration metadata, and converts a concrete Client back into that metadata.
type ClientRegistrationStrategy interface {
	// NewClient constructs a new concrete Client from the given id, secret, and metadata. The secret is provided
	// pre-generated so callers can control its format and control the plaintext value returned to the client.
	NewClient(ctx context.Context, id string, secret ClientSecret, metadata *ClientRegistrationMetadata) (client Client, err error)

	// PatchClient applies the complete metadata set onto an existing concrete Client, implementing the full
	// replacement semantics of RFC 7592 Section 2.2: values absent from the metadata revert to their default or are
	// removed. It is not a merge. A nil secret leaves the existing client secret untouched.
	PatchClient(ctx context.Context, client Client, secret ClientSecret, metadata *ClientRegistrationMetadata) (patched Client, err error)

	// MetadataFromClient converts a concrete Client back into its RFC 7591 / RFC 7592 metadata representation, as
	// returned by the client registration and client configuration endpoints.
	MetadataFromClient(ctx context.Context, client Client) (metadata *ClientRegistrationMetadata, err error)
}

// ClientRegistrationValidator validates submitted client registration metadata beyond what parsing and type
// coercion already enforce, such as cross-field consistency and deployment-specific policy.
type ClientRegistrationValidator interface {
	// ValidateClientRegistrationMetadata validates metadata submitted for the given client, returning an error
	// (typically wrapping ErrInvalidClientMetadata) when the metadata is invalid. client is nil on a client
	// registration request, and the existing client on a client configuration request.
	ValidateClientRegistrationMetadata(ctx context.Context, client Client, metadata *ClientRegistrationMetadata) (err error)
}

// ClientRegistrationEndpointAuthStrategy authenticates requests made to the client registration and client
// configuration endpoints.
type ClientRegistrationEndpointAuthStrategy interface {
	// AuthenticateClientRegistrationRequest authenticates the request and returns the Requester it authenticates as.
	// id is empty for client registration requests (RFC 7591), and carries the target client id for client
	// configuration requests (RFC 7592), letting the strategy verify the credential is authorized for that specific
	// client.
	AuthenticateClientRegistrationRequest(ctx context.Context, r *http.Request, id string) (requester Requester, err error)
}
