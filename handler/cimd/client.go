// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package cimd

import (
	"context"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/handler/rfc7591"
	"authelia.com/provider/oauth2/x/errorsx"
)

// Client is a client resolved from a Client ID Metadata Document.
//
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-02#section-4
type Client struct {
	*oauth2.DefaultRegisteredClient
}

// IsClientIDMetadataDocumentClient returns true.
func (c *Client) IsClientIDMetadataDocumentClient() (is bool) {
	return true
}

// ClientStrategy builds the client a validated Client ID Metadata Document describes.
type ClientStrategy interface {
	// NewClient returns the client the record describes. The client must implement
	// oauth2.ClientIDMetadataDocumentClient and report true, and must have the identifier record.ID. The record is
	// a copy the client may retain.
	NewClient(ctx context.Context, record *oauth2.ClientIDMetadataDocumentRecord) (client oauth2.Client, err error)
}

// DefaultClientStrategy is the ClientStrategy which builds a *Client.
type DefaultClientStrategy struct{}

// NewClient returns a *Client built from the record with rfc7591.DefaultClientRegistrationStrategy. The client has
// no secret.
//
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-02#section-4.1
func (DefaultClientStrategy) NewClient(ctx context.Context, record *oauth2.ClientIDMetadataDocumentRecord) (client oauth2.Client, err error) {
	if client, err = rfc7591.NewDefaultClientRegistrationStrategy().NewClient(ctx, record.ID, nil, record.Metadata); err != nil {
		return nil, err
	}

	registered, ok := client.(*oauth2.DefaultRegisteredClient)
	if !ok {
		return nil, errorsx.WithStack(oauth2.ErrServerError.WithDebugf("The default client registration strategy returned a '%T' for the Client ID Metadata Document '%s'.", client, record.ID))
	}

	registered.ClientIDIssuedAt = record.FetchedAt

	return &Client{DefaultRegisteredClient: registered}, nil
}

var (
	_ oauth2.ClientIDMetadataDocumentClient = (*Client)(nil)
	_ ClientStrategy                        = DefaultClientStrategy{}
)
