// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package jwt

import (
	"context"
	"errors"

	"authelia.com/provider/jose"
)

// IsClientIDMetadataDocumentClient reports whether client was resolved from a Client ID Metadata Document, which it
// declares through an IsClientIDMetadataDocumentClient method returning true.
//
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-03#section-9.1
func IsClientIDMetadataDocumentClient(client any) (is bool) {
	c, ok := client.(interface{ IsClientIDMetadataDocumentClient() bool })

	return ok && c.IsClientIDMetadataDocumentClient()
}

// ClientJWKSFetcherStrategyProvider is implemented by a StrategyConfig to select the JWKSFetcherStrategy by client. A
// nil strategy means the 'jwks_uri' of that client must not be fetched. The selected strategy should refuse special-use
// addresses, as the 'jwks_uri' of a client is chosen by the client, which oauth2.Config does by default.
type ClientJWKSFetcherStrategyProvider interface {
	// GetClientJWKSFetcherStrategy returns the strategy used to fetch the 'jwks_uri' of the given client.
	GetClientJWKSFetcherStrategy(ctx context.Context, client any) (strategy JWKSFetcherStrategy)
}

// ClientJWKSFetcherStrategy returns the strategy the config selects to fetch the 'jwks_uri' of the given client, which
// fails every fetch when the config selects none, as for a client resolved from a Client ID Metadata Document without
// a strategy configured for it.
//
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-03#section-10.7
func ClientJWKSFetcherStrategy(ctx context.Context, config StrategyConfig, client any) (fetcher JWKSFetcherStrategy) {
	if fetcher = config.GetClientJWKSFetcherStrategy(ctx, client); fetcher != nil {
		return fetcher
	}

	return &unavailableJWKSFetcherStrategy{}
}

type unavailableJWKSFetcherStrategy struct{}

func (unavailableJWKSFetcherStrategy) Resolve(_ context.Context, location string, _ bool) (jwks *jose.JSONWebKeySet, err error) {
	return nil, errors.New("no JSON Web Key Set fetcher is configured for clients resolved from a Client ID Metadata Document")
}

func (r *decoratedJARClient) IsClientIDMetadataDocumentClient() (is bool) {
	return IsClientIDMetadataDocumentClient(r.JARClient)
}

func (r *decoratedIDTokenClient) IsClientIDMetadataDocumentClient() (is bool) {
	return IsClientIDMetadataDocumentClient(r.IDTokenClient)
}

func (r *decoratedJARMClient) IsClientIDMetadataDocumentClient() (is bool) {
	return IsClientIDMetadataDocumentClient(r.JARMClient)
}

func (r *decoratedUserInfoClient) IsClientIDMetadataDocumentClient() (is bool) {
	return IsClientIDMetadataDocumentClient(r.UserInfoClient)
}

func (r *decoratedJWTProfileAccessTokenClient) IsClientIDMetadataDocumentClient() (is bool) {
	return IsClientIDMetadataDocumentClient(r.JWTProfileAccessTokenClient)
}

func (r *decoratedIntrospectionClient) IsClientIDMetadataDocumentClient() (is bool) {
	return IsClientIDMetadataDocumentClient(r.IntrospectionClient)
}

func (r *decoratedSecurityEventTokenClient) IsClientIDMetadataDocumentClient() (is bool) {
	return IsClientIDMetadataDocumentClient(r.SecurityEventTokenClient)
}
