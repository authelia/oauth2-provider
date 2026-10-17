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
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-02#section-7.1
func IsClientIDMetadataDocumentClient(client any) (is bool) {
	c, ok := client.(interface{ IsClientIDMetadataDocumentClient() bool })

	return ok && c.IsClientIDMetadataDocumentClient()
}

// ClientJWKSFetcherStrategyProvider is optionally implemented by a StrategyConfig to select the JWKSFetcherStrategy
// by client. A nil strategy means the 'jwks_uri' of that client must not be fetched.
type ClientJWKSFetcherStrategyProvider interface {
	// GetClientJWKSFetcherStrategy returns the strategy used to fetch the 'jwks_uri' of the given client.
	GetClientJWKSFetcherStrategy(ctx context.Context, client any) (strategy JWKSFetcherStrategy)
}

// ClientJWKSFetcherStrategy returns the strategy used to fetch the 'jwks_uri' of the given client. The 'jwks_uri' of
// a client resolved from a Client ID Metadata Document is only fetched by a strategy the config selects for it, and
// the returned strategy fails every fetch when there is none.
//
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-02#section-8.6
func ClientJWKSFetcherStrategy(ctx context.Context, config StrategyConfig, client any) (fetcher JWKSFetcherStrategy) {
	if provider, ok := config.(ClientJWKSFetcherStrategyProvider); ok {
		if fetcher = provider.GetClientJWKSFetcherStrategy(ctx, client); fetcher != nil {
			return fetcher
		}

		return &unavailableJWKSFetcherStrategy{}
	}

	if IsClientIDMetadataDocumentClient(client) {
		return &unavailableJWKSFetcherStrategy{}
	}

	return config.GetJWKSFetcherStrategy(ctx)
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
