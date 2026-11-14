// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"slices"
)

// JWTAssertionAudienceConfig is the configuration JWTBearerGrantAudiences reads.
type JWTAssertionAudienceConfig interface {
	IssuerProvider
	EndpointURLsProvider
	AllowedJWTAssertionAudiencesProvider
}

// JWTBearerGrantAudiences returns the 'aud' values identifying this authorization server in an RFC 7523 JWT
// authorization grant: the issuer identifier, the token endpoint URL and its RFC 8705 mutual TLS alias, then the
// values of AllowedJWTAssertionAudiencesProvider. Empty and duplicate values are omitted.
//
// See: https://www.rfc-editor.org/rfc/rfc10070#section-4
func JWTBearerGrantAudiences(ctx context.Context, config JWTAssertionAudienceConfig) (audiences []string) {
	urls := config.GetEndpointURLs(ctx)

	return jwtAssertionAudiences(
		[]string{config.GetIssuer(ctx)},
		urls.URLs(EndpointToken),
		config.GetAllowedJWTAssertionAudiences(ctx),
	)
}

// ClientAssertionAudienceEndpointProvider is optionally implemented by an EndpointClientAuthStrategy to name the
// endpoint whose URL and RFC 8705 mutual TLS alias may be the 'aud' of a client assertion presented there when
// DisableClientAssertionIssuerAudience is set. A strategy which does not implement it uses the endpoint of its name.
type ClientAssertionAudienceEndpointProvider interface {
	GetClientAssertionAudienceEndpoint() (endpoint EndpointName)
}

// clientAssertionAudienceEndpoint returns the endpoint a client assertion is presented to, or an empty value when it is
// not known.
func clientAssertionAudienceEndpoint(strategy EndpointClientAuthStrategy) (endpoint EndpointName) {
	if p, ok := strategy.(ClientAssertionAudienceEndpointProvider); ok {
		return p.GetClientAssertionAudienceEndpoint()
	}

	switch ClientAuthEndpoint(strategy.Name()) {
	case ClientAuthEndpointToken:
		return EndpointToken
	case ClientAuthEndpointRevocation:
		return EndpointRevocation
	case ClientAuthEndpointIntrospection:
		return EndpointIntrospection
	case ClientAuthEndpointBackChannelAuthentication:
		return EndpointBackChannelAuthentication
	default:
		return ""
	}
}

// clientAssertionLegacyAudiences returns the client assertion 'aud' values accepted when
// DisableClientAssertionIssuerAudience is set: the issuer identifier, and the URL and RFC 8705 mutual TLS alias of the
// endpoint the assertion is presented to.
//
// See: https://www.rfc-editor.org/rfc/rfc10070#section-4
func clientAssertionLegacyAudiences(ctx context.Context, config JWTAssertionAudienceConfig, endpoint EndpointName) (audiences []string) {
	return jwtAssertionAudiences(
		[]string{config.GetIssuer(ctx)},
		config.GetEndpointURLs(ctx).URLs(endpoint),
	)
}

// jwtAssertionAudiences flattens the groups in order, omitting empty and duplicate values.
func jwtAssertionAudiences(groups ...[]string) (audiences []string) {
	for _, group := range groups {
		for _, value := range group {
			if value == "" || slices.Contains(audiences, value) {
				continue
			}

			audiences = append(audiences, value)
		}
	}

	return audiences
}
