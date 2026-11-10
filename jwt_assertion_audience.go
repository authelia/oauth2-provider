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

// clientAssertionLegacyAudiences returns the client assertion 'aud' values RFC 7523 and RFC 9126 permitted before
// RFC 10070, accepted only when DisableClientAssertionIssuerAudience is set.
func clientAssertionLegacyAudiences(ctx context.Context, config JWTAssertionAudienceConfig) (audiences []string) {
	urls := config.GetEndpointURLs(ctx)

	return jwtAssertionAudiences(
		[]string{config.GetIssuer(ctx)},
		urls.URLs(EndpointToken),
		urls.URLs(EndpointPushedAuthorizationRequest),
		config.GetAllowedJWTAssertionAudiences(ctx),
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
