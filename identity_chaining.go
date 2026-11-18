// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
)

// AuthorizationGrantIssuerProvider is optionally implemented by an RFC8693TokenType which issues JWT authorization
// grants for an authorization server in another trust domain.
//
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-chaining-17#section-2.3
type AuthorizationGrantIssuerProvider interface {
	// GetAuthorizationGrantIssuer returns the 'iss' claim of the grants the type issues, which is empty when it issues
	// none.
	GetAuthorizationGrantIssuer(ctx context.Context) (issuer string)
}

// IsAuthorizationGrantIssuer reports whether the issuer is the one a token type issues JWT authorization grants as. A
// grant is issued for another trust domain, so this authorization server accepts no token from such an issuer.
//
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-chaining-17#section-2.3
// See: https://datatracker.ietf.org/doc/html/rfc8725#section-3.12
func IsAuthorizationGrantIssuer(ctx context.Context, types map[string]RFC8693TokenType, issuer string) (is bool) {
	if issuer == "" {
		return false
	}

	for _, tokenType := range types {
		if provider, ok := tokenType.(AuthorizationGrantIssuerProvider); ok && provider.GetAuthorizationGrantIssuer(ctx) == issuer {
			return true
		}
	}

	return false
}
