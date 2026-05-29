// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package openid

import (
	"context"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/token/jwt"
	"authelia.com/provider/oauth2/x/errorsx"
)

// DefaultIDTokenValidationStrategy is the default TokenValidationStrategy. It decodes an inbound id_token via the
// embedded jwt.Strategy, using the request's registered client as the source of JSON Web Keys for signature
// verification when available.
//
// Validation responsibility split:
//
//   - This strategy enforces JWS/JWE structural validation, signature verification, signature algorithm enforcement,
//     and the time-based claims ('exp', 'nbf', 'iat') performed by jwt.Strategy.Decode when a client is supplied.
//   - Application-specific claim checks — most notably 'iss' (issuer) and 'aud' (audience) — are intentionally
//     LEFT TO THE CALLER. RFC 8693 ID tokens may originate from federated identity providers, so the AS-specific
//     issuer/audience policy lives one layer up (e.g. rfc8693.IDTokenTypeHandler.validate enforces 'iss' against
//     the configured issuer and the client's per-role issuer allow-list).
//
// The strategy is safe to use concurrently provided the embedded jwt.Strategy is itself concurrent-safe (the
// reference DefaultStrategy is).
type DefaultIDTokenValidationStrategy struct {
	jwt.Strategy
}

// ValidateIDToken implements TokenValidationStrategy.ValidateIDToken. The supplied token is decoded and verified
// using the embedded jwt.Strategy; the request's client is wrapped via jwt.WithIDTokenClient so the strategy can
// resolve the signing key from the client's registered JSON Web Key Set when the client implements jwt.IDTokenClient.
//
// Returns the decoded jwt.MapClaims on success. Decode errors propagate as the jwt.ValidationError they originated
// as (callers typically map these to oauth2.ErrInvalidRequest).
func (s *DefaultIDTokenValidationStrategy) ValidateIDToken(ctx context.Context, request oauth2.Requester, token string) (jwt.MapClaims, error) {
	if s.Strategy == nil {
		return nil, errorsx.WithStack(oauth2.ErrServerError.WithDebug("Failed to validate id_token because the JWT strategy is not configured."))
	}

	var opts []jwt.StrategyOpt

	if request != nil {
		if client := request.GetClient(); client != nil {
			opts = append(opts, jwt.WithIDTokenClient(client))
		}
	}

	decoded, err := s.Strategy.Decode(ctx, token, opts...)
	if err != nil {
		return nil, err
	}

	claims, ok := decoded.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errorsx.WithStack(oauth2.ErrServerError.WithDebug("Failed to validate id_token because the decoded JWT claims are not of the expected map type."))
	}

	return claims, nil
}

var (
	_ TokenValidationStrategy = (*DefaultIDTokenValidationStrategy)(nil)
)
