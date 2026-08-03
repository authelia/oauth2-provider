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
//   - This strategy enforces JWS/JWE structural validation, signature verification and signature algorithm
//     enforcement via jwt.Strategy.Decode, then validates the time-based claims ('exp', 'nbf', 'iat') itself via
//     jwt.MapClaims.Valid. Note that jwt.Strategy.Decode does NOT validate time-based claims.
//   - Application-specific claim checks, most notably 'iss' (issuer) and 'aud' (audience), are intentionally
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
func (s *DefaultIDTokenValidationStrategy) ValidateIDToken(ctx context.Context, request oauth2.Requester, token string, opts ...oauth2.IDTokenValidationOpt) (claims jwt.MapClaims, err error) {
	if s.Strategy == nil {
		return nil, errorsx.WithStack(oauth2.ErrServerError.WithDebug("Failed to validate id_token because the JWT strategy is not configured."))
	}

	o := oauth2.NewIDTokenValidationOpts(opts...)

	var sopts []jwt.StrategyOpt

	if o.AllowUnverified {
		// The client must NOT be supplied here: jwt.DefaultStrategy.Decode verifies whenever a client is present,
		// regardless of jwt.WithAllowUnverified.
		sopts = append(sopts, jwt.WithAllowUnverified())
	} else if request != nil {
		if client := request.GetClient(); client != nil {
			sopts = append(sopts, jwt.WithIDTokenClient(client))
		}
	}

	var decoded *jwt.Token

	if decoded, err = s.Strategy.Decode(ctx, token, sopts...); err != nil {
		return nil, err
	}

	var ok bool

	if claims, ok = decoded.Claims.(jwt.MapClaims); !ok {
		return nil, errorsx.WithStack(oauth2.ErrServerError.WithDebug("Failed to validate id_token because the decoded JWT claims are not of the expected map type."))
	}

	if o.AllowUnverified {
		return claims, nil
	}

	var copts []jwt.ClaimValidationOption

	if o.AllowExpired {
		copts = append(copts, jwt.ValidateIgnoreExpiration())
	}

	if err = claims.Valid(copts...); err != nil {
		return nil, errorsx.WithStack(err)
	}

	return claims, nil
}

var (
	_ TokenValidationStrategy = (*DefaultIDTokenValidationStrategy)(nil)
)
