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
// embedded jwt.Strategy, verifying the signature with the request's registered client's JSON Web Keys when available,
// and validates the time-based claims ('exp', 'nbf', 'iat'), which jwt.Strategy.Decode does not. The 'exp' and 'iat'
// claims must be present unless oauth2.WithAllowExpired is used.
//
// The 'typ' header must be absent, 'JWT', or 'dpop+id_token'; the check is skipped when unverified tokens are allowed.
// The 'iss' and 'aud' claims are not validated and are left to the caller.
//
// See: https://datatracker.ietf.org/doc/html/rfc8725#section-3.11
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

	if err = decoded.Valid(jwt.ValidateTypes(jwt.JSONWebTokenTypeJWT, jwt.JSONWebTokenTypeDPoPIDToken), jwt.ValidateAllowEmptyType(true)); err != nil {
		return nil, errorsx.WithStack(err)
	}

	var copts []jwt.ClaimValidationOption

	// OpenID Connect Core 1.0 Section 2: the 'exp' and 'iat' claims are REQUIRED.
	if o.AllowExpired {
		copts = append(copts, jwt.ValidateIgnoreExpiration())
	} else {
		copts = append(copts, jwt.ValidateRequireExpiresAt(), jwt.ValidateRequireIssuedAt())
	}

	if err = claims.Valid(copts...); err != nil {
		return nil, errorsx.WithStack(err)
	}

	return claims, nil
}

var (
	_ TokenValidationStrategy = (*DefaultIDTokenValidationStrategy)(nil)
)
