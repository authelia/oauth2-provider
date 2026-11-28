// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package openid

import (
	"context"
	"errors"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
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
			if o.IDTokenHint {
				sopts = append(sopts, jwt.WithIDTokenHintClient(client))
			} else {
				sopts = append(sopts, jwt.WithIDTokenClient(client))
			}
		}
	}

	if len(o.SigningAlgValues) != 0 {
		sopts = append(sopts, jwt.WithSigAlgorithm(jwt.ToSignatureAlgorithms(o.SigningAlgValues)...))
	}

	var decoded *jwt.Token

	if decoded, err = s.Decode(ctx, token, sopts...); err != nil {
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

	copts := []jwt.ClaimValidationOption{jwt.ValidateClockSkew(o.ClockSkew), jwt.ValidateRequireIssuedAt()}

	// OpenID Connect Core 1.0 Section 2: the 'exp' and 'iat' claims are REQUIRED. An expired ID Token must still have
	// one, so a JWT of another kind without it is not accepted, per RFC 8725 Section 3.12.
	if o.AllowExpired {
		if exp, _ := claims.GetExpirationTime(); exp == nil {
			return nil, errorsx.WithStack(&jwt.ValidationError{Errors: jwt.ValidationErrorExpired, Inner: errors.New("token is missing the 'exp' claim")})
		}

		copts = append(copts, jwt.ValidateIgnoreExpiration())
	} else {
		copts = append(copts, jwt.ValidateRequireExpiresAt())
	}

	if err = claims.Valid(copts...); err != nil {
		return nil, errorsx.WithStack(err)
	}

	return claims, nil
}

var (
	_ TokenValidationStrategy = (*DefaultIDTokenValidationStrategy)(nil)
)

// validateIDTokenHint returns the subject of an 'id_token_hint': an ID Token previously issued by this authorization
// server to the client, which may be expired.
//
// See: https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
// See: https://datatracker.ietf.org/doc/html/rfc8725#section-3.12
func validateIDTokenHint(ctx context.Context, strategy jwt.Strategy, config any, issuer string, client oauth2.Client, hint string) (subject string, err error) {
	if issuer == "" {
		return "", errors.New("the issuer is not configured")
	}

	if client == nil {
		return "", errors.New("the request has no client")
	}

	validator := &DefaultIDTokenValidationStrategy{Strategy: strategy}

	opts := oauth2.IDTokenValidationClientOpts(ctx, config, client)

	var claims jwt.MapClaims

	if claims, err = validator.ValidateIDToken(ctx, &oauth2.Request{Client: client}, hint, append([]oauth2.IDTokenValidationOpt{oauth2.WithAllowExpired(), oauth2.WithIDTokenHint()}, opts...)...); err != nil {
		return "", err
	}

	if err = claims.Valid(jwt.ValidateIgnoreExpiration(), jwt.ValidateClockSkew(oauth2.NewIDTokenValidationOpts(opts...).ClockSkew), jwt.ValidateIssuer(issuer), jwt.ValidateAudienceAny(client.GetID())); err != nil {
		return "", err
	}

	if azp, present := claims[consts.ClaimAuthorizedParty]; present && azp != client.GetID() {
		return "", errors.New("the 'azp' claim is not the client")
	}

	if subject, _ = claims.GetSubject(); subject == "" {
		return "", errors.New("the 'sub' claim is missing")
	}

	return subject, nil
}
