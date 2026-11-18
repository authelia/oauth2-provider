// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

// Package jwtgrant verifies a JWT presented as an authorization grant. It holds the checks the RFC 7523 and Identity
// Assertion JWT Authorization Grant handlers have in common. The name every function takes is the noun used for the
// grant in error hints.
//
// See: https://datatracker.ietf.org/doc/html/rfc7523#section-3
package jwtgrant

import (
	"context"
	"errors"
	"slices"
	"time"

	"authelia.com/provider/jose"
	josejwt "authelia.com/provider/jose/jwt"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/token/jwt"
	"authelia.com/provider/oauth2/x/errorsx"
)

// Keys is the key material and the permitted algorithms of a trusted issuer. JSONWebKeys takes precedence over
// JSONWebKeysURI.
type Keys struct {
	Issuer         string
	JSONWebKeys    *jose.JSONWebKeySet
	JSONWebKeysURI string
	SigningAlgs    []string
}

// TimeOptions is the clock skew allowed for the 'nbf' and 'iat' claims and the longest lifetime a grant may have.
type TimeOptions struct {
	Skew, MaxDuration time.Duration
}

// Parse parses a compact serialized grant signed with one of the algorithms and returns it with its unverified 'iss'
// claim, which selects the trusted issuer.
//
// See: https://datatracker.ietf.org/doc/html/rfc7523#section-3
func Parse(name string, algs []jose.SignatureAlgorithm, assertion string) (token *josejwt.JSONWebToken, issuer string, err error) {
	token, err = josejwt.ParseSigned(assertion, algs)
	if err != nil {
		return nil, "", errorsx.WithStack(oauth2.ErrInvalidGrant.WithHintf("Unable to parse the %s.", name).WithWrap(err).WithDebugError(err))
	}

	if len(token.Headers) != 1 {
		return nil, "", errorsx.WithStack(oauth2.ErrInvalidGrant.WithHintf("The %s must have exactly one signature.", name))
	}

	var unverified josejwt.Claims

	if err = token.UnsafeClaimsWithoutVerification(&unverified); err != nil || unverified.Issuer == "" {
		return nil, "", errorsx.WithStack(oauth2.ErrInvalidGrant.WithHintf("The %s must contain an 'iss' claim.", name))
	}

	return token, unverified.Issuer, nil
}

// UnverifiedClaims returns the claims of a grant without verifying its signature. It is only for a grant Verify has
// already accepted in the same request.
func UnverifiedClaims(name string, algs []jose.SignatureAlgorithm, assertion string) (claims josejwt.Claims, raw map[string]any, err error) {
	token, err := josejwt.ParseSigned(assertion, algs)
	if err != nil {
		return claims, nil, errorsx.WithStack(oauth2.ErrInvalidGrant.WithHintf("Unable to parse the %s.", name).WithWrap(err).WithDebugError(err))
	}

	raw = map[string]any{}

	if err = token.UnsafeClaimsWithoutVerification(&claims, &raw); err != nil {
		return claims, nil, errorsx.WithStack(oauth2.ErrInvalidGrant.WithHintf("Unable to parse the %s.", name).WithWrap(err).WithDebugError(err))
	}

	return claims, raw, nil
}

// CheckAlgorithm requires the algorithm of the header to be one the issuer permits, which is only RS256 when the
// issuer lists none.
func CheckAlgorithm(keys Keys, header jose.Header) (err error) {
	algs := keys.SigningAlgs
	if len(algs) == 0 {
		algs = []string{string(jose.RS256)}
	}

	if !slices.Contains(algs, header.Algorithm) {
		return errorsx.WithStack(oauth2.ErrInvalidGrant.WithHintf("The algorithm '%s' is not permitted for the issuer '%s'.", header.Algorithm, keys.Issuer))
	}

	return nil
}

// Verify requires the algorithm of the grant to be one the issuer permits, verifies its signature with a key of the
// issuer, and returns its claims and the 'kid' of the key that verified it. The fetcher is only called when the issuer
// has no static keys. A fetched key set is refetched once, ignoring the cache, unless a cached key the grant names by
// 'kid' failed to verify it.
//
// See: https://datatracker.ietf.org/doc/html/rfc7523#section-3
func Verify(ctx context.Context, name string, token *josejwt.JSONWebToken, keys Keys, fetcher func(ctx context.Context) jwt.JWKSFetcherStrategy) (claims josejwt.Claims, raw map[string]any, kid string, err error) {
	if len(token.Headers) != 1 {
		return claims, nil, "", errorsx.WithStack(oauth2.ErrInvalidGrant.WithHintf("The %s must have exactly one signature.", name))
	}

	header := token.Headers[0]

	if err = CheckAlgorithm(keys, header); err != nil {
		return claims, nil, "", err
	}

	switch {
	case keys.JSONWebKeys != nil:
		claims, raw, kid, err = verifyWithKeys(token, keys.JSONWebKeys, header)
	case keys.JSONWebKeysURI == "":
		return claims, nil, "", errorsx.WithStack(oauth2.ErrServerError.WithDebugf("The trusted issuer '%s' has no keys.", keys.Issuer))
	default:
		strategy := fetcher(ctx)

		for _, ignoreCache := range []bool{false, true} {
			var jwks *jose.JSONWebKeySet

			if jwks, err = strategy.Resolve(ctx, keys.JSONWebKeysURI, ignoreCache); err != nil {
				return claims, nil, "", errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
			}

			if claims, raw, kid, err = verifyWithKeys(token, jwks, header); err == nil || (header.KeyID != "" && !errors.Is(err, errNoCandidateKey)) {
				break
			}
		}
	}

	if err != nil {
		return josejwt.Claims{}, nil, "", errorsx.WithStack(oauth2.ErrInvalidGrant.WithHintf("No key of the issuer verifies the %s.", name).WithWrap(err).WithDebugError(err))
	}

	return claims, raw, kid, nil
}

// ValidateTime checks the 'exp', 'nbf' and 'iat' claims of a verified grant. A grant without an 'iat' claim has its
// lifetime measured from now.
//
// See: https://datatracker.ietf.org/doc/html/rfc7523#section-3
func ValidateTime(name string, claims josejwt.Claims, opts TimeOptions) (err error) {
	if claims.Expiry == nil {
		return errorsx.WithStack(oauth2.ErrInvalidGrant.WithHintf("The %s must contain an 'exp' claim.", name))
	}

	now := time.Now()
	skewed := now.Add(max(opts.Skew, 0))

	issued := now
	if claims.IssuedAt != nil {
		issued = claims.IssuedAt.Time()
	}

	switch {
	case claims.Expiry.Time().Before(now):
		return errorsx.WithStack(oauth2.ErrInvalidGrant.WithHintf("The %s is expired.", name))
	case claims.NotBefore != nil && claims.NotBefore.Time().After(skewed):
		return errorsx.WithStack(oauth2.ErrInvalidGrant.WithHintf("The %s is not yet valid.", name))
	case claims.IssuedAt != nil && issued.After(skewed):
		return errorsx.WithStack(oauth2.ErrInvalidGrant.WithHintf("The 'iat' claim of the %s is in the future.", name))
	case claims.Expiry.Time().Sub(issued) > opts.MaxDuration:
		return errorsx.WithStack(oauth2.ErrInvalidGrant.WithHintf("The 'exp' claim of the %s is unreasonably far in the future.", name))
	}

	return nil
}

// CheckUnused rejects a grant the used callback reports as already redeemed.
//
// See: https://datatracker.ietf.org/doc/html/rfc7523#section-3
func CheckUnused(ctx context.Context, name string, used func(ctx context.Context) (bool, error)) (err error) {
	var ok bool

	if ok, err = used(ctx); err != nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	} else if ok {
		return errorsx.WithStack(oauth2.ErrInvalidGrant.WithHintf("The %s was already redeemed.", name))
	}

	return nil
}

// Consume marks a grant as redeemed with the mark callback, which MUST be atomic and return an error matching
// oauth2.ErrJTIKnown for a grant already marked.
//
// See: https://datatracker.ietf.org/doc/html/rfc7523#section-3
func Consume(ctx context.Context, name string, mark func(ctx context.Context) error) (err error) {
	if err = mark(ctx); err != nil {
		if errors.Is(err, oauth2.ErrJTIKnown) {
			return errorsx.WithStack(oauth2.ErrInvalidGrant.WithHintf("The %s was already redeemed.", name))
		}

		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}

	return nil
}

// CapExpiry returns the expiry of an access token limited to the expiry of the grant plus the allowance, truncated to
// the second so the access token never outlives that limit.
//
// See: https://datatracker.ietf.org/doc/html/rfc7521#section-4.1
func CapExpiry(expires, grant time.Time, allowance time.Duration) (capped time.Time) {
	if limit := grant.UTC().Add(allowance); limit.Before(expires) {
		return limit.Truncate(time.Second)
	}

	return expires
}

var errNoCandidateKey = errors.New("no candidate key matches the token header")

func verifyWithKeys(token *josejwt.JSONWebToken, jwks *jose.JSONWebKeySet, header jose.Header) (claims josejwt.Claims, raw map[string]any, kid string, err error) {
	if jwks == nil {
		return claims, nil, "", errNoCandidateKey
	}

	err = errNoCandidateKey

	for _, candidate := range jwks.Keys {
		if header.KeyID != "" && candidate.KeyID != header.KeyID {
			continue
		}

		if candidate.Use != "" && candidate.Use != consts.JSONWebTokenUseSignature {
			continue
		}

		if candidate.Algorithm != "" && candidate.Algorithm != header.Algorithm {
			continue
		}

		verified := map[string]any{}

		var verifiedClaims josejwt.Claims

		if err = token.Claims(&candidate, &verifiedClaims, &verified); err != nil {
			continue
		}

		return verifiedClaims, verified, candidate.KeyID, nil
	}

	return claims, nil, "", err
}
