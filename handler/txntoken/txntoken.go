// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

// Package txntoken provides helpers for a workload to extract and validate a Transaction Token as described in
// draft-ietf-oauth-transaction-tokens-11 Section 12.
package txntoken

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"time"

	"authelia.com/provider/jose"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/token/jwt"
)

// HeaderName is the HTTP header which carries a Transaction Token, per draft-ietf-oauth-transaction-tokens-11 Section 12.1.
const HeaderName = "Txn-Token"

var (
	// ErrTokenAbsent is returned when the request carries no Txn-Token header value.
	ErrTokenAbsent = errors.New("txntoken: the request has no Txn-Token header")

	// ErrMultipleTokens is returned when the request carries more than one Txn-Token header value.
	ErrMultipleTokens = errors.New("txntoken: the request has more than one Txn-Token header value")

	// ErrInvalidToken is returned, wrapping the cause, when a Transaction Token fails validation.
	ErrInvalidToken = errors.New("txntoken: invalid transaction token")
)

// Config configures Validate.
type Config struct {
	// TrustDomain is the Trust Domain of the workload, which the 'aud' claim must contain.
	TrustDomain string

	// KeyFunc returns the verification key for the token. Verifying an HS* algorithm requires it to return a
	// jose.JSONWebKey.
	KeyFunc jwt.Keyfunc

	// Algorithms are the accepted signature algorithms. When empty the asymmetric algorithms RS*, PS*, ES* and EdDSA
	// are accepted.
	Algorithms []jose.SignatureAlgorithm

	// ClockSkew accepts an 'iat' or 'nbf' claim up to this duration in the future on a token whose signature was
	// verified. It does not apply to 'exp'. A value that is not positive accepts neither claim in the future.
	ClockSkew time.Duration
}

// DefaultAlgorithms returns the asymmetric signature algorithms accepted when Config.Algorithms is empty.
func DefaultAlgorithms() []jose.SignatureAlgorithm {
	return []jose.SignatureAlgorithm{
		jose.RS256, jose.RS384, jose.RS512,
		jose.PS256, jose.PS384, jose.PS512,
		jose.ES256, jose.ES384, jose.ES512,
		jose.EdDSA,
	}
}

// Claims are the validated claims of a Transaction Token.
type Claims struct {
	Subject            string
	Issuer             string
	Transaction        string
	Scope              string
	RequestingWorkload string

	// RequestingWorkloadChain is the workloads which requested the tokens this one replaced, oldest first. It is nil on a
	// token that replaced none. The draft leaves this mechanism to the implementation, so 'req_wl_chain' is specific to
	// this library.
	//
	// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-transaction-tokens-11#section-13.15
	RequestingWorkloadChain []string

	Audience  []string
	IssuedAt  time.Time
	ExpiresAt time.Time

	RequestContext     map[string]any
	TransactionContext map[string]any

	// Extra holds every claim not mapped to a named field. Unknown claims are retained but never acted on, per
	// draft-ietf-oauth-transaction-tokens-11 Section 9.2.
	Extra map[string]any
}

// FromRequest returns the Transaction Token from the Txn-Token header of the request. A request with no value, an
// empty value, or more than one value is refused, and the Authorization header is never consulted, per
// draft-ietf-oauth-transaction-tokens-11 Section 12.1.
func FromRequest(r *http.Request) (string, error) {
	values := r.Header.Values(HeaderName)

	switch len(values) {
	case 0:
		return "", ErrTokenAbsent
	case 1:
		if values[0] == "" {
			return "", ErrTokenAbsent
		}

		return values[0], nil
	default:
		return "", ErrMultipleTokens
	}
}

// Validate verifies a Transaction Token for a workload, per draft-ietf-oauth-transaction-tokens-11 Sections 9 and
// 12.2. It checks the signature, the 'typ' header, 'exp', 'iat' and 'nbf' subject to Config.ClockSkew, 'aud' against the
// Trust Domain, and the presence of 'iat', 'txn', 'sub', 'scope' and 'req_wl'. Every failure wraps ErrInvalidToken.
func Validate(token string, config Config) (*Claims, error) {
	if config.TrustDomain == "" {
		return nil, invalid(errors.New("the trust domain is not configured"))
	}

	if config.KeyFunc == nil {
		return nil, invalid(errors.New("the key function is not configured"))
	}

	algs := config.Algorithms
	if len(algs) == 0 {
		algs = DefaultAlgorithms()
	}

	var resolved bool

	keyfunc := func(t *jwt.Token) (any, error) {
		key, err := config.KeyFunc(t)

		resolved = err == nil && key != nil

		return key, err
	}

	parsed, err := jwt.ParseCustomWithClaims(token, jwt.MapClaims{}, keyfunc, algs...)

	switch {
	case err == nil:
		if !parsed.IsSignatureValid() {
			return nil, invalid(errors.New("the signature is not valid"))
		}
	case !resolved || !jwt.IsTimingValidationError(err):
		return nil, invalid(err)
	default:
		if err = parsed.Claims.Valid(jwt.ValidateClockSkew(config.ClockSkew)); err != nil {
			return nil, invalid(err)
		}
	}

	if typ, _ := parsed.Header[consts.JSONWebTokenHeaderType].(string); !oauth2.IsTxnTokenType(typ) {
		return nil, invalid(fmt.Errorf("the 'typ' header %q is not a transaction token", typ))
	}

	mc, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return nil, invalid(errors.New("the claims are not an object"))
	}

	return extract(mc, config.TrustDomain)
}

func extract(mc jwt.MapClaims, trustDomain string) (*Claims, error) {
	claims := &Claims{}

	exp, ok := numericDate(mc[consts.ClaimExpirationTime])
	if !ok {
		return nil, invalid(errors.New("the 'exp' claim is missing or not numeric"))
	}

	if !exp.After(jwt.TimeFunc()) {
		return nil, invalid(errors.New("the token is expired"))
	}

	claims.ExpiresAt = exp

	claims.Audience = audience(mc[consts.ClaimAudience])
	if !slices.Contains(claims.Audience, trustDomain) {
		return nil, invalid(errors.New("the 'aud' claim does not contain the trust domain"))
	}

	if claims.IssuedAt, ok = numericDate(mc[consts.ClaimIssuedAt]); !ok {
		return nil, invalid(errors.New("the 'iat' claim is missing or not numeric"))
	}

	for _, field := range []struct {
		name string
		dst  *string
	}{
		{consts.ClaimTransaction, &claims.Transaction},
		{consts.ClaimSubject, &claims.Subject},
		{consts.ClaimScope, &claims.Scope},
		{consts.ClaimRequestingWorkload, &claims.RequestingWorkload},
	} {
		if value, _ := mc[field.name].(string); value != "" {
			*field.dst = value
		} else {
			return nil, invalid(fmt.Errorf("the '%s' claim is missing or not a non-empty string", field.name))
		}
	}

	claims.Issuer, _ = mc[consts.ClaimIssuer].(string)

	var err error

	if claims.RequestingWorkloadChain, err = workloadChain(mc[consts.ClaimRequestingWorkloadChain]); err != nil {
		return nil, invalid(err)
	}

	if claims.RequestContext, err = object(mc, consts.ClaimRequestContext); err != nil {
		return nil, invalid(err)
	}

	if claims.TransactionContext, err = object(mc, consts.ClaimTransactionContext); err != nil {
		return nil, invalid(err)
	}

	claims.Extra = map[string]any{}

	for k, v := range mc {
		switch k {
		case consts.ClaimExpirationTime, consts.ClaimAudience, consts.ClaimIssuedAt, consts.ClaimTransaction,
			consts.ClaimSubject, consts.ClaimScope, consts.ClaimRequestingWorkload, consts.ClaimIssuer,
			consts.ClaimRequestContext, consts.ClaimTransactionContext, consts.ClaimRequestingWorkloadChain:
			continue
		}

		claims.Extra[k] = v
	}

	return claims, nil
}

func workloadChain(value any) (chain []string, err error) {
	if value == nil {
		return nil, nil
	}

	items, ok := value.([]any)
	if !ok {
		return nil, fmt.Errorf("the '%s' claim is not an array", consts.ClaimRequestingWorkloadChain)
	}

	for _, item := range items {
		workload, _ := item.(string)
		if workload == "" {
			return nil, fmt.Errorf("the '%s' claim has a value that is not a non-empty string", consts.ClaimRequestingWorkloadChain)
		}

		chain = append(chain, workload)
	}

	return chain, nil
}

func invalid(cause error) error {
	return fmt.Errorf("%w: %w", ErrInvalidToken, cause)
}

func numericDate(v any) (time.Time, bool) {
	switch n := v.(type) {
	case float64:
		return time.Unix(int64(n), 0).UTC(), true
	case int64:
		return time.Unix(n, 0).UTC(), true
	case json.Number:
		i, err := n.Int64()
		if err != nil {
			f, ferr := n.Float64()
			if ferr != nil {
				return time.Time{}, false
			}

			return time.Unix(int64(f), 0).UTC(), true
		}

		return time.Unix(i, 0).UTC(), true
	default:
		return time.Time{}, false
	}
}

func audience(v any) []string {
	switch aud := v.(type) {
	case string:
		return []string{aud}
	case []string:
		return aud
	case []any:
		out := make([]string, 0, len(aud))

		for _, item := range aud {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}

		return out
	default:
		return nil
	}
}

func object(mc jwt.MapClaims, name string) (map[string]any, error) {
	v, ok := mc[name]
	if !ok || v == nil {
		return nil, nil
	}

	m, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("the '%s' claim is not an object", name)
	}

	return m, nil
}
