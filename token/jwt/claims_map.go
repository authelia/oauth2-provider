// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package jwt

import (
	"bytes"
	"crypto/subtle"
	"errors"
	"time"

	jjson "github.com/go-jose/go-jose/v4/json"

	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/x/errorsx"
)

var TimeFunc = time.Now

// MapClaims provides backwards compatible validations not available in `go-jose`.
// It was taken from [here](https://raw.githubusercontent.com/form3tech-oss/jwt-go/master/map_claims.go).
//
// Claims type that uses the map[string]any for JSON decoding
// This is the default claims type if you don't supply one
type MapClaims map[string]any

// GetIssuer returns the iss claim.
func (m MapClaims) GetIssuer() (iss string, ok bool) {
	var v any

	if v, ok = m[consts.ClaimIssuer]; !ok {
		return "", false
	}

	iss, ok = v.(string)

	return iss, ok
}

// VerifyIssuer compares the iss claim against cmp.
// If required is false, this method will return true if the value matches or is unset
func (m MapClaims) VerifyIssuer(cmp string, required bool) (ok bool) {
	var iss string

	if iss, ok = m.GetIssuer(); !ok {
		return !required
	}

	return verifyMapString(iss, cmp, required)
}

// GetSubject returns the sub claim.
func (m MapClaims) GetSubject() (sub string, ok bool) {
	var v any

	if v, ok = m[consts.ClaimSubject]; !ok {
		return "", false
	}

	sub, ok = v.(string)

	return sub, ok
}

// VerifySubject compares the iss claim against cmp.
// If required is false, this method will return true if the value matches or is unset
func (m MapClaims) VerifySubject(cmp string, required bool) (ok bool) {
	var sub string

	if sub, ok = m.GetSubject(); !ok {
		return !required
	}

	return verifyMapString(sub, cmp, required)
}

// GetAudience returns the aud claim.
func (m MapClaims) GetAudience() (aud []string, ok bool) {
	var v any

	if v, ok = m[consts.ClaimAudience]; !ok {
		return nil, false
	}

	return StringSliceFromMap(v)
}

// VerifyAudience compares the aud claim against cmp.
// If required is false, this method will return true if the value matches or is unset
func (m MapClaims) VerifyAudience(cmp string, required bool) (ok bool) {
	var aud []string

	if aud, ok = m.GetAudience(); !ok {
		return !required
	}

	return verifyAud(aud, cmp, required)
}

// VerifyAudienceAll compares the aud claim against cmp.
// If required is false, this method will return true if the value matches or is unset.
// This variant requires all of the audience values in the cmp.
func (m MapClaims) VerifyAudienceAll(cmp []string, required bool) (ok bool) {
	var aud []string

	if aud, ok = m.GetAudience(); !ok {
		return !required
	}

	return verifyAudAll(aud, cmp, required)
}

// VerifyAudienceAny compares the aud claim against cmp.
// If required is false, this method will return true if the value matches or is unset.
// This variant requires any of the audience values in the cmp.
func (m MapClaims) VerifyAudienceAny(cmp []string, required bool) (ok bool) {
	var aud []string

	if aud, ok = m.GetAudience(); !ok {
		return !required
	}

	return verifyAudAny(aud, cmp, required)
}

// GetExpiresAt returns the exp claim.
func (m MapClaims) GetExpiresAt() (exp int64, ok bool) {
	return m.toInt64(consts.ClaimExpirationTime)
}

// VerifyExpiresAt compares the exp claim against cmp.
// If required is false, this method will return true if the value matches or is unset
func (m MapClaims) VerifyExpiresAt(cmp int64, required bool) (ok bool) {
	var exp int64

	if exp, ok = m.GetExpiresAt(); !ok {
		return !required
	}

	return verifyInt64Future(exp, cmp, required)
}

// GetIssuedAt returns the iat claim.
func (m MapClaims) GetIssuedAt() (iat int64, ok bool) {
	return m.toInt64(consts.ClaimIssuedAt)
}

// VerifyIssuedAt compares the iat claim against cmp.
// If required is false, this method will return true if the value matches or is unset
func (m MapClaims) VerifyIssuedAt(cmp int64, required bool) (ok bool) {
	var iat int64

	if iat, ok = m.GetIssuedAt(); !ok {
		return !required
	}

	return verifyInt64Past(iat, cmp, required)
}

// GetNotBefore returns the nbf claim.
func (m MapClaims) GetNotBefore() (nbf int64, ok bool) {
	return m.toInt64(consts.ClaimNotBefore)
}

// VerifyNotBefore compares the nbf claim against cmp.
// If required is false, this method will return true if the value matches or is unset
func (m MapClaims) VerifyNotBefore(cmp int64, required bool) (ok bool) {
	var nbf int64

	if nbf, ok = m.GetNotBefore(); !ok {
		return !required
	}

	return verifyInt64Past(nbf, cmp, required)
}

// Valid validates the given claims. By default it only validates time based claims "exp, iat, nbf"; there is no
// accounting for clock skew, and if any of the above claims are not in the token, the claims will still be considered
// valid. However all of these options can be tuned by the opts.
func (m MapClaims) Valid(opts ...ClaimValidationOption) (err error) {
	vopts := &ClaimValidationOptions{}

	for _, opt := range opts {
		opt(vopts)
	}

	var now int64

	if vopts.timef != nil {
		now = vopts.timef().UTC().Unix()
	} else {
		now = TimeFunc().UTC().Unix()
	}

	vErr := new(ValidationError)

	if !m.VerifyExpiresAt(now, vopts.expRequired) {
		vErr.Inner = errors.New("Token is expired")
		vErr.Errors |= ValidationErrorExpired
	}

	if !m.VerifyIssuedAt(now, vopts.iatRequired) {
		vErr.Inner = errors.New("Token used before issued")
		vErr.Errors |= ValidationErrorIssuedAt
	}

	if !m.VerifyNotBefore(now, vopts.nbfRequired) {
		vErr.Inner = errors.New("Token is not valid yet")
		vErr.Errors |= ValidationErrorNotValidYet
	}

	if len(vopts.iss) != 0 {
		if !m.VerifyIssuer(vopts.iss, true) {
			vErr.Inner = errors.New("Token has invalid issuer")
			vErr.Errors |= ValidationErrorIssuer
		}
	}

	if len(vopts.sub) != 0 {
		if !m.VerifySubject(vopts.sub, true) {
			vErr.Inner = errors.New("Token has invalid subject")
			vErr.Errors |= ValidationErrorSubject
		}
	}

	if len(vopts.aud) != 0 {
		if !m.VerifyAudienceAny(vopts.aud, true) {
			vErr.Inner = errors.New("Token has invalid audience")
			vErr.Errors |= ValidationErrorAudience
		}
	}

	if len(vopts.audAll) != 0 {
		if !m.VerifyAudienceAll(vopts.audAll, true) {
			vErr.Inner = errors.New("Token has invalid audience")
			vErr.Errors |= ValidationErrorAudience
		}
	}

	if vErr.valid() {
		return nil
	}

	return vErr
}

func (m MapClaims) UnmarshalJSON(data []byte) error {
	decoder := jjson.NewDecoder(bytes.NewReader(data))
	decoder.SetNumberType(jjson.UnmarshalIntOrFloat)

	mp := map[string]any(m)

	if err := decoder.Decode(&mp); err != nil {
		return errorsx.WithStack(err)
	}

	return nil
}

func (m MapClaims) toInt64(claim string) (val int64, ok bool) {
	var v any

	if v, ok = m[claim]; !ok {
		return 0, false
	}

	return toInt64(v)
}

type ClaimValidationOption func(opts *ClaimValidationOptions)

type ClaimValidationOptions struct {
	timef       func() time.Time
	iss         string
	aud         []string
	audAll      []string
	sub         string
	expRequired bool
	iatRequired bool
	nbfRequired bool
}

func ValidateTimeFunc(timef func() time.Time) ClaimValidationOption {
	return func(opts *ClaimValidationOptions) {
		opts.timef = timef
	}
}

func ValidateIssuer(iss string) ClaimValidationOption {
	return func(opts *ClaimValidationOptions) {
		opts.iss = iss
	}
}

func ValidateAudienceAny(aud ...string) ClaimValidationOption {
	return func(opts *ClaimValidationOptions) {
		opts.aud = aud
	}
}

func ValidateAudienceAll(aud ...string) ClaimValidationOption {
	return func(opts *ClaimValidationOptions) {
		opts.audAll = aud
	}
}

func ValidateSubject(sub string) ClaimValidationOption {
	return func(opts *ClaimValidationOptions) {
		opts.sub = sub
	}
}

func ValidateRequireExpiresAt() ClaimValidationOption {
	return func(opts *ClaimValidationOptions) {
		opts.expRequired = true
	}
}

func ValidateRequireIssuedAt() ClaimValidationOption {
	return func(opts *ClaimValidationOptions) {
		opts.iatRequired = true
	}
}

func ValidateRequireNotBefore() ClaimValidationOption {
	return func(opts *ClaimValidationOptions) {
		opts.nbfRequired = true
	}
}

func verifyAud(aud []string, cmp string, required bool) bool {
	if len(aud) == 0 {
		return !required
	}

	for _, a := range aud {
		if subtle.ConstantTimeCompare([]byte(a), []byte(cmp)) == 1 {
			return true
		}
	}

	return false
}

func verifyAudAny(aud []string, cmp []string, required bool) bool {
	if len(aud) == 0 {
		return !required
	}

	for _, c := range cmp {
		for _, a := range aud {
			if subtle.ConstantTimeCompare([]byte(a), []byte(c)) == 1 {
				return true
			}
		}
	}

	return false
}

func verifyAudAll(aud []string, cmp []string, required bool) bool {
	if len(aud) == 0 {
		return !required
	}

outer:
	for _, c := range cmp {
		for _, a := range aud {
			if subtle.ConstantTimeCompare([]byte(a), []byte(c)) == 1 {
				continue outer
			}
		}

		return false
	}

	return true
}

// verifyInt64Future ensures the given value is in the future.
func verifyInt64Future(value, now int64, required bool) bool {
	if value == 0 {
		return !required
	}

	return now <= value
}

// verifyInt64Past ensures the given value is in the past or the current value.
func verifyInt64Past(value, now int64, required bool) bool {
	if value == 0 {
		return !required
	}

	return now >= value
}

func verifyMapString(value, cmp string, required bool) bool {
	if value == "" {
		return !required
	}

	return subtle.ConstantTimeCompare([]byte(value), []byte(cmp)) == 1
}
