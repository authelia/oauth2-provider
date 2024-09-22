// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package jwt

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
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
	return StringSliceFromMap(m[consts.ClaimAudience])
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

	return verifyExp(exp, cmp, required)
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
		now = vopts.timef().Unix()
	} else {
		now = TimeFunc().Unix()
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

func (m MapClaims) UnmarshalJSON(b []byte) error {
	// This custom unmarshal allows to configure the
	// go-jose decoding settings since there is no other way
	// see https://github.com/square/go-jose/issues/353.
	// If issue is closed with a better solution
	// this custom Unmarshal method can be removed
	d := jjson.NewDecoder(bytes.NewReader(b))
	mp := map[string]any(m)
	d.SetNumberType(jjson.UnmarshalIntOrFloat)
	if err := d.Decode(&mp); err != nil {
		return errorsx.WithStack(err)
	}

	return nil
}

func (m MapClaims) toInt64(claim string) (val int64, ok bool) {
	var err error

	switch t := m[claim].(type) {
	case float64:
		return int64(t), true
	case int64:
		return t, true
	case json.Number:
		if val, err = t.Int64(); err == nil {
			return val, true
		}

		var valf float64

		if valf, err = t.Float64(); err != nil {
			return 0, false
		}

		return int64(valf), true
	}

	return 0, false
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

func verifyExp(exp int64, now int64, required bool) bool {
	if exp == 0 {
		return !required
	}

	return now <= exp
}

func verifyInt64Past(iat int64, now int64, required bool) bool {
	if iat == 0 {
		return !required
	}

	return now >= iat
}

func verifyMapString(iss string, cmp string, required bool) bool {
	if iss == "" {
		return !required
	}

	return subtle.ConstantTimeCompare([]byte(iss), []byte(cmp)) == 1
}
