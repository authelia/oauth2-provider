// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package jwt

import (
	"bytes"
	"crypto/subtle"
	"errors"
	"fmt"
	"time"

	jjson "github.com/go-jose/go-jose/v4/json"

	"authelia.com/provider/oauth2/x/errorsx"
)

// MapClaims is a simple map based claims structure.
type MapClaims map[string]any

// GetIssuer returns the 'iss' claim.
func (m MapClaims) GetIssuer() (iss string, err error) {
	return m.toString(ClaimIssuer)
}

// VerifyIssuer compares the iss claim against cmp.
// If required is false, this method will return true if the value matches or is unset
func (m MapClaims) VerifyIssuer(cmp string, required bool) (ok bool) {
	var (
		iss string
		err error
	)

	if iss, err = m.GetIssuer(); err != nil {
		return false
	}

	if iss == "" {
		return !required
	}

	return verifyString(iss, cmp, required)
}

// GetSubject returns the 'sub' claim.
func (m MapClaims) GetSubject() (sub string, err error) {
	return m.toString(ClaimSubject)
}

// VerifySubject compares the iss claim against cmp.
// If required is false, this method will return true if the value matches or is unset
func (m MapClaims) VerifySubject(cmp string, required bool) (ok bool) {
	var (
		sub string
		err error
	)

	if sub, err = m.GetSubject(); err != nil {
		return false
	}

	if sub == "" {
		return !required
	}

	return verifyString(sub, cmp, required)
}

// GetAudience returns the 'aud' claim.
func (m MapClaims) GetAudience() (aud ClaimStrings, err error) {
	return m.toClaimsString(ClaimAudience)
}

// VerifyAudience compares the aud claim against cmp.
// If required is false, this method will return true if the value matches or is unset
func (m MapClaims) VerifyAudience(cmp string, required bool) (ok bool) {
	var (
		aud ClaimStrings
		err error
	)

	if aud, err = m.GetAudience(); err != nil {
		return false
	}

	if aud == nil {
		return !required
	}

	return verifyAud(aud, cmp, required)
}

// VerifyAudienceAll compares the aud claim against cmp.
// If required is false, this method will return true if the value matches or is unset.
// This variant requires all of the audience values in the cmp.
func (m MapClaims) VerifyAudienceAll(cmp []string, required bool) (ok bool) {
	var (
		aud ClaimStrings
		err error
	)

	if aud, err = m.GetAudience(); err != nil {
		return false
	}

	if aud == nil {
		return !required
	}

	return verifyAudAll(aud, cmp, required)
}

// VerifyAudienceAny compares the aud claim against cmp.
// If required is false, this method will return true if the value matches or is unset.
// This variant requires any of the audience values in the cmp.
func (m MapClaims) VerifyAudienceAny(cmp []string, required bool) (ok bool) {
	var (
		aud ClaimStrings
		err error
	)

	if aud, err = m.GetAudience(); err != nil {
		return false
	}

	if aud == nil {
		return !required
	}

	return verifyAudAny(aud, cmp, required)
}

// GetExpirationTime returns the 'exp' claim.
func (m MapClaims) GetExpirationTime() (exp *NumericDate, err error) {
	return m.toNumericDate(ClaimExpirationTime)
}

// VerifyExpirationTime compares the exp claim against cmp.
// If required is false, this method will return true if the value matches or is unset
func (m MapClaims) VerifyExpirationTime(cmp int64, required bool) (ok bool) {
	var (
		exp *NumericDate
		err error
	)

	if exp, err = m.GetExpirationTime(); err != nil {
		return false
	}

	if exp == nil {
		return !required
	}

	return verifyInt64Future(exp.Int64(), cmp, required)
}

// GetIssuedAt returns the 'iat' claim.
func (m MapClaims) GetIssuedAt() (iat *NumericDate, err error) {
	return m.toNumericDate(ClaimIssuedAt)
}

// VerifyIssuedAt compares the iat claim against cmp.
// If required is false, this method will return true if the value matches or is unset
func (m MapClaims) VerifyIssuedAt(cmp int64, required bool) (ok bool) {
	var (
		iat *NumericDate
		err error
	)

	if iat, err = m.GetIssuedAt(); err != nil {
		return false
	}

	if iat == nil {
		return !required
	}

	return verifyInt64Past(iat.Int64(), cmp, required)
}

// GetNotBefore returns the 'nbf' claim.
func (m MapClaims) GetNotBefore() (nbf *NumericDate, err error) {
	return m.toNumericDate(ClaimNotBefore)
}

// VerifyNotBefore compares the nbf claim against cmp.
// If required is false, this method will return true if the value matches or is unset
func (m MapClaims) VerifyNotBefore(cmp int64, required bool) (ok bool) {
	var (
		nbf *NumericDate
		err error
	)

	if nbf, err = m.GetNotBefore(); err != nil {
		return false
	}

	if nbf == nil {
		return !required
	}

	return verifyInt64Past(nbf.Int64(), cmp, required)
}

func (m MapClaims) ToMapClaims() MapClaims {
	if m == nil {
		return nil
	}

	return m
}

func (m MapClaims) ToMap() map[string]any {
	return m
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

	if !m.VerifyExpirationTime(now, vopts.expRequired) {
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

func (m MapClaims) toNumericDate(key string) (date *NumericDate, err error) {
	var (
		v  any
		ok bool
	)

	if v, ok = m[key]; !ok {
		return nil, nil
	}

	return toNumericDate(v)
}

func (m MapClaims) toString(key string) (value string, err error) {
	var (
		ok  bool
		raw any
	)

	if raw, ok = m[key]; !ok {
		return "", nil
	}

	if value, ok = raw.(string); !ok {
		return "", newError(fmt.Sprintf("%s is invalid", key), ErrInvalidType)
	}

	return value, nil
}

func (m MapClaims) toClaimsString(key string) (ClaimStrings, error) {
	var cs []string

	switch v := m[key].(type) {
	case string:
		cs = append(cs, v)
	case []string:
		cs = v
	case []any:
		for _, a := range v {
			if vs, ok := a.(string); !ok {
				return nil, newError(fmt.Sprintf("%s is invalid", key), ErrInvalidType)
			} else {
				cs = append(cs, vs)
			}
		}
	case nil:
		return nil, nil
	default:
		return cs, newError(fmt.Sprintf("%s is invalid", key), ErrInvalidType)
	}

	return cs, nil
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

func verifyString(value, cmp string, required bool) bool {
	if value == "" {
		return !required
	}

	return subtle.ConstantTimeCompare([]byte(value), []byte(cmp)) == 1
}
