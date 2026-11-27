// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package jwt

import (
	"crypto/subtle"
	"time"
)

// ClaimValidationOption configures ClaimValidationOptions.
type ClaimValidationOption func(opts *ClaimValidationOptions)

// ClaimValidationOptions holds the options used when validating claims.
type ClaimValidationOptions struct {
	timef          func() time.Time
	clockSkew      time.Duration
	maxLifetime    time.Duration
	iss            string
	aud            []string
	audAll         []string
	sub            string
	azp            string
	expRequired    bool
	expIgnored     bool
	iatRequired    bool
	nbfRequired    bool
	issNotRequired bool
	audNotRequired bool

	securityEventReceiver bool
}

// ValidateSecurityEventReceiver validates SecurityEventTokenClaims as the Receiver of the SET. A 'sub_id' format this
// package does not define is accepted at any depth (SSF 1.0 Figure 13), an additional Complex Subject member whose
// value is an object with a format counts as a member (SSF 1.0 §3.3), duplicate identifiers of an Aliases subject are
// accepted (RFC 9493 §3.2.8), and the deprecated RISC sessions-revoked event type is accepted (RISC 1.0 §2.11).
// Nothing else changes, and other claim types ignore the option.
func ValidateSecurityEventReceiver() ClaimValidationOption {
	return func(opts *ClaimValidationOptions) {
		opts.securityEventReceiver = true
	}
}

// ValidateTimeFunc sets the function used to obtain the current time, in place of TimeFunc.
func ValidateTimeFunc(timef func() time.Time) ClaimValidationOption {
	return func(opts *ClaimValidationOptions) {
		opts.timef = timef
	}
}

// ValidateClockSkew accepts an 'iat' or 'nbf' claim up to skew in the future. It does not apply to 'exp'. A negative
// skew is treated as zero.
//
// See: https://openid.net/specs/fapi-security-profile-2_0-final.html#section-5.3.2.1
func ValidateClockSkew(skew time.Duration) ClaimValidationOption {
	return func(opts *ClaimValidationOptions) {
		opts.clockSkew = max(skew, 0)
	}
}

// ValidateMaximumLifetime rejects an 'nbf' claim more than lifetime in the past, and an 'exp' claim more than lifetime
// after the 'nbf' claim. It does not require either claim. A zero or negative lifetime disables the check.
//
// See: https://openid.net/specs/fapi-message-signing-2_0-final.html#section-5.3.1
func ValidateMaximumLifetime(lifetime time.Duration) ClaimValidationOption {
	return func(opts *ClaimValidationOptions) {
		opts.maxLifetime = lifetime
	}
}

// ValidateIssuer requires the 'iss' claim to equal iss.
func ValidateIssuer(iss string) ClaimValidationOption {
	return func(opts *ClaimValidationOptions) {
		opts.iss = iss
	}
}

// ValidateAuthorizedParty requires the 'azp' claim to equal azp when the claim is present.
func ValidateAuthorizedParty(azp string) ClaimValidationOption {
	return func(opts *ClaimValidationOptions) {
		opts.azp = azp
	}
}

// ValidateDoNotRequireIssuer makes the 'iss' claim optional for ValidateIssuer.
func ValidateDoNotRequireIssuer() ClaimValidationOption {
	return func(opts *ClaimValidationOptions) {
		opts.issNotRequired = true
	}
}

// ValidateAudienceAny requires the 'aud' claim to contain at least one of the given values.
func ValidateAudienceAny(aud ...string) ClaimValidationOption {
	return func(opts *ClaimValidationOptions) {
		opts.aud = aud
	}
}

// ValidateAudienceAll requires the 'aud' claim to contain all of the given values.
func ValidateAudienceAll(aud ...string) ClaimValidationOption {
	return func(opts *ClaimValidationOptions) {
		opts.audAll = aud
	}
}

// ValidateDoNotRequireAudience makes the 'aud' claim optional for ValidateAudienceAny and ValidateAudienceAll.
func ValidateDoNotRequireAudience() ClaimValidationOption {
	return func(opts *ClaimValidationOptions) {
		opts.audNotRequired = true
	}
}

// ValidateSubject requires the 'sub' claim to equal sub.
func ValidateSubject(sub string) ClaimValidationOption {
	return func(opts *ClaimValidationOptions) {
		opts.sub = sub
	}
}

// ValidateRequireExpiresAt requires the 'exp' claim to be present.
func ValidateRequireExpiresAt() ClaimValidationOption {
	return func(opts *ClaimValidationOptions) {
		opts.expRequired = true
	}
}

// ValidateIgnoreExpiration skips the 'exp' claim check, permitting an expired token to validate, such as the
// 'id_token_hint' of an OpenID Connect RP-Initiated Logout request. 'iat' and 'nbf' are still enforced when present.
// This option takes precedence over ValidateRequireExpiresAt.
func ValidateIgnoreExpiration() ClaimValidationOption {
	return func(opts *ClaimValidationOptions) {
		opts.expIgnored = true
	}
}

// ValidateRequireIssuedAt requires the 'iat' claim to be present.
func ValidateRequireIssuedAt() ClaimValidationOption {
	return func(opts *ClaimValidationOptions) {
		opts.iatRequired = true
	}
}

// ValidateRequireNotBefore requires the 'nbf' claim to be present.
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

func validInt64Future(value, now int64, required bool) bool {
	if value == 0 {
		return !required
	}

	return now < value
}

func validInt64Past(value, now int64, required bool) bool {
	if value == 0 {
		return !required
	}

	return now >= value
}

// validLifetime ensures nbf is no more than lifetime before now, and exp is no more than lifetime after nbf.
func validLifetime(nbf, exp *NumericDate, now int64, lifetime time.Duration) bool {
	if lifetime <= 0 || nbf == nil {
		return true
	}

	seconds, n := uint64(lifetime/time.Second), nbf.Int64()

	if now > n && uint64(now)-uint64(n) > seconds { //nolint:gosec // G115: now > n, so the unsigned difference is exact.
		return false
	}

	if exp == nil {
		return true
	}

	e := exp.Int64()

	return e <= n || uint64(e)-uint64(n) <= seconds //nolint:gosec // G115: e > n, so the unsigned difference is exact.
}

func validString(value, cmp string, required bool) bool {
	if value == "" {
		return !required
	}

	return subtle.ConstantTimeCompare([]byte(value), []byte(cmp)) == 1
}

type validDateFunc func(value, now int64, required bool) bool

func validDate(valid validDateFunc, now int64, required bool, date *NumericDate, err error) bool {
	if err != nil || valid == nil {
		return false
	}

	if date == nil {
		return !required
	}

	if valid(date.Int64(), now, required) {
		return true
	}

	return false
}
