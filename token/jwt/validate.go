package jwt

import (
	"crypto/subtle"
	"time"
)

type ClaimValidationOption func(opts *ClaimValidationOptions)

type ClaimValidationOptions struct {
	timef          func() time.Time
	iss            string
	aud            []string
	audAll         []string
	sub            string
	expRequired    bool
	iatRequired    bool
	nbfRequired    bool
	issNotRequired bool
	audNotRequired bool
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

func ValidateDoNotRequireIssuer() ClaimValidationOption {
	return func(opts *ClaimValidationOptions) {
		opts.issNotRequired = true
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

func ValidateDoNotRequireAudience() ClaimValidationOption {
	return func(opts *ClaimValidationOptions) {
		opts.audNotRequired = true
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

// validInt64Future ensures the given value is in the future.
func validInt64Future(value, now int64, required bool) bool {
	if value == 0 {
		return !required
	}

	return now <= value
}

// validInt64Past ensures the given value is in the past or the current value.
func validInt64Past(value, now int64, required bool) bool {
	if value == 0 {
		return !required
	}

	return now >= value
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
