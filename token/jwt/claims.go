// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package jwt

import (
	"maps"
	"time"

	"authelia.com/provider/oauth2/internal/claimvalue"
)

// Claims is the set of registered claim accessors implemented by the claim types of this package.
type Claims interface {
	// GetExpirationTime returns the 'exp' claim (RFC 7519 Section 4.1.4).
	GetExpirationTime() (exp *NumericDate, err error)
	// GetIssuedAt returns the 'iat' claim (RFC 7519 Section 4.1.6).
	GetIssuedAt() (iat *NumericDate, err error)
	// GetNotBefore returns the 'nbf' claim (RFC 7519 Section 4.1.5).
	GetNotBefore() (nbf *NumericDate, err error)
	// GetIssuer returns the 'iss' claim (RFC 7519 Section 4.1.1).
	GetIssuer() (iss string, err error)
	// GetSubject returns the 'sub' claim (RFC 7519 Section 4.1.2).
	GetSubject() (sub string, err error)
	// GetAudience returns the 'aud' claim (RFC 7519 Section 4.1.3).
	GetAudience() (aud ClaimStrings, err error)
	// ToMapClaims returns the claims as MapClaims.
	ToMapClaims() MapClaims
	// Valid validates the claims, with the validation tuned by the opts.
	Valid(opts ...ClaimValidationOption) (err error)
}

// Mapper is the interface used internally to map key-value pairs.
type Mapper interface {
	// ToMap returns the key-value pairs as a map.
	ToMap() map[string]any
	// Add adds a key-value pair.
	Add(key string, value any)
	// Get returns the value of the key.
	Get(key string) any
}

// ToString will return a string representation of a map.
func ToString(i any) string {
	if i == nil {
		return ""
	}

	if s, ok := i.(string); ok {
		return s
	}

	if sl, ok := i.([]string); ok {
		if len(sl) == 1 {
			return sl[0]
		}
	}

	return ""
}

// ToTime will try to convert a given input to a [time.Time] structure.
func ToTime(i any) time.Time {
	if t, ok := i.(time.Time); ok {
		return t
	}

	t, _ := claimvalue.Time(i)

	return t
}

// Filter will filter out elements based on keys in a given input map na key-slice.
func Filter(elements map[string]any, keys ...string) map[string]any {
	result := Copy(elements)

	for _, key := range keys {
		delete(result, key)
	}

	return result
}

// Copy will copy all elements in a map and return a new representational map.
func Copy(elements map[string]any) (result map[string]any) {
	result = make(map[string]any, len(elements))

	maps.Copy(result, elements)

	return result
}

// StringSliceFromMap asserts a map any value to a []string provided it has a good type.
func StringSliceFromMap(value any) (values []string, ok bool) {
	return claimvalue.Slice[string](value)
}
