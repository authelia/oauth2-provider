// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package jwt

import (
	"maps"
	"time"

	"authelia.com/provider/oauth2/internal/claimvalue"
)

type Claims interface {
	GetExpirationTime() (exp *NumericDate, err error)
	GetIssuedAt() (iat *NumericDate, err error)
	GetNotBefore() (nbf *NumericDate, err error)
	GetIssuer() (iss string, err error)
	GetSubject() (sub string, err error)
	GetAudience() (aud ClaimStrings, err error)
	ToMapClaims() MapClaims
	Valid(opts ...ClaimValidationOption) (err error)
}

// Mapper is the interface used internally to map key-value pairs
type Mapper interface {
	ToMap() map[string]any
	Add(key string, value any)
	Get(key string) any
}

// ToString will return a string representation of a map
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

// ToTime will try to convert a given input to a time.Time structure
func ToTime(i any) time.Time {
	if t, ok := i.(time.Time); ok {
		return t
	}

	t, _ := claimvalue.Time(i)

	return t
}

// Filter will filter out elements based on keys in a given input map na key-slice
func Filter(elements map[string]any, keys ...string) map[string]any {
	result := Copy(elements)

	for _, key := range keys {
		delete(result, key)
	}

	return result
}

// Copy will copy all elements in a map and return a new representational map
func Copy(elements map[string]any) (result map[string]any) {
	result = make(map[string]any, len(elements))

	maps.Copy(result, elements)

	return result
}

// StringSliceFromMap asserts a map any value to a []string provided it has a good type.
func StringSliceFromMap(value any) (values []string, ok bool) {
	return claimvalue.Slice[string](value)
}
