// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package jwt

import (
	"time"
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
	if i == nil {
		return time.Time{}
	}

	if t, ok := i.(int64); ok {
		return time.Unix(t, 0).UTC()
	} else if t, ok := i.(float64); ok {
		return time.Unix(int64(t), 0).UTC()
	} else if t, ok := i.(time.Time); ok {
		return t
	}

	return time.Time{}
}

// Filter will filter out elements based on keys in a given input map na key-slice
func Filter(elements map[string]any, keys ...string) map[string]any {
	var keyIdx = make(map[string]bool)
	var result = make(map[string]any)

	for _, key := range keys {
		keyIdx[key] = true
	}

	for k, e := range elements {
		if _, ok := keyIdx[k]; !ok {
			result[k] = e
		}
	}

	return result
}

// Copy will copy all elements in a map and return a new representational map
func Copy(elements map[string]any) (result map[string]any) {
	result = make(map[string]any, len(elements))
	for k, v := range elements {
		result[k] = v
	}

	return result
}

// StringSliceFromMap asserts a map any value to a []string provided it has a good type.
func StringSliceFromMap(value any) (values []string, ok bool) {
	switch v := value.(type) {
	case nil:
		return nil, true
	case []string:
		return v, true
	case string:
		return []string{v}, true
	case []any:
		for _, item := range v {
			switch iv := item.(type) {
			case string:
				values = append(values, iv)
			default:
				return nil, false
			}
		}

		return values, true
	default:
		return nil, false
	}
}
