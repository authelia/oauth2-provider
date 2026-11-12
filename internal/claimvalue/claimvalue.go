// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

// Package claimvalue converts the values of decoded JSON claims to Go types.
package claimvalue

import (
	"encoding/json"
	"time"
)

// Slice returns value as a []T. A nil value is a nil slice, a single T is a slice of one element, and every element of
// a []any must be a T.
func Slice[T any](value any) (values []T, ok bool) {
	switch v := value.(type) {
	case nil:
		return nil, true
	case []T:
		return v, true
	case []any:
		for _, item := range v {
			var t T

			if t, ok = item.(T); !ok {
				return nil, false
			}

			values = append(values, t)
		}

		return values, true
	case T:
		return []T{v}, true
	default:
		return nil, false
	}
}

// Number returns value as a T. A JSON number decodes to a float64 or a json.Number, and a claim set in process may hold
// any Go integer or floating point type. Converting a fractional value to int64 truncates it.
//
//nolint:gocyclo
func Number[T int64 | float64](value any) (number T, ok bool) {
	switch n := value.(type) {
	case float64:
		return T(n), true
	case float32:
		return T(n), true
	case int:
		return T(n), true
	case int8:
		return T(n), true
	case int16:
		return T(n), true
	case int32:
		return T(n), true
	case int64:
		return T(n), true
	case uint:
		return T(n), true
	case uint8:
		return T(n), true
	case uint16:
		return T(n), true
	case uint32:
		return T(n), true
	case uint64:
		return T(n), true
	case uintptr:
		return T(n), true
	case json.Number:
		if i, err := n.Int64(); err == nil {
			return T(i), true
		}

		f, err := n.Float64()
		if err != nil {
			return 0, false
		}

		return T(f), true
	default:
		return 0, false
	}
}

// Time returns value as the UTC time of a NumericDate, the whole seconds since the epoch.
//
// See: https://www.rfc-editor.org/rfc/rfc7519#section-2
func Time(value any) (t time.Time, ok bool) {
	var seconds int64

	if seconds, ok = Number[int64](value); !ok {
		return time.Time{}, false
	}

	return time.Unix(seconds, 0).UTC(), true
}
