// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

// Package clone deep copies the JSON-shaped values held by sessions and claims.
package clone

import (
	"slices"
)

// Map returns a deep copy of m, or nil if m is nil.
func Map(m map[string]any) map[string]any {
	if m == nil {
		return nil
	}

	cloned := make(map[string]any, len(m))

	for k, v := range m {
		cloned[k] = Value(v)
	}

	return cloned
}

// Slice returns a deep copy of s, or nil if s is nil.
func Slice(s []any) []any {
	if s == nil {
		return nil
	}

	cloned := make([]any, len(s))

	for i, v := range s {
		cloned[i] = Value(v)
	}

	return cloned
}

// Value returns a deep copy of v when it is a map[string]any, []any, or []string. Any other value is returned as is,
// which is a copy for the scalar types JSON decodes to.
func Value(v any) any {
	switch value := v.(type) {
	case map[string]any:
		return Map(value)
	case []any:
		return Slice(value)
	case []string:
		return slices.Clone(value)
	default:
		return v
	}
}
