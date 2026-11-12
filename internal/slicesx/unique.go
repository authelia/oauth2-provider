// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

// Package slicesx holds slice functions the standard library slices package lacks.
package slicesx

// Unique returns the distinct elements of s in the order they first appear.
func Unique[S ~[]E, E comparable](s S) S {
	u := make(S, 0, len(s))
	seen := make(map[E]struct{}, len(s))

	for _, v := range s {
		if _, ok := seen[v]; ok {
			continue
		}

		seen[v] = struct{}{}

		u = append(u, v)
	}

	return u
}
