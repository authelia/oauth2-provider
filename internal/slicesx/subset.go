// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package slicesx

import (
	"slices"
)

// Subset returns true if every element of sub is in super. An empty sub is a subset of any super.
func Subset[E comparable](super, sub []E) bool {
	for _, v := range sub {
		if !slices.Contains(super, v) {
			return false
		}
	}

	return true
}
