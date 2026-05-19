// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package stringslice

func Merge(parts ...[]string) []string {
	var result []string
	for _, part := range parts {
		result = append(result, part...)
	}

	return result
}
