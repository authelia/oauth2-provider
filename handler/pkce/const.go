// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package pkce

import "regexp"

var (
	verifierWrongFormat = regexp.MustCompile(`[^\w.~-]`)
)
