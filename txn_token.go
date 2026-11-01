// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"strings"

	"authelia.com/provider/oauth2/internal/consts"
)

// IsTxnTokenType returns true when typ is the JOSE 'typ' header value of a Transaction Token, compared
// case-insensitively with or without the 'application/' prefix per RFC 8725 Section 3.11.
//
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-transaction-tokens-11#section-9.1
func IsTxnTokenType(typ string) bool {
	return strings.EqualFold(typ, consts.JSONWebTokenTypeTxnToken) || strings.EqualFold(typ, "application/"+consts.JSONWebTokenTypeTxnToken)
}
