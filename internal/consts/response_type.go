// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package consts

// Response Type strings.
const (
	ResponseTypeAuthorizationCodeFlow = valueCode
	ResponseTypeImplicitFlowIDToken   = valueIDToken
	ResponseTypeImplicitFlowToken     = "token"
	ResponseTypeImplicitFlowBoth      = "id_token token"
	ResponseTypeHybridFlowIDToken     = "code id_token"
	ResponseTypeHybridFlowToken       = "code token"
	ResponseTypeHybridFlowBoth        = "code id_token token"
	ResponseTypeNone                  = valueNone
)
