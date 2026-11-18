// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

// Package asc evaluates OpenID Connect Advanced Syntax for Claims 1.0: the Transformed Claims and the Selective
// Abort/Omit rules of the 'claims' request parameter.
//
// An integrator which enables it must:
//   - set oauth2.ClaimsASC.Evaluator, for example NewEvaluator;
//   - call openid.EvaluateUserInfoClaims when building the UserInfo response, otherwise the rules and Transformed
//     Claims of the 'userinfo' delivery are not applied;
//   - persist Request.Claims in storage, including '_asc' and the nested claim requests;
//   - keep the session claims and source claims to what the End-User consented to release, as an abort or an omission
//     reveals information (ASC Section 7.4 and 8.7);
//   - check oauth2.ClaimsRequest.HasSelectiveAbortOmit before filtering released claims with
//     oauth2.ClaimRequest.Matches (ASC Section 7.2.1).
//
// The metadata of the enabled components is published by the NewOpenIDConnectProviderMetadata method of the provider.
//
// See: https://openid.net/specs/openid-connect-advanced-syntax-for-claims-1_0.html
package asc

import (
	"strconv"
	"strings"
)

// See: https://www.rfc-editor.org/rfc/rfc6901#section-4
func parsePointer(pointer string) (tokens []string, ok bool) {
	if pointer == "" {
		return nil, true
	}

	if pointer[0] != '/' {
		return nil, false
	}

	tokens = strings.Split(pointer[1:], "/")

	for i, token := range tokens {
		tokens[i] = strings.ReplaceAll(strings.ReplaceAll(token, "~1", "/"), "~0", "~")
	}

	return tokens, true
}

type omitted struct{}

func resolve(document any, tokens []string) (value any, ok bool) {
	value = document

	for _, token := range tokens {
		switch node := value.(type) {
		case map[string]any:
			if value, ok = node[token]; !ok {
				return nil, false
			}
		case []any:
			index, ok := arrayIndex(token, len(node))
			if !ok {
				return nil, false
			}

			if value = node[index]; value == (omitted{}) {
				return nil, false
			}
		default:
			return nil, false
		}
	}

	return value, true
}

func omit(document any, tokens []string) {
	if len(tokens) == 0 {
		return
	}

	parent, ok := resolve(document, tokens[:len(tokens)-1])
	if !ok {
		return
	}

	token := tokens[len(tokens)-1]

	switch node := parent.(type) {
	case map[string]any:
		delete(node, token)
	case []any:
		if index, ok := arrayIndex(token, len(node)); ok {
			node[index] = omitted{}
		}
	}
}

func compact(value any) any {
	switch node := value.(type) {
	case map[string]any:
		kept := make(map[string]any, len(node))

		for name, member := range node {
			kept[name] = compact(member)
		}

		return kept
	case []any:
		kept := make([]any, 0, len(node))

		for _, item := range node {
			if _, gone := item.(omitted); !gone {
				kept = append(kept, compact(item))
			}
		}

		return kept
	default:
		return value
	}
}

func arrayIndex(token string, length int) (index int, ok bool) {
	if token == "" || (len(token) > 1 && token[0] == '0') {
		return 0, false
	}

	for _, r := range token {
		if r < '0' || r > '9' {
			return 0, false
		}
	}

	index, err := strconv.Atoi(token)
	if err != nil || index >= length {
		return 0, false
	}

	return index, true
}
