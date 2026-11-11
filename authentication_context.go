// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"slices"

	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/token/jwt"
)

// ApplyAuthenticationContext adds the 'auth_time', 'acr' and 'amr' claims of the End-User authentication recorded on the
// ID Token claims of session to claims, for a session which has them. A claim already present in claims is kept.
//
// See: https://www.rfc-editor.org/rfc/rfc9068#section-2.2.1 and https://www.rfc-editor.org/rfc/rfc9470#section-6
func ApplyAuthenticationContext(claims map[string]any, session Session) {
	if claims == nil {
		return
	}

	s, ok := session.(interface{ IDTokenClaims() *jwt.IDTokenClaims })
	if !ok {
		return
	}

	login := s.IDTokenClaims()
	if login == nil {
		return
	}

	if _, ok = claims[consts.ClaimAuthenticationTime]; !ok && login.AuthTime != nil && !login.AuthTime.IsZero() {
		claims[consts.ClaimAuthenticationTime] = login.AuthTime.Unix()
	}

	if _, ok = claims[consts.ClaimAuthenticationContextClassReference]; !ok && login.AuthenticationContextClassReference != "" {
		claims[consts.ClaimAuthenticationContextClassReference] = login.AuthenticationContextClassReference
	}

	if _, ok = claims[consts.ClaimAuthenticationMethodsReference]; !ok && len(login.AuthenticationMethodsReferences) != 0 {
		claims[consts.ClaimAuthenticationMethodsReference] = slices.Clone(login.AuthenticationMethodsReferences)
	}
}
