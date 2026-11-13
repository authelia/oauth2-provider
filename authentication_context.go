// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"slices"

	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/token/jwt"
)

// AuthenticationContextSession is a Session which records the authentication context claims the authorization request
// required, so every access token derived from the authorization response conveys them: 'acr' when it carried
// 'acr_values', and 'auth_time' when it carried 'max_age'.
//
// See: https://www.rfc-editor.org/rfc/rfc9470#section-5 and https://www.rfc-editor.org/rfc/rfc9068#section-2.2.1
type AuthenticationContextSession interface {
	// SetRequestedAuthenticationContextClaims records the authentication context claims the authorization request
	// required.
	SetRequestedAuthenticationContextClaims(claims []string)

	// GetRequestedAuthenticationContextClaims returns the authentication context claims the authorization request
	// required.
	GetRequestedAuthenticationContextClaims() (claims []string)
}

// AuthenticationContextClaimsClient is a client which receives the 'auth_time', 'acr' and 'amr' claims it lists
// whether or not the authorization request required them. They are conveyed in the JWT access tokens issued to the
// client, and in the introspection responses sent to it.
//
// See: https://www.rfc-editor.org/rfc/rfc9068#section-2.2.1 and https://www.rfc-editor.org/rfc/rfc9470#section-6
type AuthenticationContextClaimsClient interface {
	// GetAuthenticationContextClaims returns the authentication context claims conveyed to this client.
	GetAuthenticationContextClaims() (claims []string)

	Client
}

// RecordAuthenticationContextRequirements records on session the authentication context claims the 'acr_values' and
// 'max_age' parameters of request require access tokens to convey, replacing any recorded before.
//
// See: https://www.rfc-editor.org/rfc/rfc9470#section-5
func RecordAuthenticationContextRequirements(request Requester, session Session) {
	target, ok := session.(AuthenticationContextSession)
	if !ok || request == nil {
		return
	}

	var claims []string

	form := request.GetRequestForm()

	if form.Get(consts.FormParameterAuthenticationContextClassReferenceValues) != "" {
		claims = append(claims, consts.ClaimAuthenticationContextClassReference)
	}

	if form.Has(consts.FormParameterMaximumAge) {
		claims = append(claims, consts.ClaimAuthenticationTime)
	}

	target.SetRequestedAuthenticationContextClaims(claims)
}

// GetRequestedAuthenticationContextClaims returns the authentication context claims recorded on session by
// RecordAuthenticationContextRequirements, or nil for a session which does not record them.
func GetRequestedAuthenticationContextClaims(session Session) (claims []string) {
	if s, ok := session.(AuthenticationContextSession); ok {
		return s.GetRequestedAuthenticationContextClaims()
	}

	return nil
}

// ApplyAuthenticationContext adds the 'auth_time', 'acr' and 'amr' claims of the End-User authentication recorded on the
// ID Token claims of session to claims. A claim is added only when the authorization request required it, or when
// recipient is an AuthenticationContextClaimsClient which lists it. A claim already present in claims is kept.
//
// The recipient is the client a JWT access token is issued to, or the client which called the introspection endpoint.
//
// See: https://www.rfc-editor.org/rfc/rfc9068#section-2.2.1, https://www.rfc-editor.org/rfc/rfc9068#section-6 and
// https://www.rfc-editor.org/rfc/rfc9470#section-6
func ApplyAuthenticationContext(claims map[string]any, session Session, recipient Client) {
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

	conveyed := GetRequestedAuthenticationContextClaims(session)

	if client, ok := recipient.(AuthenticationContextClaimsClient); ok {
		conveyed = append(slices.Clone(conveyed), client.GetAuthenticationContextClaims()...)
	}

	if len(conveyed) == 0 {
		return
	}

	if isAuthenticationContextClaimConveyed(claims, conveyed, consts.ClaimAuthenticationTime) && login.AuthTime != nil && !login.AuthTime.IsZero() {
		claims[consts.ClaimAuthenticationTime] = login.AuthTime.Unix()
	}

	if isAuthenticationContextClaimConveyed(claims, conveyed, consts.ClaimAuthenticationContextClassReference) && login.AuthenticationContextClassReference != "" {
		claims[consts.ClaimAuthenticationContextClassReference] = login.AuthenticationContextClassReference
	}

	if isAuthenticationContextClaimConveyed(claims, conveyed, consts.ClaimAuthenticationMethodsReference) && len(login.AuthenticationMethodsReferences) != 0 {
		claims[consts.ClaimAuthenticationMethodsReference] = slices.Clone(login.AuthenticationMethodsReferences)
	}
}

func isAuthenticationContextClaimConveyed(claims map[string]any, conveyed []string, claim string) bool {
	if _, ok := claims[claim]; ok {
		return false
	}

	return slices.Contains(conveyed, claim)
}
