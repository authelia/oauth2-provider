// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc8693

import (
	"authelia.com/provider/oauth2/handler/openid"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/token/jwt"
)

// Session is required to support token exchange
type Session interface {
	// SetSubject sets the session's subject.
	SetSubject(subject string)

	SetActorToken(token map[string]any)

	GetActorToken() map[string]any

	SetSubjectToken(token map[string]any)

	GetSubjectToken() map[string]any

	SetClaimActor(act map[string]any)

	AccessTokenClaimsMap() map[string]any
}

type DefaultSession struct {
	*openid.DefaultSession

	ActorToken   map[string]any `json:"-"`
	SubjectToken map[string]any `json:"-"`
	Extra        map[string]any `json:"extra,omitempty"`
}

func (s *DefaultSession) SetActorToken(token map[string]any) {
	s.ActorToken = token
}

func (s *DefaultSession) GetActorToken() map[string]any {
	return s.ActorToken
}

func (s *DefaultSession) SetSubjectToken(token map[string]any) {
	s.SubjectToken = token
}

func (s *DefaultSession) GetSubjectToken() map[string]any {
	return s.SubjectToken
}

// SetClaimActor records the RFC 8693 §4.1 'act' claim describing the actor in a delegation flow.
//
// The claim is written to two places so it propagates through both opaque and JWT token issuance paths:
//
//   - s.Extra — surfaces in DefaultSession.AccessTokenClaimsMap and therefore in introspection responses for
//     opaque access tokens stored verbatim.
//   - s.DefaultSession.Claims.Extra — flattened into the JWT body by jwt.IDTokenClaims.ToMap, so the 'act' claim
//     is included in issued ID tokens and custom JWTs.
func (s *DefaultSession) SetClaimActor(act map[string]any) {
	s.Extra[consts.ClaimActor] = act

	if s.DefaultSession == nil {
		return
	}

	if s.DefaultSession.Claims == nil {
		s.DefaultSession.Claims = &jwt.IDTokenClaims{}
	}

	if s.DefaultSession.Claims.Extra == nil {
		s.DefaultSession.Claims.Extra = map[string]any{}
	}

	s.DefaultSession.Claims.Extra[consts.ClaimActor] = act
}

func (s *DefaultSession) AccessTokenClaimsMap() map[string]any {
	tokenObject := map[string]any{
		consts.ClaimSubject:  s.GetSubject(),
		consts.ClaimUsername: s.GetUsername(),
	}

	for k, v := range s.Extra {
		tokenObject[k] = v
	}

	return tokenObject
}
