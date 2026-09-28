// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc8693

import (
	"time"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/handler/openid"
	"authelia.com/provider/oauth2/internal/clone"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/token/jwt"
)

// Session is implemented by sessions that support RFC 8693 OAuth 2.0 Token Exchange. It exposes the subject and actor
// tokens involved in the exchange and the claims derived from them.
type Session interface {
	// SetSubject sets the session's subject.
	SetSubject(subject string)

	// SetActorToken stores the claims of the actor token, i.e. the token representing the party acting on behalf of
	// the subject in a delegation flow.
	SetActorToken(token map[string]any)

	// GetActorToken returns the previously stored actor token claims, or nil if none were set.
	GetActorToken() map[string]any

	// SetSubjectToken stores the claims of the subject token, i.e. the token representing the party on whose behalf
	// the request is being made.
	SetSubjectToken(token map[string]any)

	// GetSubjectToken returns the previously stored subject token claims, or nil if none were set.
	GetSubjectToken() map[string]any

	// SetClaimActor records the RFC 8693 §4.1 'act' claim describing the actor in a delegation flow.
	SetClaimActor(act map[string]any)

	// AccessTokenClaimsMap returns the claims to include in the exchanged access token.
	AccessTokenClaimsMap() map[string]any
}

type DefaultSession struct {
	*openid.DefaultSession

	ActorToken     map[string]any `json:"-"`
	SubjectToken   map[string]any `json:"-"`
	Extra          map[string]any `json:"extra,omitempty"`
	ExpiryDeadline time.Time      `json:"expiry_deadline,omitzero"`
}

// NewDefaultSession returns a *DefaultSession with the embedded OpenID Connect session and the Extra map SetClaimActor
// writes to already initialised.
func NewDefaultSession() *DefaultSession {
	return &DefaultSession{
		DefaultSession: openid.NewDefaultSession(),
		Extra:          map[string]any{},
	}
}

// Clone returns a deep copy of the session, or nil if the receiver is nil. The copy keeps this type, so the actor and
// subject tokens and the Extra claims such as 'act' and 'may_act' survive a refresh.
func (s *DefaultSession) Clone() oauth2.Session {
	if s == nil {
		return nil
	}

	cloned := &DefaultSession{
		ActorToken:     clone.Map(s.ActorToken),
		SubjectToken:   clone.Map(s.SubjectToken),
		Extra:          clone.Map(s.Extra),
		ExpiryDeadline: s.ExpiryDeadline,
	}

	if s.DefaultSession != nil {
		cloned.DefaultSession, _ = s.DefaultSession.Clone().(*openid.DefaultSession)
	}

	return cloned
}

// SetExpiryDeadline sets the latest time a token issued for the session may expire, which a refresh of the session
// keeps.
func (s *DefaultSession) SetExpiryDeadline(deadline time.Time) {
	s.ExpiryDeadline = deadline
}

// GetExpiryDeadline implements oauth2.ExpiryDeadlineSession.
func (s *DefaultSession) GetExpiryDeadline() time.Time {
	if s == nil {
		return time.Time{}
	}

	return s.ExpiryDeadline
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
//   - s.Extra surfaces in DefaultSession.AccessTokenClaimsMap and therefore in introspection responses for
//     opaque access tokens stored verbatim.
//   - s.DefaultSession.Claims.Extra flattened into the JWT body by jwt.IDTokenClaims.ToMap, so the 'act' claim
//     is included in issued ID tokens and custom JWTs.
func (s *DefaultSession) SetClaimActor(act map[string]any) {
	if s.Extra == nil {
		s.Extra = map[string]any{}
	}

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
