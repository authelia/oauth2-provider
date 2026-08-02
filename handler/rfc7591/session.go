// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc7591

import (
	"github.com/mohae/deepcopy"

	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
)

// Session is implemented by sessions backing an RFC 7591 / RFC 7592 client registration access token.
type Session interface {
	oauth2.Session

	// GetClientRegistrationKind returns which role this session plays.
	GetClientRegistrationKind() (kind Kind)

	// SetClientRegistrationKind sets which role this session plays.
	SetClientRegistrationKind(kind Kind)

	// GetGrantableScopes returns the scopes this session permits to be granted to the client it creates or manages.
	GetGrantableScopes() (scopes oauth2.Arguments)

	// SetGrantableScopes sets the scopes this session permits to be granted.
	SetGrantableScopes(scopes oauth2.Arguments)

	// IsClientRegistration reports whether this session is a client registration session at all.
	IsClientRegistration() (is bool)
}

// DefaultSession is the default Session implementation. It MUST be constructed with NewDefaultSession: the composite
// literal &DefaultSession{} leaves the embedded pointer nil, and while hoauth2.JWTSession guards its getters against
// a nil receiver it does not guard its setters, so any promoted setter - SetSubject, SetExpiresAt - panics on such a
// value. That includes passing one to a store's GetAccessTokenSession, which hydrates by assigning into the session
// it is given.
//
// The contract is stated here rather than enforced by shadowing every promoted method with a lazy initialiser,
// because such a guarantee would be false the moment hoauth2.JWTSession grew a method this type did not shadow.
//
// The embedded type is *hoauth2.JWTSession rather than a plainer session because these tokens are ordinary access
// tokens: JWTProfileCoreStrategy.GenerateAccessToken routes to GenerateJWT whenever EnforceJWTProfileAccessTokens is
// set or the bound client enables JWT profile access tokens, and GenerateJWT rejects any session that does not
// implement hoauth2.JWTSessionContainer. Only JWTSession does.
type DefaultSession struct {
	*hoauth2.JWTSession

	Kind            Kind             `json:"client_registration_kind"`
	GrantableScopes oauth2.Arguments `json:"grantable_scopes"`
}

// NewDefaultSession returns a *DefaultSession with its embedded JWTSession initialised.
func NewDefaultSession() (session *DefaultSession) {
	return &DefaultSession{JWTSession: &hoauth2.JWTSession{}}
}

func (s *DefaultSession) GetClientRegistrationKind() (kind Kind) {
	return s.Kind
}

func (s *DefaultSession) SetClientRegistrationKind(kind Kind) {
	s.Kind = kind
}

func (s *DefaultSession) GetGrantableScopes() (scopes oauth2.Arguments) {
	return s.GrantableScopes
}

func (s *DefaultSession) SetGrantableScopes(scopes oauth2.Arguments) {
	s.GrantableScopes = scopes
}

func (s *DefaultSession) IsClientRegistration() (is bool) {
	return s.Kind != KindNone
}

// Clone overrides the embedded hoauth2.JWTSession.Clone, which deep-copies only the embedded value and would
// therefore return a *hoauth2.JWTSession with Kind and GrantableScopes silently dropped.
func (s *DefaultSession) Clone() (session oauth2.Session) {
	if s == nil {
		return nil
	}

	return deepcopy.Copy(s).(oauth2.Session)
}

var (
	_ Session = (*DefaultSession)(nil)
)
