// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"time"

	"github.com/mohae/deepcopy"
)

// Session is an interface that is used to store session data between OAuth2 requests. It can be used to look up
// when a session expires or what the subject's name was.
type Session interface {
	// SetExpiresAt sets the expiration time of a token.
	//
	//  session.SetExpiresAt(oauth2.AccessToken, time.Now().UTC().Add(time.Hour))
	SetExpiresAt(key TokenType, exp time.Time)

	// GetExpiresAt returns the expiration time of a token if set, or time.IsZero() if not.
	//
	//  session.GetExpiresTimeX(oauth2.AccessToken)
	GetExpiresAt(key TokenType) time.Time

	// GetUsername returns the username, if set. This is optional and only used during token introspection.
	GetUsername() string

	// GetSubject returns the subject, if set. This is optional and only used during token introspection.
	GetSubject() string

	// Clone clones the session.
	Clone() Session
}

// DefaultSession is a default implementation of the Session interface.
type DefaultSession struct {
	// ExpiresAt maps each token type to its expiration time.
	ExpiresAt map[TokenType]time.Time `json:"expires_at"`

	// Username is the subject's username. It is optional and only used during token introspection.
	Username string `json:"username"`

	// Subject is the subject's identifier. It is optional and only used during token introspection.
	Subject string `json:"subject"`

	// Extra holds arbitrary additional claims associated with the session.
	Extra map[string]any `json:"extra"`
}

// SetExpiresAt sets the expiration time of the token identified by key.
func (s *DefaultSession) SetExpiresAt(key TokenType, exp time.Time) {
	if s.ExpiresAt == nil {
		s.ExpiresAt = make(map[TokenType]time.Time)
	}
	s.ExpiresAt[key] = exp
}

// GetExpiresAt returns the expiration time of the token identified by key, or the zero time if it is not set.
func (s *DefaultSession) GetExpiresAt(key TokenType) time.Time {
	if s.ExpiresAt == nil {
		s.ExpiresAt = make(map[TokenType]time.Time)
	}

	return s.ExpiresAt[key]
}

// GetUsername returns the username, or an empty string if it is not set.
func (s *DefaultSession) GetUsername() string {
	if s == nil {
		return ""
	}
	return s.Username
}

// SetSubject sets the subject's identifier.
func (s *DefaultSession) SetSubject(subject string) {
	s.Subject = subject
}

// GetSubject returns the subject, or an empty string if it is not set.
func (s *DefaultSession) GetSubject() string {
	if s == nil {
		return ""
	}

	return s.Subject
}

// Clone returns a deep copy of the session, or nil if the receiver is nil.
func (s *DefaultSession) Clone() Session {
	if s == nil {
		return nil
	}

	return deepcopy.Copy(s).(Session)
}

// ExtraClaimsSession provides an interface for session to store any extra claims.
type ExtraClaimsSession interface {
	// GetExtraClaims returns a map to store extra claims.
	// The returned value can be modified in-place.
	GetExtraClaims() map[string]any
}

// GetExtraClaims implements ExtraClaimsSession for DefaultSession.
// The returned value can be modified in-place.
func (s *DefaultSession) GetExtraClaims() map[string]any {
	if s == nil {
		return nil
	}

	if s.Extra == nil {
		s.Extra = make(map[string]any)
	}

	return s.Extra
}
