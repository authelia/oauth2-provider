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

	// JWKThumbprint is the RFC 7638 JWK Thumbprint (jkt) this session's tokens are DPoP bound to, if any.
	JWKThumbprint string `json:"jwk_thumbprint,omitempty"`

	// ClientCertificateThumbprint is the RFC 8705 X.509 SHA-256 certificate thumbprint (x5t#S256) this session's
	// tokens are bound to, if any.
	ClientCertificateThumbprint string `json:"client_certificate_thumbprint,omitempty"`

	// PublicKeyJWK is the raw JWK JSON of the DPoP proof-of-possession public key this session's ID Tokens are
	// bound to, if any.
	PublicKeyJWK []byte `json:"public_key_jwk,omitempty"`

	// RequestedJWKThumbprint is the RFC 9449 Section 10.1 'dpop_jkt' the authentication request carried, if any.
	RequestedJWKThumbprint string `json:"requested_jwk_thumbprint,omitempty"`

	// KeyBindingGranted records that the 'bound_key' scope was granted, so this grant's ID Tokens are key bound.
	KeyBindingGranted bool `json:"key_binding_granted,omitempty"`
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

// SetDPoPJWKThumbprint implements DPoPBoundSession for DefaultSession.
func (s *DefaultSession) SetDPoPJWKThumbprint(jkt string) {
	s.JWKThumbprint = jkt
}

// GetDPoPJWKThumbprint implements DPoPBoundSession for DefaultSession.
func (s *DefaultSession) GetDPoPJWKThumbprint() string {
	if s == nil {
		return ""
	}

	return s.JWKThumbprint
}

// SetClientCertificateSHA256Thumbprint implements MTLSBoundSession for DefaultSession.
func (s *DefaultSession) SetClientCertificateSHA256Thumbprint(x5t string) {
	s.ClientCertificateThumbprint = x5t
}

// GetClientCertificateSHA256Thumbprint implements MTLSBoundSession for DefaultSession.
func (s *DefaultSession) GetClientCertificateSHA256Thumbprint() string {
	if s == nil {
		return ""
	}

	return s.ClientCertificateThumbprint
}

// SetDPoPPublicKeyJWK implements DPoPBoundSession for DefaultSession.
func (s *DefaultSession) SetDPoPPublicKeyJWK(jwk []byte) {
	s.PublicKeyJWK = jwk
}

// GetDPoPPublicKeyJWK implements DPoPBoundSession for DefaultSession.
func (s *DefaultSession) GetDPoPPublicKeyJWK() (jwk []byte) {
	if s == nil {
		return nil
	}

	return s.PublicKeyJWK
}

// SetRequestedDPoPJWKThumbprint implements DPoPBoundSession for DefaultSession.
func (s *DefaultSession) SetRequestedDPoPJWKThumbprint(jkt string) {
	s.RequestedJWKThumbprint = jkt
}

// GetRequestedDPoPJWKThumbprint implements DPoPBoundSession for DefaultSession.
func (s *DefaultSession) GetRequestedDPoPJWKThumbprint() (jkt string) {
	if s == nil {
		return ""
	}

	return s.RequestedJWKThumbprint
}

// SetOIDCKeyBindingGranted implements DPoPBoundSession for DefaultSession.
func (s *DefaultSession) SetOIDCKeyBindingGranted(granted bool) {
	s.KeyBindingGranted = granted
}

// GetOIDCKeyBindingGranted implements DPoPBoundSession for DefaultSession.
func (s *DefaultSession) GetOIDCKeyBindingGranted() (granted bool) {
	if s == nil {
		return false
	}

	return s.KeyBindingGranted
}

var (
	_ DPoPBoundSession = (*DefaultSession)(nil)
	_ MTLSBoundSession = (*DefaultSession)(nil)
)
