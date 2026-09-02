// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"time"

	"github.com/mohae/deepcopy"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/token/jwt"
)

type JWTSessionContainer interface {
	// GetJWTClaims returns the claims.
	GetJWTClaims() jwt.JWTClaimsContainer

	// GetJWTHeader returns the header.
	GetJWTHeader() *jwt.Headers

	oauth2.Session
}

// JWTSession Container for the JWT session.
type JWTSession struct {
	JWTClaims                   *jwt.JWTClaims
	JWTHeader                   *jwt.Headers
	ExpiresAt                   map[oauth2.TokenType]time.Time
	Username                    string
	Subject                     string
	JWKThumbprint               string
	ClientCertificateThumbprint string
	RequestedJWKThumbprint      string
	PublicKeyJWK                []byte
	KeyBindingGranted           bool
}

// SetRequestedDPoPJWKThumbprint implements oauth2.DPoPBoundSession for JWTSession.
func (s *JWTSession) SetRequestedDPoPJWKThumbprint(jkt string) {
	s.RequestedJWKThumbprint = jkt
}

// GetRequestedDPoPJWKThumbprint implements oauth2.DPoPBoundSession for JWTSession.
func (s *JWTSession) GetRequestedDPoPJWKThumbprint() (jkt string) {
	if s == nil {
		return ""
	}

	return s.RequestedJWKThumbprint
}

// SetDPoPPublicKeyJWK implements oauth2.DPoPBoundSession for JWTSession.
func (s *JWTSession) SetDPoPPublicKeyJWK(jwk []byte) {
	s.PublicKeyJWK = jwk
}

// GetDPoPPublicKeyJWK implements oauth2.DPoPBoundSession for JWTSession.
func (s *JWTSession) GetDPoPPublicKeyJWK() (jwk []byte) {
	if s == nil {
		return nil
	}

	return s.PublicKeyJWK
}

// SetOIDCKeyBindingGranted implements oauth2.DPoPBoundSession for JWTSession.
func (s *JWTSession) SetOIDCKeyBindingGranted(granted bool) {
	s.KeyBindingGranted = granted
}

// GetOIDCKeyBindingGranted implements oauth2.DPoPBoundSession for JWTSession.
func (s *JWTSession) GetOIDCKeyBindingGranted() (granted bool) {
	if s == nil {
		return false
	}

	return s.KeyBindingGranted
}

var (
	_ oauth2.DPoPBoundSession = (*JWTSession)(nil)
	_ oauth2.MTLSBoundSession = (*JWTSession)(nil)
)

func (j *JWTSession) GetJWTClaims() jwt.JWTClaimsContainer {
	if j.JWTClaims == nil {
		j.JWTClaims = &jwt.JWTClaims{}
	}
	return j.JWTClaims
}

func (j *JWTSession) GetJWTHeader() *jwt.Headers {
	if j.JWTHeader == nil {
		j.JWTHeader = &jwt.Headers{
			Extra: map[string]any{
				jwt.JSONWebTokenHeaderType: jwt.JSONWebTokenTypeAccessToken,
			},
		}
	} else if j.JWTHeader.Extra[jwt.JSONWebTokenHeaderType] == nil {
		j.JWTHeader.Extra[jwt.JSONWebTokenHeaderType] = jwt.JSONWebTokenTypeAccessToken
	}

	return j.JWTHeader
}

func (j *JWTSession) SetExpiresAt(key oauth2.TokenType, exp time.Time) {
	if j.ExpiresAt == nil {
		j.ExpiresAt = make(map[oauth2.TokenType]time.Time)
	}
	j.ExpiresAt[key] = exp
}

func (j *JWTSession) GetExpiresAt(key oauth2.TokenType) time.Time {
	if j.ExpiresAt == nil {
		j.ExpiresAt = make(map[oauth2.TokenType]time.Time)
	}

	if _, ok := j.ExpiresAt[key]; !ok {
		return time.Time{}
	}
	return j.ExpiresAt[key]
}

func (j *JWTSession) GetUsername() string {
	if j == nil {
		return ""
	}
	return j.Username
}

func (j *JWTSession) SetSubject(subject string) {
	j.Subject = subject
}

func (j *JWTSession) GetSubject() string {
	if j == nil {
		return ""
	}

	return j.Subject
}

func (j *JWTSession) SetDPoPJWKThumbprint(jkt string) {
	j.JWKThumbprint = jkt
}

func (j *JWTSession) GetDPoPJWKThumbprint() string {
	if j == nil {
		return ""
	}

	return j.JWKThumbprint
}

func (j *JWTSession) SetClientCertificateSHA256Thumbprint(x5t string) {
	j.ClientCertificateThumbprint = x5t
}

func (j *JWTSession) GetClientCertificateSHA256Thumbprint() string {
	if j == nil {
		return ""
	}

	return j.ClientCertificateThumbprint
}

func (j *JWTSession) Clone() oauth2.Session {
	if j == nil {
		return nil
	}

	return deepcopy.Copy(j).(oauth2.Session)
}

// GetExtraClaims implements ExtraClaimsSession for JWTSession.
// The returned value is a copy of JWTSession claims.
func (j *JWTSession) GetExtraClaims() map[string]any {
	if j == nil {
		return nil
	}

	// We make a clone so that WithScopeField does not change the original value.
	return j.Clone().(*JWTSession).GetJWTClaims().WithScopeField(jwt.JWTScopeFieldString).ToMapClaims()
}
