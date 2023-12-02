// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"time"

	"github.com/mohae/deepcopy"

	"github.com/authelia/goauth2"
	"github.com/authelia/goauth2/token/jwt"
)

type JWTSessionContainer interface {
	// GetJWTClaims returns the claims.
	GetJWTClaims() jwt.JWTClaimsContainer

	// GetJWTHeader returns the header.
	GetJWTHeader() *jwt.Headers

	goauth2.Session
}

// JWTSession Container for the JWT session.
type JWTSession struct {
	JWTClaims *jwt.JWTClaims
	JWTHeader *jwt.Headers
	ExpiresAt map[goauth2.TokenType]time.Time
	Username  string
	Subject   string
}

func (j *JWTSession) GetJWTClaims() jwt.JWTClaimsContainer {
	if j.JWTClaims == nil {
		j.JWTClaims = &jwt.JWTClaims{}
	}
	return j.JWTClaims
}

func (j *JWTSession) GetJWTHeader() *jwt.Headers {
	if j.JWTHeader == nil {
		j.JWTHeader = &jwt.Headers{}
	}
	return j.JWTHeader
}

func (j *JWTSession) SetExpiresAt(key goauth2.TokenType, exp time.Time) {
	if j.ExpiresAt == nil {
		j.ExpiresAt = make(map[goauth2.TokenType]time.Time)
	}
	j.ExpiresAt[key] = exp
}

func (j *JWTSession) GetExpiresAt(key goauth2.TokenType) time.Time {
	if j.ExpiresAt == nil {
		j.ExpiresAt = make(map[goauth2.TokenType]time.Time)
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

func (j *JWTSession) Clone() goauth2.Session {
	if j == nil {
		return nil
	}

	return deepcopy.Copy(j).(goauth2.Session)
}

// GetExtraClaims implements ExtraClaimsSession for JWTSession.
// The returned value is a copy of JWTSession claims.
func (j *JWTSession) GetExtraClaims() map[string]interface{} {
	if j == nil {
		return nil
	}

	// We make a clone so that WithScopeField does not change the original value.
	return j.Clone().(*JWTSession).GetJWTClaims().WithScopeField(jwt.JWTScopeFieldString).ToMapClaims()
}
