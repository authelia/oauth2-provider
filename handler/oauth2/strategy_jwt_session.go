// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"time"

	"github.com/mohae/deepcopy"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
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
	JWTClaims *jwt.JWTClaims
	JWTHeader *jwt.Headers
	ExpiresAt map[oauth2.TokenType]time.Time
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
		j.JWTHeader = &jwt.Headers{
			Extra: map[string]any{
				consts.JSONWebTokenHeaderType: consts.JSONWebTokenTypeAccessToken,
			},
		}
	} else if j.JWTHeader.Extra[consts.JSONWebTokenHeaderType] == nil {
		j.JWTHeader.Extra[consts.JSONWebTokenHeaderType] = consts.JSONWebTokenTypeAccessToken
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
