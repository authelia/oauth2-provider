// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package openid

import (
	"context"
	"strconv"
	"time"

	"github.com/mohae/deepcopy"
	"github.com/pkg/errors"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/stringslice"
	"authelia.com/provider/oauth2/token/jwt"
	"authelia.com/provider/oauth2/x/errorsx"
)

const defaultExpiryTime = time.Hour

type Session interface {
	// IDTokenClaims returns a pointer to claims which will be modified in-place by handlers.
	// Session should store this pointer and return always the same pointer.
	IDTokenClaims() *jwt.IDTokenClaims
	// IDTokenHeaders returns a pointer to header values which will be modified in-place by handlers.
	// Session should store this pointer and return always the same pointer.
	IDTokenHeaders() *jwt.Headers

	oauth2.Session
}

// DefaultSession is a session container for the id token.
type DefaultSession struct {
	Claims    *jwt.IDTokenClaims             `json:"id_token_claims"`
	Headers   *jwt.Headers                   `json:"headers"`
	ExpiresAt map[oauth2.TokenType]time.Time `json:"expires_at"`
	Username  string                         `json:"username"`
	Subject   string                         `json:"subject"`
}

func NewDefaultSession() *DefaultSession {
	return &DefaultSession{
		Claims: &jwt.IDTokenClaims{
			RequestedAt: jwt.Now(),
		},
		Headers: &jwt.Headers{},
	}
}

func (s *DefaultSession) Clone() oauth2.Session {
	if s == nil {
		return nil
	}

	return deepcopy.Copy(s).(oauth2.Session)
}

func (s *DefaultSession) SetExpiresAt(key oauth2.TokenType, exp time.Time) {
	if s.ExpiresAt == nil {
		s.ExpiresAt = make(map[oauth2.TokenType]time.Time)
	}

	s.ExpiresAt[key] = exp
}

func (s *DefaultSession) GetExpiresAt(key oauth2.TokenType) time.Time {
	if s.ExpiresAt == nil {
		s.ExpiresAt = make(map[oauth2.TokenType]time.Time)
	}

	if _, ok := s.ExpiresAt[key]; !ok {
		return time.Time{}
	}
	return s.ExpiresAt[key]
}

func (s *DefaultSession) GetUsername() string {
	if s == nil {
		return ""
	}
	return s.Username
}

func (s *DefaultSession) SetSubject(subject string) {
	s.Subject = subject
}

func (s *DefaultSession) GetSubject() string {
	if s == nil {
		return ""
	}

	return s.Subject
}

func (s *DefaultSession) IDTokenHeaders() *jwt.Headers {
	if s.Headers == nil {
		s.Headers = &jwt.Headers{}
	}
	return s.Headers
}

func (s *DefaultSession) IDTokenClaims() *jwt.IDTokenClaims {
	if s.Claims == nil {
		s.Claims = &jwt.IDTokenClaims{}
	}
	return s.Claims
}

type DefaultStrategy struct {
	jwt.Strategy

	Config interface {
		oauth2.IDTokenIssuerProvider
		oauth2.IDTokenLifespanProvider
		oauth2.MinParameterEntropyProvider
	}
}

// GenerateIDToken returns a JWT string.
//
// lifespan is ignored if requester.GetSession().IDTokenClaims().ExpirationTime is not zero.
//
// TODO: Refactor time permitting.
//
//nolint:gocyclo
func (h DefaultStrategy) GenerateIDToken(ctx context.Context, lifespan time.Duration, requester oauth2.Requester) (token string, err error) {
	if lifespan == 0 {
		lifespan = defaultExpiryTime
	}

	sess, ok := requester.GetSession().(Session)
	if !ok {
		return "", errorsx.WithStack(oauth2.ErrServerError.WithDebug("Failed to generate id token because session must be of type oauth2/handler/openid.Session."))
	}

	claims := sess.IDTokenClaims()
	if claims.Subject == "" {
		return "", errorsx.WithStack(oauth2.ErrServerError.WithDebug("Failed to generate id token because subject is an empty string."))
	}

	jwtClient := jwt.NewIDTokenClient(requester.GetClient())

	if requester.GetRequestForm().Get(consts.FormParameterGrantType) != consts.GrantTypeRefreshToken {
		var maxAge int64

		if maxAge, err = strconv.ParseInt(requester.GetRequestForm().Get(consts.FormParameterMaximumAge), 10, 64); err != nil {
			maxAge = 0
		}

		// Adds a bit of wiggle room for timing issues
		if claims.GetAuthTimeSafe().After(time.Now().UTC().Add(time.Second * 5)) {
			return "", errorsx.WithStack(oauth2.ErrServerError.WithDebug("Failed to validate OpenID Connect request because authentication time is in the future."))
		}

		if maxAge > 0 {
			switch {
			case claims.AuthTime == nil, claims.AuthTime.IsZero():
				return "", errorsx.WithStack(oauth2.ErrServerError.WithDebug("Failed to generate id token because authentication time claim is required when max_age is set."))
			case claims.RequestedAt == nil, claims.RequestedAt.IsZero():
				return "", errorsx.WithStack(oauth2.ErrServerError.WithDebug("Failed to generate id token because requested at claim is required when max_age is set."))
			case claims.AuthTime.Add(time.Second * time.Duration(maxAge)).Before(claims.RequestedAt.Time):
				return "", errorsx.WithStack(oauth2.ErrServerError.WithDebug("Failed to generate id token because authentication time does not satisfy max_age time."))
			}
		}

		prompt := requester.GetRequestForm().Get(consts.FormParameterPrompt)
		if prompt != "" {
			if claims.AuthTime == nil || claims.AuthTime.IsZero() {
				return "", errorsx.WithStack(oauth2.ErrServerError.WithDebug("Unable to determine validity of prompt parameter because auth_time is missing in id token claims."))
			}
		}

		switch prompt {
		case consts.PromptTypeNone:
			if !claims.GetAuthTimeSafe().Equal(claims.GetRequestedAtSafe()) && claims.GetAuthTimeSafe().After(claims.GetRequestedAtSafe()) {
				return "", errorsx.WithStack(oauth2.ErrServerError.
					WithDebugf("Failed to generate id token because prompt was set to 'none' but auth_time ('%s') happened after the authorization request ('%s') was registered, indicating that the user was logged in during this request which is not allowed.", claims.GetAuthTimeSafe(), claims.GetRequestedAtSafe()))
			}
		case consts.PromptTypeLogin:
			if !claims.GetAuthTimeSafe().Equal(claims.GetRequestedAtSafe()) && claims.GetAuthTimeSafe().Before(claims.GetRequestedAtSafe()) {
				return "", errorsx.WithStack(oauth2.ErrServerError.
					WithDebugf("Failed to generate id token because prompt was set to 'login' but auth_time ('%s') happened before the authorization request ('%s') was registered, indicating that the user was not re-authenticated which is forbidden.", claims.GetAuthTimeSafe(), claims.GetRequestedAtSafe()))
			}
		}

		// If acr_values was requested but no acr value was provided in the ID token, fall back to level 0 which means least
		// confidence in authentication.
		if requester.GetRequestForm().Get(consts.FormParameterAuthenticationContextClassReferenceValues) != "" && claims.AuthenticationContextClassReference == "" {
			claims.AuthenticationContextClassReference = "0"
		}

		if tokenHintString := requester.GetRequestForm().Get(consts.FormParameterIDTokenHint); tokenHintString != "" {
			var tokenHint *jwt.Token

			tokenHint, err = h.Strategy.Decode(ctx, tokenHintString, jwt.WithClient(jwtClient))

			var ve *jwt.ValidationError
			if errors.As(err, &ve) && ve.Has(jwt.ValidationErrorExpired) {
				// Expired ID Tokens are allowed as values to id_token_hint
			} else if err != nil {
				return "", errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugf("Unable to decode id token from 'id_token_hint' parameter because %s.", err.Error()))
			}

			var subHint string

			if subHint, err = tokenHint.Claims.GetSubject(); subHint == "" || err != nil {
				return "", errorsx.WithStack(oauth2.ErrServerError.WithDebug("Provided id token from 'id_token_hint' does not have a subject."))
			} else if subHint != claims.Subject {
				return "", errorsx.WithStack(oauth2.ErrServerError.WithDebug("Subject from authorization mismatches id token subject from 'id_token_hint'."))
			}
		}
	}

	if claims.ExpirationTime == nil || claims.ExpirationTime.IsZero() {
		claims.ExpirationTime = jwt.NewNumericDate(time.Now().Add(lifespan))
	}

	if claims.ExpirationTime.Before(time.Now().UTC()) {
		return "", errorsx.WithStack(oauth2.ErrServerError.WithDebug("Failed to generate id token because expiry claim can not be in the past."))
	}

	if claims.AuthTime == nil || claims.AuthTime.IsZero() {
		claims.AuthTime = jwt.Now()
	}

	if claims.Issuer == "" {
		claims.Issuer = h.Config.GetIDTokenIssuer(ctx)
	}

	// OPTIONAL. String value used to associate a Client session with an ID Token, and to mitigate replay attacks.
	if nonce := requester.GetRequestForm().Get(consts.FormParameterNonce); len(nonce) == 0 {
	} else if len(nonce) > 0 && len(nonce) < h.Config.GetMinParameterEntropy(ctx) {
		// We're assuming that using less then, by default, 8 characters for the state can not be considered "unguessable"
		return "", errorsx.WithStack(oauth2.ErrInsufficientEntropy.WithHintf("Parameter 'nonce' is set but does not satisfy the minimum entropy of %d characters.", h.Config.GetMinParameterEntropy(ctx)))
	} else if len(nonce) > 0 {
		claims.Nonce = nonce
	}

	claims.Audience = stringslice.Unique(append(claims.Audience, requester.GetClient().GetID()))
	claims.IssuedAt = jwt.Now()

	token, _, err = h.Strategy.Encode(ctx, claims.ToMapClaims(), jwt.WithHeaders(sess.IDTokenHeaders()), jwt.WithClient(jwtClient))

	return token, err
}
