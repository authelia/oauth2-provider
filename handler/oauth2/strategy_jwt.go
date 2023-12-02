// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"strings"
	"time"

	"github.com/ory/x/errorsx"
	"github.com/pkg/errors"

	"github.com/authelia/goauth2"
	"github.com/authelia/goauth2/token/jwt"
)

// DefaultJWTStrategy is a JWT RS256 strategy.
type DefaultJWTStrategy struct {
	jwt.Signer
	HMACSHAStrategy *HMACSHAStrategy
	Config          interface {
		goauth2.AccessTokenIssuerProvider
		goauth2.JWTScopeFieldProvider
	}
}

func (h DefaultJWTStrategy) signature(token string) string {
	split := strings.Split(token, ".")
	if len(split) != 3 {
		return ""
	}

	return split[2]
}

func (h DefaultJWTStrategy) AccessTokenSignature(ctx context.Context, token string) string {
	return h.signature(token)
}

func (h *DefaultJWTStrategy) GenerateAccessToken(ctx context.Context, requester goauth2.Requester) (token string, signature string, err error) {
	return h.generate(ctx, goauth2.AccessToken, requester)
}

func (h *DefaultJWTStrategy) ValidateAccessToken(ctx context.Context, _ goauth2.Requester, token string) error {
	_, err := validate(ctx, h.Signer, token)
	return err
}

func (h DefaultJWTStrategy) RefreshTokenSignature(ctx context.Context, token string) string {
	return h.HMACSHAStrategy.RefreshTokenSignature(ctx, token)
}

func (h DefaultJWTStrategy) AuthorizeCodeSignature(ctx context.Context, token string) string {
	return h.HMACSHAStrategy.AuthorizeCodeSignature(ctx, token)
}

func (h *DefaultJWTStrategy) GenerateRefreshToken(ctx context.Context, req goauth2.Requester) (token string, signature string, err error) {
	return h.HMACSHAStrategy.GenerateRefreshToken(ctx, req)
}

func (h *DefaultJWTStrategy) ValidateRefreshToken(ctx context.Context, req goauth2.Requester, token string) error {
	return h.HMACSHAStrategy.ValidateRefreshToken(ctx, req, token)
}

func (h *DefaultJWTStrategy) GenerateAuthorizeCode(ctx context.Context, req goauth2.Requester) (token string, signature string, err error) {
	return h.HMACSHAStrategy.GenerateAuthorizeCode(ctx, req)
}

func (h *DefaultJWTStrategy) ValidateAuthorizeCode(ctx context.Context, req goauth2.Requester, token string) error {
	return h.HMACSHAStrategy.ValidateAuthorizeCode(ctx, req, token)
}

func validate(ctx context.Context, jwtStrategy jwt.Signer, token string) (t *jwt.Token, err error) {
	t, err = jwtStrategy.Decode(ctx, token)
	if err == nil {
		err = t.Claims.Valid()
		return
	}

	var e *jwt.ValidationError
	if err != nil && errors.As(err, &e) {
		err = errorsx.WithStack(toRFCErr(e).WithWrap(err).WithDebug(err.Error()))
	}

	return
}

func toRFCErr(v *jwt.ValidationError) *goauth2.RFC6749Error {
	switch {
	case v == nil:
		return nil
	case v.Has(jwt.ValidationErrorMalformed):
		return goauth2.ErrInvalidTokenFormat
	case v.Has(jwt.ValidationErrorUnverifiable | jwt.ValidationErrorSignatureInvalid):
		return goauth2.ErrTokenSignatureMismatch
	case v.Has(jwt.ValidationErrorExpired):
		return goauth2.ErrTokenExpired
	case v.Has(jwt.ValidationErrorAudience |
		jwt.ValidationErrorIssuedAt |
		jwt.ValidationErrorIssuer |
		jwt.ValidationErrorNotValidYet |
		jwt.ValidationErrorId |
		jwt.ValidationErrorClaimsInvalid):
		return goauth2.ErrTokenClaim
	default:
		return goauth2.ErrRequestUnauthorized
	}
}

func (h *DefaultJWTStrategy) generate(ctx context.Context, tokenType goauth2.TokenType, requester goauth2.Requester) (string, string, error) {
	if jwtSession, ok := requester.GetSession().(JWTSessionContainer); !ok {
		return "", "", errors.Errorf("Session must be of type JWTSessionContainer but got type: %T", requester.GetSession())
	} else if jwtSession.GetJWTClaims() == nil {
		return "", "", errors.New("GetTokenClaims() must not be nil")
	} else {
		claims := jwtSession.GetJWTClaims().
			With(
				jwtSession.GetExpiresAt(tokenType),
				requester.GetGrantedScopes(),
				requester.GetGrantedAudience(),
			).
			WithDefaults(
				time.Now().UTC(),
				h.Config.GetAccessTokenIssuer(ctx),
			).
			WithScopeField(
				h.Config.GetJWTScopeField(ctx),
			)

		return h.Signer.Generate(ctx, claims.ToMapClaims(), jwtSession.GetJWTHeader())
	}
}
