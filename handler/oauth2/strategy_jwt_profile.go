// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"strings"
	"time"

	"github.com/pkg/errors"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/errorsx"
	"authelia.com/provider/oauth2/token/jwt"
)

// JWTProfileCoreStrategy is a JWT RS256 strategy.
type JWTProfileCoreStrategy struct {
	jwt.Signer
	HMACCoreStrategy *HMACCoreStrategy
	Config           interface {
		oauth2.AccessTokenIssuerProvider
		oauth2.JWTScopeFieldProvider
	}
}

func (h *JWTProfileCoreStrategy) AccessTokenSignature(ctx context.Context, token string) string {
	return h.signature(token)
}

func (h *JWTProfileCoreStrategy) GenerateAccessToken(ctx context.Context, requester oauth2.Requester) (token string, signature string, err error) {
	return h.generate(ctx, oauth2.AccessToken, requester)
}

func (h *JWTProfileCoreStrategy) ValidateAccessToken(ctx context.Context, _ oauth2.Requester, token string) error {
	_, err := validate(ctx, h.Signer, token)
	return err
}

func (h *JWTProfileCoreStrategy) RefreshTokenSignature(ctx context.Context, token string) string {
	return h.HMACCoreStrategy.RefreshTokenSignature(ctx, token)
}

func (h *JWTProfileCoreStrategy) AuthorizeCodeSignature(ctx context.Context, token string) string {
	return h.HMACCoreStrategy.AuthorizeCodeSignature(ctx, token)
}

func (h *JWTProfileCoreStrategy) GenerateRefreshToken(ctx context.Context, req oauth2.Requester) (token string, signature string, err error) {
	return h.HMACCoreStrategy.GenerateRefreshToken(ctx, req)
}

func (h *JWTProfileCoreStrategy) ValidateRefreshToken(ctx context.Context, req oauth2.Requester, token string) error {
	return h.HMACCoreStrategy.ValidateRefreshToken(ctx, req, token)
}

func (h *JWTProfileCoreStrategy) GenerateAuthorizeCode(ctx context.Context, req oauth2.Requester) (token string, signature string, err error) {
	return h.HMACCoreStrategy.GenerateAuthorizeCode(ctx, req)
}

func (h *JWTProfileCoreStrategy) ValidateAuthorizeCode(ctx context.Context, req oauth2.Requester, token string) error {
	return h.HMACCoreStrategy.ValidateAuthorizeCode(ctx, req, token)
}

func (h *JWTProfileCoreStrategy) RFC8628UserCodeSignature(ctx context.Context, token string) (signature string, err error) {
	return h.HMACCoreStrategy.RFC8628UserCodeSignature(ctx, token)
}

func (h *JWTProfileCoreStrategy) GenerateRFC8628UserCode(ctx context.Context) (token string, signature string, err error) {
	return h.HMACCoreStrategy.GenerateRFC8628UserCode(ctx)
}

func (h *JWTProfileCoreStrategy) ValidateRFC8628UserCode(ctx context.Context, r oauth2.Requester, code string) (err error) {
	return h.HMACCoreStrategy.ValidateRFC8628UserCode(ctx, r, code)
}

func (h *JWTProfileCoreStrategy) RFC8628DeviceCodeSignature(ctx context.Context, token string) (signature string, err error) {
	return h.HMACCoreStrategy.RFC8628DeviceCodeSignature(ctx, token)
}

func (h *JWTProfileCoreStrategy) GenerateRFC8628DeviceCode(ctx context.Context) (token string, signature string, err error) {
	return h.HMACCoreStrategy.GenerateRFC8628DeviceCode(ctx)
}

func (h *JWTProfileCoreStrategy) ValidateRFC8628DeviceCode(ctx context.Context, r oauth2.Requester, code string) (err error) {
	return h.HMACCoreStrategy.ValidateRFC8628DeviceCode(ctx, r, code)
}

func (h *JWTProfileCoreStrategy) signature(token string) string {
	split := strings.Split(token, ".")
	if len(split) != 3 {
		return ""
	}

	return split[2]
}

func validate(ctx context.Context, jwtStrategy jwt.Signer, token string) (t *jwt.Token, err error) {
	t, err = jwtStrategy.Decode(ctx, token)
	if err == nil {
		err = t.Claims.Valid()
		return
	}

	var e *jwt.ValidationError
	if err != nil && errors.As(err, &e) {
		err = errorsx.WithStack(toRFCErr(e).WithWrap(err).WithDebugError(err))
	}

	return
}

func toRFCErr(v *jwt.ValidationError) *oauth2.RFC6749Error {
	switch {
	case v == nil:
		return nil
	case v.Has(jwt.ValidationErrorMalformed):
		return oauth2.ErrInvalidTokenFormat
	case v.Has(jwt.ValidationErrorUnverifiable | jwt.ValidationErrorSignatureInvalid):
		return oauth2.ErrTokenSignatureMismatch
	case v.Has(jwt.ValidationErrorExpired):
		return oauth2.ErrTokenExpired
	case v.Has(jwt.ValidationErrorAudience |
		jwt.ValidationErrorIssuedAt |
		jwt.ValidationErrorIssuer |
		jwt.ValidationErrorNotValidYet |
		jwt.ValidationErrorId |
		jwt.ValidationErrorClaimsInvalid):
		return oauth2.ErrTokenClaim
	default:
		return oauth2.ErrRequestUnauthorized
	}
}

func (h *JWTProfileCoreStrategy) generate(ctx context.Context, tokenType oauth2.TokenType, requester oauth2.Requester) (string, string, error) {
	if jwtSession, ok := requester.GetSession().(JWTSessionContainer); !ok {
		return "", "", errors.Errorf("Session must be of type JWTSessionContainer but got type: %T", requester.GetSession())
	} else if jwtSession.GetJWTClaims() == nil {
		return "", "", errors.New("GetTokenClaims() must not be nil")
	} else {
		claims := jwtSession.GetJWTClaims().
			Sanitize().
			With(
				jwtSession.GetExpiresAt(tokenType),
				requester.GetGrantedScopes(),
				requester.GetGrantedAudience(),
			).
			WithDefaults(
				time.Now().UTC(),
				time.Now().UTC(),
				h.Config.GetAccessTokenIssuer(ctx),
			).
			WithScopeField(
				h.Config.GetJWTScopeField(ctx),
			)

		return h.Signer.Generate(ctx, claims.ToMapClaims(), jwtSession.GetJWTHeader())
	}
}
