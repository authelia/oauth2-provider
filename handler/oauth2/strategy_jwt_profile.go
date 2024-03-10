// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"strings"
	"time"

	"github.com/pkg/errors"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
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
		oauth2.JWTProfileAccessTokensProvider
	}
}

func (s *JWTProfileCoreStrategy) AccessTokenSignature(ctx context.Context, tokenString string) (signature string) {
	var possible bool

	if possible, signature = s.IsPossiblyJWTProfileAccessToken(ctx, tokenString); possible {
		return
	}

	return s.HMACCoreStrategy.AccessTokenSignature(ctx, tokenString)
}

func (s *JWTProfileCoreStrategy) GenerateAccessToken(ctx context.Context, requester oauth2.Requester) (token string, signature string, err error) {
	var (
		client oauth2.JWTProfileClient
		ok     bool
	)

	if s.Config.GetEnforceJWTProfileAccessTokens(ctx) {
		return s.GenerateJWT(ctx, oauth2.AccessToken, requester, nil)
	}

	if client, ok = requester.GetClient().(oauth2.JWTProfileClient); ok && client.GetEnableJWTProfileOAuthAccessTokens() {
		return s.GenerateJWT(ctx, oauth2.AccessToken, requester, client)
	}

	return s.HMACCoreStrategy.GenerateAccessToken(ctx, requester)
}

func (s *JWTProfileCoreStrategy) ValidateAccessToken(ctx context.Context, requester oauth2.Requester, tokenString string) (err error) {
	if possible, _ := s.IsPossiblyJWTProfileAccessToken(ctx, tokenString); possible {
		_, err = validateJWT(ctx, s.Signer, tokenString)

		return
	}

	return s.HMACCoreStrategy.ValidateAccessToken(ctx, requester, tokenString)
}

func (s *JWTProfileCoreStrategy) RefreshTokenSignature(ctx context.Context, tokenString string) string {
	return s.HMACCoreStrategy.RefreshTokenSignature(ctx, tokenString)
}

func (s *JWTProfileCoreStrategy) AuthorizeCodeSignature(ctx context.Context, tokenString string) string {
	return s.HMACCoreStrategy.AuthorizeCodeSignature(ctx, tokenString)
}

func (s *JWTProfileCoreStrategy) GenerateRefreshToken(ctx context.Context, req oauth2.Requester) (tokenString string, signature string, err error) {
	return s.HMACCoreStrategy.GenerateRefreshToken(ctx, req)
}

func (s *JWTProfileCoreStrategy) ValidateRefreshToken(ctx context.Context, req oauth2.Requester, tokenString string) (err error) {
	return s.HMACCoreStrategy.ValidateRefreshToken(ctx, req, tokenString)
}

func (s *JWTProfileCoreStrategy) GenerateAuthorizeCode(ctx context.Context, req oauth2.Requester) (tokenString string, signature string, err error) {
	return s.HMACCoreStrategy.GenerateAuthorizeCode(ctx, req)
}

func (s *JWTProfileCoreStrategy) ValidateAuthorizeCode(ctx context.Context, req oauth2.Requester, tokenString string) error {
	return s.HMACCoreStrategy.ValidateAuthorizeCode(ctx, req, tokenString)
}

func (s *JWTProfileCoreStrategy) RFC8628UserCodeSignature(ctx context.Context, tokenString string) (signature string, err error) {
	return s.HMACCoreStrategy.RFC8628UserCodeSignature(ctx, tokenString)
}

func (s *JWTProfileCoreStrategy) GenerateRFC8628UserCode(ctx context.Context) (tokenString string, signature string, err error) {
	return s.HMACCoreStrategy.GenerateRFC8628UserCode(ctx)
}

func (s *JWTProfileCoreStrategy) ValidateRFC8628UserCode(ctx context.Context, r oauth2.Requester, tokenString string) (err error) {
	return s.HMACCoreStrategy.ValidateRFC8628UserCode(ctx, r, tokenString)
}

func (s *JWTProfileCoreStrategy) RFC8628DeviceCodeSignature(ctx context.Context, tokenString string) (signature string, err error) {
	return s.HMACCoreStrategy.RFC8628DeviceCodeSignature(ctx, tokenString)
}

func (s *JWTProfileCoreStrategy) GenerateRFC8628DeviceCode(ctx context.Context) (tokenString string, signature string, err error) {
	return s.HMACCoreStrategy.GenerateRFC8628DeviceCode(ctx)
}

func (s *JWTProfileCoreStrategy) ValidateRFC8628DeviceCode(ctx context.Context, r oauth2.Requester, tokenString string) (err error) {
	return s.HMACCoreStrategy.ValidateRFC8628DeviceCode(ctx, r, tokenString)
}

func (s *JWTProfileCoreStrategy) IsPossiblyJWTProfileAccessToken(ctx context.Context, tokenString string) (jwt bool, signature string) {
	if s.HMACCoreStrategy.hasPrefix(tokenString, tokenPrefixPartAccessToken) {
		return false, ""
	}

	parts := strings.SplitN(tokenString, ".", 4)

	if len(parts) != 3 {
		return false, ""
	}

	return true, parts[2]
}

func (s *JWTProfileCoreStrategy) GenerateJWT(ctx context.Context, tokenType oauth2.TokenType, requester oauth2.Requester, client oauth2.JWTProfileClient) (tokenString string, signature string, err error) {
	var (
		session JWTSessionContainer
		ok      bool
		claims  jwt.JWTClaimsContainer
		header  *jwt.Headers
	)

	if session, ok = requester.GetSession().(JWTSessionContainer); !ok {
		return "", "", errors.Errorf("Session must be of type JWTSessionContainer but got type: %T", requester.GetSession())
	}

	if claims = session.GetJWTClaims(); claims == nil {
		return "", "", errors.New("JWT Claims must not be nil")
	}

	header = session.GetJWTHeader()

	if client != nil {
		if kid := client.GetAccessTokenSignedResponseKeyID(); len(kid) != 0 {
			header.SetDefaultString(consts.JSONWebTokenHeaderKeyIdentifier, kid)
		}

		if alg := client.GetAccessTokenSignedResponseAlg(); len(alg) != 0 {
			header.SetDefaultString(consts.JSONWebTokenHeaderAlgorithm, alg)
		}
	}

	claims = claims.
		Sanitize().
		With(
			session.GetExpiresAt(tokenType),
			requester.GetGrantedScopes(),
			requester.GetGrantedAudience(),
		).
		WithDefaults(
			time.Now().UTC(),
			time.Now().UTC(),
			s.Config.GetAccessTokenIssuer(ctx),
		).
		WithScopeField(
			s.Config.GetJWTScopeField(ctx),
		)

	return s.Signer.Generate(ctx, claims.ToMapClaims(), header)
}

func validateJWT(ctx context.Context, jwtStrategy jwt.Signer, token string) (t *jwt.Token, err error) {
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
