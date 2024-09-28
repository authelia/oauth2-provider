// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/pkg/errors"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/token/jwt"
)

// JWTProfileCoreStrategy is a JWT RS256 strategy.
type JWTProfileCoreStrategy struct {
	jwt.Strategy

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
		_, err = validateJWT(ctx, s.Strategy, jwt.NewJWTProfileAccessTokenClient(requester.GetClient()), tokenString)

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

	return s.Strategy.Encode(ctx, jwt.WithClaims(claims.ToMapClaims()), jwt.WithHeaders(header), jwt.WithJWTProfileAccessTokenClient(client))
}

func validateJWT(ctx context.Context, strategy jwt.Strategy, client jwt.Client, tokenString string) (token *jwt.Token, err error) {
	if token, err = strategy.Decode(ctx, tokenString, jwt.WithClient(client)); err != nil {
		return nil, fmtValidateJWTError(token, client, err)
	}

	if err = token.Claims.Valid(); err != nil {
		return token, fmtValidateJWTError(token, client, err)
	}

	return token, nil
}

func fmtValidateJWTError(token *jwt.Token, client jwt.Client, inner error) (err error) {
	var (
		clientText          string
		sigKID, sigAlg      string
		encKID, encAlg, enc string
	)

	if client != nil {
		clientText = fmt.Sprintf("provided by client with id '%s' ", client.GetID())
		sigKID, sigAlg = client.GetSigningKeyID(), client.GetSigningAlg()
		encKID, encAlg, enc = client.GetEncryptionKeyID(), client.GetEncryptionAlg(), client.GetEncryptionEnc()
	}

	if errJWTValidation := new(jwt.ValidationError); errors.As(inner, &errJWTValidation) {
		switch {
		case errJWTValidation.Has(jwt.ValidationErrorHeaderKeyIDInvalid):
			return oauth2.ErrInvalidTokenFormat.WithDebugf("Token %sis expected to be signed with the 'kid' header value '%s' but it was signed with the 'kid' header value '%s'.", clientText, sigKID, token.KeyID)
		case errJWTValidation.Has(jwt.ValidationErrorHeaderAlgorithmInvalid):
			return oauth2.ErrInvalidTokenFormat.WithDebugf("Token %sis expected to be signed with the 'alg' header value '%s' but it was signed with the 'alg' header value '%s'.", clientText, sigAlg, token.SignatureAlgorithm)
		case errJWTValidation.Has(jwt.ValidationErrorHeaderTypeInvalid):
			return oauth2.ErrInvalidTokenFormat.WithDebugf("Token %sis expected to be signed with the 'typ' header value '%s' but it was signed with the 'typ' header value '%s'.", clientText, consts.JSONWebTokenTypeJWT, token.Header[consts.JSONWebTokenHeaderType])
		case errJWTValidation.Has(jwt.ValidationErrorHeaderEncryptionTypeInvalid):
			return oauth2.ErrInvalidTokenFormat.WithDebugf("Token %sis expected to be encrypted with the 'typ' header value '%s' but it was encrypted with the 'typ' header value '%s'.", clientText, consts.JSONWebTokenTypeJWT, token.HeaderJWE[consts.JSONWebTokenHeaderType])
		case errJWTValidation.Has(jwt.ValidationErrorHeaderContentTypeInvalidMismatch):
			return oauth2.ErrInvalidTokenFormat.WithDebugf("Token %sis expected to be encrypted with a 'cty' header value and signed with a 'typ' value that match but it was encrypted with the 'cty' header value '%s' and signed with the 'typ' header value '%s'.", clientText, token.HeaderJWE[consts.JSONWebTokenHeaderContentType], token.HeaderJWE[consts.JSONWebTokenHeaderType])
		case errJWTValidation.Has(jwt.ValidationErrorHeaderContentTypeInvalid):
			return oauth2.ErrInvalidTokenFormat.WithDebugf("Token %sis expected to be encrypted with the 'cty' header value '%s' but it was encrypted with the 'cty' header value '%s'.", clientText, consts.JSONWebTokenTypeJWT, token.HeaderJWE[consts.JSONWebTokenHeaderContentType])
		case errJWTValidation.Has(jwt.ValidationErrorHeaderEncryptionKeyIDInvalid):
			return oauth2.ErrInvalidTokenFormat.WithDebugf("Token %sis expected to be encrypted with the 'kid' header value '%s' but it was encrypted with the 'kid' header value '%s'.", clientText, encKID, token.EncryptionKeyID)
		case errJWTValidation.Has(jwt.ValidationErrorHeaderKeyAlgorithmInvalid):
			return oauth2.ErrInvalidTokenFormat.WithDebugf("Token %sis expected to be encrypted with the 'alg' header value '%s' but it was encrypted with the 'alg' header value '%s'.", clientText, encAlg, token.KeyAlgorithm)
		case errJWTValidation.Has(jwt.ValidationErrorHeaderContentEncryptionInvalid):
			return oauth2.ErrInvalidTokenFormat.WithDebugf("Token %sis expected to be encrypted with the 'enc' header value '%s' but it was encrypted with the 'enc' header value '%s'.", clientText, enc, token.ContentEncryption)
		case errJWTValidation.Has(jwt.ValidationErrorMalformedNotCompactSerialized):
			return oauth2.ErrInvalidTokenFormat.WithDebugf("Token %sis malformed. The token does not appear to be a JWE or JWS compact serialized JWT.", clientText)
		case errJWTValidation.Has(jwt.ValidationErrorMalformed):
			return oauth2.ErrInvalidTokenFormat.WithDebugf("Token %sis malformed. %s.", clientText, strings.TrimPrefix(errJWTValidation.Error(), "go-jose/go-jose: "))
		case errJWTValidation.Has(jwt.ValidationErrorUnverifiable):
			return oauth2.ErrTokenSignatureMismatch.WithDebugf("Token %sis not able to be verified. %s.", clientText, strings.TrimPrefix(errJWTValidation.Error(), "go-jose/go-jose: "))
		case errJWTValidation.Has(jwt.ValidationErrorSignatureInvalid):
			return oauth2.ErrTokenSignatureMismatch.WithDebugf("Token %shas an invalid signature.", clientText)
		case errJWTValidation.Has(jwt.ValidationErrorExpired):
			exp, ok := token.Claims.GetExpiresAt()
			if ok {
				return oauth2.ErrTokenExpired.WithDebugf("Token %sexpired at %d.", clientText, exp)
			} else {
				return oauth2.ErrTokenExpired.WithDebugf("Token %sdoes not have an 'exp' claim or it has an invalid type.", clientText)
			}
		case errJWTValidation.Has(jwt.ValidationErrorIssuedAt):
			iat, ok := token.Claims.GetIssuedAt()
			if ok {
				return oauth2.ErrTokenClaim.WithDebugf("Token %sis issued in the future. The token was issued at %d.", clientText, iat)
			} else {
				return oauth2.ErrTokenClaim.WithDebugf("Token %sis issued in the future. The token does not have an 'iat' claim or it has an invalid type.", clientText)
			}
		case errJWTValidation.Has(jwt.ValidationErrorNotValidYet):
			nbf, ok := token.Claims.GetNotBefore()
			if ok {
				return oauth2.ErrTokenClaim.WithDebugf("Token %sis not valid yet. The token is not valid before %d.", clientText, nbf)
			} else {
				return oauth2.ErrTokenClaim.WithDebugf("Token %sis not valid yet. The token does not have an 'nbf' claim or it has an invalid type.", clientText)
			}
		case errJWTValidation.Has(jwt.ValidationErrorIssuer):
			iss, ok := token.Claims.GetIssuer()
			if ok {
				return oauth2.ErrTokenClaim.WithDebugf("Token %shas an invalid issuer. The token was expected to have an 'iss' claim with one of the following values: ''. The 'iss' claim has a value of '%s'.", clientText, iss)
			} else {
				return oauth2.ErrTokenClaim.WithDebugf("Token %shas an invalid issuer. The token does not have an 'iss' claim or it has an invalid type.", clientText)
			}
		case errJWTValidation.Has(jwt.ValidationErrorAudience):
			aud, ok := token.Claims.GetAudience()
			if ok {
				return oauth2.ErrTokenClaim.WithDebugf("Token %shas an invalid audience. The token was expected to have an 'iss' claim with one of the following values: ''. The 'iss' claim has a value of '%s'.", clientText, aud)
			} else {
				return oauth2.ErrTokenClaim.WithDebugf("Token %shas an invalid audience. The token does not have an 'iss' claim or it has an invalid type.", clientText)
			}
		case errJWTValidation.Has(jwt.ValidationErrorClaimsInvalid):
			return oauth2.ErrTokenClaim.WithDebugf("Token %shas invalid claims. Error occurred trying to validate the request objects claims: %s", clientText, strings.TrimPrefix(errJWTValidation.Error(), "go-jose/go-jose: "))
		default:
			return oauth2.ErrTokenClaim.WithDebugf("Token %scould not be validated. Error occurred trying to validate the token: %s", clientText, strings.TrimPrefix(errJWTValidation.Error(), "go-jose/go-jose: "))
		}
	} else if errJWKLookup := new(jwt.JWKLookupError); errors.As(inner, &errJWKLookup) {
		return oauth2.ErrRequestUnauthorized.WithDebugf("Token %scould not be validated due to a key lookup error. %s.", clientText, errJWKLookup.Description)
	} else {
		return oauth2.ErrRequestUnauthorized.WithDebugf("Token %scould not be validated. %s", clientText, oauth2.ErrorToDebugRFC6749Error(inner).Error())
	}
}
