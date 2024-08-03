package jwt

import (
	"context"
	"fmt"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/x/errorsx"
)

// Strategy represents the strategy for encoding and decoding JWT's.
type Strategy interface {
	Encode(ctx context.Context, client Client, claims MapClaims, headers, headersJWE Mapper) (tokenString string, signature string, err error)
	Decode(ctx context.Context, tokenString string, client Client) (token *Token, err error)
	DecodeCustom(ctx context.Context, tokenString string, client Client, encryptionKeyAlgorithms []jose.KeyAlgorithm, contentEncryption []jose.ContentEncryption, signatureAlgorithms []jose.SignatureAlgorithm) (token *Token, err error)
	//	Validate(ctx context.Context, recipient Client, tokenString string) (signature string, err error)
}

type JWKSFetcherStrategy interface {
	// Resolve returns the JSON Web Key Set, or an error if something went wrong. The forceRefresh, if true, forces
	// the strategy to fetch the key from the remote. If forceRefresh is false, the strategy may use a caching strategy
	// to fetch the key.
	Resolve(ctx context.Context, location string, ignoreCache bool) (jwks *jose.JSONWebKeySet, err error)
}

type StrategyConfig interface {
	// GetJWKSFetcherStrategy returns the JWKS fetcher strategy.
	GetJWKSFetcherStrategy(ctx context.Context) (strategy JWKSFetcherStrategy)
}

// DefaultStrategy is responsible for providing JWK encoding and cryptographic functionality.
type DefaultStrategy struct {
	Config StrategyConfig
	Issuer Issuer
}

// Encode generates a new JWT and encodes it.
func (j *DefaultStrategy) Encode(ctx context.Context, client Client, claims MapClaims, headers, headersJWE Mapper) (tokenString string, signature string, err error) {
	var (
		jwks *jose.JSONWebKeySet
		key  *jose.JSONWebKey
	)

	if jwks, err = j.Issuer.GetJSONWebKeys(ctx); err != nil {
		return "", "", errorsx.WithStack(fmt.Errorf("error occurred retrieving issuer jwks: %w", err))
	}

	if client == nil {
		if key, err = findKey("", string(jose.RS256), consts.JSONWebTokenUseSignature, jwks, false); err != nil {
			return "", "", errorsx.WithStack(fmt.Errorf("error occurred retrieving issuer jwk: %w", err))
		}
	} else if key, err = findKey(client.GetSignatureKeyID(), client.GetSignatureAlg(), consts.JSONWebTokenUseSignature, jwks, true); err != nil {
		return "", "", errorsx.WithStack(fmt.Errorf("error occurred retrieving issuer jwk: %w", err))
	}

	if client == nil {
		return encodeCompactSigned(ctx, claims, headers, key)
	}

	kid, alg, enc := client.GetEncryptionKeyID(), client.GetEncryptionAlg(), client.GetEncryptionEnc()

	if len(kid) == 0 && len(alg) == 0 {
		return encodeCompactSigned(ctx, claims, headers, key)
	}

	var ekey *jose.JSONWebKey

	if ekey, err = findKey(kid, alg, consts.JSONWebTokenUseEncryption, client.GetJSONWebKeys(), true); err != nil {
		return "", "", errorsx.WithStack(fmt.Errorf("error occurred retrieving client jwk: %w", err))
	}

	return encodeNestedCompactEncrypted(claims, headers, headersJWE, key, ekey, jose.ContentEncryption(enc))
}

func (j *DefaultStrategy) Decode(ctx context.Context, tokenString string, client Client) (token *Token, err error) {
	return j.DecodeCustom(ctx, tokenString, client, EncryptionKeyAlgorithms, ContentEncryptionAlgorithms, SignatureAlgorithms)
}

func (j *DefaultStrategy) DecodeCustom(ctx context.Context, tokenString string, client Client, encryptionKeyAlgorithms []jose.KeyAlgorithm, contentEncryption []jose.ContentEncryption, signatureAlgorithms []jose.SignatureAlgorithm) (token *Token, err error) {
	var (
		issuerJWKs *jose.JSONWebKeySet
		key        *jose.JSONWebKey
		t          *jwt.JSONWebToken
	)

	if issuerJWKs, err = j.Issuer.GetJSONWebKeys(ctx); err != nil {
		return nil, err
	}

	if IsEncryptedJWT(tokenString) {
		var nested *jwt.NestedJSONWebToken
		var jwe *jose.JSONWebEncryption

		if jwe, err = jose.ParseEncryptedCompact(tokenString, encryptionKeyAlgorithms, contentEncryption); err != nil {
			return nil, errorsx.WithStack(err)
		}
		if nested, err = jwt.ParseSignedAndEncrypted(tokenString, encryptionKeyAlgorithms, contentEncryption, signatureAlgorithms); err != nil {
			return nil, errorsx.WithStack(err)
		}

		var (
			kid, alg string
		)

		if kid, alg, _, err = headerValidateJWE(nested.Headers); err != nil {
			return nil, errorsx.WithStack(err)
		}

		if key, err = findKey(kid, alg, consts.JSONWebTokenUseEncryption, issuerJWKs, true); err != nil {
			return nil, errorsx.WithStack(err)
		}

		if t, err = nested.Decrypt(key); err != nil {
			return nil, errorsx.WithStack(err)
		}
	} else if t, err = jwt.ParseSigned(tokenString, signatureAlgorithms); err != nil {
		return nil, errorsx.WithStack(err)
	}

	var kid, alg string

	if kid, alg, err = headerValidateJWS(t.Headers); err != nil {
		return nil, errorsx.WithStack(err)
	}

	if client != nil && client.IsClientSigned() {
		if ckid := client.GetSignatureKeyID(); ckid != "" && ckid != kid {
			return nil, errorsx.WithStack(fmt.Errorf("error validating the jws header: kid '%s' does not match the registered kid '%s'", kid, ckid))
		}

		if calg := client.GetSignatureAlg(); calg != "" && calg != alg {
			return nil, errorsx.WithStack(fmt.Errorf("error validating the jws header: alg '%s' does not match the registered alg '%s'", alg, calg))
		}

		if key, err = FindClientPublicJWK(ctx, client, j.Config.GetJWKSFetcherStrategy(ctx), kid, alg, consts.JSONWebTokenUseSignature); err != nil {
			return nil, errorsx.WithStack(err)
		}
	} else if key, err = findKey(kid, alg, consts.JSONWebTokenUseSignature, issuerJWKs, true); err != nil {
		return nil, errorsx.WithStack(err)
	}

	claims := MapClaims{}

	if err = t.UnsafeClaimsWithoutVerification(&claims); err != nil {
		return nil, &ValidationError{Errors: ValidationErrorClaimsInvalid, text: err.Error()}
	}

	if err = t.Claims(key, &claims); err != nil {
		return nil, errorsx.WithStack(&ValidationError{Errors: ValidationErrorSignatureInvalid, text: err.Error()})
	}

	if token, err = newToken(t, claims); err != nil {
		return nil, errorsx.WithStack(err)
	}

	if err = claims.Valid(); err != nil {
		return token, errorsx.WithStack(&ValidationError{Inner: err, Errors: ValidationErrorClaimsInvalid})
	}

	token.valid = true

	return token, nil
}
