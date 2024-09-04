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
	Encode(ctx context.Context, opts ...StrategyOpt) (tokenString string, signature string, err error)
	Decode(ctx context.Context, tokenString string, opts ...StrategyOpt) (token *Token, err error)
	Decrypt(ctx context.Context, tokenStringEnc string, opts ...StrategyOpt) (tokenString, signature string, jwe *jose.JSONWebEncryption, err error)
}

type StrategyConfig interface {
	// GetJWKSFetcherStrategy returns the JWKS fetcher strategy.
	GetJWKSFetcherStrategy(ctx context.Context) (strategy JWKSFetcherStrategy)
}

type JWKSFetcherStrategy interface {
	// Resolve returns the JSON Web Key Set, or an error if something went wrong. The forceRefresh, if true, forces
	// the strategy to fetch the key from the remote. If forceRefresh is false, the strategy may use a caching strategy
	// to fetch the key.
	Resolve(ctx context.Context, location string, ignoreCache bool) (jwks *jose.JSONWebKeySet, err error)
}

// DefaultStrategy is responsible for providing JWK encoding and cryptographic functionality.
type DefaultStrategy struct {
	Config StrategyConfig
	Issuer Issuer
}

func (j *DefaultStrategy) Encode(ctx context.Context, opts ...StrategyOpt) (tokenString string, signature string, err error) {
	o := &optsStrategy{
		claims:  MapClaims{},
		headers: NewHeaders(),
	}

	for _, opt := range opts {
		if err = opt(o); err != nil {
			return "", "", err
		}
	}

	var (
		keySig *jose.JSONWebKey
	)

	if o.client == nil {
		if keySig, err = j.Issuer.GetIssuerJWK(ctx, "", string(jose.RS256), consts.JSONWebTokenUseSignature); err != nil {
			return "", "", errorsx.WithStack(fmt.Errorf("error occurred retrieving issuer jwk: %w", err))
		}
	} else if keySig, err = j.Issuer.GetIssuerJWK(ctx, o.client.GetSignatureKeyID(), o.client.GetSignatureAlg(), consts.JSONWebTokenUseSignature); err != nil {
		return "", "", errorsx.WithStack(fmt.Errorf("error occurred retrieving issuer jwk: %w", err))
	}

	if o.client == nil {
		return encodeCompactSigned(ctx, o.claims, o.headers, keySig)
	}

	kid, alg, enc := o.client.GetEncryptionKeyID(), o.client.GetEncryptionAlg(), o.client.GetEncryptionEnc()

	if len(kid) == 0 && len(alg) == 0 {
		return encodeCompactSigned(ctx, o.claims, o.headers, keySig)
	}

	if len(enc) == 0 {
		enc = string(jose.A128CBC_HS256)
	}

	var keyEnc *jose.JSONWebKey

	if IsEncryptedJWTClientSecretAlg(alg) {
		if keyEnc, err = NewJWKFromClientSecret(ctx, o.client, kid, alg, consts.JSONWebTokenUseEncryption); err != nil {
			return "", "", errorsx.WithStack(fmt.Errorf("error occurred retrieving issuer jwk: error occurred retrieving the client secret: %w", err))
		}
	} else if keyEnc, err = FindClientPublicJWK(ctx, o.client, j.Config.GetJWKSFetcherStrategy(ctx), kid, alg, consts.JSONWebTokenUseEncryption, false); err != nil {
		return "", "", errorsx.WithStack(fmt.Errorf("error occurred retrieving client jwk: %w", err))
	}

	return encodeNestedCompactEncrypted(ctx, o.claims, o.headers, o.headersJWE, keySig, keyEnc, jose.ContentEncryption(enc))
}

func (j *DefaultStrategy) Decode(ctx context.Context, tokenString string, opts ...StrategyOpt) (token *Token, err error) {
	o := &optsStrategy{
		sigAlgorithm:      SignatureAlgorithms,
		keyAlgorithm:      EncryptionKeyAlgorithms,
		contentEncryption: ContentEncryptionAlgorithms,
		jwsKeyFunc:        nil,
		jweKeyFunc:        nil,
	}

	for _, opt := range opts {
		if err = opt(o); err != nil {
			return nil, errorsx.WithStack(err)
		}
	}

	var (
		key *jose.JSONWebKey
		t   *jwt.JSONWebToken
		jwe *jose.JSONWebEncryption
	)

	if IsEncryptedJWT(tokenString) {
		if jwe, err = jose.ParseEncryptedCompact(tokenString, o.keyAlgorithm, o.contentEncryption); err != nil {
			return nil, errorsx.WithStack(&ValidationError{Errors: ValidationErrorMalformed, Inner: err})
		}

		var (
			kid, alg, cty string
		)

		if kid, alg, _, cty, err = headerValidateJWE(jwe.Header); err != nil {
			return nil, errorsx.WithStack(&ValidationError{Errors: ValidationErrorMalformed, Inner: err})
		}

		if o.jweKeyFunc != nil {
			if key, err = o.jweKeyFunc(ctx, jwe, kid, alg); err != nil {
				return nil, errorsx.WithStack(&ValidationError{Errors: ValidationErrorUnverifiable, Inner: err})
			}
		} else if IsEncryptedJWTClientSecretAlg(alg) {
			if o.client == nil {
				return nil, errorsx.WithStack(&ValidationError{Errors: ValidationErrorUnverifiable, Inner: err})
			}

			if key, err = NewJWKFromClientSecret(ctx, o.client, kid, alg, consts.JSONWebTokenUseEncryption); err != nil {
				return nil, errorsx.WithStack(&ValidationError{Errors: ValidationErrorUnverifiable, Inner: err})
			}
		} else if key, err = j.Issuer.GetIssuerStrictJWK(ctx, kid, alg, consts.JSONWebTokenUseEncryption); err != nil {
			return nil, errorsx.WithStack(&ValidationError{Errors: ValidationErrorUnverifiable, Inner: err})
		}

		var rawJWT []byte

		if rawJWT, err = jwe.Decrypt(key); err != nil {
			return nil, errorsx.WithStack(&ValidationError{Errors: ValidationErrorMalformed, Inner: err})
		}

		if t, err = jwt.ParseSigned(string(rawJWT), o.sigAlgorithm); err != nil {
			return nil, errorsx.WithStack(&ValidationError{Errors: ValidationErrorMalformed, Inner: err})
		}

		if err = headerValidateJWSNested(t.Headers, cty); err != nil {
			return nil, errorsx.WithStack(&ValidationError{Errors: ValidationErrorMalformed, Inner: err})
		}
	} else if t, err = jwt.ParseSigned(tokenString, o.sigAlgorithm); err != nil {
		return nil, errorsx.WithStack(&ValidationError{Errors: ValidationErrorMalformed, Inner: err})
	}

	claims := MapClaims{}

	if err = t.UnsafeClaimsWithoutVerification(&claims); err != nil {
		return nil, errorsx.WithStack(&ValidationError{Errors: ValidationErrorClaimsInvalid, Inner: err})
	}

	var kid, alg string

	if kid, alg, err = headerValidateJWS(t.Headers); err != nil {
		return nil, errorsx.WithStack(&ValidationError{Errors: ValidationErrorMalformed, Inner: err})
	}

	if alg == consts.JSONWebTokenAlgNone {
		if err = t.UnsafeClaimsWithoutVerification(&claims); err != nil {
			return nil, errorsx.WithStack(&ValidationError{Errors: ValidationErrorSignatureInvalid, Inner: err})
		}
	} else {
		if o.jwsKeyFunc != nil {
			if key, err = o.jwsKeyFunc(ctx, t, claims); err != nil {
				return nil, errorsx.WithStack(&ValidationError{Errors: ValidationErrorUnverifiable, Inner: err})
			}
		} else if o.client != nil && o.client.IsClientSigned() {
			if ckid := o.client.GetSignatureKeyID(); ckid != "" && ckid != kid {
				return nil, errorsx.WithStack(&ValidationError{Errors: ValidationErrorMalformed, Inner: fmt.Errorf("error validating the jws header: kid '%s' does not match the registered kid '%s'", kid, ckid)})
			}

			if calg := o.client.GetSignatureAlg(); calg != "" && calg != alg {
				return nil, errorsx.WithStack(&ValidationError{Errors: ValidationErrorMalformed, Inner: fmt.Errorf("error validating the jws header: alg '%s' does not match the registered alg '%s'", alg, calg)})
			}

			if key, err = FindClientPublicJWK(ctx, o.client, j.Config.GetJWKSFetcherStrategy(ctx), kid, alg, consts.JSONWebTokenUseSignature, true); err != nil {
				return nil, errorsx.WithStack(&ValidationError{Errors: ValidationErrorUnverifiable, Inner: err})
			}
		} else if key, err = j.Issuer.GetIssuerStrictJWK(ctx, kid, alg, consts.JSONWebTokenUseSignature); err != nil {
			return nil, errorsx.WithStack(&ValidationError{Errors: ValidationErrorUnverifiable, Inner: err})
		}

		if err = t.Claims(key.Public(), &claims); err != nil {
			return nil, errorsx.WithStack(&ValidationError{Errors: ValidationErrorSignatureInvalid, Inner: err})
		}
	}

	if token, err = newToken(t, claims); err != nil {
		return nil, errorsx.WithStack(err)
	}

	token.AssignJWE(jwe)

	if err = claims.Valid(); err != nil {
		return token, errorsx.WithStack(err)
	}

	token.valid = true

	return token, nil
}

func (j *DefaultStrategy) Decrypt(ctx context.Context, tokenStringEnc string, opts ...StrategyOpt) (tokenString, signature string, jwe *jose.JSONWebEncryption, err error) {
	if !IsEncryptedJWT(tokenStringEnc) {
		if IsSignedJWT(tokenStringEnc) {
			return tokenStringEnc, "", nil, nil
		} else {
			return tokenStringEnc, "", nil, fmt.Errorf("token does not appear to be a jwe or jws compact serializd jwt")
		}
	}

	o := &optsStrategy{
		sigAlgorithm:      SignatureAlgorithmsNone,
		keyAlgorithm:      EncryptionKeyAlgorithms,
		contentEncryption: ContentEncryptionAlgorithms,
	}

	for _, opt := range opts {
		if err = opt(o); err != nil {
			return "", "", nil, errorsx.WithStack(&ValidationError{Errors: ValidationErrorUnverifiable, Inner: err})
		}
	}

	var (
		key *jose.JSONWebKey
	)

	if jwe, err = jose.ParseEncryptedCompact(tokenStringEnc, o.keyAlgorithm, o.contentEncryption); err != nil {
		return "", "", nil, errorsx.WithStack(&ValidationError{Errors: ValidationErrorMalformed, Inner: err})
	}

	var (
		kid, alg, cty string
	)

	if kid, alg, _, cty, err = headerValidateJWE(jwe.Header); err != nil {
		return "", "", nil, errorsx.WithStack(&ValidationError{Errors: ValidationErrorMalformed, Inner: err})
	}

	if o.jweKeyFunc != nil {
		if key, err = o.jweKeyFunc(ctx, jwe, kid, alg); err != nil {
			return "", "", nil, errorsx.WithStack(&ValidationError{Errors: ValidationErrorUnverifiable, Inner: err})
		}
	} else if IsEncryptedJWTClientSecretAlg(alg) {
		if o.client == nil {
			return "", "", nil, errorsx.WithStack(&ValidationError{Errors: ValidationErrorUnverifiable, Inner: err})
		}

		if key, err = NewJWKFromClientSecret(ctx, o.client, kid, alg, consts.JSONWebTokenUseEncryption); err != nil {
			return "", "", nil, errorsx.WithStack(&ValidationError{Errors: ValidationErrorUnverifiable, Inner: err})
		}
	} else if key, err = j.Issuer.GetIssuerStrictJWK(ctx, kid, alg, consts.JSONWebTokenUseEncryption); err != nil {
		return "", "", nil, errorsx.WithStack(&ValidationError{Errors: ValidationErrorUnverifiable, Inner: err})
	}

	var tokenRaw []byte

	if tokenRaw, err = jwe.Decrypt(key); err != nil {
		return "", "", nil, errorsx.WithStack(&ValidationError{Errors: ValidationErrorMalformed, Inner: err})
	}

	tokenString = string(tokenRaw)

	var t *jwt.JSONWebToken

	if t, err = jwt.ParseSigned(tokenString, SignatureAlgorithmsNone); err != nil {
		return "", "", nil, errorsx.WithStack(&ValidationError{Errors: ValidationErrorMalformed, Inner: err})
	}

	if err = headerValidateJWSNested(t.Headers, cty); err != nil {
		return "", "", nil, errorsx.WithStack(&ValidationError{Errors: ValidationErrorMalformed, Inner: err})
	}

	if signature, err = getJWTSignature(tokenString); err != nil {
		return "", "", nil, errorsx.WithStack(&ValidationError{Errors: ValidationErrorMalformed, Inner: err})
	}

	return string(tokenRaw), signature, jwe, nil
}
