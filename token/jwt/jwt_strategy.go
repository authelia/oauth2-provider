package jwt

import (
	"context"
	"fmt"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/x/errorsx"
)

// Strategy represents the strategy for encoding and decoding JWT's. It's important to note that this is an interface
// specifically so it can be mocked and the opts values have very important semantics which are difficult to document.
type Strategy interface {
	// Encode a JWT as either a JWS or JWE nested JWS.
	Encode(ctx context.Context, opts ...StrategyOpt) (tokenString string, signature string, err error)

	// Decrypt a JWT or if the provided JWT is a JWS just return it.
	Decrypt(ctx context.Context, tokenStringEnc string, opts ...StrategyOpt) (tokenString, signature string, jwe *jose.JSONWebEncryption, err error)

	// Decode a JWT. This performs decryption as well as basic signature validation. Optionally the signature validation
	// can be skipped and validated later using Validate.
	Decode(ctx context.Context, tokenString string, opts ...StrategyOpt) (token *Token, err error)

	// Validate allows performing the signature validation step after using the Decode function without a client while
	// also using WithAllowUnverified.
	Validate(ctx context.Context, token *Token, opts ...StrategyOpt) (err error)
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
	o := &StrategyOpts{
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
	} else if keySig, err = j.Issuer.GetIssuerJWK(ctx, o.client.GetSigningKeyID(), o.client.GetSigningAlg(), consts.JSONWebTokenUseSignature); err != nil {
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
			return "", "", errorsx.WithStack(fmt.Errorf("Failed to encrypt the JWT using the client secret. %w", err))
		}
	} else if keyEnc, err = FindClientPublicJWK(ctx, o.client, j.Config.GetJWKSFetcherStrategy(ctx), kid, alg, consts.JSONWebTokenUseEncryption, false); err != nil {
		return "", "", errorsx.WithStack(fmt.Errorf("Failed to encrypt the JWT using the client configuration. %w", err))
	}

	return encodeNestedCompactEncrypted(ctx, o.claims, o.headers, o.headersJWE, keySig, keyEnc, jose.ContentEncryption(enc))
}

func (j *DefaultStrategy) Decrypt(ctx context.Context, tokenStringEnc string, opts ...StrategyOpt) (tokenString, signature string, jwe *jose.JSONWebEncryption, err error) {
	if !IsEncryptedJWT(tokenStringEnc) {
		if IsSignedJWT(tokenStringEnc) {
			return tokenStringEnc, "", nil, nil
		} else {
			return tokenStringEnc, "", nil, fmt.Errorf("Provided value does not appear to be a JWE or JWS compact serialized JWT")
		}
	}

	o := &StrategyOpts{
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

	return tokenString, signature, jwe, nil
}

func (j *DefaultStrategy) Decode(ctx context.Context, tokenString string, opts ...StrategyOpt) (token *Token, err error) {
	o := &StrategyOpts{
		sigAlgorithm:      SignatureAlgorithms,
		keyAlgorithm:      EncryptionKeyAlgorithms,
		contentEncryption: ContentEncryptionAlgorithms,
		jwsKeyFunc:        nil,
		jweKeyFunc:        nil,
	}

	for _, opt := range opts {
		if err = opt(o); err != nil {
			return token, errorsx.WithStack(err)
		}
	}

	var (
		t   *jwt.JSONWebToken
		jwe *jose.JSONWebEncryption
	)

	tokenString, _, jwe, err = j.Decrypt(ctx, tokenString, opts...)
	if err != nil {
		return token, err
	}

	if t, err = jwt.ParseSigned(tokenString, o.sigAlgorithm); err != nil {
		return token, errorsx.WithStack(&ValidationError{Errors: ValidationErrorMalformed, Inner: err})
	}

	if token, err = newToken(t, nil); err != nil {
		return token, errorsx.WithStack(err)
	}

	token.AssignJWE(jwe)

	claims := MapClaims{}

	if err = t.UnsafeClaimsWithoutVerification(&claims); err != nil {
		return token, errorsx.WithStack(&ValidationError{Errors: ValidationErrorClaimsInvalid, Inner: err})
	}

	token.Claims = claims

	var alg string

	if _, alg, err = headerValidateJWS(t.Headers); err != nil {
		return token, errorsx.WithStack(&ValidationError{Errors: ValidationErrorMalformed, Inner: err})
	}

	validate := o.client != nil || !o.allowUnverified

	if alg != consts.JSONWebTokenAlgNone && validate {
		if err = j.validate(ctx, t, &claims, o); err != nil {
			return nil, errorsx.WithStack(err)
		}
	}

	token.valid = validate

	return token, nil
}

func (j *DefaultStrategy) Validate(ctx context.Context, token *Token, opts ...StrategyOpt) (err error) {
	if token == nil {
		return errorsx.WithStack(fmt.Errorf("token is nil"))
	}

	if token.valid {
		return nil
	}

	if token.parsedToken == nil {
		return errorsx.WithStack(fmt.Errorf("token is in an inconsistent state"))
	}

	o := &StrategyOpts{
		sigAlgorithm:      SignatureAlgorithms,
		keyAlgorithm:      EncryptionKeyAlgorithms,
		contentEncryption: ContentEncryptionAlgorithms,
		jwsKeyFunc:        nil,
		jweKeyFunc:        nil,
	}

	for _, opt := range opts {
		if err = opt(o); err != nil {
			return errorsx.WithStack(err)
		}
	}

	if err = j.validate(ctx, token.parsedToken, &MapClaims{}, o); err != nil {
		return err
	}

	token.valid = true

	return nil
}

func (j *DefaultStrategy) validate(ctx context.Context, t *jwt.JSONWebToken, dest any, o *StrategyOpts) (err error) {
	var (
		key      *jose.JSONWebKey
		kid, alg string
	)

	if kid, alg, err = headerValidateJWS(t.Headers); err != nil {
		return errorsx.WithStack(&ValidationError{Errors: ValidationErrorMalformed, Inner: err})
	}

	claims := MapClaims{}

	if o.jwsKeyFunc != nil {
		if key, err = o.jwsKeyFunc(ctx, t, claims); err != nil {
			return errorsx.WithStack(&ValidationError{Errors: ValidationErrorUnverifiable, Inner: err})
		}
	} else if o.client != nil && o.client.IsClientSigned() {
		if IsSignedJWTClientSecretAlg(alg) {
			if kid != "" {
				return errorsx.WithStack(&ValidationError{Errors: ValidationErrorHeaderKeyIDInvalid, Inner: fmt.Errorf("error validating the jws header: alg '%s' does not support tokens with a kid but the token has kid '%s'", alg, kid)})
			}

			if key, err = NewJWKFromClientSecret(ctx, o.client, "", alg, consts.JSONWebTokenUseSignature); err != nil {
				return errorsx.WithStack(&ValidationError{Errors: ValidationErrorUnverifiable, Inner: err})
			}
		} else {
			if key, err = FindClientPublicJWK(ctx, o.client, j.Config.GetJWKSFetcherStrategy(ctx), kid, alg, consts.JSONWebTokenUseSignature, true); err != nil {
				return errorsx.WithStack(&ValidationError{Errors: ValidationErrorUnverifiable, Inner: err})
			}
		}
	} else if key, err = j.Issuer.GetIssuerStrictJWK(ctx, kid, alg, consts.JSONWebTokenUseSignature); err != nil {
		return errorsx.WithStack(&ValidationError{Errors: ValidationErrorUnverifiable, Inner: err})
	}

	if err = t.Claims(getPublicJWK(key), &dest); err != nil {
		return errorsx.WithStack(&ValidationError{Errors: ValidationErrorSignatureInvalid, Inner: err})
	}

	return nil
}
