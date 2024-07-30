package jwt

import (
	"context"
	"fmt"

	"authelia.com/provider/oauth2/x/errorsx"
	"github.com/go-jose/go-jose/v4"
)

type Provider interface {
	Encode(ctx context.Context, recipient Recipient, claims MapClaims, headers, headersEnc Mapper) (tokenString string, signature string, err error)
	Decode(ctx context.Context, recipient Recipient, tokenString string) (token *Token, err error)
	Validate(ctx context.Context, recipient Recipient, tokenString string) (signature string, err error)
}

type GetIssuerJSONWebKeyFunc func(ctx context.Context, kid, alg, enc, use string) (key jose.JSONWebKey, err error)

type GetIssuerJWKSFunc func(ctx context.Context) (jwks *jose.JSONWebKeySet, err error)

type GetJSONWebKeyFunc func(ctx context.Context, jwks *jose.JSONWebKeySet, kid, alg, enc, use string) (key jose.JSONWebKey, err error)

// DefaultProvider is responsible for providing JWK encoding and cryptographic functionality.
type DefaultProvider struct {
	GetIssuerJSONWebKey GetIssuerJSONWebKeyFunc
	GetJSONWebKey       GetJSONWebKeyFunc
}

// Encode generates a new JWT and encodes it.
func (j *DefaultProvider) Encode(ctx context.Context, recipient Recipient, claims MapClaims, headers, headersJWE Mapper) (tokenString string, signature string, err error) {
	var (
		key jose.JSONWebKey
	)

	if key, err = j.GetIssuerJSONWebKey(ctx, recipient.GetSignatureKeyID(), recipient.GetSignatureAlg(), "", "sig"); err != nil {
		return "", "", errorsx.WithStack(fmt.Errorf("error occurred retrieving issuer jwk: %w", err))
	}

	kid, alg, enc := recipient.GetEncryptionKeyID(), recipient.GetEncryptionAlg(), recipient.GetEncryptionEnc()

	if len(kid) == 0 && len(alg) == 0 {
		return encodeCompactSigned(ctx, claims, headers, key)
	}

	var ekey jose.JSONWebKey

	if ekey, err = j.GetJSONWebKey(ctx, recipient.GetJSONWebKeySet(), kid, alg, enc, "enc"); err != nil {
		return "", "", errorsx.WithStack(fmt.Errorf("error occurred retrieving client jwk: %w", err))
	}

	return encodeNestedCompactEncrypted(claims, headers, headersJWE, key, ekey, jose.ContentEncryption(enc))
}
