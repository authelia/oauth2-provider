package jwt

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"

	"github.com/go-jose/go-jose/v4"
)

// NewDefaultIssuer returns a new issuer and verifies that one RS256 key exists.
func NewDefaultIssuer(keys ...jose.JSONWebKey) (issuer *DefaultIssuer, err error) {
	jwks := &jose.JSONWebKeySet{
		Keys: make([]jose.JSONWebKey, len(keys)),
	}

	hasRS256 := false

	for i, key := range keys {
		jwks.Keys[i] = key

		if hasRS256 {
			continue
		}

		if key.Use != JSONWebTokenUseSignature {
			continue
		}

		if key.Algorithm != string(jose.RS256) {
			continue
		}

		hasRS256 = true
	}

	if !hasRS256 {
		return nil, errors.New("no RS256 signature algorithm found")
	}

	return NewDefaultIssuerUnverifiedFromJWKS(jwks), nil
}

func NewDefaultIssuerFromJWKS(jwks *jose.JSONWebKeySet) (issuer *DefaultIssuer, err error) {
	for _, key := range jwks.Keys {
		if key.Use != JSONWebTokenUseSignature {
			continue
		}

		if key.Algorithm != string(jose.RS256) {
			continue
		}

		return &DefaultIssuer{jwks: jwks}, nil
	}

	return nil, errors.New("no RS256 signature algorithm found")
}

// NewDefaultIssuerUnverifiedFromJWKS returns a new issuer from a jose.JSONWebKeySet without verification.
func NewDefaultIssuerUnverifiedFromJWKS(jwks *jose.JSONWebKeySet) (issuer *DefaultIssuer) {
	return &DefaultIssuer{jwks: jwks}
}

// MustNewDefaultIssuerRS256 is the same as NewDefaultIssuerRS256 but it panics if an error occurs.
func MustNewDefaultIssuerRS256(key any) (issuer *DefaultIssuer) {
	var err error

	if issuer, err = NewDefaultIssuerRS256(key); err != nil {
		panic(err)
	}

	return issuer
}

// NewDefaultIssuerRS256 returns an issuer with a single key and returns an error if it's not an RSA2048 or higher key.
func NewDefaultIssuerRS256(key any) (issuer *DefaultIssuer, err error) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		if n := k.Size(); n < 256 {
			return nil, fmt.Errorf("key must be an *rsa.PrivateKey with at least 2048 bits but got %d", n*8)
		}

		return NewDefaultIssuerRS256Unverified(key), nil
	default:
		return nil, fmt.Errorf("key must be an *rsa.PrivateKey but got %T", k)
	}
}

// NewDefaultIssuerRS256Unverified returns an issuer with a single key asserting the type is an RSA key.
func NewDefaultIssuerRS256Unverified(key any) (issuer *DefaultIssuer) {
	return &DefaultIssuer{
		jwks: &jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{
				{
					Key:       key,
					KeyID:     "default",
					Algorithm: string(jose.RS256),
					Use:       JSONWebTokenUseSignature,
				},
			},
		},
	}
}

// GenDefaultIssuer generates a *DefaultIssuer with a random RSA key.
func GenDefaultIssuer() (issuer *DefaultIssuer, err error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	return NewDefaultIssuerRS256(key)
}

// MustGenDefaultIssuer is the same as GenDefaultIssuer but it panics on an error.
func MustGenDefaultIssuer() (issuer *DefaultIssuer) {
	var err error

	if issuer, err = GenDefaultIssuer(); err != nil {
		panic(err)
	}

	return issuer
}

type DefaultIssuer struct {
	jwks *jose.JSONWebKeySet
}

func (i *DefaultIssuer) GetIssuerJWK(ctx context.Context, kid, alg, use string) (jwk *jose.JSONWebKey, err error) {
	return SearchJWKS(i.jwks, kid, alg, use, false)
}

func (i *DefaultIssuer) GetIssuerStrictJWK(ctx context.Context, kid, alg, use string) (jwk *jose.JSONWebKey, err error) {
	return SearchJWKS(i.jwks, kid, alg, use, true)
}

type Issuer interface {
	GetIssuerJWK(ctx context.Context, kid, alg, use string) (jwk *jose.JSONWebKey, err error)
	GetIssuerStrictJWK(ctx context.Context, kid, alg, use string) (jwk *jose.JSONWebKey, err error)
}
