// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package jwt

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"slices"

	"authelia.com/provider/jose"
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

// NewDefaultIssuerFromJWKS returns a new issuer from a jose.JSONWebKeySet and verifies that one RS256 signature key
// exists.
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

// DefaultIssuer is the default Issuer, backed by a JSON Web Key Set. It implements IssuerVerificationJWKProvider, see
// WithVerificationOnlyKeys.
type DefaultIssuer struct {
	jwks         *jose.JSONWebKeySet
	verification *jose.JSONWebKeySet
}

// WithVerificationOnlyKeys returns a copy of the issuer which has the given keys as its verification only keys,
// replacing any it had. A verification only key verifies and decrypts tokens but is never used to issue one, which
// allows a new key to be published before it is used and an old key to be honored after it is retired. See
// IssuerVerificationJWKProvider for the semantics, including the requirement to keep publishing these keys.
func (i *DefaultIssuer) WithVerificationOnlyKeys(keys ...jose.JSONWebKey) (issuer *DefaultIssuer) {
	issuer = &DefaultIssuer{}

	if i != nil {
		issuer.jwks = i.jwks
	}

	if len(keys) != 0 {
		issuer.verification = &jose.JSONWebKeySet{Keys: slices.Clone(keys)}
	}

	return issuer
}

// GetIssuerJWK returns the issuing key which matches the alg and use values exactly, and the kid value when it is not
// empty. When more than one key matches the first is returned. A verification only key is never returned. The error
// is a *JWKLookupError.
func (i *DefaultIssuer) GetIssuerJWK(ctx context.Context, kid, alg, use string) (jwk *jose.JSONWebKey, err error) {
	return searchJWKS(i.issuingKeys(), kid, alg, use, false, false)
}

// GetIssuerStrictJWK returns the issuing key which matches the alg and use values exactly, and the kid value when it
// is not empty. It returns an error when more than one key matches. A verification only key is never returned. The
// error is a *JWKLookupError.
func (i *DefaultIssuer) GetIssuerStrictJWK(ctx context.Context, kid, alg, use string) (jwk *jose.JSONWebKey, err error) {
	return searchJWKS(i.issuingKeys(), kid, alg, use, true, false)
}

// GetIssuerVerificationJWK returns the key from the issuing keys and the verification only keys which matches the alg
// and use values exactly, and the kid value when it is not empty. It returns an error when more than one key matches,
// so a verification only key must not share the kid, alg, and use values of another key. The error is a
// *JWKLookupError.
func (i *DefaultIssuer) GetIssuerVerificationJWK(ctx context.Context, kid, alg, use string) (jwk *jose.JSONWebKey, err error) {
	return searchJWKS(i.verificationKeys(), kid, alg, use, true, false)
}

// GetIssuerSigningAlgValues returns the sorted unique algorithms of the issuing keys with a use of sig, excluding none.
// The algorithms of the verification only keys are not included.
//
// See: https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
func (i *DefaultIssuer) GetIssuerSigningAlgValues(ctx context.Context) (algs []string) {
	return keyAlgValues(i.issuingKeys(), JSONWebTokenUseSignature)
}

// GetIssuerDecryptionAlgValues returns the sorted unique algorithms of the issuing keys and the verification only keys
// with a use of enc.
func (i *DefaultIssuer) GetIssuerDecryptionAlgValues(ctx context.Context) (algs []string) {
	return keyAlgValues(i.verificationKeys(), JSONWebTokenUseEncryption)
}

func (i *DefaultIssuer) issuingKeys() (jwks *jose.JSONWebKeySet) {
	if i == nil {
		return nil
	}

	return i.jwks
}

func (i *DefaultIssuer) verificationKeys() (jwks *jose.JSONWebKeySet) {
	switch {
	case i == nil:
		return nil
	case i.verification == nil:
		return i.jwks
	case i.jwks == nil:
		return i.verification
	default:
		return &jose.JSONWebKeySet{Keys: slices.Concat(i.jwks.Keys, i.verification.Keys)}
	}
}

func keyAlgValues(jwks *jose.JSONWebKeySet, use string) (algs []string) {
	if jwks == nil {
		return nil
	}

	for _, key := range jwks.Keys {
		if key.Use != use {
			continue
		}

		if key.Algorithm == "" || key.Algorithm == JSONWebTokenAlgNone {
			continue
		}

		algs = append(algs, key.Algorithm)
	}

	slices.Sort(algs)

	return slices.Compact(algs)
}

// Issuer provides the JSON Web Keys and algorithms used to issue tokens. The kid, alg, and use values of a lookup
// select a key as follows: the use value ('sig' or 'enc') and the alg value must match the key exactly, and the kid
// value must match the key when it is not empty, while an empty kid value matches any key. A lookup which finds no
// key returns a *JWKLookupError.
//
// The keys returned by GetIssuerJWK and GetIssuerStrictJWK are the issuing keys, which sign the tokens the server
// issues. Every algorithm returned by GetIssuerSigningAlgValues must resolve via GetIssuerJWK with an empty kid value
// and a use value of 'sig', and every algorithm which resolves this way must be returned, as the former is advertised
// and accepted in client registrations and the latter is what tokens are signed with. An implementation which
// resolves aliases of an algorithm, such as 'EdDSA' and 'Ed25519', must therefore return each alias it resolves.
//
// An implementation which holds keys that must verify or decrypt but never issue, such as during a key rotation,
// also implements IssuerVerificationJWKProvider.
type Issuer interface {
	// GetIssuerJWK returns the issuing key which matches the kid, alg, and use values. When more than one key matches
	// the first is returned, which makes the order of the keys the preference when the kid value is empty. This is
	// the lookup used to sign a token.
	GetIssuerJWK(ctx context.Context, kid, alg, use string) (jwk *jose.JSONWebKey, err error)

	// GetIssuerStrictJWK returns the issuing key which matches the kid, alg, and use values, and returns an error
	// when more than one key matches. This is the lookup used to sign a token with an explicitly selected key, and to
	// verify and decrypt a token when the implementation is not an IssuerVerificationJWKProvider.
	GetIssuerStrictJWK(ctx context.Context, kid, alg, use string) (jwk *jose.JSONWebKey, err error)

	// GetIssuerSigningAlgValues returns the sorted unique signing algorithms of the issuing keys with a use value of
	// 'sig', excluding 'none'. These are the algorithms the server can sign with, so the algorithms of keys which
	// only verify are not included.
	//
	// See: https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
	GetIssuerSigningAlgValues(ctx context.Context) (algs []string)

	// GetIssuerDecryptionAlgValues returns the sorted unique key management algorithms of the keys with a use value
	// of 'enc' which the server decrypts with. Unlike GetIssuerSigningAlgValues this includes the algorithms of the
	// verification only keys of an IssuerVerificationJWKProvider, as a JWE is only accepted when its algorithm is one
	// of these values.
	GetIssuerDecryptionAlgValues(ctx context.Context) (algs []string)
}

// IssuerVerificationJWKProvider is optionally implemented by an Issuer which has verification only keys: keys which
// verify the signature of, and decrypt, the tokens of the server but which never sign one. This permits rotating a
// key without an interruption. A new key is first added as a verification only key so that it is published before any
// token is signed with it, and a retired key is kept as a verification only key until every token signed with it, and
// every JWE a client may still encrypt to it, has expired.
//
// The verification only keys must never be returned by Issuer.GetIssuerJWK or Issuer.GetIssuerStrictJWK, and their
// algorithms must not be returned by Issuer.GetIssuerSigningAlgValues unless an issuing key has the same algorithm.
// The algorithms of those with a use value of 'enc' must be returned by Issuer.GetIssuerDecryptionAlgValues.
//
// This library does not serve the JSON Web Key Set of the server. The implementer must publish the public part of
// every verification only key at the 'jwks_uri' for as long as it is one, otherwise other parties can neither verify
// the tokens signed with a retired key nor learn of a new key before it is used.
//
// See: https://openid.net/specs/openid-connect-core-1_0.html#RotateSigKeys
// See: https://openid.net/specs/openid-connect-core-1_0.html#RotateEncKeys
type IssuerVerificationJWKProvider interface {
	// GetIssuerVerificationJWK returns the key from the issuing keys and the verification only keys which matches the
	// kid, alg, and use values, with the semantics of Issuer.GetIssuerStrictJWK: it returns an error when more than
	// one key matches. A token which has no 'kid' header value can therefore only be verified while a single key has
	// its algorithm.
	GetIssuerVerificationJWK(ctx context.Context, kid, alg, use string) (jwk *jose.JSONWebKey, err error)
}
