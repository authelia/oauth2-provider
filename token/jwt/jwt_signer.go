// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

// Package jwt is able to generate and validate json web tokens.
// Follows https://datatracker.ietf.org/doc/html/rfc7519

package jwt

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"strings"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/pkg/errors"

	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/x/errorsx"
)

type Signer interface {
	Generate(ctx context.Context, claims MapClaims, header Mapper) (tokenString string, signature string, err error)
	Validate(ctx context.Context, tokenString string) (signature string, err error)
	Hash(ctx context.Context, in []byte) ([]byte, error)
	Decode(ctx context.Context, tokenString string) (token *Token, err error)
	GetSignature(ctx context.Context, token string) (signature string, err error)
	GetSigningMethodLength(ctx context.Context) (length int)
}

var SHA256HashSize = crypto.SHA256.Size()

type GetPrivateKeyFunc func(ctx context.Context) (key any, err error)

// DefaultSigner is responsible for generating and validating JWT challenges
type DefaultSigner struct {
	GetPrivateKey GetPrivateKeyFunc
}

// Generate generates a new authorize code or returns an error. set secret
func (j *DefaultSigner) Generate(ctx context.Context, claims MapClaims, header Mapper) (tokenString string, signature string, err error) {
	key, err := j.GetPrivateKey(ctx)
	if err != nil {
		return "", "", err
	}

	switch t := key.(type) {
	case *jose.JSONWebKey:
		return generateToken(claims, header, jose.SignatureAlgorithm(t.Algorithm), t.Key)
	case jose.JSONWebKey:
		return generateToken(claims, header, jose.SignatureAlgorithm(t.Algorithm), t.Key)
	case *rsa.PrivateKey:
		return generateToken(claims, header, jose.RS256, t)
	case *ecdsa.PrivateKey:
		return generateToken(claims, header, jose.ES256, t)
	case jose.OpaqueSigner:
		switch tt := t.Public().Key.(type) {
		case *rsa.PrivateKey:
			alg := jose.RS256
			if len(t.Algs()) > 0 {
				alg = t.Algs()[0]
			}

			return generateToken(claims, header, alg, t)
		case *ecdsa.PrivateKey:
			alg := jose.ES256
			if len(t.Algs()) > 0 {
				alg = t.Algs()[0]
			}

			return generateToken(claims, header, alg, t)
		default:
			return "", "", errors.Errorf("unsupported private / public key pairs: %T, %T", t, tt)
		}
	default:
		return "", "", errors.Errorf("unsupported private key type: %T", t)
	}
}

// Validate validates a token and returns its signature or an error if the token is not valid.
func (j *DefaultSigner) Validate(ctx context.Context, token string) (string, error) {
	key, err := j.GetPrivateKey(ctx)
	if err != nil {
		return "", err
	}

	if t, ok := key.(*jose.JSONWebKey); ok {
		key = t.Key
	}

	switch t := key.(type) {
	case *rsa.PrivateKey:
		return validateToken(token, t.PublicKey)
	case *ecdsa.PrivateKey:
		return validateToken(token, t.PublicKey)
	case jose.OpaqueSigner:
		return validateToken(token, t.Public().Key)
	default:
		return "", errors.New("Unable to validate token. Invalid PrivateKey type")
	}
}

// Decode will decode a JWT token
func (j *DefaultSigner) Decode(ctx context.Context, token string) (*Token, error) {
	key, err := j.GetPrivateKey(ctx)
	if err != nil {
		return nil, err
	}

	if t, ok := key.(*jose.JSONWebKey); ok {
		key = t.Key
	}

	switch t := key.(type) {
	case *rsa.PrivateKey:
		return decodeToken(token, t.PublicKey)
	case *ecdsa.PrivateKey:
		return decodeToken(token, t.PublicKey)
	case jose.OpaqueSigner:
		return decodeToken(token, t.Public().Key)
	default:
		return nil, errors.New("Unable to decode token. Invalid PrivateKey type")
	}
}

// GetSignature will return the signature of a token
func (j *DefaultSigner) GetSignature(ctx context.Context, token string) (string, error) {
	return getTokenSignature(token)
}

// Hash will return a given hash based on the byte input or an error upon fail
func (j *DefaultSigner) Hash(ctx context.Context, in []byte) ([]byte, error) {
	return hashSHA256(in)
}

// GetSigningMethodLength will return the length of the signing method
func (j *DefaultSigner) GetSigningMethodLength(ctx context.Context) int {
	return SHA256HashSize
}

func generateToken(claims MapClaims, header Mapper, signingMethod jose.SignatureAlgorithm, privateKey any) (tokenString string, signature string, err error) {
	if header == nil || claims == nil {
		err = errors.New("either claims or header is nil")
		return
	}

	token := NewWithClaims(signingMethod, claims)
	token.Header = assign(token.Header, header.ToMap())

	if tokenString, err = token.SignedString(privateKey); err != nil {
		return tokenString, signature, err
	}

	if signature, err = getTokenSignature(tokenString); err != nil {
		return tokenString, signature, err
	}

	return tokenString, signature, nil
}

func peakSignedHeaderType(raw string) (typ string, err error) {
	token, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{consts.JSONWebTokenAlgNone, jose.HS256, jose.HS384, jose.HS512, jose.RS256, jose.RS384, jose.RS512, jose.PS256, jose.PS384, jose.PS512, jose.ES256, jose.ES384, jose.ES512})
	if err != nil {
		return "", err
	}

	if len(token.Headers) == 0 {
		return "", fmt.Errorf("no header")
	}

	if atyp, ok := token.Headers[0].ExtraHeaders[consts.JSONWebTokenHeaderType]; !ok {
		return "", nil
	} else if typ, ok = atyp.(string); ok {
		return typ, nil
	}

	return "", fmt.Errorf("invalid typ")
}

func decodeToken(token string, verificationKey any) (*Token, error) {
	keyFunc := func(*Token) (any, error) { return verificationKey, nil }
	return ParseWithClaims(token, MapClaims{}, keyFunc)
}

func validateToken(tokenStr string, verificationKey any) (string, error) {
	_, err := decodeToken(tokenStr, verificationKey)
	if err != nil {
		return "", err
	}
	return getTokenSignature(tokenStr)
}

func getTokenSignature(token string) (string, error) {
	split := strings.Split(token, ".")
	if len(split) != 3 {
		return "", errors.New("header, body and signature must all be set")
	}
	return split[2], nil
}

func hashSHA256(in []byte) ([]byte, error) {
	hash := sha256.New()
	_, err := hash.Write(in)
	if err != nil {
		return []byte{}, errorsx.WithStack(err)
	}
	return hash.Sum([]byte{}), nil
}

func assign(a, b map[string]any) map[string]any {
	for k, w := range b {
		if _, ok := a[k]; ok {
			continue
		}
		a[k] = w
	}
	return a
}
