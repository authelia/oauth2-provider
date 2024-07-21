// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package jwt

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/x/errorsx"
)

// NewWithClaims creates an unverified Token with the given claims and signing method
func NewWithClaims(method jose.SignatureAlgorithm, claims MapClaims) *Token {
	return &Token{
		Claims:             claims,
		SignatureAlgorithm: method,
		Header:             map[string]any{},
		EncryptionHeader:   map[string]any{},
	}
}

// Parse is an overload for ParseCustom which accepts all normal algs including 'none'.
func Parse(tokenString string, keyFunc Keyfunc) (*Token, error) {
	return ParseCustom(tokenString, keyFunc, SignatureAlgorithmsNone...)
}

// ParseCustom parses, validates, and returns a token. The keyFunc will receive the parsed token and should
// return the key for validating. If everything is kosher, err will be nil.
func ParseCustom(tokenString string, keyFunc Keyfunc, algs ...jose.SignatureAlgorithm) (token *Token, err error) {
	return ParseCustomWithClaims(tokenString, MapClaims{}, keyFunc, algs...)
}

// ParseWithClaims is an overload for ParseCustomWithClaims which accepts all normal algs including 'none'.
func ParseWithClaims(tokenString string, claims MapClaims, keyFunc Keyfunc) (token *Token, err error) {
	return ParseCustomWithClaims(tokenString, claims, keyFunc, SignatureAlgorithmsNone...)
}

// ParseCustomWithClaims parses, validates, and returns a token with its respective claims. The keyFunc will receive the parsed token and should
// return the key for validating. If everything is kosher, err will be nil.
func ParseCustomWithClaims(tokenString string, claims MapClaims, keyFunc Keyfunc, algs ...jose.SignatureAlgorithm) (token *Token, err error) {
	var parsed *jwt.JSONWebToken

	if parsed, err = jwt.ParseSigned(tokenString, algs); err != nil {
		return &Token{}, &ValidationError{Errors: ValidationErrorMalformed, text: err.Error()}
	}

	// fill unverified claims
	// This conversion is required because go-jose supports
	// only marshalling structs or maps but not alias types from maps
	//
	// The KeyFunc(*Token) function requires the claims to be set into the
	// Token, that is an unverified token, therefore an UnsafeClaimsWithoutVerification is done first
	// then with the returned key, the claims gets verified.
	if err = parsed.UnsafeClaimsWithoutVerification(&claims); err != nil {
		return nil, &ValidationError{Errors: ValidationErrorClaimsInvalid, text: err.Error()}
	}

	// creates an unsafe token
	if token, err = newToken(parsed, claims); err != nil {
		return nil, err
	}

	if keyFunc == nil {
		return token, &ValidationError{Errors: ValidationErrorUnverifiable, text: "no Keyfunc was provided."}
	}

	var key any

	if key, err = keyFunc(token); err != nil {
		// keyFunc returned an error
		var ve *ValidationError

		if errors.As(err, &ve) {
			return token, ve
		}

		return token, &ValidationError{Errors: ValidationErrorUnverifiable, Inner: err}
	}
	if key == nil {
		return token, &ValidationError{Errors: ValidationErrorSignatureInvalid, text: "keyfunc returned a nil verification key"}
	}
	// To verify signature go-jose requires a pointer to
	// public key instead of the public key value.
	// The pointer values provides that pointer.
	// E.g. transform rsa.PublicKey -> *rsa.PublicKey
	key = pointer(key)

	// verify signature with returned key
	_, validNoneKey := key.(*unsafeNoneMagicConstant)
	isSignedToken := !(token.SignatureAlgorithm == SigningMethodNone && validNoneKey)
	if isSignedToken {
		if err = parsed.Claims(key, &claims); err != nil {
			return token, &ValidationError{Errors: ValidationErrorSignatureInvalid, text: err.Error()}
		}
	}

	// Validate claims
	// This validation is performed to be backwards compatible
	// with jwt-go library behavior
	if err = claims.Valid(); err != nil {
		if e, ok := err.(*ValidationError); !ok {
			err = &ValidationError{Inner: e, Errors: ValidationErrorClaimsInvalid}
		}
		return token, err
	}

	token.valid = true

	return token, nil
}

// Token represets a JWT Token
// This token provide an adaptation to
// transit from [jwt-go](https://github.com/dgrijalva/jwt-go)
// to [go-jose](https://github.com/square/go-jose)
// It provides method signatures compatible with jwt-go but implemented
// using go-json
type Token struct {
	SignatureAlgorithm   jose.SignatureAlgorithm
	ContentEncryption    jose.ContentEncryption
	KeyAlgorithm         jose.KeyAlgorithm
	CompressionAlgorithm jose.CompressionAlgorithm

	Header           map[string]any
	EncryptionHeader map[string]any

	Claims MapClaims

	valid bool
}

// Valid informs if the token was verified against a given verification key
// and claims are valid
func (t *Token) Valid() bool {
	return t.valid
}

// Claims is a port from https://github.com/dgrijalva/jwt-go/blob/master/claims.go
// including its validation methods, which are not available in go-jose library
//
// > For a type to be a Claims object, it must just have a Valid method that determines
// if the token is invalid for any supported reason
type Claims interface {
	Valid() error
}

func (t *Token) toSignedJoseHeader() (header map[jose.HeaderKey]any) {
	header = map[jose.HeaderKey]any{
		consts.JSONWebTokenHeaderType: consts.JSONWebTokenTypeJWT,
	}

	for k, v := range t.Header {
		header[jose.HeaderKey(k)] = v
	}

	return header
}

func (t *Token) toEncryptedJoseHeader() (header map[jose.HeaderKey]any) {
	header = map[jose.HeaderKey]any{
		consts.JSONWebTokenHeaderType: consts.JSONWebTokenTypeJWT,
	}

	if cty, ok := t.Header[consts.JSONWebTokenHeaderType]; ok {
		header[consts.JSONWebTokenHeaderContentType] = cty
	}

	for k, v := range t.EncryptionHeader {
		header[jose.HeaderKey(k)] = v
	}

	return header
}

func (t *Token) CompactEncrypted(skey, ekey any) (tokenString string, err error) {
	var (
		signed string
	)

	if signed, err = t.CompactSigned(skey); err != nil {
		return "", err
	}

	rcpt := jose.Recipient{
		Algorithm: t.KeyAlgorithm,
		Key:       ekey,
	}

	opts := &jose.EncrypterOptions{
		Compression:  t.CompressionAlgorithm,
		ExtraHeaders: t.toEncryptedJoseHeader(),
	}

	if _, ok := opts.ExtraHeaders[consts.JSONWebTokenHeaderContentType]; !ok {
		var typ any

		if typ, ok = t.Header[consts.JSONWebTokenHeaderType]; ok {
			opts.ExtraHeaders[consts.JSONWebTokenHeaderContentType] = typ
		} else {
			opts.ExtraHeaders[consts.JSONWebTokenHeaderContentType] = consts.JSONWebTokenTypeJWT
		}
	}

	var encrypter jose.Encrypter

	if encrypter, err = jose.NewEncrypter(t.ContentEncryption, rcpt, opts); err != nil {
		return "", errorsx.WithStack(err)
	}

	var token *jose.JSONWebEncryption

	if token, err = encrypter.Encrypt([]byte(signed)); err != nil {
		return "", errorsx.WithStack(err)
	}

	return token.CompactSerialize()
}

// CompactSigned provides a compatible `jwt-go` Token.CompactSigned method
//
// > Get the complete, signed token
func (t *Token) CompactSigned(k any) (tokenString string, err error) {
	if _, ok := k.(unsafeNoneMagicConstant); ok {
		return unsignedToken(t)
	}

	key := jose.SigningKey{
		Algorithm: t.SignatureAlgorithm,
		Key:       k,
	}

	opts := &jose.SignerOptions{ExtraHeaders: t.toSignedJoseHeader()}

	var signer jose.Signer

	if signer, err = jose.NewSigner(key, opts); err != nil {
		return "", errorsx.WithStack(err)
	}

	// A explicit conversion from type alias MapClaims
	// to map[string]any is required because the
	// go-jose CompactSerialize() only support explicit maps
	// as claims or structs but not type aliases from maps.
	claims := map[string]any(t.Claims)

	if tokenString, err = jwt.Signed(signer).Claims(claims).Serialize(); err != nil {
		return "", &ValidationError{Errors: ValidationErrorClaimsInvalid, Inner: err}
	}

	return tokenString, nil
}

func (t *Token) IsJWTProfileAccessToken() bool {
	var (
		raw      any
		cty, typ string
		ok       bool
	)

	if t.EncryptionHeader != nil && len(t.EncryptionHeader) > 0 {
		if raw, ok = t.EncryptionHeader[consts.JSONWebTokenHeaderContentType]; ok {
			cty, ok = raw.(string)

			if !ok {
				return false
			}

			if cty != consts.JSONWebTokenTypeAccessToken && cty != consts.JSONWebTokenTypeAccessTokenAlternative {
				return false
			}
		}
	}

	if raw, ok = t.Header[consts.JSONWebTokenHeaderType]; !ok {
		return false
	}

	typ, ok = raw.(string)

	return ok && (typ == consts.JSONWebTokenTypeAccessToken || typ == consts.JSONWebTokenTypeAccessTokenAlternative)
}

func unsignedToken(token *Token) (tokenString string, err error) {
	token.Header[consts.JSONWebTokenHeaderAlgorithm] = consts.JSONWebTokenAlgNone

	if _, ok := token.Header[consts.JSONWebTokenHeaderType]; !ok {
		token.Header[consts.JSONWebTokenHeaderType] = consts.JSONWebTokenTypeJWT
	}

	var (
		hbytes, bbytes []byte
	)

	if hbytes, err = json.Marshal(&token.Header); err != nil {
		return "", errorsx.WithStack(err)
	}

	if bbytes, err = json.Marshal(&token.Claims); err != nil {
		return "", errorsx.WithStack(err)
	}

	return fmt.Sprintf("%s.%s.", base64.RawURLEncoding.EncodeToString(hbytes), base64.RawURLEncoding.EncodeToString(bbytes)), nil
}

func newToken(parsedToken *jwt.JSONWebToken, claims MapClaims) (*Token, error) {
	token := &Token{Claims: claims}
	if len(parsedToken.Headers) != 1 {
		return nil, &ValidationError{text: fmt.Sprintf("only one header supported, got %v", len(parsedToken.Headers)), Errors: ValidationErrorMalformed}
	}

	// copy headers
	h := parsedToken.Headers[0]
	token.Header = map[string]any{
		consts.JSONWebTokenHeaderAlgorithm: h.Algorithm,
	}
	if h.KeyID != "" {
		token.Header[consts.JSONWebTokenHeaderKeyIdentifier] = h.KeyID
	}
	for k, v := range h.ExtraHeaders {
		token.Header[string(k)] = v
	}

	token.SignatureAlgorithm = jose.SignatureAlgorithm(h.Algorithm)

	return token, nil
}

// if underline value of v is not a pointer
// it creates a pointer of it and returns it
func pointer(v any) any {
	if reflect.ValueOf(v).Kind() != reflect.Ptr {
		value := reflect.New(reflect.ValueOf(v).Type())
		value.Elem().Set(reflect.ValueOf(v))
		return value.Interface()
	}
	return v
}

type PotentialTokenType int

const (
	Unknown PotentialTokenType = iota
	Opaque
	SignedJWT
	EncryptedJWT
)

func GetPotentialTokenType(token string) PotentialTokenType {
	switch strings.Count(token, ".") {
	case 1:
		return Opaque
	case 2:
		return SignedJWT
	case 4:
		return EncryptedJWT
	default:
		return Unknown
	}
}
