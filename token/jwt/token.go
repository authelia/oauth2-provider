// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package jwt

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/x/errorsx"
)

// New returns a new Token.
func New() *Token {
	return &Token{
		Header:    map[string]any{},
		HeaderJWE: map[string]any{},
	}
}

// NewWithClaims creates an unverified Token with the given claims and signing method
func NewWithClaims(alg jose.SignatureAlgorithm, claims MapClaims) *Token {
	return &Token{
		Claims:             claims,
		SignatureAlgorithm: alg,
		Header:             map[string]any{},
		HeaderJWE:          map[string]any{},
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
		return &Token{}, &ValidationError{Errors: ValidationErrorMalformed, Inner: err}
	}

	// fill unverified claims
	// This conversion is required because go-jose supports
	// only marshalling structs or maps but not alias types from maps
	//
	// The KeyFunc(*Token) function requires the claims to be set into the
	// Token, that is an unverified token, therefore an UnsafeClaimsWithoutVerification is done first
	// then with the returned key, the claims gets verified.
	if err = parsed.UnsafeClaimsWithoutVerification(&claims); err != nil {
		return nil, &ValidationError{Errors: ValidationErrorClaimsInvalid, Inner: err}
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
	KeyID                string
	SignatureAlgorithm   jose.SignatureAlgorithm   // alg (JWS)
	KeyAlgorithm         jose.KeyAlgorithm         // alg (JWE)
	ContentEncryption    jose.ContentEncryption    // enc (JWE)
	CompressionAlgorithm jose.CompressionAlgorithm // zip (JWE)

	Header    map[string]any
	HeaderJWE map[string]any

	Claims MapClaims

	parsedToken *jwt.JSONWebToken

	valid bool
}

// IsSignatureValid informs if the token was verified against a given verification key
// and claims are valid
func (t *Token) IsSignatureValid() bool {
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

	for k, v := range t.HeaderJWE {
		header[jose.HeaderKey(k)] = v
	}

	return header
}

// SetJWS sets the JWS output values.
func (t *Token) SetJWS(header Mapper, claims MapClaims, alg jose.SignatureAlgorithm) {
	assign(t.Header, header.ToMap())

	t.SignatureAlgorithm = alg

	t.Claims = claims
}

// SetJWE sets the JWE output values.
func (t *Token) SetJWE(header Mapper, alg jose.KeyAlgorithm, enc jose.ContentEncryption, zip jose.CompressionAlgorithm) {
	assign(t.HeaderJWE, header.ToMap())

	t.KeyAlgorithm = alg
	t.ContentEncryption = enc
	t.CompressionAlgorithm = zip
}

// AssignJWE assigns values derived from the JWE decryption process to the Token.
func (t *Token) AssignJWE(jwe *jose.JSONWebEncryption) {
	if jwe == nil {
		return
	}

	t.HeaderJWE = map[string]any{
		consts.JSONWebTokenHeaderAlgorithm: jwe.Header.Algorithm,
	}

	if jwe.Header.KeyID != "" {
		t.HeaderJWE[consts.JSONWebTokenHeaderKeyIdentifier] = jwe.Header.KeyID
	}

	for header, value := range jwe.Header.ExtraHeaders {
		h := string(header)

		t.HeaderJWE[h] = value

		switch h {
		case consts.JSONWebTokenHeaderEncryptionAlgorithm:
			if v, ok := value.(string); ok {
				t.ContentEncryption = jose.ContentEncryption(v)
			}
		case consts.JSONWebTokenHeaderCompressionAlgorithm:
			if v, ok := value.(string); ok {
				t.CompressionAlgorithm = jose.CompressionAlgorithm(v)
			}
		}
	}

	t.KeyAlgorithm = jose.KeyAlgorithm(jwe.Header.Algorithm)
}

// CompactEncrypted serializes this token as a Compact Encrypted string, and returns the token string, signature, and
// an error if one occurred.
func (t *Token) CompactEncrypted(keySig, keyEnc any) (tokenString, signature string, err error) {
	var (
		signed string
	)

	if signed, signature, err = t.CompactSigned(keySig); err != nil {
		return "", "", err
	}

	rcpt := jose.Recipient{
		Algorithm: t.KeyAlgorithm,
		Key:       keyEnc,
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
		return "", "", errorsx.WithStack(err)
	}

	var token *jose.JSONWebEncryption

	if token, err = encrypter.Encrypt([]byte(signed)); err != nil {
		return "", "", errorsx.WithStack(err)
	}

	if tokenString, err = token.CompactSerialize(); err != nil {
		return "", "", errorsx.WithStack(err)
	}

	return tokenString, signature, nil
}

// CompactSigned serializes this token as a Compact Signed string, and returns the token string, signature, and
// an error if one occurred.
func (t *Token) CompactSigned(k any) (tokenString, signature string, err error) {
	if tokenString, err = t.CompactSignedString(k); err != nil {
		return "", "", err
	}

	if signature, err = getJWTSignature(tokenString); err != nil {
		return "", "", err
	}

	return tokenString, signature, nil
}

// CompactSignedString provides a compatible `jwt-go` Token.CompactSigned method
//
// > Get the complete, signed token
func (t *Token) CompactSignedString(k any) (tokenString string, err error) {
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

// Valid validates the token headers given various input options. This does not validate any claims.
func (t *Token) Valid(opts ...TokenValidationOption) (err error) {
	vopts := &TokenValidationOptions{
		types: []string{consts.JSONWebTokenTypeJWT},
	}

	for _, opt := range opts {
		opt(vopts)
	}

	vErr := new(ValidationError)

	if !t.valid {
		vErr.Inner = errors.New("token has an invalid or unverified signature")
		vErr.Errors |= ValidationErrorSignatureInvalid
	}

	if len(vopts.types) != 0 {
		if !validateTokenType(vopts.types, t.Header) {
			vErr.Inner = errors.New("token has an invalid typ")
			vErr.Errors |= ValidationErrorHeaderTypeInvalid
		}
	}

	if len(vopts.alg) != 0 {
		if vopts.alg != string(t.SignatureAlgorithm) {
			vErr.Inner = errors.New("token has an invalid alg")
			vErr.Errors |= ValidationErrorHeaderAlgorithmInvalid
		}
	}

	if len(vopts.kid) != 0 {
		if vopts.kid != t.KeyID {
			vErr.Inner = errors.New("token has an invalid kid")
			vErr.Errors |= ValidationErrorHeaderKeyIDInvalid
		}
	}

	if vErr.valid() {
		return nil
	}

	return vErr
}

// IsJWTProfileAccessToken returns true if the token is a JWT Profile Access Token.
func (t *Token) IsJWTProfileAccessToken() (ok bool) {
	var (
		raw      any
		cty, typ string
	)

	if t.HeaderJWE != nil && len(t.HeaderJWE) > 0 {
		if raw, ok = t.HeaderJWE[consts.JSONWebTokenHeaderContentType]; ok {
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

type TokenValidationOption func(opts *TokenValidationOptions)

type TokenValidationOptions struct {
	types []string
	alg   string
	kid   string
}

func ValidateTypes(types ...string) TokenValidationOption {
	return func(validator *TokenValidationOptions) {
		validator.types = types
	}
}

func ValidateAlgorithm(alg string) TokenValidationOption {
	return func(validator *TokenValidationOptions) {
		validator.alg = alg
	}
}

func ValidateKeyID(kid string) TokenValidationOption {
	return func(validator *TokenValidationOptions) {
		validator.kid = kid
	}
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
	token := &Token{Claims: claims, parsedToken: parsedToken}
	if len(parsedToken.Headers) != 1 {
		return nil, &ValidationError{text: fmt.Sprintf("only one header supported, got %v", len(parsedToken.Headers)), Errors: ValidationErrorMalformed}
	}

	// copy headers
	h := parsedToken.Headers[0]
	token.Header = map[string]any{
		consts.JSONWebTokenHeaderAlgorithm: h.Algorithm,
	}

	token.SignatureAlgorithm = jose.SignatureAlgorithm(h.Algorithm)

	if h.KeyID != "" {
		token.Header[consts.JSONWebTokenHeaderKeyIdentifier] = h.KeyID
		token.KeyID = h.KeyID
	}

	for k, v := range h.ExtraHeaders {
		token.Header[string(k)] = v
	}

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

func validateTokenType(typValues []string, header map[string]any) bool {
	var (
		typ string
		raw any
		ok  bool
	)

	if raw, ok = header[consts.JSONWebTokenHeaderType]; !ok {
		return false
	}

	if typ, ok = raw.(string); !ok {
		return false
	}

	for _, t := range typValues {
		if t == typ {
			return true
		}
	}

	return false
}
