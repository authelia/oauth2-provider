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
	"authelia.com/provider/oauth2/internal/stringslice"
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
		return &Token{Claims: MapClaims(nil)}, &ValidationError{Errors: ValidationErrorMalformed, Inner: err}
	}

	// fill unverified claims
	// This conversion is required because go-jose supports
	// only marshalling structs or maps but not alias types from maps
	//
	// The KeyFunc(*Token) function requires the claims to be set into the
	// Token, that is an unverified token, therefore an UnsafeClaimsWithoutVerification is done first
	// then with the returned key, the claims gets verified.
	if err = parsed.UnsafeClaimsWithoutVerification(&claims); err != nil {
		return &Token{Claims: MapClaims(nil)}, &ValidationError{Errors: ValidationErrorClaimsInvalid, Inner: err}
	}

	// creates an unsafe token
	if token, err = newToken(parsed, claims); err != nil {
		return &Token{Claims: MapClaims(nil)}, err
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

// Token represets a JWT Token.
type Token struct {
	KeyID                string
	SignatureAlgorithm   jose.SignatureAlgorithm // alg (JWS)
	EncryptionKeyID      string
	KeyAlgorithm         jose.KeyAlgorithm         // alg (JWE)
	ContentEncryption    jose.ContentEncryption    // enc (JWE)
	CompressionAlgorithm jose.CompressionAlgorithm // zip (JWE)

	Header    map[string]any
	HeaderJWE map[string]any

	Claims Claims

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
// type Claims interface {
//	Valid() error
//}

func (t *Token) toSignedJoseHeader() (header map[jose.HeaderKey]any) {
	header = map[jose.HeaderKey]any{
		JSONWebTokenHeaderType: JSONWebTokenTypeJWT,
	}

	for k, v := range t.Header {
		header[jose.HeaderKey(k)] = v
	}

	return header
}

func (t *Token) toEncryptedJoseHeader() (header map[jose.HeaderKey]any) {
	header = map[jose.HeaderKey]any{
		JSONWebTokenHeaderType: JSONWebTokenTypeJWT,
	}

	if cty, ok := t.Header[JSONWebTokenHeaderType]; ok {
		header[JSONWebTokenHeaderContentType] = cty
	}

	for k, v := range t.HeaderJWE {
		header[jose.HeaderKey(k)] = v
	}

	return header
}

// SetJWS sets the JWS output values.
func (t *Token) SetJWS(header Mapper, claims Claims, kid string, alg jose.SignatureAlgorithm) {
	assign(t.Header, header.ToMap())

	t.KeyID = kid
	t.SignatureAlgorithm = alg

	t.Claims = claims
}

// SetJWE sets the JWE output values.
func (t *Token) SetJWE(header Mapper, kid string, alg jose.KeyAlgorithm, enc jose.ContentEncryption, zip jose.CompressionAlgorithm) {
	assign(t.HeaderJWE, header.ToMap())

	t.EncryptionKeyID = kid
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
		JSONWebTokenHeaderAlgorithm: jwe.Header.Algorithm,
	}

	if jwe.Header.KeyID != "" {
		t.HeaderJWE[JSONWebTokenHeaderKeyIdentifier] = jwe.Header.KeyID
		t.EncryptionKeyID = jwe.Header.KeyID
	}

	for header, value := range jwe.Header.ExtraHeaders {
		h := string(header)

		t.HeaderJWE[h] = value

		switch h {
		case JSONWebTokenHeaderEncryptionAlgorithm:
			if v, ok := value.(string); ok {
				t.ContentEncryption = jose.ContentEncryption(v)
			}
		case JSONWebTokenHeaderCompressionAlgorithm:
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

	if _, ok := opts.ExtraHeaders[JSONWebTokenHeaderContentType]; !ok {
		var typ any

		if typ, ok = t.Header[JSONWebTokenHeaderType]; ok {
			opts.ExtraHeaders[JSONWebTokenHeaderContentType] = typ
		} else {
			opts.ExtraHeaders[JSONWebTokenHeaderContentType] = JSONWebTokenTypeJWT
		}
	}

	var encrypter jose.Encrypter

	if encrypter, err = jose.NewEncrypter(t.ContentEncryption, rcpt, opts); err != nil {
		return "", "", fmt.Errorf("error initializing jwt encrypter using key algorithm '%s' and content encryption '%s' and key id '%s' using key type '%s': %w", t.KeyAlgorithm, t.ContentEncryption, t.KeyID, strKeyType(keyEnc), errorsx.WithStack(err))
	}

	var token *jose.JSONWebEncryption

	if token, err = encrypter.Encrypt([]byte(signed)); err != nil {
		return "", "", fmt.Errorf("error encrypting jwt using key algorithm '%s' and content encryption '%s' and key id '%s' using key type '%s': %w", t.KeyAlgorithm, t.ContentEncryption, t.KeyID, strKeyType(keyEnc), errorsx.WithStack(err))
	}

	if tokenString, err = token.CompactSerialize(); err != nil {
		return "", "", errorsx.WithStack(err)
	}

	return tokenString, signature, nil
}

// CompactSigned serializes this token as a Compact Signed string, and returns the token string, signature, and
// an error if one occurred.
func (t *Token) CompactSigned(keySig any) (tokenString, signature string, err error) {
	if tokenString, err = t.CompactSignedString(keySig); err != nil {
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
func (t *Token) CompactSignedString(keySig any) (tokenString string, err error) {
	if isUnsafeNoneMagicConstant(keySig) {
		return unsignedToken(t)
	}

	key := jose.SigningKey{
		Algorithm: t.SignatureAlgorithm,
		Key:       keySig,
	}

	opts := &jose.SignerOptions{ExtraHeaders: t.toSignedJoseHeader()}

	var signer jose.Signer

	if signer, err = jose.NewSigner(key, opts); err != nil {
		return "", fmt.Errorf("error signing jwt using alg '%s' and key id '%s' using key type '%s': %w", t.SignatureAlgorithm, t.KeyID, strKeyType(keySig), errorsx.WithStack(err))
	}

	// A explicit conversion from type alias MapClaims
	// to map[string]any is required because the
	// go-jose CompactSerialize() only support explicit maps
	// as claims or structs but not type aliases from maps.
	// claims := t.Claims.ToMapClaims()

	if tokenString, err = jwt.Signed(signer).Claims(t.Claims.ToMapClaims().ToMap()).Serialize(); err != nil {
		return "", &ValidationError{Errors: ValidationErrorClaimsInvalid, Inner: err}
	}

	return tokenString, nil
}

// Valid validates the token headers given various input options. This does not validate any claims.
func (t *Token) Valid(opts ...HeaderValidationOption) (err error) {
	vopts := &HeaderValidationOptions{
		types: []string{JSONWebTokenTypeJWT},
	}

	for _, opt := range opts {
		opt(vopts)
	}

	vErr := new(ValidationError)

	if !t.valid {
		vErr.Inner = errors.New("token has an invalid or unverified signature")
		vErr.Errors |= ValidationErrorSignatureInvalid
	}

	if t.HeaderJWE != nil && (t.KeyAlgorithm != "" || t.ContentEncryption != "") {
		if !validateTokenType([]string{consts.JSONWebTokenTypeJWT}, t.HeaderJWE, vopts.allowEmptyType) {
			vErr.Inner = errors.New("token was encrypted with invalid typ")
			vErr.Errors |= ValidationErrorHeaderEncryptionTypeInvalid
		}

		ttyp := t.Header[JSONWebTokenHeaderType]
		cty := t.HeaderJWE[JSONWebTokenHeaderContentType]

		if cty != ttyp {
			vErr.Inner = errors.New("token was encrypted with a cty value that doesn't match the typ value")
			vErr.Errors |= ValidationErrorHeaderContentTypeInvalidMismatch
		}

		if len(vopts.types) != 0 {
			if !validateTokenTypeValue(vopts.types, cty) {
				vErr.Inner = errors.New("token was encrypted with an invalid cty")
				vErr.Errors |= ValidationErrorHeaderContentTypeInvalid
			}
		}
	}

	if len(vopts.types) != 0 {
		if !validateTokenType(vopts.types, t.Header, vopts.allowEmptyType) {
			vErr.Inner = errors.New("token was signed with an invalid typ")
			vErr.Errors |= ValidationErrorHeaderTypeInvalid
		}
	}

	if len(vopts.alg) != 0 {
		if vopts.alg != string(t.SignatureAlgorithm) {
			vErr.Inner = errors.New("token was signed with an invalid alg")
			vErr.Errors |= ValidationErrorHeaderAlgorithmInvalid
		}
	}

	if len(vopts.kid) != 0 {
		if vopts.kid != t.KeyID {
			vErr.Inner = errors.New("token was signed with an invalid kid")
			vErr.Errors |= ValidationErrorHeaderKeyIDInvalid
		}
	}

	if len(vopts.keyAlg) != 0 && len(t.KeyAlgorithm) != 0 {
		if vopts.keyAlg != string(t.KeyAlgorithm) {
			vErr.Inner = errors.New("token was encrypted with an invalid alg")
			vErr.Errors |= ValidationErrorHeaderKeyAlgorithmInvalid
		}
	}

	if len(vopts.contentEnc) != 0 && len(t.ContentEncryption) != 0 {
		if vopts.contentEnc != string(t.ContentEncryption) {
			vErr.Inner = errors.New("token was encrypted with an invalid enc")
			vErr.Errors |= ValidationErrorHeaderContentEncryptionInvalid
		}
	}

	if len(vopts.kidEnc) != 0 && len(t.EncryptionKeyID) != 0 {
		if vopts.kidEnc != t.EncryptionKeyID {
			vErr.Inner = errors.New("token was encrypted with an invalid kid")
			vErr.Errors |= ValidationErrorHeaderEncryptionKeyIDInvalid
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
		if raw, ok = t.HeaderJWE[JSONWebTokenHeaderContentType]; ok {
			cty, ok = raw.(string)

			if !ok {
				return false
			}

			if cty != JSONWebTokenTypeAccessToken && cty != JSONWebTokenTypeAccessTokenAlternative {
				return false
			}
		}
	}

	if raw, ok = t.Header[JSONWebTokenHeaderType]; !ok {
		return false
	}

	typ, ok = raw.(string)

	return ok && (typ == JSONWebTokenTypeAccessToken || typ == JSONWebTokenTypeAccessTokenAlternative)
}

type HeaderValidationOption func(opts *HeaderValidationOptions)

type HeaderValidationOptions struct {
	allowEmptyType bool
	types          []string
	alg            string
	kid            string
	kidEnc         string
	keyAlg         string
	contentEnc     string
}

func ValidateAllowEmptyType(value bool) HeaderValidationOption {
	return func(opts *HeaderValidationOptions) {
		opts.allowEmptyType = value
	}
}

func ValidateTypes(types ...string) HeaderValidationOption {
	return func(validator *HeaderValidationOptions) {
		validator.types = types
	}
}

func ValidateKeyID(kid string) HeaderValidationOption {
	return func(validator *HeaderValidationOptions) {
		validator.kid = kid
	}
}

func ValidateAlgorithm(alg string) HeaderValidationOption {
	return func(validator *HeaderValidationOptions) {
		validator.alg = alg
	}
}

func ValidateEncryptionKeyID(kid string) HeaderValidationOption {
	return func(validator *HeaderValidationOptions) {
		validator.kidEnc = kid
	}
}

func ValidateKeyAlgorithm(alg string) HeaderValidationOption {
	return func(validator *HeaderValidationOptions) {
		validator.keyAlg = alg
	}
}

func ValidateContentEncryption(enc string) HeaderValidationOption {
	return func(validator *HeaderValidationOptions) {
		validator.contentEnc = enc
	}
}

func unsignedToken(token *Token) (tokenString string, err error) {
	token.Header[JSONWebTokenHeaderAlgorithm] = JSONWebTokenAlgNone

	if _, ok := token.Header[JSONWebTokenHeaderType]; !ok {
		token.Header[JSONWebTokenHeaderType] = JSONWebTokenTypeJWT
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

	if token.Claims == nil {
		token.Claims = MapClaims{}
	}

	if len(parsedToken.Headers) != 1 {
		return nil, &ValidationError{text: fmt.Sprintf("only one header supported, got %v", len(parsedToken.Headers)), Errors: ValidationErrorMalformed}
	}

	// copy headers
	h := parsedToken.Headers[0]
	token.Header = map[string]any{
		JSONWebTokenHeaderAlgorithm: h.Algorithm,
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

func validateTokenType(values []string, header map[string]any, allowEmpty bool) bool {
	var (
		raw any
		ok  bool
	)

	if raw, ok = header[consts.JSONWebTokenHeaderType]; !ok {
		// Only allow the JWT typ to be empty explicitly. In addition if it's allowed we must assume the media type
		// is JWT for safety so unless it's allowed we should return a validation error here.
		if !allowEmpty || !stringslice.HasI(values, consts.JSONWebTokenTypeJWT) {
			return false
		}

		// Assume JWT if not present.
		return validateTokenTypeValue(values, consts.JSONWebTokenTypeJWT)
	}

	return validateTokenTypeValue(values, raw)
}

func validateTokenTypeValue(values []string, raw any) bool {
	var (
		typ string
		ok  bool
	)

	if typ, ok = raw.(string); !ok {
		return false
	}

	for _, t := range values {
		// 5.1 Media type names are not case sensitive.
		if strings.EqualFold(t, typ) {
			return true
		}
	}

	return false
}

func isUnsafeNoneMagicConstant(k any) bool {
	switch key := k.(type) {
	case unsafeNoneMagicConstant:
		return true
	case jose.JSONWebKey:
		if _, ok := key.Key.(unsafeNoneMagicConstant); ok {
			return true
		}
	case *jose.JSONWebKey:
		if _, ok := key.Key.(unsafeNoneMagicConstant); ok {
			return true
		}
	}

	return false
}
