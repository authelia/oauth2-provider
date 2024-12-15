package jwt

import (
	"context"
	"crypto"
	"crypto/aes"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"reflect"
	"regexp"
	"strings"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/pkg/errors"
)

var (
	reSignedJWT    = regexp.MustCompile(`^[-_A-Za-z0-9]+\.[-_A-Za-z0-9]+\.([-_A-Za-z0-9]+)?$`)
	reEncryptedJWT = regexp.MustCompile(`^[-_A-Za-z0-9]+\.[-_A-Za-z0-9]+\.[-_A-Za-z0-9]+\.[-_A-Za-z0-9]+\.[-_A-Za-z0-9]+$`)
)

// IsSignedJWT returns true if a given token string meets the basic criteria of a compact serialized signed JWT.
func IsSignedJWT(tokenString string) (signed bool) {
	return reSignedJWT.MatchString(tokenString)
}

// IsEncryptedJWT returns true if a given token string meets the basic criteria of a compact serialized encrypted JWT.
func IsEncryptedJWT(tokenString string) (encrypted bool) {
	return reEncryptedJWT.MatchString(tokenString)
}

// IsSignedJWTClientSecretAlgStr returns true if the given alg string is a client secret based signature algorithm.
func IsSignedJWTClientSecretAlgStr(alg string) (csa bool) {
	if a := jose.SignatureAlgorithm(alg); IsSignedJWTClientSecretAlg(a) {
		return true
	}

	return false
}

func IsSignedJWTClientSecretAlg(alg jose.SignatureAlgorithm) (csa bool) {
	switch alg {
	case jose.HS256, jose.HS384, jose.HS512:
		return true
	default:
		return false
	}
}

// IsEncryptedJWTClientSecretAlg returns true if a given alg string is a client secret based encryption algorithm
// i.e. symmetric.
func IsEncryptedJWTClientSecretAlg(alg string) (csa bool) {
	switch a := jose.KeyAlgorithm(alg); a {
	case jose.A128KW, jose.A192KW, jose.A256KW, jose.DIRECT, jose.A128GCMKW, jose.A192GCMKW, jose.A256GCMKW:
		return true
	default:
		return IsEncryptedJWTPasswordBasedAlg(a)
	}
}

// IsEncryptedJWTPasswordBasedAlg returns true if a given jose.KeyAlgorithm is a Password Based Algorithm.
func IsEncryptedJWTPasswordBasedAlg(alg jose.KeyAlgorithm) (pba bool) {
	switch alg {
	case jose.PBES2_HS256_A128KW, jose.PBES2_HS384_A192KW, jose.PBES2_HS512_A256KW:
		return true
	default:
		return false
	}
}

func headerValidateJWS(headers []jose.Header) (kid, alg string, err error) {
	switch len(headers) {
	case 1:
		break
	case 0:
		return "", "", fmt.Errorf("jws header is missing")
	default:
		return "", "", fmt.Errorf("jws header is malformed")
	}

	if headers[0].Algorithm == "" && headers[0].KeyID == "" {
		return "", "", fmt.Errorf("jws header 'alg' and 'kid' values are missing or empty")
	}

	if headers[0].JSONWebKey != nil {
		return "", "", fmt.Errorf("jws header 'jwk' value is present but not supported")
	}

	return headers[0].KeyID, headers[0].Algorithm, nil
}

func headerValidateJWE(header jose.Header) (kid, alg, enc, cty string, err error) {
	if header.KeyID == "" && !IsEncryptedJWTClientSecretAlg(header.Algorithm) {
		return "", "", "", "", fmt.Errorf("jwe header 'kid' value is missing or empty")
	}

	if header.Algorithm == "" {
		return "", "", "", "", fmt.Errorf("jwe header 'alg' value is missing or empty")
	}

	var (
		value any
		ok    bool
	)

	if IsEncryptedJWTPasswordBasedAlg(jose.KeyAlgorithm(header.Algorithm)) {
		if value, ok = header.ExtraHeaders[JSONWebTokenHeaderPBES2Count]; ok {
			switch p2c := value.(type) {
			case float64:
				if p2c > 5000000 {
					return "", "", "", "", fmt.Errorf("jwe header 'p2c' has an invalid value '%d': more than 5,000,000", int(p2c))
				} else if p2c < 200000 {
					return "", "", "", "", fmt.Errorf("jwe header 'p2c' has an invalid value '%d': less than 200,000", int(p2c))
				}
			default:
				return "", "", "", "", fmt.Errorf("jwe header 'p2c' value has invalid type %T", p2c)
			}
		}
	}

	if value, ok = header.ExtraHeaders[JSONWebTokenHeaderEncryptionAlgorithm]; ok {
		switch encv := value.(type) {
		case string:
			if encv != "" {
				enc = encv

				break
			}

			return "", "", "", "", fmt.Errorf("jwe header 'enc' value is empty")
		default:
			return "", "", "", "", fmt.Errorf("jwe header 'enc' value has invalid type %T", encv)
		}
	}

	if value, ok = header.ExtraHeaders[JSONWebTokenHeaderContentType]; ok {
		cty, _ = value.(string)
	}

	return header.KeyID, header.Algorithm, enc, cty, nil
}

// PrivateKey properly describes crypto.PrivateKey.
type PrivateKey interface {
	Public() crypto.PublicKey
	Equal(x crypto.PrivateKey) bool
}

const (
	JWKLookupErrorClientNoJWKS uint32 = 1 << iota
)

type JWKLookupError struct {
	Description string
	Errors      uint32 // bitfield.  see JWKLookupError... constants
}

func (e *JWKLookupError) GetDescription() string {
	return e.Description
}

func (e *JWKLookupError) Error() string {
	return fmt.Sprintf("Error occurred retrieving the JSON Web Key. %s", e.Description)
}

// FindClientPublicJWK given a BaseClient, JWKSFetcherStrategy, and search parameters will return a *jose.JSONWebKey on
// a valid match. The *jose.JSONWebKey is guaranteed to match the alg and use values, and if strict is true it must
// match the kid value as well.
func FindClientPublicJWK(ctx context.Context, client BaseClient, fetcher JWKSFetcherStrategy, kid, alg, use string, strict bool) (key *jose.JSONWebKey, err error) {
	var (
		keys *jose.JSONWebKeySet
	)

	if keys = client.GetJSONWebKeys(); keys != nil {
		return SearchJWKS(keys, kid, alg, use, strict)
	}

	if location := client.GetJSONWebKeysURI(); len(location) > 0 {
		if keys, err = fetcher.Resolve(ctx, location, false); err != nil {
			return nil, err
		}

		if key, err = SearchJWKS(keys, kid, alg, use, strict); err == nil {
			return key, nil
		}

		if keys, err = fetcher.Resolve(ctx, location, true); err != nil {
			return nil, err
		}

		return SearchJWKS(keys, kid, alg, use, strict)
	}

	return nil, &JWKLookupError{Description: "No JWKs have been registered for the client"}
}

func SearchJWKS(jwks *jose.JSONWebKeySet, kid, alg, use string, strict bool) (key *jose.JSONWebKey, err error) {
	if len(jwks.Keys) == 0 {
		return nil, &JWKLookupError{Description: "The retrieved JSON Web Key Set does not contain any key."}
	}

	var keys []jose.JSONWebKey

	if kid == "" {
		keys = jwks.Keys
	} else {
		keys = jwks.Key(kid)
	}

	if len(keys) == 0 {
		return nil, &JWKLookupError{Description: fmt.Sprintf("The JSON Web Token uses signing key with kid '%s' which was not found", kid)}
	}

	var matched []jose.JSONWebKey

	for _, k := range keys {
		if k.Use != use {
			continue
		}

		if k.Algorithm != alg {
			continue
		}

		matched = append(matched, k)
	}

	switch len(matched) {
	case 1:
		return &matched[0], nil
	case 0:
		return nil, &JWKLookupError{Description: fmt.Sprintf("Unable to find JSON web key with kid '%s', use '%s', and alg '%s' in JSON Web Key Set", kid, use, alg)}
	default:
		if strict {
			return nil, &JWKLookupError{Description: fmt.Sprintf("Unable to find JSON web key with kid '%s', use '%s', and alg '%s' in JSON Web Key Set", kid, use, alg)}
		}

		return &matched[0], nil
	}
}

// NewClientSecretJWKFromClient returns a client secret based JWK from a client.
func NewClientSecretJWKFromClient(ctx context.Context, client BaseClient, kid, alg, enc, use string) (jwk *jose.JSONWebKey, err error) {
	var (
		secret []byte
		ok     bool
	)

	if secret, ok, err = client.GetClientSecretPlainText(); err != nil {
		return nil, &JWKLookupError{Description: fmt.Sprintf("The client returned an error while trying to retrieve the plaintext client secret. %s", err.Error())}
	}

	if !ok {
		return nil, &JWKLookupError{Description: "The client is not configured with a client secret"}
	}

	return NewClientSecretJWK(ctx, secret, kid, alg, enc, use)
}

// NewClientSecretJWK returns a client secret based JWK from a client secret value.
//
// The symmetric encryption key is derived from the client_secret value by using the left-most bits of a truncated
// SHA-2 hash of the octets of the UTF-8 representation of the client_secret. For keys of 256 or fewer bits, SHA-256
// is used; for keys of 257-384 bits, SHA-384 is used; for keys of 385-512 bits, SHA-512 is used. The hash value MUST
// be truncated retaining the left-most bits to the appropriate bit length for the AES key wrapping or direct
// encryption algorithm used, for instance, truncating the SHA-256 hash to 128 bits for A128KW. If a symmetric key with
// greater than 512 bits is needed, a different method of deriving the key from the client_secret would have to be
// defined by an extension. Symmetric encryption MUST NOT be used by public (non-confidential) Clients because of
// their inability to keep secrets.
func NewClientSecretJWK(ctx context.Context, secret []byte, kid, alg, enc, use string) (jwk *jose.JSONWebKey, err error) {
	if len(secret) == 0 {
		return nil, &JWKLookupError{Description: "The client is not configured with a client secret that can be used for symmetric algorithms"}
	}

	switch use {
	case JSONWebTokenUseSignature:
		var (
			hasher hash.Hash
		)

		switch jose.SignatureAlgorithm(alg) {
		case jose.HS256:
			hasher = sha256.New()
		case jose.HS384:
			hasher = sha512.New384()
		case jose.HS512:
			hasher = sha512.New()
		default:
			return nil, &JWKLookupError{Description: fmt.Sprintf("Unsupported algorithm '%s'", alg)}
		}

		if _, err = hasher.Write(secret); err != nil {
			return nil, &JWKLookupError{Description: fmt.Sprintf("Unable to derive key from hashing the client secret. %s", err.Error())}
		}

		return &jose.JSONWebKey{
			Key:       hasher.Sum(nil),
			KeyID:     kid,
			Algorithm: alg,
			Use:       use,
		}, nil
	case JSONWebTokenUseEncryption:
		var (
			hasher hash.Hash
			bits   int
		)

		keyAlg := jose.KeyAlgorithm(alg)

		switch keyAlg {
		case jose.A128KW, jose.A128GCMKW, jose.A192KW, jose.A192GCMKW, jose.A256KW, jose.A256GCMKW, jose.PBES2_HS256_A128KW:
			hasher = sha256.New()
		case jose.PBES2_HS384_A192KW:
			hasher = sha512.New384()
		case jose.PBES2_HS512_A256KW, jose.DIRECT:
			hasher = sha512.New()
		default:
			return nil, &JWKLookupError{Description: fmt.Sprintf("Unsupported algorithm '%s'", alg)}
		}

		switch keyAlg {
		case jose.A128KW, jose.A128GCMKW, jose.PBES2_HS256_A128KW:
			bits = aes.BlockSize
		case jose.A192KW, jose.A192GCMKW, jose.PBES2_HS384_A192KW:
			bits = aes.BlockSize * 1.5
		case jose.A256KW, jose.A256GCMKW, jose.PBES2_HS512_A256KW:
			bits = aes.BlockSize * 2
		default:
			switch jose.ContentEncryption(enc) {
			case jose.A128CBC_HS256, "":
				bits = aes.BlockSize * 2
			case jose.A192CBC_HS384:
				bits = aes.BlockSize * 3
			case jose.A256CBC_HS512:
				bits = aes.BlockSize * 4
			default:
				return nil, &JWKLookupError{Description: fmt.Sprintf("Unsupported content encryption for the direct key algorthm '%s'", enc)}
			}
		}

		if _, err = hasher.Write(secret); err != nil {
			return nil, &JWKLookupError{Description: fmt.Sprintf("Unable to derive key from hashing the client secret. %s", err.Error())}
		}

		return &jose.JSONWebKey{
			Key:       hasher.Sum(nil)[:bits],
			KeyID:     kid,
			Algorithm: alg,
			Use:       use,
		}, nil
	default:
		return &jose.JSONWebKey{
			Key:       secret,
			KeyID:     kid,
			Algorithm: alg,
			Use:       use,
		}, nil
	}
}

// EncodeCompactSigned helps encoding a token using a signature backed compact encoding.
func EncodeCompactSigned(ctx context.Context, claims Claims, headers Mapper, key *jose.JSONWebKey) (tokenString string, signature string, err error) {
	token := New()

	if headers == nil {
		headers = &Headers{}
	}

	token.SetJWS(headers, claims, key.KeyID, jose.SignatureAlgorithm(key.Algorithm))

	return token.CompactSigned(key)
}

// EncodeNestedCompactEncrypted helps encoding a token using a signature backed compact encoding, then nests that within
// an encrypted compact encoded JWT.
func EncodeNestedCompactEncrypted(ctx context.Context, claims Claims, headers, headersJWE Mapper, keySig, keyEnc *jose.JSONWebKey, enc jose.ContentEncryption) (tokenString string, signature string, err error) {
	token := New()

	if headers == nil {
		headers = &Headers{}
	}

	if headersJWE == nil {
		headersJWE = &Headers{}
	}

	token.SetJWS(headers, claims, keySig.KeyID, jose.SignatureAlgorithm(keySig.Algorithm))
	token.SetJWE(headersJWE, keyEnc.KeyID, jose.KeyAlgorithm(keyEnc.Algorithm), enc, jose.NONE)

	return token.CompactEncrypted(keySig, keyEnc)
}

func getJWTSignature(tokenString string) (signature string, err error) {
	switch segments := strings.SplitN(tokenString, ".", 5); len(segments) {
	case 5:
		return "", errors.WithStack(errors.New("invalid token: the token is probably encrypted"))
	case 3:
		return segments[2], nil
	default:
		return "", errors.WithStack(fmt.Errorf("invalid token: the format is unknown"))
	}
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

func getPublicJWK(jwk *jose.JSONWebKey) jose.JSONWebKey {
	if jwk == nil {
		return jose.JSONWebKey{}
	}

	if _, ok := jwk.Key.([]byte); ok && IsSignedJWTClientSecretAlgStr(jwk.Algorithm) {
		return jose.JSONWebKey{
			KeyID:                       jwk.KeyID,
			Key:                         jwk.Key,
			Algorithm:                   jwk.Algorithm,
			Use:                         jwk.Use,
			Certificates:                jwk.Certificates,
			CertificatesURL:             jwk.CertificatesURL,
			CertificateThumbprintSHA1:   jwk.CertificateThumbprintSHA1,
			CertificateThumbprintSHA256: jwk.CertificateThumbprintSHA256,
		}
	}

	return jwk.Public()
}

// UnsafeParseSignedAny is a function that will attempt to parse any signed token without any verification process.
// It's unsafe for production and should only be used for tests.
func UnsafeParseSignedAny(tokenString string, dest any) (token *jwt.JSONWebToken, err error) {
	if token, err = jwt.ParseSigned(tokenString, SignatureAlgorithmsNone); err != nil {
		return nil, err
	}

	if err = token.UnsafeClaimsWithoutVerification(dest); err != nil {
		return nil, err
	}

	return token, nil
}

func newError(message string, err error, more ...error) error {
	var format string
	var args []any
	if message != "" {
		format = "%w: %s"
		args = []any{err, message}
	} else {
		format = "%w"
		args = []any{err}
	}

	for _, e := range more {
		format += ": %w"
		args = append(args, e)
	}

	err = fmt.Errorf(format, args...)
	return err
}

func toMap(obj any) (result map[string]any) {
	result = map[string]any{}

	if obj == nil {
		return result
	}

	v := reflect.TypeOf(obj)

	reflectValue := reflect.ValueOf(obj)
	reflectValue = reflect.Indirect(reflectValue)

	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}

	for i := 0; i < v.NumField(); i++ {
		tag, opts := parseTag(v.Field(i).Tag.Get("json"))
		field := reflectValue.Field(i).Interface()
		if tag != "" && tag != "-" {
			if opts.Contains("omitempty") && isEmptyValue(reflect.ValueOf(field)) {
				continue
			}

			if v.Field(i).Type.Kind() == reflect.Struct {
				result[tag] = toMap(field)
			} else {
				result[tag] = field
			}
		}
	}

	return result
}

type tagOptionsJSON string

func parseTag(tag string) (string, tagOptionsJSON) {
	tag, opt, _ := strings.Cut(tag, ",")
	return tag, tagOptionsJSON(opt)
}

func (o tagOptionsJSON) Contains(optionName string) bool {
	if len(o) == 0 {
		return false
	}

	s := string(o)

	for s != "" {
		var name string
		name, s, _ = strings.Cut(s, ",")
		if name == optionName {
			return true
		}
	}

	return false
}

func isEmptyValue(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.Array, reflect.Map, reflect.Slice, reflect.String:
		return v.Len() == 0
	case reflect.Bool,
		reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr,
		reflect.Float32, reflect.Float64,
		reflect.Interface, reflect.Pointer:
		return v.IsZero()
	default:
		return false
	}
}
