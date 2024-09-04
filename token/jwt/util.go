package jwt

import (
	"context"
	"crypto"
	"fmt"
	"regexp"
	"strings"

	"github.com/go-jose/go-jose/v4"
	"github.com/pkg/errors"

	"authelia.com/provider/oauth2/internal/consts"
)

var (
	reSignedJWT    = regexp.MustCompile(`^[-_A-Za-z0-9]+\.[-_A-Za-z0-9]+\.[-_A-Za-z0-9]+$`)
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

// IsEncryptedJWTClientSecretAlg returns true if a given alg string is a client secret based algorithm i.e. symmetric.
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

	if headers[0].Algorithm == "" {
		return "", "", fmt.Errorf("jws header 'alg' value is missing or empty")
	}

	if headers[0].KeyID == "" && headers[0].Algorithm != consts.JSONWebTokenAlgNone {
		return "", "", fmt.Errorf("jws header 'kid' value is missing or empty")
	}

	if headers[0].JSONWebKey != nil {
		return "", "", fmt.Errorf("jws header 'jwk' value is present but not supported")
	}

	return headers[0].KeyID, headers[0].Algorithm, nil
}

func headerValidateJWSNested(headers []jose.Header, cty string) (err error) {
	switch len(headers) {
	case 1:
		break
	case 0:
		return fmt.Errorf("jws header is missing")
	default:
		return fmt.Errorf("jws header is malformed")
	}

	typ, ok := headers[0].ExtraHeaders[consts.JSONWebTokenHeaderType]
	if !ok {
		return fmt.Errorf("jws header 'typ' value is missing")
	}

	switch typ {
	case "":
		return fmt.Errorf("jws header 'typ' value is empty")
	case cty:
		return nil
	default:
		return fmt.Errorf("jws header 'typ' value '%s' is invalid: jwe header 'cty' value '%s' should match the jws header 'typ' value", typ, cty)
	}
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
		if value, ok = header.ExtraHeaders[consts.JSONWebTokenHeaderPBES2Count]; ok {
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

	if value, ok = header.ExtraHeaders[consts.JSONWebTokenHeaderEncryptionAlgorithm]; ok {
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

	if value, ok = header.ExtraHeaders[consts.JSONWebTokenHeaderContentType]; !ok {
		return "", "", "", "", fmt.Errorf("jwe header 'cty' value is missing")
	} else {
		switch ctyv := value.(type) {
		case string:
			switch ctyv {
			case consts.JSONWebTokenTypeJWT, consts.JSONWebTokenTypeAccessToken, consts.JSONWebTokenTypeAccessTokenAlternative, consts.JSONWebTokenTypeTokenIntrospection:
				cty = ctyv
				break
			default:
				return "", "", "", "", fmt.Errorf("jwe header 'cty' value '%s' is invalid", cty)
			}
		default:
			return "", "", "", "", fmt.Errorf("jwe header 'cty' value has invalid type %T", cty)
		}
	}

	if header.JSONWebKey != nil {
		return "", "", "", "", fmt.Errorf("jwe header 'jwk' value is present but not supported")
	}

	return header.KeyID, header.Algorithm, enc, cty, nil
}

// PrivateKey properly describes crypto.PrivateKey.
type PrivateKey interface {
	Public() crypto.PublicKey
	Equal(x crypto.PrivateKey) bool
}

type JWKLookupError struct {
	Description string
}

func (e *JWKLookupError) GetDescription() string {
	return e.Description
}

func (e *JWKLookupError) Error() string {
	return fmt.Sprintf("Error occurrered looking up JSON Web Key: %s", e.Description)
}

// FindClientPublicJWK given a BaseClient, JWKSFetcherStrategy, and search parameters will return a *jose.JSONWebKey on
// a valid match. The *jose.JSONWebKey is guaranteed to match the alg and use values, and if strict is true it must
// match the kid value as well.
func FindClientPublicJWK(ctx context.Context, client BaseClient, fetcher JWKSFetcherStrategy, kid, alg, use string, strict bool) (key *jose.JSONWebKey, err error) {
	if strict && kid == "" {
		return nil, &JWKLookupError{Description: "The JSON Web Key strict search was attempted without a kid but the strict search doesn't permit this."}
	}

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

	return nil, &JWKLookupError{Description: "No JWKs have been registered for the client."}
}

func SearchJWKS(jwks *jose.JSONWebKeySet, kid, alg, use string, strict bool) (key *jose.JSONWebKey, err error) {
	if len(jwks.Keys) == 0 {
		return nil, &JWKLookupError{Description: "The retrieved JSON Web Key Set does not contain any key."}
	}

	if strict && kid == "" {
		return nil, &JWKLookupError{Description: "The JSON Web Key strict search was attempted without a kid but the strict search doesn't permit this."}
	}

	var keys []jose.JSONWebKey

	if kid == "" {
		keys = jwks.Keys
	} else {
		keys = jwks.Key(kid)
	}

	if len(keys) == 0 {
		return nil, &JWKLookupError{Description: fmt.Sprintf("The JSON Web Token uses signing key with kid '%s' which was not found.", kid)}
	}

	for _, k := range keys {
		if k.Use != use {
			continue
		}

		if k.Algorithm != alg {
			continue
		}

		return &k, nil
	}

	return nil, &JWKLookupError{Description: fmt.Sprintf("Unable to find JSON web key with kid '%s', use '%s', and alg '%s' in JSON Web Key Set.", kid, use, alg)}
}

func NewJWKFromClientSecret(ctx context.Context, client BaseClient, kid, alg, use string) (jwk *jose.JSONWebKey, err error) {
	var secret []byte

	if secret, err = client.GetClientSecretPlainText(); err != nil {
		return nil, err
	}

	return &jose.JSONWebKey{
		Key:       secret,
		KeyID:     kid,
		Algorithm: alg,
		Use:       use,
	}, nil
}

func encodeCompactSigned(ctx context.Context, claims MapClaims, headers Mapper, key *jose.JSONWebKey) (tokenString string, signature string, err error) {
	token := New()

	token.SetJWS(headers, claims, jose.SignatureAlgorithm(key.Algorithm))

	return token.CompactSigned(key)
}

func encodeNestedCompactEncrypted(ctx context.Context, claims MapClaims, headers, headersJWE Mapper, keySig, keyEnc *jose.JSONWebKey, enc jose.ContentEncryption) (tokenString string, signature string, err error) {
	token := New()

	token.SetJWS(headers, claims, jose.SignatureAlgorithm(keySig.Algorithm))
	token.SetJWE(headersJWE, jose.KeyAlgorithm(keyEnc.Algorithm), enc, jose.NONE)

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
