package jwt

import (
	"context"
	"crypto"
	"fmt"
	"strings"

	"github.com/go-jose/go-jose/v4"

	"authelia.com/provider/oauth2/internal/consts"
)

func headerValidateJWS(headers []jose.Header) (kid, alg string, err error) {
	if len(headers) == 0 {
		return "", "", fmt.Errorf("jws header is missing")
	}

	if headers[0].KeyID == "" {
		return "", "", fmt.Errorf("jws header value 'kid' is missing")
	}

	if headers[0].Algorithm == "" {
		return "", "", fmt.Errorf("jws header value 'alg' is missing")
	}

	if headers[0].JSONWebKey != nil {
		return "", "", fmt.Errorf("jws header value 'jwk' is present but not supported")
	}

	return headers[0].KeyID, headers[0].Algorithm, nil
}

func headerValidateJWE(headers []jose.Header) (kid, alg, enc string, err error) {
	if len(headers) == 0 {
		return "", "", "", fmt.Errorf("jwe header is missing")
	}

	if headers[0].KeyID == "" {
		return "", "", "", fmt.Errorf("jwe header value 'kid' is missing or empty")
	}

	if headers[0].Algorithm == "" {
		return "", "", "", fmt.Errorf("jwe header value 'alg' is missing or empty")
	}

	var (
		value any
		ok    bool
	)

	if value, ok = headers[0].ExtraHeaders[consts.JSONWebTokenHeaderEncryptionAlgorithm]; ok {
		switch encv := value.(type) {
		case string:
			if enc != "" {
				break
			}

			return "", "", "", fmt.Errorf("jwe header value 'enc' has empty value")
		default:
			return "", "", "", fmt.Errorf("jwe header value 'enc' has invalid type %T", encv)
		}
	}

	if value, ok = headers[0].ExtraHeaders[consts.JSONWebTokenHeaderContentType]; !ok {
		return "", "", "", fmt.Errorf("jwe header value 'cty' is missing")
	} else {
		switch cty := value.(type) {
		case string:
			switch cty {
			case consts.JSONWebTokenTypeJWT, consts.JSONWebTokenTypeAccessToken, consts.JSONWebTokenTypeAccessTokenAlternative, consts.JSONWebTokenTypeTokenIntrospection:
				break
			default:
				return "", "", "", fmt.Errorf("jwe header value 'cty' has invalid value '%s'", cty)
			}
		default:
			return "", "", "", fmt.Errorf("jwe header value 'cty' has invalid type %T", cty)
		}
	}

	if headers[0].JSONWebKey != nil {
		return "", "", "", fmt.Errorf("jwe header value 'jwk' is present but not supported")
	}

	return headers[0].KeyID, headers[0].Algorithm, enc, nil
}

func IsSignedJWT(tokenString string) (signed bool) {
	return strings.Count(tokenString, ".") == 2
}

func IsEncryptedJWT(tokenString string) (encrypted bool) {
	return strings.Count(tokenString, ".") == 4
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
	return fmt.Sprintf("error occurrered looking up JSON web key: %s", e.Description)
}

func FindClientPublicJWK(ctx context.Context, client JWKClient, fetcher JWKSFetcherStrategy, kid, alg, use string) (key *jose.JSONWebKey, err error) {
	var (
		keys *jose.JSONWebKeySet
	)

	if keys = client.GetJSONWebKeys(); keys != nil {
		return findKey(kid, alg, use, keys, true)
	}

	if location := client.GetJSONWebKeysURI(); len(location) > 0 {
		if keys, err = fetcher.Resolve(ctx, location, false); err != nil {
			return nil, err
		}

		if key, err = findKey(kid, alg, use, keys, true); err == nil {
			return key, nil
		}

		if keys, err = fetcher.Resolve(ctx, location, true); err != nil {
			return nil, err
		}

		return findKey(kid, alg, use, keys, true)
	}

	return nil, ErrNotRegistered
}

func findKey(kid, alg, use string, jwks *jose.JSONWebKeySet, requireKID bool) (key *jose.JSONWebKey, err error) {
	if len(jwks.Keys) == 0 {
		return nil, &JWKLookupError{Description: "The retrieved JSON Web Key Set does not contain any key."}
	}

	var keys []jose.JSONWebKey

	if kid == "" && !requireKID {
		keys = jwks.Keys
	} else {
		keys = jwks.Key(kid)
	}

	if len(keys) == 0 {
		return nil, &JWKLookupError{Description: fmt.Sprintf("The JSON Web Token uses signing key with kid '%s', which could not be found.", kid)}
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
