// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package ssfreceiver

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"slices"

	"github.com/hashicorp/go-retryablehttp"

	"authelia.com/provider/jose"
	josejwt "authelia.com/provider/jose/jwt"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/token/jwt"
)

// interoperabilityProfileKeyBits is the least size of the RSA key that signs a SET under the CAEP Interoperability
// Profile.
//
// See: https://openid.net/specs/openid-caep-interoperability-profile-1_0.html#section-2.6
const interoperabilityProfileKeyBits = 2048

// keyFunc returns the function which resolves the key that verifies a SET received on the stream of the record. The
// Transmitter is the Issuer of the record and never a value of the SET.
//
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-4.1.4
// See: https://www.rfc-editor.org/rfc/rfc8417#section-5.1
func (r *Receiver) keyFunc(record *StreamRecord) jwt.KeyFuncJWS {
	var issuer string

	if record != nil {
		issuer = record.Issuer
	}

	return func(ctx context.Context, token *josejwt.JSONWebToken, _ jwt.MapClaims) (key *jose.JSONWebKey, err error) {
		if token == nil || len(token.Headers) != 1 {
			return nil, fmt.Errorf("%w: the token does not have exactly one header", ErrSigningKey)
		}

		return r.signingKey(ctx, issuer, token.Headers[0].KeyID, token.Headers[0].Algorithm)
	}
}

// signingKey returns the public key of the Transmitter for the 'kid' and 'alg'. The JSON Web Key Set is the
// 'jwks_uri' of the validated metadata, and is fetched again, once, when it has no such key. Under the CAEP
// Interoperability Profile a key that is not an RSA key of at least 2048 bits is no such key.
func (r *Receiver) signingKey(ctx context.Context, issuer, kid, alg string) (key *jose.JSONWebKey, err error) {
	// RFC 8417 Section 5.1: no secret is shared with a Transmitter, so only an asymmetric signature is accepted.
	if alg == "" || alg == jwt.JSONWebTokenAlgNone || jwt.IsSignedJWTClientSecretAlgStr(alg) {
		return nil, fmt.Errorf("%w: the algorithm is not an asymmetric signature algorithm", ErrSigningKey)
	}

	var configuration *oauth2.SSFConfiguration

	if configuration, err = r.Discover(ctx, issuer); err != nil {
		return nil, err
	}

	fetcher := oauth2.SpecialUseAddressGuardJWKSFetcherStrategy(ctx, r.Config.SpecialUseAddressGuard, r.jwksFetcher())

	for _, ignoreCache := range []bool{false, true} {
		var jwks *jose.JSONWebKeySet

		if jwks, err = fetcher.Resolve(ctx, configuration.JWKSURI, ignoreCache); err != nil {
			return nil, fmt.Errorf("ssfreceiver: the keys of the transmitter could not be fetched: %w", err)
		}

		if key, err = searchSigningKey(jwks, kid, alg); err != nil {
			continue
		}

		if !r.Config.EnforceCAEPInteroperabilityProfile || isInteroperabilityProfileKey(key) {
			return key, nil
		}

		err = fmt.Errorf("%w: the key is not an RSA key of at least %d bits", ErrSigningKey, interoperabilityProfileKeyBits)
	}

	return nil, err
}

func searchSigningKey(jwks *jose.JSONWebKeySet, kid, alg string) (key *jose.JSONWebKey, err error) {
	if key, err = jwt.SearchJWKS(jwks, kid, alg, jwt.JSONWebTokenUseSignature, true); err != nil {
		return nil, signingKeyError(err)
	}

	// A key labeled with the 'use' and 'alg' is selected by the labels alone. Searching for it again without them has
	// the key itself checked: a symmetric key, a key of another type and a key whose 'key_ops' omit 'verify' are not
	// found.
	unlabeled := &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: key.Key, KeyID: key.KeyID, KeyOps: key.KeyOps}}}

	if _, err = jwt.SearchJWKS(unlabeled, key.KeyID, alg, jwt.JSONWebTokenUseSignature, true); err != nil {
		return nil, signingKeyError(err)
	}

	// RFC 7517 Section 4.3: the key is used to verify, which 'key_ops' of 'sign' alone does not permit.
	if key.KeyOps != nil && !slices.Contains(key.KeyOps, "verify") {
		return nil, fmt.Errorf("%w: the 'key_ops' of the key do not include 'verify'", ErrSigningKey)
	}

	public := key.Public()

	return &public, nil
}

// isInteroperabilityProfileKey returns true when the key is an RSA key of at least 2048 bits, measured by its modulus.
//
// See: https://openid.net/specs/openid-caep-interoperability-profile-1_0.html#section-2.6
func isInteroperabilityProfileKey(key *jose.JSONWebKey) bool {
	if key == nil {
		return false
	}

	public, ok := key.Public().Key.(*rsa.PublicKey)

	return ok && public != nil && public.N != nil && public.N.BitLen() >= interoperabilityProfileKeyBits
}

func signingKeyError(err error) error {
	var lookup *jwt.JWKLookupError

	if errors.As(err, &lookup) {
		return fmt.Errorf("%w: %s", ErrSigningKey, lookup.Description)
	}

	return fmt.Errorf("%w: %w", ErrSigningKey, err)
}

// jwksFetcher returns Config.JWKSFetcher, or the default strategy, which caches a JSON Web Key Set for an hour and
// forces at most one refresh of a location per minute.
func (r *Receiver) jwksFetcher() (fetcher jwt.JWKSFetcherStrategy) {
	if r.Config.JWKSFetcher != nil {
		return r.Config.JWKSFetcher
	}

	r.fetcherOnce.Do(func() {
		r.fetcher = oauth2.NewDefaultJWKSFetcherStrategy(oauth2.JWKSFetcherWithHTTPClientSource(func(context.Context) *retryablehttp.Client {
			return r.baseHTTPClient()
		}))
	})

	return r.fetcher
}
