// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc7591

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/jose"

	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/handler/rfc9449"
	"authelia.com/provider/oauth2/internal/gen"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestAuthenticateClientRegistrationJWT(t *testing.T) {
	ctx := context.Background()

	auth, config, store, access := newJWTAuthFixtures(t)

	require.Equal(t, testJWTIssuer+":authelia:oauth2:dynamic-client-registration:policy", config.GetRFC7591ClientRegistrationPolicyClaim(ctx))

	other := newJWTAuthSigner(config)
	proofKey := newProofKey(t)
	jkt := proofThumbprint(t, proofKey)

	opaque := mintAccessToken(t, ctx, store, access.HMACCoreStrategy, []string{testRegistrationScope}, []string{testEndpoint})

	trustedKey := gen.MustRSAKey()

	trusted := newJWTAuthKeyedSigner(t, config, trustedKey, "trusted-1")
	trustedOther := newJWTAuthKeyedSigner(t, config, gen.MustRSAKey(), "trusted-2")
	unpublished := newJWTAuthKeyedSigner(t, config, gen.MustRSAKey(), "trusted-1")
	absent := newJWTAuthKeyedSigner(t, config, trustedKey, "absent")
	unnamed := newJWTAuthKeyedSigner(t, config, trustedKey, "")

	hmacKey := &jose.JSONWebKey{Key: []byte("a-shared-secret-of-at-least-32-bytes"), KeyID: "shared", Algorithm: string(jose.HS256), Use: jwt.JSONWebTokenUseSignature}

	jwks := newJWKSServer(t, &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{publicJWK(t, trusted), publicJWK(t, trustedOther), *hmacKey}})

	undiscoverable := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(undiscoverable.Close)

	config.RFC7591ClientRegistrationTrustedIssuers = []oauth2.RFC7591TrustedIssuer{
		{Issuer: testJWTTrustedIssuer, JSONWebKeysURI: jwks.URL},
		{Issuer: "", JSONWebKeysURI: jwks.URL},
		{Issuer: undiscoverable.URL, JSONWebKeysURI: ""},
		{Issuer: testJWTIssuer, JSONWebKeysURI: jwks.URL},
	}

	trustedClaims := func(overrides jwt.MapClaims) jwt.MapClaims {
		claims := jwt.MapClaims{jwt.ClaimIssuer: testJWTTrustedIssuer}

		for name, value := range overrides {
			claims[name] = value
		}

		return claims
	}

	testCases := []struct {
		name   string
		token  func(t *testing.T) string
		scheme string
		proof  func(t *testing.T, token string) string
		err    error
		reason string
		key    string
		policy bool
	}{
		{
			name:   "ShouldAcceptAValidToken",
			token:  func(t *testing.T) string { return signJWTAuthToken(t, access, jwt.JSONWebTokenTypeAccessToken, nil) },
			key:    testJWTCounterKey,
			policy: true,
		},
		{
			name: "ShouldAcceptTheFullMediaType",
			token: func(t *testing.T) string {
				return signJWTAuthToken(t, access, "application/at+jwt", nil)
			},
			key:    testJWTCounterKey,
			policy: true,
		},
		{
			name: "ShouldRejectTheJWTType",
			token: func(t *testing.T) string {
				return signJWTAuthToken(t, access, jwt.JSONWebTokenTypeJWT, nil)
			},
			err: oauth2.ErrInvalidToken,
		},
		{
			name: "ShouldRejectAnotherIssuer",
			token: func(t *testing.T) string {
				return signJWTAuthToken(t, access, jwt.JSONWebTokenTypeAccessToken, jwt.MapClaims{jwt.ClaimIssuer: testJWTOtherIssuer})
			},
			err: oauth2.ErrInvalidToken,
		},
		{
			name: "ShouldRejectAMissingIssuer",
			token: func(t *testing.T) string {
				return signJWTAuthToken(t, access, jwt.JSONWebTokenTypeAccessToken, jwt.MapClaims{jwt.ClaimIssuer: nil})
			},
			err: oauth2.ErrInvalidToken,
		},
		{
			name: "ShouldRejectAnAudienceWithoutTheEndpoint",
			token: func(t *testing.T) string {
				return signJWTAuthToken(t, access, jwt.JSONWebTokenTypeAccessToken, jwt.MapClaims{jwt.ClaimAudience: []string{testAudienceWrong}})
			},
			err: oauth2.ErrInvalidToken,
		},
		{
			name: "ShouldRejectAnExpiredToken",
			token: func(t *testing.T) string {
				return signJWTAuthToken(t, access, jwt.JSONWebTokenTypeAccessToken, jwt.MapClaims{jwt.ClaimExpirationTime: time.Now().Add(-time.Minute).Unix()})
			},
			err: oauth2.ErrInvalidToken,
		},
		{
			name: "ShouldRejectATokenWithoutAnExpiry",
			token: func(t *testing.T) string {
				return signJWTAuthToken(t, access, jwt.JSONWebTokenTypeAccessToken, jwt.MapClaims{jwt.ClaimExpirationTime: nil})
			},
			err: oauth2.ErrInvalidToken,
		},
		{
			name: "ShouldRejectATokenWithoutAJWTID",
			token: func(t *testing.T) string {
				return signJWTAuthToken(t, access, jwt.JSONWebTokenTypeAccessToken, jwt.MapClaims{jwt.ClaimJWTID: nil})
			},
			err: oauth2.ErrInvalidToken,
		},
		{
			name: "ShouldRejectAnEmptyJWTID",
			token: func(t *testing.T) string {
				return signJWTAuthToken(t, access, jwt.JSONWebTokenTypeAccessToken, jwt.MapClaims{jwt.ClaimJWTID: ""})
			},
			err: oauth2.ErrInvalidToken,
		},
		{
			name: "ShouldReportInsufficientScope",
			token: func(t *testing.T) string {
				return signJWTAuthToken(t, access, jwt.JSONWebTokenTypeAccessToken, jwt.MapClaims{jwt.ClaimScope: testScopeRead})
			},
			err: oauth2.ErrInsufficientScope,
		},
		{
			name: "ShouldRejectAnotherSigningKey",
			token: func(t *testing.T) string {
				return signJWTAuthToken(t, other, jwt.JSONWebTokenTypeAccessToken, nil)
			},
			err: oauth2.ErrInvalidToken,
		},
		{
			name: "ShouldRejectAnUnsignedToken",
			token: func(t *testing.T) string {
				header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"at+jwt"}`))
				payload := base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"https://auth.example.com","aud":["https://auth.example.com/register"],"scope":"authelia:oauth2:dynamic-client-registration","jti":"j1","exp":` + strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10) + `}`))

				return header + "." + payload + "."
			},
			err: oauth2.ErrInvalidToken,
		},
		{
			name:  "ShouldRejectAnEncryptedToken",
			token: func(t *testing.T) string { return "aGVhZGVy.a2V5.aXY.Y2lwaGVydGV4dA.dGFn" },
			err:   oauth2.ErrInvalidToken,
		},
		{
			name: "ShouldRejectABoundTokenWithoutAProof",
			token: func(t *testing.T) string {
				return signJWTAuthToken(t, access, jwt.JSONWebTokenTypeAccessToken, jwt.MapClaims{jwt.ClaimConfirmation: map[string]any{jwt.ClaimConfirmationJWKThumbprint: jkt}})
			},
			scheme: oauth2.DPoPAccessToken,
			err:    oauth2.ErrInvalidDPoPProof,
		},
		{
			name: "ShouldRejectABoundTokenPresentedAsBearer",
			token: func(t *testing.T) string {
				return signJWTAuthToken(t, access, jwt.JSONWebTokenTypeAccessToken, jwt.MapClaims{jwt.ClaimConfirmation: map[string]any{jwt.ClaimConfirmationJWKThumbprint: jkt}})
			},
			err: oauth2.ErrInvalidToken,
		},
		{
			name: "ShouldAcceptABoundTokenWithAValidProof",
			token: func(t *testing.T) string {
				return signJWTAuthToken(t, access, jwt.JSONWebTokenTypeAccessToken, jwt.MapClaims{jwt.ClaimConfirmation: map[string]any{jwt.ClaimConfirmationJWKThumbprint: jkt}})
			},
			scheme: oauth2.DPoPAccessToken,
			proof: func(t *testing.T, token string) string {
				return signDPoPProof(t, proofKey, "proof-1", http.MethodPost, testEndpoint, token)
			},
			key:    testJWTCounterKey,
			policy: true,
		},
		{
			name: "ShouldAcceptATrustedIssuer",
			token: func(t *testing.T) string {
				return signJWTAuthToken(t, trusted, jwt.JSONWebTokenTypeAccessToken, trustedClaims(nil))
			},
			key:    testJWTTrustedCounterKey,
			policy: true,
		},
		{
			name: "ShouldAcceptATrustedIssuerSignedByAnotherPublishedKey",
			token: func(t *testing.T) string {
				return signJWTAuthToken(t, trustedOther, jwt.JSONWebTokenTypeAccessToken, trustedClaims(nil))
			},
			key:    testJWTTrustedCounterKey,
			policy: true,
		},
		{
			name: "ShouldRejectAnUnlistedIssuerSignedByAPublishedKey",
			token: func(t *testing.T) string {
				return signJWTAuthToken(t, trusted, jwt.JSONWebTokenTypeAccessToken, jwt.MapClaims{jwt.ClaimIssuer: testJWTOtherIssuer})
			},
			err:    oauth2.ErrInvalidToken,
			reason: "the issuer 'https://auth.example.co' is neither this server nor a trusted issuer",
		},
		{
			name: "ShouldRejectATrustedIssuerSignedByAnUnpublishedKey",
			token: func(t *testing.T) string {
				return signJWTAuthToken(t, unpublished, jwt.JSONWebTokenTypeAccessToken, trustedClaims(nil))
			},
			err: oauth2.ErrInvalidToken,
		},
		{
			name: "ShouldRejectATrustedIssuerSignedByAKeyAbsentFromTheSet",
			token: func(t *testing.T) string {
				return signJWTAuthToken(t, absent, jwt.JSONWebTokenTypeAccessToken, trustedClaims(nil))
			},
			err:    oauth2.ErrInvalidToken,
			reason: "The JSON Web Token uses signing key with kid 'absent' which was not found",
		},
		{
			name: "ShouldRejectATrustedIssuerWithoutAKeyIDAndAnAmbiguousSet",
			token: func(t *testing.T) string {
				return signJWTAuthToken(t, unnamed, jwt.JSONWebTokenTypeAccessToken, trustedClaims(nil))
			},
			err:    oauth2.ErrInvalidToken,
			reason: "Unable to find JSON web key with kid '', use 'sig', and alg 'RS256' in JSON Web Key Set",
		},
		{
			name: "ShouldRejectATrustedIssuerSignedByASymmetricKey",
			token: func(t *testing.T) string {
				token, _, err := jwt.EncodeCompactSigned(ctx, signJWTAuthClaims(trustedClaims(nil)), &jwt.Headers{Extra: map[string]any{jwt.JSONWebTokenHeaderType: jwt.JSONWebTokenTypeAccessToken}}, hmacKey)
				require.NoError(t, err)

				return token
			},
			err:    oauth2.ErrInvalidToken,
			reason: testUnexpectedHS256Reason,
		},
		{
			name: "ShouldRejectThisIssuerSignedByATrustedIssuerKey",
			token: func(t *testing.T) string {
				return signJWTAuthToken(t, trusted, jwt.JSONWebTokenTypeAccessToken, nil)
			},
			err:    oauth2.ErrInvalidToken,
			reason: "The JSON Web Token uses signing key with kid 'trusted-1' which was not found",
		},
		{
			name: "ShouldRejectAMissingIssuerSignedByAPublishedKey",
			token: func(t *testing.T) string {
				return signJWTAuthToken(t, trusted, jwt.JSONWebTokenTypeAccessToken, jwt.MapClaims{jwt.ClaimIssuer: nil})
			},
			err: oauth2.ErrInvalidToken,
		},
		{
			name: "ShouldRejectAnEmptyIssuerSignedByAPublishedKey",
			token: func(t *testing.T) string {
				return signJWTAuthToken(t, trusted, jwt.JSONWebTokenTypeAccessToken, jwt.MapClaims{jwt.ClaimIssuer: ""})
			},
			err: oauth2.ErrInvalidToken,
		},
		{
			name: "ShouldReportATrustedIssuerWhoseKeySetCannotBeDiscoveredAsAServerError",
			token: func(t *testing.T) string {
				return signJWTAuthToken(t, trusted, jwt.JSONWebTokenTypeAccessToken, jwt.MapClaims{jwt.ClaimIssuer: undiscoverable.URL})
			},
			err: oauth2.ErrServerError,
		},
		{
			name: "ShouldRejectATrustedIssuerWithTheJWTType",
			token: func(t *testing.T) string {
				return signJWTAuthToken(t, trusted, jwt.JSONWebTokenTypeJWT, trustedClaims(nil))
			},
			err: oauth2.ErrInvalidToken,
		},
		{
			name: "ShouldRejectATrustedIssuerWithoutAnExpiry",
			token: func(t *testing.T) string {
				return signJWTAuthToken(t, trusted, jwt.JSONWebTokenTypeAccessToken, trustedClaims(jwt.MapClaims{jwt.ClaimExpirationTime: nil}))
			},
			err: oauth2.ErrInvalidToken,
		},
		{
			name: "ShouldRejectATrustedIssuerWithoutAJWTID",
			token: func(t *testing.T) string {
				return signJWTAuthToken(t, trusted, jwt.JSONWebTokenTypeAccessToken, trustedClaims(jwt.MapClaims{jwt.ClaimJWTID: nil}))
			},
			err: oauth2.ErrInvalidToken,
		},
		{
			name: "ShouldRejectATrustedIssuerWithAnAudienceWithoutTheEndpoint",
			token: func(t *testing.T) string {
				return signJWTAuthToken(t, trusted, jwt.JSONWebTokenTypeAccessToken, trustedClaims(jwt.MapClaims{jwt.ClaimAudience: []string{testAudienceWrong}}))
			},
			err: oauth2.ErrInvalidToken,
		},
		{
			name: "ShouldReportInsufficientScopeForATrustedIssuer",
			token: func(t *testing.T) string {
				return signJWTAuthToken(t, trusted, jwt.JSONWebTokenTypeAccessToken, trustedClaims(jwt.MapClaims{jwt.ClaimScope: testScopeRead}))
			},
			err: oauth2.ErrInsufficientScope,
		},
		{
			name: "ShouldRejectABoundTrustedIssuerTokenPresentedAsBearer",
			token: func(t *testing.T) string {
				return signJWTAuthToken(t, trusted, jwt.JSONWebTokenTypeAccessToken, trustedClaims(jwt.MapClaims{jwt.ClaimConfirmation: map[string]any{jwt.ClaimConfirmationJWKThumbprint: jkt}}))
			},
			err: oauth2.ErrInvalidToken,
		},
		{
			name:  "ShouldResolveAnOpaqueTokenFromStorage",
			token: func(t *testing.T) string { return opaque },
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			token := tc.token(t)

			persistJWTAuthToken(t, store, token)

			scheme := tc.scheme
			if scheme == "" {
				scheme = oauth2.BearerAccessToken
			}

			var proof string

			if tc.proof != nil {
				proof = tc.proof(t, token)
			}

			requester, err := auth.AuthenticateClientRegistrationRequest(ctx, bindingRequest(scheme, token, proof, nil), "")

			if tc.err != nil {
				require.Error(t, err)
				assert.ErrorIs(t, err, tc.err)
				assert.Nil(t, requester)

				if tc.reason != "" {
					assert.Contains(t, oauth2.ErrorToDebugRFC6749Error(err).Error(), tc.reason)
				}

				return
			}

			require.NoError(t, err)

			pr, ok := requester.(RegistrationPolicyRequester)
			require.True(t, ok)

			if tc.key == "" {
				assert.Equal(t, "session:"+requester.GetID(), pr.GetRegistrationCounterKey())
				assert.NotEqual(t, "session:", pr.GetRegistrationCounterKey())

				return
			}

			assert.Equal(t, tc.key, pr.GetRegistrationCounterKey())
			assert.Equal(t, testOnboardingClientID, requester.GetClient().GetID())
			assert.Equal(t, tc.key != testJWTTrustedCounterKey, pr.GetRegistrationPolicyPatternsPermitted())

			raw, present := pr.GetRegistrationPolicyClaim()
			assert.Equal(t, tc.policy, present)

			policy, err := ParseRegistrationPolicy(raw, nil, true)
			require.NoError(t, err)
			assert.Equal(t, int64(2), policy.MaxRegistrations())
		})
	}
}

func TestAuthenticateClientRegistrationJWTStrategyResolution(t *testing.T) {
	ctx := context.Background()

	testCases := []struct {
		name  string
		setup func(auth *DefaultEndpointAuthStrategy, access *hoauth2.JWTProfileCoreStrategy)
		err   error
	}{
		{
			name:  "ShouldUseTheAccessTokenStrategy",
			setup: func(auth *DefaultEndpointAuthStrategy, access *hoauth2.JWTProfileCoreStrategy) {},
		},
		{
			name: "ShouldUseTheConfiguredJWTStrategy",
			setup: func(auth *DefaultEndpointAuthStrategy, access *hoauth2.JWTProfileCoreStrategy) {
				auth.AccessTokenStrategy = access.HMACCoreStrategy
				auth.JWTStrategy = access.Strategy
			},
		},
		{
			name: "ShouldTakeTheStoragePathWithoutAJWTStrategy",
			setup: func(auth *DefaultEndpointAuthStrategy, access *hoauth2.JWTProfileCoreStrategy) {
				auth.AccessTokenStrategy = access.HMACCoreStrategy
			},
			err: oauth2.ErrInvalidToken,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			auth, _, store, access := newJWTAuthFixtures(t)

			tc.setup(auth, access)

			token := signJWTAuthToken(t, access, jwt.JSONWebTokenTypeAccessToken, nil)

			persistJWTAuthToken(t, store, token)

			requester, err := auth.AuthenticateClientRegistrationRequest(ctx, bindingRequest(oauth2.BearerAccessToken, token, "", nil), "")

			if tc.err != nil {
				require.Error(t, err)
				assert.ErrorIs(t, err, tc.err)

				return
			}

			require.NoError(t, err)

			pr, ok := requester.(RegistrationPolicyRequester)
			require.True(t, ok)
			assert.Equal(t, testJWTCounterKey, pr.GetRegistrationCounterKey())
		})
	}
}

func TestAuthenticateClientRegistrationJWTStorage(t *testing.T) {
	ctx := context.Background()

	const policyClaim = testJWTIssuer + ":authelia:oauth2:dynamic-client-registration:policy"

	authenticate := func(auth *DefaultEndpointAuthStrategy, token string) (RegistrationPolicyRequester, error) {
		requester, err := auth.AuthenticateClientRegistrationRequest(ctx, bindingRequest(oauth2.BearerAccessToken, token, "", nil), "")
		if err != nil {
			return nil, err
		}

		return requester.(RegistrationPolicyRequester), nil
	}

	t.Run("ShouldRejectATokenAbsentFromStorage", func(t *testing.T) {
		auth, _, _, access := newJWTAuthFixtures(t)

		_, err := authenticate(auth, signJWTAuthToken(t, access, jwt.JSONWebTokenTypeAccessToken, jwt.MapClaims{policyClaim: nil}))

		require.ErrorIs(t, err, oauth2.ErrInvalidToken)
	})

	t.Run("ShouldRejectARevokedToken", func(t *testing.T) {
		auth, _, store, access := newJWTAuthFixtures(t)

		token := signJWTAuthToken(t, access, jwt.JSONWebTokenTypeAccessToken, nil)

		persistJWTAuthToken(t, store, token)

		_, err := authenticate(auth, token)
		require.NoError(t, err)

		require.NoError(t, store.RevokeAccessToken(ctx, testJWTRequestID))

		_, err = authenticate(auth, token)
		require.ErrorIs(t, err, oauth2.ErrInvalidToken)
	})

	t.Run("ShouldKeepTheCounterKeyAcrossARefresh", func(t *testing.T) {
		auth, _, store, access := newJWTAuthFixtures(t)

		original := signJWTAuthToken(t, access, jwt.JSONWebTokenTypeAccessToken, jwt.MapClaims{jwt.ClaimJWTID: "original"})
		refreshed := signJWTAuthToken(t, access, jwt.JSONWebTokenTypeAccessToken, jwt.MapClaims{jwt.ClaimJWTID: "refreshed"})

		persistJWTAuthToken(t, store, original)
		persistJWTAuthToken(t, store, refreshed)

		first, err := authenticate(auth, original)
		require.NoError(t, err)

		second, err := authenticate(auth, refreshed)
		require.NoError(t, err)

		assert.Equal(t, testJWTCounterKey, first.GetRegistrationCounterKey())
		assert.Equal(t, first.GetRegistrationCounterKey(), second.GetRegistrationCounterKey())
	})

	t.Run("ShouldAcceptAnUnstoredTokenWhenStateless", func(t *testing.T) {
		auth, config, _, access := newJWTAuthFixtures(t)

		config.RFC7591ClientRegistrationStatelessAccessTokens = true

		requester, err := authenticate(auth, signJWTAuthToken(t, access, jwt.JSONWebTokenTypeAccessToken, jwt.MapClaims{policyClaim: map[string]any{testMetadataClientName: map[string]any{policyRuleOneOf: []any{"a"}}}}))

		require.NoError(t, err)
		assert.Equal(t, `jwt:["https://auth.example.com","j1"]`, requester.GetRegistrationCounterKey())
	})

	t.Run("ShouldRejectAnUnstoredCountedTokenWhenStateless", func(t *testing.T) {
		auth, config, _, access := newJWTAuthFixtures(t)

		config.RFC7591ClientRegistrationStatelessAccessTokens = true

		_, err := authenticate(auth, signJWTAuthToken(t, access, jwt.JSONWebTokenTypeAccessToken, nil))

		require.ErrorIs(t, err, oauth2.ErrInvalidToken)
	})

	t.Run("ShouldUseTheSessionKeyForAStoredCountedTokenWhenStateless", func(t *testing.T) {
		auth, config, store, access := newJWTAuthFixtures(t)

		config.RFC7591ClientRegistrationStatelessAccessTokens = true

		token := signJWTAuthToken(t, access, jwt.JSONWebTokenTypeAccessToken, nil)

		persistJWTAuthToken(t, store, token)

		requester, err := authenticate(auth, token)

		require.NoError(t, err)
		assert.Equal(t, testJWTCounterKey, requester.GetRegistrationCounterKey())
	})
}

func TestAuthenticateClientRegistrationJWTRequiresAnIssuer(t *testing.T) {
	ctx := context.Background()

	auth, config, store, access := newJWTAuthFixtures(t)

	token := signJWTAuthToken(t, access, jwt.JSONWebTokenTypeAccessToken, nil)

	persistJWTAuthToken(t, store, token)

	config.AccessTokenIssuer = ""

	_, err := auth.AuthenticateClientRegistrationRequest(ctx, bindingRequest(oauth2.BearerAccessToken, token, "", nil), "")

	require.Error(t, err)
	assert.ErrorIs(t, err, oauth2.ErrInvalidToken)
}

func persistJWTAuthToken(t *testing.T, store *storage.MemoryStore, token string) {
	t.Helper()

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return
	}

	require.NoError(t, store.CreateAccessTokenSession(context.Background(), parts[2], &oauth2.Request{ID: testJWTRequestID, Client: &oauth2.DefaultClient{ID: testOnboardingClientID}, Session: &oauth2.DefaultSession{}}))
}

func newJWTAuthFixtures(t *testing.T) (auth *DefaultEndpointAuthStrategy, config *oauth2.Config, store *storage.MemoryStore, access *hoauth2.JWTProfileCoreStrategy) {
	t.Helper()

	_, config, store, _ = newAuthFixtures(t)

	config.AccessTokenIssuer = testJWTIssuer
	config.DPoPEnabled = true
	config.DPoPStrategy = rfc9449.NewDefaultStrategy(config, store)

	access = newJWTAuthSigner(config)

	return NewDefaultEndpointAuthStrategy(config, store, access, access), config, store, access
}

func newJWTAuthSigner(config *oauth2.Config) (strategy *hoauth2.JWTProfileCoreStrategy) {
	return &hoauth2.JWTProfileCoreStrategy{
		HMACCoreStrategy: hoauth2.NewHMACCoreStrategy(config, "authelia_%s_"),
		Strategy: &jwt.DefaultStrategy{
			Config: config,
			Issuer: jwt.NewDefaultIssuerRS256Unverified(gen.MustRSAKey()),
		},
		Config: config,
	}
}

func newJWTAuthKeyedSigner(t *testing.T, config *oauth2.Config, key any, kid string) (strategy *hoauth2.JWTProfileCoreStrategy) {
	t.Helper()

	issuer, err := jwt.NewDefaultIssuer(jose.JSONWebKey{Key: key, KeyID: kid, Algorithm: string(jose.RS256), Use: jwt.JSONWebTokenUseSignature})
	require.NoError(t, err)

	return &hoauth2.JWTProfileCoreStrategy{
		HMACCoreStrategy: hoauth2.NewHMACCoreStrategy(config, "authelia_%s_"),
		Strategy:         &jwt.DefaultStrategy{Config: config, Issuer: issuer},
		Config:           config,
	}
}

func publicJWK(t *testing.T, strategy *hoauth2.JWTProfileCoreStrategy) jose.JSONWebKey {
	t.Helper()

	key, err := strategy.Strategy.(*jwt.DefaultStrategy).Issuer.GetIssuerJWK(context.Background(), "", string(jose.RS256), jwt.JSONWebTokenUseSignature)
	require.NoError(t, err)

	return key.Public()
}

func newJWKSServer(t *testing.T, jwks *jose.JSONWebKeySet) *httptest.Server {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		_ = json.NewEncoder(w).Encode(jwks)
	}))

	t.Cleanup(server.Close)

	return server
}

func signJWTAuthToken(t *testing.T, strategy *hoauth2.JWTProfileCoreStrategy, typ string, overrides jwt.MapClaims) string {
	t.Helper()

	token, _, err := strategy.Encode(context.Background(), signJWTAuthClaims(overrides), jwt.WithHeaders(&jwt.Headers{Extra: map[string]any{jwt.JSONWebTokenHeaderType: typ}}))
	require.NoError(t, err)

	return token
}

func signJWTAuthClaims(overrides jwt.MapClaims) jwt.MapClaims {
	claims := jwt.MapClaims{
		jwt.ClaimIssuer:           testJWTIssuer,
		jwt.ClaimSubject:          "onboarding-bot",
		jwt.ClaimAudience:         []string{testEndpoint},
		jwt.ClaimScope:            testRegistrationScope,
		jwt.ClaimClientIdentifier: testOnboardingClientID,
		jwt.ClaimJWTID:            "j1",
		jwt.ClaimIssuedAt:         time.Now().Unix(),
		jwt.ClaimExpirationTime:   time.Now().Add(time.Hour).Unix(),
		testJWTIssuer + ":authelia:oauth2:dynamic-client-registration:policy": map[string]any{policyMemberMaxRegistrations: 2},
	}

	for name, value := range overrides {
		if value == nil {
			delete(claims, name)

			continue
		}

		claims[name] = value
	}

	return claims
}

func TestAuthenticateClientRegistrationJWTResolvesAnIssuedToken(t *testing.T) {
	testCases := []struct {
		name  string
		setup func(auth *DefaultEndpointAuthStrategy, access *hoauth2.JWTProfileCoreStrategy)
	}{
		{
			name:  "ShouldResolveWithTheAccessTokenStrategy",
			setup: func(auth *DefaultEndpointAuthStrategy, access *hoauth2.JWTProfileCoreStrategy) {},
		},
		{
			name: "ShouldResolveWithTheConfiguredJWTStrategy",
			setup: func(auth *DefaultEndpointAuthStrategy, access *hoauth2.JWTProfileCoreStrategy) {
				auth.AccessTokenStrategy = access.HMACCoreStrategy
				auth.JWTStrategy = access.Strategy
			},
		},
	}

	for _, tc := range testCases {
		for name, store := range map[string]Storage{
			"MemoryStore":          storage.NewMemoryStore(),
			"HydratingMemoryStore": storage.NewHydratingMemoryStore(),
		} {
			t.Run(tc.name+"/"+name, func(t *testing.T) {
				ctx := context.Background()

				auth, config, _, access := newJWTAuthFixtures(t)

				auth.Store = store
				config.EnforceJWTProfileAccessTokens = true

				tc.setup(auth, access)

				request := &oauth2.Request{
					ID:     testJWTRequestID,
					Client: &oauth2.DefaultClient{ID: testOnboardingClientID},
					Session: &hoauth2.JWTSession{
						JWTClaims: &jwt.JWTClaims{Subject: "onboarding-bot"},
						ExpiresAt: map[oauth2.TokenType]time.Time{oauth2.AccessToken: time.Now().Add(time.Hour)},
					},
					GrantedScope:    oauth2.Arguments{testRegistrationScope},
					GrantedAudience: oauth2.Arguments{testEndpoint},
				}

				token, signature, err := access.GenerateAccessToken(ctx, request)
				require.NoError(t, err)
				require.NoError(t, store.CreateAccessTokenSession(ctx, signature, request))

				requester, err := auth.AuthenticateClientRegistrationRequest(ctx, bindingRequest(oauth2.BearerAccessToken, token, "", nil), "")
				require.NoError(t, err)

				assert.Equal(t, testJWTCounterKey, requester.(RegistrationPolicyRequester).GetRegistrationCounterKey())
			})
		}
	}
}
