// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package jwtgrant_test

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/jose"
	josejwt "authelia.com/provider/jose/jwt"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/gen"
	"authelia.com/provider/oauth2/internal/jwtgrant"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestVerify(t *testing.T) {
	signer, other := gen.MustRSAKey(), gen.MustRSAKey()

	unused := func(t *testing.T) func(ctx context.Context) jwt.JWKSFetcherStrategy {
		return func(_ context.Context) jwt.JWKSFetcherStrategy {
			t.Fatal("the fetcher must not be used")

			return nil
		}
	}

	t.Run("ShouldVerifyWithAStaticKeyAndReturnItsKeyID", func(t *testing.T) {
		keys := jwtgrant.Keys{Issuer: testIssuer, JSONWebKeys: set(public(signer, "a"))}

		claims, raw, kid, err := jwtgrant.Verify(t.Context(), testName, parse(t, sign(t, signer, "a")), keys, unused(t))

		require.NoError(t, err)
		assert.Equal(t, "a", kid)
		assert.Equal(t, "alice", raw["sub"])
		assert.Equal(t, "alice", claims.Subject)
		assert.Equal(t, testIssuer, claims.Issuer)
	})

	t.Run("ShouldReturnTheKeyIDOfTheVerifyingKeyForAGrantWithoutAKeyID", func(t *testing.T) {
		keys := jwtgrant.Keys{Issuer: testIssuer, JSONWebKeys: set(public(other, "a"), public(signer, "b"))}

		_, raw, kid, err := jwtgrant.Verify(t.Context(), testName, parse(t, sign(t, signer, "")), keys, unused(t))

		require.NoError(t, err)
		assert.Equal(t, "b", kid)
		assert.Equal(t, "alice", raw["sub"])
	})

	t.Run("ShouldRejectAnAlgorithmTheIssuerDoesNotPermitBeforeFetchingKeys", func(t *testing.T) {
		keys := jwtgrant.Keys{Issuer: testIssuer, JSONWebKeysURI: testURI, SigningAlgs: []string{string(jose.ES256)}}

		_, raw, kid, err := jwtgrant.Verify(t.Context(), testName, parse(t, sign(t, signer, "a")), keys, unused(t))

		require.ErrorIs(t, err, oauth2.ErrInvalidGrant)
		assert.Nil(t, raw)
		assert.Empty(t, kid)
		assert.Equal(t, "The algorithm 'RS256' is not permitted for the issuer '"+testIssuer+"'.", hint(t, err))
	})

	t.Run("ShouldSkipAKeyForAnotherUse", func(t *testing.T) {
		key := public(signer, "a")
		key.Use = "enc"

		_, _, kid, err := jwtgrant.Verify(t.Context(), testName, parse(t, sign(t, signer, "a")), jwtgrant.Keys{Issuer: testIssuer, JSONWebKeys: set(key)}, unused(t))

		require.ErrorIs(t, err, oauth2.ErrInvalidGrant)
		assert.Empty(t, kid)
		assert.Equal(t, "No key of the issuer verifies the "+testName+".", hint(t, err))
	})

	t.Run("ShouldSkipAKeyForAnotherAlgorithm", func(t *testing.T) {
		key := public(signer, "a")
		key.Algorithm = string(jose.PS256)

		_, _, _, err := jwtgrant.Verify(t.Context(), testName, parse(t, sign(t, signer, "a")), jwtgrant.Keys{Issuer: testIssuer, JSONWebKeys: set(key)}, unused(t))

		require.ErrorIs(t, err, oauth2.ErrInvalidGrant)
	})

	t.Run("ShouldPreferStaticKeysOverTheURI", func(t *testing.T) {
		keys := jwtgrant.Keys{Issuer: testIssuer, JSONWebKeys: set(public(signer, "a")), JSONWebKeysURI: testURI}

		_, _, kid, err := jwtgrant.Verify(t.Context(), testName, parse(t, sign(t, signer, "a")), keys, unused(t))

		require.NoError(t, err)
		assert.Equal(t, "a", kid)
	})

	t.Run("ShouldRefetchOnceWhenTheNamedKeyIsNotCached", func(t *testing.T) {
		stub := &stubFetcher{sets: []*jose.JSONWebKeySet{set(public(other, "z")), set(public(signer, "a"))}}

		_, raw, kid, err := jwtgrant.Verify(t.Context(), testName, parse(t, sign(t, signer, "a")), jwtgrant.Keys{Issuer: testIssuer, JSONWebKeysURI: testURI}, stub.strategy)

		require.NoError(t, err)
		assert.Equal(t, []bool{false, true}, stub.calls)
		assert.Equal(t, []string{testURI, testURI}, stub.locations)
		assert.Equal(t, "a", kid)
		assert.Equal(t, "alice", raw["sub"])
	})

	t.Run("ShouldNotRefetchWhenTheNamedCachedKeyFailsToVerify", func(t *testing.T) {
		stub := &stubFetcher{sets: []*jose.JSONWebKeySet{set(public(other, "a")), set(public(signer, "a"))}}

		_, _, kid, err := jwtgrant.Verify(t.Context(), testName, parse(t, sign(t, signer, "a")), jwtgrant.Keys{Issuer: testIssuer, JSONWebKeysURI: testURI}, stub.strategy)

		require.ErrorIs(t, err, oauth2.ErrInvalidGrant)
		assert.Equal(t, []bool{false}, stub.calls)
		assert.Empty(t, kid)
	})

	t.Run("ShouldAnswerServerErrorWithoutKeys", func(t *testing.T) {
		_, _, _, err := jwtgrant.Verify(t.Context(), testName, parse(t, sign(t, signer, "a")), jwtgrant.Keys{Issuer: testIssuer}, unused(t))

		require.ErrorIs(t, err, oauth2.ErrServerError)
	})

	t.Run("ShouldAnswerServerErrorWhenTheFetchFails", func(t *testing.T) {
		stub := &stubFetcher{err: errors.New("boom")}

		_, _, _, err := jwtgrant.Verify(t.Context(), testName, parse(t, sign(t, signer, "a")), jwtgrant.Keys{Issuer: testIssuer, JSONWebKeysURI: testURI}, stub.strategy)

		require.ErrorIs(t, err, oauth2.ErrServerError)
		assert.Equal(t, []bool{false}, stub.calls)
	})
}

func TestParse(t *testing.T) {
	signer := gen.MustRSAKey()

	t.Run("ShouldReturnTheTokenAndTheIssuer", func(t *testing.T) {
		token, issuer, err := jwtgrant.Parse(testName, testAlgs, sign(t, signer, "a"))

		require.NoError(t, err)
		require.NotNil(t, token)
		assert.Equal(t, testIssuer, issuer)
	})

	t.Run("ShouldRejectAMalformedGrant", func(t *testing.T) {
		_, _, err := jwtgrant.Parse(testName, testAlgs, "not-a-jwt")

		require.ErrorIs(t, err, oauth2.ErrInvalidGrant)
		assert.Equal(t, "Unable to parse the "+testName+".", hint(t, err))
	})

	t.Run("ShouldRejectAnAlgorithmThatIsNotPermitted", func(t *testing.T) {
		_, _, err := jwtgrant.Parse(testName, []jose.SignatureAlgorithm{jose.ES256}, sign(t, signer, "a"))

		require.ErrorIs(t, err, oauth2.ErrInvalidGrant)
	})

	t.Run("ShouldRejectAGrantWithoutAnIssuer", func(t *testing.T) {
		_, _, err := jwtgrant.Parse(testName, testAlgs, signClaims(t, signer, "a", map[string]any{"sub": "alice"}))

		require.ErrorIs(t, err, oauth2.ErrInvalidGrant)
		assert.Equal(t, "The "+testName+" must contain an 'iss' claim.", hint(t, err))
	})
}

func TestUnverifiedClaims(t *testing.T) {
	signer := gen.MustRSAKey()

	t.Run("ShouldReturnTheClaims", func(t *testing.T) {
		claims, raw, err := jwtgrant.UnverifiedClaims(testName, testAlgs, sign(t, signer, "a"))

		require.NoError(t, err)
		assert.Equal(t, testIssuer, claims.Issuer)
		assert.Equal(t, "alice", raw["sub"])
	})

	t.Run("ShouldRejectAMalformedGrant", func(t *testing.T) {
		_, raw, err := jwtgrant.UnverifiedClaims(testName, testAlgs, "not-a-jwt")

		require.ErrorIs(t, err, oauth2.ErrInvalidGrant)
		assert.Nil(t, raw)
		assert.Equal(t, "Unable to parse the "+testName+".", hint(t, err))
	})
}

func TestCheckAlgorithm(t *testing.T) {
	testCases := []struct {
		name string
		algs []string
		alg  jose.SignatureAlgorithm
		err  error
	}{
		{name: "ShouldDefaultToRS256", alg: jose.RS256},
		{name: "ShouldRejectES256ByDefault", alg: jose.ES256, err: oauth2.ErrInvalidGrant},
		{name: "ShouldAcceptAListedAlgorithm", algs: []string{"ES256", "PS256"}, alg: jose.PS256},
		{name: "ShouldRejectAnUnlistedAlgorithm", algs: []string{"ES256"}, alg: jose.RS256, err: oauth2.ErrInvalidGrant},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := jwtgrant.CheckAlgorithm(jwtgrant.Keys{Issuer: testIssuer, SigningAlgs: tc.algs}, jose.Header{Algorithm: string(tc.alg)})

			if tc.err == nil {
				require.NoError(t, err)

				return
			}

			require.ErrorIs(t, err, tc.err)
			assert.Equal(t, fmt.Sprintf("The algorithm '%s' is not permitted for the issuer '%s'.", tc.alg, testIssuer), hint(t, err))
		})
	}
}

func TestValidateTime(t *testing.T) {
	opts := jwtgrant.TimeOptions{Skew: 5 * time.Second, MaxDuration: time.Hour}

	date := func(offset time.Duration) *josejwt.NumericDate {
		return josejwt.NewNumericDate(time.Now().Add(offset))
	}

	testCases := []struct {
		name   string
		claims josejwt.Claims
		hint   string
	}{
		{
			name:   "ShouldAcceptAValidGrant",
			claims: josejwt.Claims{IssuedAt: date(-time.Minute), NotBefore: date(-time.Minute), Expiry: date(time.Minute)},
		},
		{
			name:   "ShouldRejectAMissingExpiry",
			claims: josejwt.Claims{IssuedAt: date(-time.Minute)},
			hint:   "The " + testName + " must contain an 'exp' claim.",
		},
		{
			name:   "ShouldRejectAnExpiredGrant",
			claims: josejwt.Claims{IssuedAt: date(-2 * time.Minute), Expiry: date(-time.Minute)},
			hint:   "The " + testName + " is expired.",
		},
		{
			name:   "ShouldRejectANotBeforeBeyondTheSkew",
			claims: josejwt.Claims{IssuedAt: date(-time.Minute), NotBefore: date(10 * time.Second), Expiry: date(time.Minute)},
			hint:   "The " + testName + " is not yet valid.",
		},
		{
			name:   "ShouldAcceptANotBeforeWithinTheSkew",
			claims: josejwt.Claims{IssuedAt: date(-time.Minute), NotBefore: date(3 * time.Second), Expiry: date(time.Minute)},
		},
		{
			name:   "ShouldRejectAnIssuedAtInTheFuture",
			claims: josejwt.Claims{IssuedAt: date(10 * time.Second), Expiry: date(time.Minute)},
			hint:   "The 'iat' claim of the " + testName + " is in the future.",
		},
		{
			name:   "ShouldRejectALifetimeOverTheMaximum",
			claims: josejwt.Claims{IssuedAt: date(-time.Minute), Expiry: date(2 * time.Hour)},
			hint:   "The 'exp' claim of the " + testName + " is unreasonably far in the future.",
		},
		{
			name:   "ShouldMeasureAMissingIssuedAtFromNow",
			claims: josejwt.Claims{Expiry: date(2 * time.Hour)},
			hint:   "The 'exp' claim of the " + testName + " is unreasonably far in the future.",
		},
		{
			name:   "ShouldMeasureAMissingIssuedAtFromNowAndAcceptAShortLifetime",
			claims: josejwt.Claims{Expiry: date(30 * time.Minute)},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := jwtgrant.ValidateTime(testName, tc.claims, opts)

			if tc.hint == "" {
				require.NoError(t, err)

				return
			}

			require.ErrorIs(t, err, oauth2.ErrInvalidGrant)
			assert.Equal(t, tc.hint, hint(t, err))
		})
	}
}

func TestCapExpiry(t *testing.T) {
	n := time.Now().Unix()

	t.Run("ShouldCapAtTheGrant", func(t *testing.T) {
		assert.Equal(t, time.Unix(n, 0).UTC(), jwtgrant.CapExpiry(time.Now().Add(time.Hour), time.Unix(n, 500e6), 0))
	})

	t.Run("ShouldKeepAnEarlierExpiry", func(t *testing.T) {
		expires := time.Unix(n-60, 0).UTC()

		assert.Equal(t, expires, jwtgrant.CapExpiry(expires, time.Unix(n, 0), 0))
	})

	t.Run("ShouldAddTheAllowance", func(t *testing.T) {
		assert.Equal(t, time.Unix(n+30, 0).UTC(), jwtgrant.CapExpiry(time.Now().Add(time.Hour), time.Unix(n, 500e6), 30*time.Second))
	})
}

func TestReplay(t *testing.T) {
	t.Run("ShouldAcceptAnUnusedGrant", func(t *testing.T) {
		require.NoError(t, jwtgrant.CheckUnused(t.Context(), testName, func(_ context.Context) (bool, error) { return false, nil }))
	})

	t.Run("ShouldRejectAUsedGrant", func(t *testing.T) {
		err := jwtgrant.CheckUnused(t.Context(), testName, func(_ context.Context) (bool, error) { return true, nil })

		require.ErrorIs(t, err, oauth2.ErrInvalidGrant)
		assert.Equal(t, "The "+testName+" was already redeemed.", hint(t, err))
	})

	t.Run("ShouldAnswerServerErrorWhenTheCheckFails", func(t *testing.T) {
		err := jwtgrant.CheckUnused(t.Context(), testName, func(_ context.Context) (bool, error) { return false, errors.New("boom") })

		require.ErrorIs(t, err, oauth2.ErrServerError)
	})

	t.Run("ShouldRejectAGrantConsumedConcurrently", func(t *testing.T) {
		var known error = oauth2.ErrJTIKnown

		err := jwtgrant.Consume(t.Context(), testName, func(_ context.Context) error { return fmt.Errorf("x: %w", known) })

		require.ErrorIs(t, err, oauth2.ErrInvalidGrant)
		assert.Equal(t, "The "+testName+" was already redeemed.", hint(t, err))
	})

	t.Run("ShouldAnswerServerErrorWhenTheMarkFails", func(t *testing.T) {
		err := jwtgrant.Consume(t.Context(), testName, func(_ context.Context) error { return errors.New("boom") })

		require.ErrorIs(t, err, oauth2.ErrServerError)
	})

	t.Run("ShouldConsume", func(t *testing.T) {
		require.NoError(t, jwtgrant.Consume(t.Context(), testName, func(_ context.Context) error { return nil }))
	})
}

const (
	testName   = "JWT Authorization Grant"
	testIssuer = "https://issuer.example.com"
	testURI    = "https://issuer.example.com/jwks.json"
)

var testAlgs = []jose.SignatureAlgorithm{jose.RS256}

type stubFetcher struct {
	sets      []*jose.JSONWebKeySet
	err       error
	calls     []bool
	locations []string
}

func (f *stubFetcher) strategy(_ context.Context) jwt.JWKSFetcherStrategy {
	return f
}

func (f *stubFetcher) Resolve(_ context.Context, location string, ignoreCache bool) (jwks *jose.JSONWebKeySet, err error) {
	f.calls = append(f.calls, ignoreCache)
	f.locations = append(f.locations, location)

	if f.err != nil {
		return nil, f.err
	}

	return f.sets[len(f.calls)-1], nil
}

func public(key *rsa.PrivateKey, kid string) jose.JSONWebKey {
	return jose.JSONWebKey{Key: &key.PublicKey, KeyID: kid}
}

func set(keys ...jose.JSONWebKey) *jose.JSONWebKeySet {
	return &jose.JSONWebKeySet{Keys: keys}
}

func sign(t *testing.T, key *rsa.PrivateKey, kid string) string {
	t.Helper()

	return signClaims(t, key, kid, map[string]any{
		"iss": testIssuer,
		"sub": "alice",
		"exp": time.Now().Add(time.Minute).Unix(),
	})
}

func signClaims(t *testing.T, key *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()

	var signingKey any = key

	if kid != "" {
		signingKey = jose.JSONWebKey{Key: key, KeyID: kid}
	}

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: signingKey}, &jose.SignerOptions{})
	require.NoError(t, err)

	raw, err := josejwt.Signed(signer).Claims(claims).Serialize()
	require.NoError(t, err)

	return raw
}

func parse(t *testing.T, assertion string) *josejwt.JSONWebToken {
	t.Helper()

	token, _, err := jwtgrant.Parse(testName, testAlgs, assertion)
	require.NoError(t, err)

	return token
}

func hint(t *testing.T, err error) string {
	t.Helper()

	rfc, ok := errors.AsType[*oauth2.RFC6749Error](err)
	require.True(t, ok)

	return rfc.HintField
}
