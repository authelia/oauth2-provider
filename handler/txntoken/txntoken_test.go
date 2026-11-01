// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package txntoken

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/jose"
	josejwt "authelia.com/provider/jose/jwt"

	"authelia.com/provider/oauth2/token/jwt"
)

func TestValidate(t *testing.T) {
	key := newKey(t)
	other := newKey(t)

	testCases := []struct {
		name   string
		claims map[string]any
		header map[string]any
		signer any
		alg    jose.SignatureAlgorithm
		config func(c *Config)
		err    error
		check  func(t *testing.T, c *Claims)
	}{
		{name: "ShouldValidate", check: func(t *testing.T, c *Claims) {
			assert.Equal(t, "user-1", c.Subject)
			assert.Equal(t, "https://tts.example.com", c.Issuer)
			assert.Equal(t, "txn-1", c.Transaction)
			assert.Equal(t, "read write", c.Scope)
			assert.Equal(t, "wl-1", c.RequestingWorkload)
			assert.Equal(t, []string{trustDomain}, c.Audience)
			assert.Equal(t, int64(1900000000), c.ExpiresAt.Unix())
			assert.False(t, c.IssuedAt.IsZero())
			assert.Equal(t, map[string]any{"ip": "192.0.2.1"}, c.RequestContext)
			assert.Equal(t, map[string]any{"order": "o-1"}, c.TransactionContext)
			assert.Equal(t, "extra", c.Extra["unknown"])
			assert.NotContains(t, c.Extra, "sub")
		}},
		{name: "ShouldKeepActInExtra", claims: map[string]any{"act": map[string]any{"sub": "a"}}, check: func(t *testing.T, c *Claims) {
			assert.Contains(t, c.Extra, "act")
		}},
		{name: "ShouldKeepAbsentContextsNil", claims: map[string]any{"rctx": nil, "tctx": nil}, check: func(t *testing.T, c *Claims) {
			assert.Nil(t, c.RequestContext)
			assert.Nil(t, c.TransactionContext)
		}},
		{name: "ShouldAcceptAudienceArray", claims: map[string]any{"aud": []string{"other", trustDomain}}, check: func(t *testing.T, c *Claims) {
			assert.Equal(t, []string{"other", trustDomain}, c.Audience)
		}},
		{name: "ShouldAcceptTypWithPrefixAndCase", header: map[string]any{"typ": "application/TxnToken+JWT"}},
		{name: "ShouldRefuseBadSignature", signer: other, err: ErrInvalidToken},
		{name: "ShouldRefuseTypJWT", header: map[string]any{"typ": "JWT"}, err: ErrInvalidToken},
		{name: "ShouldRefuseAbsentTyp", header: map[string]any{"typ": nil}, err: ErrInvalidToken},
		{name: "ShouldRefuseWrongAudience", claims: map[string]any{"aud": "other"}, err: ErrInvalidToken},
		{name: "ShouldRefuseAudienceArrayWithoutDomain", claims: map[string]any{"aud": []string{"other"}}, err: ErrInvalidToken},
		{name: "ShouldRefuseExpired", claims: map[string]any{"exp": 1000000000}, err: ErrInvalidToken},
		{name: "ShouldRefuseMissingExp", claims: map[string]any{"exp": nil}, err: ErrInvalidToken},
		{name: "ShouldRefuseStringExp", claims: map[string]any{"exp": "1900000000"}, err: ErrInvalidToken},
		{name: "ShouldRefuseMissingIat", claims: map[string]any{"iat": nil}, err: ErrInvalidToken},
		{name: "ShouldRefuseStringIat", claims: map[string]any{"iat": "1"}, err: ErrInvalidToken},
		{name: "ShouldRefuseMissingTxn", claims: map[string]any{"txn": nil}, err: ErrInvalidToken},
		{name: "ShouldRefuseEmptyTxn", claims: map[string]any{"txn": ""}, err: ErrInvalidToken},
		{name: "ShouldRefuseNonStringTxn", claims: map[string]any{"txn": 1}, err: ErrInvalidToken},
		{name: "ShouldRefuseMissingSub", claims: map[string]any{"sub": nil}, err: ErrInvalidToken},
		{name: "ShouldRefuseMissingScope", claims: map[string]any{"scope": nil}, err: ErrInvalidToken},
		{name: "ShouldRefuseMissingReqWl", claims: map[string]any{"req_wl": nil}, err: ErrInvalidToken},
		{name: "ShouldRefuseNonObjectRctx", claims: map[string]any{"rctx": "x"}, err: ErrInvalidToken},
		{name: "ShouldRefuseNonObjectTctx", claims: map[string]any{"tctx": []string{"x"}}, err: ErrInvalidToken},
		{name: "ShouldRefuseEmptyTrustDomain", config: func(c *Config) { c.TrustDomain = "" }, err: ErrInvalidToken},
		{name: "ShouldRefuseNilKeyFunc", config: func(c *Config) { c.KeyFunc = nil }, err: ErrInvalidToken},
		{name: "ShouldRefuseHS256ByDefault", alg: jose.HS256, signer: []byte("0123456789abcdef0123456789abcdef"), config: func(c *Config) {
			c.KeyFunc = func(*jwt.Token) (any, error) { return []byte("0123456789abcdef0123456789abcdef"), nil }
		}, err: ErrInvalidToken},
		{name: "ShouldAcceptHS256WhenConfigured", alg: jose.HS256, signer: []byte("0123456789abcdef0123456789abcdef"), config: func(c *Config) {
			c.KeyFunc = func(*jwt.Token) (any, error) {
				return jose.JSONWebKey{Key: []byte("0123456789abcdef0123456789abcdef")}, nil
			}
			c.Algorithms = []jose.SignatureAlgorithm{jose.HS256}
		}},
		{name: "ShouldRefuseAlgorithmOutsideConfigured", config: func(c *Config) { c.Algorithms = []jose.SignatureAlgorithm{jose.RS256} }, err: ErrInvalidToken},
		{name: "ShouldRefuseKeyFuncError", config: func(c *Config) {
			c.KeyFunc = func(*jwt.Token) (any, error) { return nil, errors.New("no key") }
		}, err: ErrInvalidToken},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			signer := tc.signer
			if signer == nil {
				signer = key
			}

			alg := tc.alg
			if alg == "" {
				alg = jose.ES256
			}

			raw := mint(t, signer, alg, tc.header, tc.claims)

			config := Config{TrustDomain: trustDomain, KeyFunc: func(*jwt.Token) (any, error) { return &key.PublicKey, nil }}
			if tc.config != nil {
				tc.config(&config)
			}

			claims, err := Validate(raw, config)

			if tc.err != nil {
				require.ErrorIs(t, err, tc.err)
				assert.Nil(t, claims)

				return
			}

			require.NoError(t, err)
			require.NotNil(t, claims)

			if tc.check != nil {
				tc.check(t, claims)
			}
		})
	}
}

func TestValidateClockSkew(t *testing.T) {
	key := newKey(t)
	other := newKey(t)
	now := time.Now()

	within, beyond := now.Add(50*time.Second).Unix(), now.Add(70*time.Second).Unix()

	testCases := []struct {
		name     string
		skew     time.Duration
		claims   map[string]any
		header   map[string]any
		signer   any
		keyfunc  jwt.Keyfunc
		accepted bool
	}{
		{name: "ShouldAcceptIssuedAtWithinSkew", skew: time.Minute, claims: map[string]any{"iat": within}, accepted: true},
		{name: "ShouldRefuseIssuedAtBeyondSkew", skew: time.Minute, claims: map[string]any{"iat": beyond}},
		{name: "ShouldAcceptNotBeforeWithinSkew", skew: time.Minute, claims: map[string]any{"nbf": within}, accepted: true},
		{name: "ShouldRefuseNotBeforeBeyondSkew", skew: time.Minute, claims: map[string]any{"nbf": beyond}},
		{name: "ShouldRefuseIssuedAtInFutureWithZeroSkew", claims: map[string]any{"iat": within}},
		{name: "ShouldRefuseNotBeforeInFutureWithZeroSkew", claims: map[string]any{"nbf": within}},
		{name: "ShouldRefuseIssuedAtInFutureWithNegativeSkew", skew: -time.Minute, claims: map[string]any{"iat": within}},
		{name: "ShouldNotApplySkewToExpiry", skew: time.Minute, claims: map[string]any{"exp": now.Add(-10 * time.Second).Unix()}},
		{name: "ShouldRefuseExpiredWithIssuedAtWithinSkew", skew: time.Minute, claims: map[string]any{"iat": within, "exp": now.Add(-10 * time.Second).Unix()}},
		{name: "ShouldRefuseBadSignatureWithIssuedAtWithinSkew", skew: time.Minute, claims: map[string]any{"iat": within}, signer: other},
		{name: "ShouldRefuseTypJWTWithIssuedAtWithinSkew", skew: time.Minute, claims: map[string]any{"iat": within}, header: map[string]any{"typ": "JWT"}},
		{name: "ShouldRefuseWrongAudienceWithIssuedAtWithinSkew", skew: time.Minute, claims: map[string]any{"iat": within, "aud": "other"}},
		{
			name: "ShouldRefuseIssuedAtFlaggedKeyFuncError",
			skew: time.Minute,
			keyfunc: func(*jwt.Token) (any, error) {
				return nil, &jwt.ValidationError{Errors: jwt.ValidationErrorIssuedAt}
			},
		},
		{
			name: "ShouldRefuseNotBeforeFlaggedKeyFuncError",
			skew: time.Minute,
			keyfunc: func(*jwt.Token) (any, error) {
				return nil, &jwt.ValidationError{Errors: jwt.ValidationErrorNotValidYet}
			},
		},
		{
			name: "ShouldRefuseTimingFlaggedKeyFuncErrorWithKey",
			skew: time.Minute,
			keyfunc: func(*jwt.Token) (any, error) {
				return &key.PublicKey, &jwt.ValidationError{Errors: jwt.ValidationErrorIssuedAt}
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			signer := tc.signer
			if signer == nil {
				signer = key
			}

			keyfunc := tc.keyfunc
			if keyfunc == nil {
				keyfunc = func(*jwt.Token) (any, error) { return &key.PublicKey, nil }
			}

			claims, err := Validate(mint(t, signer, jose.ES256, tc.header, tc.claims), Config{TrustDomain: trustDomain, KeyFunc: keyfunc, ClockSkew: tc.skew})

			if !tc.accepted {
				require.ErrorIs(t, err, ErrInvalidToken)
				assert.Nil(t, claims)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, "user-1", claims.Subject)
		})
	}
}

func TestValidateShouldRefuseUnsigned(t *testing.T) {
	key := newKey(t)

	raw := "eyJhbGciOiJub25lIiwidHlwIjoidHhudG9rZW4rand0In0.eyJhdWQiOiJ0ZC5leGFtcGxlLmNvbSIsImV4cCI6MTkwMDAwMDAwMCwiaWF0IjoxfQ."

	claims, err := Validate(raw, Config{TrustDomain: trustDomain, KeyFunc: func(*jwt.Token) (any, error) { return &key.PublicKey, nil }})

	require.ErrorIs(t, err, ErrInvalidToken)
	assert.Nil(t, claims)
}

func TestValidateShouldRefuseGarbage(t *testing.T) {
	key := newKey(t)

	_, err := Validate("not-a-jwt", Config{TrustDomain: trustDomain, KeyFunc: func(*jwt.Token) (any, error) { return &key.PublicKey, nil }})

	require.ErrorIs(t, err, ErrInvalidToken)
}

func TestFromRequest(t *testing.T) {
	testCases := []struct {
		name   string
		header http.Header
		token  string
		err    error
	}{
		{name: "ShouldReadHeader", header: http.Header{HeaderName: {"abc"}}, token: "abc"},
		{name: "ShouldRefuseMultiple", header: http.Header{HeaderName: {"a", "b"}}, err: ErrMultipleTokens},
		{name: "ShouldRefuseAbsent", header: http.Header{}, err: ErrTokenAbsent},
		{name: "ShouldRefuseEmptyValue", header: http.Header{HeaderName: {""}}, err: ErrTokenAbsent},
		{name: "ShouldIgnoreAuthorization", header: http.Header{"Authorization": {"Bearer abc"}}, err: ErrTokenAbsent},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			token, err := FromRequest(&http.Request{Header: tc.header})

			if tc.err != nil {
				require.ErrorIs(t, err, tc.err)
				assert.Empty(t, token)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.token, token)
		})
	}
}

const trustDomain = "td.example.com"

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	return key
}

func mint(t *testing.T, key any, alg jose.SignatureAlgorithm, header, overrides map[string]any) string {
	t.Helper()

	claims := map[string]any{
		"iss":     "https://tts.example.com",
		"iat":     time.Now().Add(-time.Minute).Unix(),
		"exp":     1900000000,
		"aud":     trustDomain,
		"txn":     "txn-1",
		"sub":     "user-1",
		"scope":   "read write",
		"req_wl":  "wl-1",
		"rctx":    map[string]any{"ip": "192.0.2.1"},
		"tctx":    map[string]any{"order": "o-1"},
		"unknown": "extra",
	}

	for k, v := range overrides {
		if v == nil {
			delete(claims, k)
		} else {
			claims[k] = v
		}
	}

	opts := (&jose.SignerOptions{}).WithType("txntoken+jwt")

	for k, v := range header {
		if k == "typ" {
			if v == nil {
				opts = &jose.SignerOptions{}
			} else {
				opts = (&jose.SignerOptions{}).WithType(jose.ContentType(v.(string)))
			}

			continue
		}

		opts = opts.WithHeader(jose.HeaderKey(k), v)
	}

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key}, opts)
	require.NoError(t, err)

	raw, err := josejwt.Signed(signer).Claims(claims).Serialize()
	require.NoError(t, err)

	return raw
}
