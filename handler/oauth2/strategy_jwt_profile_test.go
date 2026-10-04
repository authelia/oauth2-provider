// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/jose"
	josejwt "authelia.com/provider/jose/jwt"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/gen"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestAccessToken(t *testing.T) {
	scopeFields := []struct {
		name  string
		field jwt.JWTScopeFieldEnum
	}{
		{name: "ScopeFieldList", field: jwt.JWTScopeFieldList},
		{name: "ScopeFieldString", field: jwt.JWTScopeFieldString},
		{name: "ScopeFieldBoth", field: jwt.JWTScopeFieldBoth},
	}

	for _, scopeField := range scopeFields {
		testCases := []struct {
			name string
			r    *oauth2.Request
			pass bool
		}{
			{
				name: "ShouldAcceptAValidToken",
				r:    jwtValidCase(oauth2.AccessToken),
				pass: true,
			},
			{
				name: "ShouldRejectAnExpiredToken",
				r:    jwtExpiredCase(oauth2.AccessToken, time.Unix(1726972738, 0)),
				pass: false,
			},
			{
				name: "ShouldAcceptAValidTokenWithZeroRefreshExpiry",
				r:    jwtValidCaseWithZeroRefreshExpiry(oauth2.AccessToken),
				pass: true,
			},
			{
				name: "ShouldAcceptAValidTokenWithRefreshExpiry",
				r:    jwtValidCaseWithRefreshExpiry(oauth2.AccessToken),
				pass: true,
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				config := &oauth2.Config{
					EnforceJWTProfileAccessTokens: true,
					GlobalSecret:                  []byte("foofoofoofoofoofoofoofoofoofoofoo"),
					JWTScopeClaimKey:              scopeField.field,
				}

				jwtStrategy := &jwt.DefaultStrategy{
					Config: config,
					Issuer: jwt.NewDefaultIssuerRS256Unverified(rsaKey),
				}

				strategy := NewCoreStrategy(config, "authelia_%s_", jwtStrategy)

				before := time.Now().Truncate(time.Second)

				token, signature, err := strategy.GenerateAccessToken(t.Context(), tc.r)
				assert.NoError(t, err)

				after := time.Now()

				parts := strings.Split(token, ".")
				require.Len(t, parts, 3, "%s - %v", token, parts)
				assert.Equal(t, parts[2], signature)

				rawPayload, err := base64.RawURLEncoding.DecodeString(parts[1])
				require.NoError(t, err)

				var payload map[string]any

				require.NoError(t, json.Unmarshal(rawPayload, &payload))

				if scopeField.field == jwt.JWTScopeFieldList || scopeField.field == jwt.JWTScopeFieldBoth {
					scope, ok := payload[consts.ClaimScopeNonStandard]
					require.True(t, ok)
					assert.Equal(t, []any{consts.ScopeEmail, consts.ScopeOffline}, scope)
				}
				if scopeField.field == jwt.JWTScopeFieldString || scopeField.field == jwt.JWTScopeFieldBoth {
					scope, ok := payload[consts.ClaimScope]
					require.True(t, ok)
					assert.Equal(t, "email offline", scope)
				}

				rawHeader, err := base64.RawURLEncoding.DecodeString(parts[0])
				require.NoError(t, err)
				var header map[string]any

				require.NoError(t, json.Unmarshal(rawHeader, &header))

				assert.Equal(t, consts.JSONWebTokenTypeAccessToken, header[consts.JSONWebTokenHeaderType])

				extraClaimsSession, ok := tc.r.GetSession().(oauth2.ExtraClaimsSession)
				require.True(t, ok)
				claims := extraClaimsSession.GetExtraClaims()
				assert.Equal(t, "bar", claims["foo"])
				assert.Equal(t, "peter", claims[consts.ClaimSubject])
				assert.Equal(t, []string{"group0"}, claims[consts.ClaimAudience])
				assert.Equal(t, "email offline", claims[consts.ClaimScope])

				assert.WithinRange(t, anyInt64ToTime(claims[consts.ClaimIssuedAt]), before, after)
				assert.WithinRange(t, anyInt64ToTime(claims[consts.ClaimNotBefore]), before, after)

				err = strategy.ValidateAccessToken(context.Background(), tc.r, token)
				if tc.pass {
					assert.NoError(t, err)
				} else {
					assert.Error(t, err)
				}
			})
		}
	}
}

func TestGenerateJWTIncludesCnf(t *testing.T) {
	config := &oauth2.Config{
		EnforceJWTProfileAccessTokens: true,
		DPoPEnabled:                   true,
		MTLSEnabled:                   true,
		GlobalSecret:                  []byte("foofoofoofoofoofoofoofoofoofoofoo"),
	}

	jwtStrategy := &jwt.DefaultStrategy{
		Config: config,
		Issuer: jwt.NewDefaultIssuerRS256Unverified(rsaKey),
	}

	strategy := NewCoreStrategy(config, "authelia_%s_", jwtStrategy)

	t.Run("ShouldIncludeCnfWhenDPoPBound", func(t *testing.T) {
		r := jwtValidCase(oauth2.AccessToken)

		dpopSession, ok := r.GetSession().(oauth2.DPoPBoundSession)
		require.True(t, ok)
		dpopSession.SetDPoPJWKThumbprint("test-jkt")

		token, _, err := strategy.GenerateAccessToken(t.Context(), r)
		require.NoError(t, err)

		parts := strings.Split(token, ".")
		require.Len(t, parts, 3, "%s - %v", token, parts)

		rawPayload, err := base64.RawURLEncoding.DecodeString(parts[1])
		require.NoError(t, err)

		var payload map[string]any
		require.NoError(t, json.Unmarshal(rawPayload, &payload))

		cnf, ok := payload[jwt.ClaimConfirmation].(map[string]any)
		require.True(t, ok, "expected cnf claim to be present and a map, got %#v", payload[jwt.ClaimConfirmation])
		assert.Equal(t, "test-jkt", cnf[jwt.ClaimConfirmationJWKThumbprint])
	})

	t.Run("ShouldNotIncludeCnfWhenNotDPoPBound", func(t *testing.T) {
		r := jwtValidCase(oauth2.AccessToken)

		token, _, err := strategy.GenerateAccessToken(t.Context(), r)
		require.NoError(t, err)

		parts := strings.Split(token, ".")
		require.Len(t, parts, 3, "%s - %v", token, parts)

		rawPayload, err := base64.RawURLEncoding.DecodeString(parts[1])
		require.NoError(t, err)

		var payload map[string]any
		require.NoError(t, json.Unmarshal(rawPayload, &payload))

		assert.NotContains(t, payload, jwt.ClaimConfirmation)
	})

	t.Run("ShouldNotAllowExtraClaimsToForgeCnfWhenNotDPoPBound", func(t *testing.T) {
		r := jwtValidCase(oauth2.AccessToken)
		r.GetSession().(*JWTSession).JWTClaims.Extra[jwt.ClaimConfirmation] = map[string]any{
			jwt.ClaimConfirmationJWKThumbprint: "forged-jkt",
		}

		token, _, err := strategy.GenerateAccessToken(t.Context(), r)
		require.NoError(t, err)

		parts := strings.Split(token, ".")
		require.Len(t, parts, 3, "%s - %v", token, parts)

		rawPayload, err := base64.RawURLEncoding.DecodeString(parts[1])
		require.NoError(t, err)

		var payload map[string]any
		require.NoError(t, json.Unmarshal(rawPayload, &payload))

		assert.NotContains(t, payload, jwt.ClaimConfirmation)
	})

	t.Run("ShouldNotAllowExtraClaimsToForgeCnfWhenDPoPBound", func(t *testing.T) {
		r := jwtValidCase(oauth2.AccessToken)
		r.GetSession().(*JWTSession).JWTClaims.Extra[jwt.ClaimConfirmation] = map[string]any{
			jwt.ClaimConfirmationJWKThumbprint: "forged-jkt",
		}
		r.GetSession().(oauth2.DPoPBoundSession).SetDPoPJWKThumbprint("test-jkt")

		token, _, err := strategy.GenerateAccessToken(t.Context(), r)
		require.NoError(t, err)

		parts := strings.Split(token, ".")
		require.Len(t, parts, 3, "%s - %v", token, parts)

		rawPayload, err := base64.RawURLEncoding.DecodeString(parts[1])
		require.NoError(t, err)

		var payload map[string]any
		require.NoError(t, json.Unmarshal(rawPayload, &payload))

		cnf, ok := payload[jwt.ClaimConfirmation].(map[string]any)
		require.True(t, ok, "expected cnf claim to be present and a map, got %#v", payload[jwt.ClaimConfirmation])
		assert.Equal(t, "test-jkt", cnf[jwt.ClaimConfirmationJWKThumbprint])
	})

	t.Run("ShouldNotAllowExtraClaimsToSupplyOtherConfirmationMethods", func(t *testing.T) {
		r := jwtValidCase(oauth2.AccessToken)
		r.GetSession().(*JWTSession).JWTClaims.Extra[jwt.ClaimConfirmation] = map[string]any{
			jwt.ClaimConfirmationX509SHA256Thumbprint: "forged-x5t",
		}
		r.GetSession().(oauth2.DPoPBoundSession).SetDPoPJWKThumbprint("test-jkt")

		token, _, err := strategy.GenerateAccessToken(t.Context(), r)
		require.NoError(t, err)

		parts := strings.Split(token, ".")
		require.Len(t, parts, 3, "%s - %v", token, parts)

		rawPayload, err := base64.RawURLEncoding.DecodeString(parts[1])
		require.NoError(t, err)

		var payload map[string]any
		require.NoError(t, json.Unmarshal(rawPayload, &payload))

		cnf, ok := payload[jwt.ClaimConfirmation].(map[string]any)
		require.True(t, ok, "expected cnf claim to be present and a map, got %#v", payload[jwt.ClaimConfirmation])
		assert.Equal(t, "test-jkt", cnf[jwt.ClaimConfirmationJWKThumbprint])
		assert.NotContains(t, cnf, jwt.ClaimConfirmationX509SHA256Thumbprint)
	})
}

func TestJWTProfileAuthorizationDetailsClaim(t *testing.T) {
	config := &oauth2.Config{
		EnforceJWTProfileAccessTokens: true,
		GlobalSecret:                  []byte("foofoofoofoofoofoofoofoofoofoofoo"),
	}

	jwtStrategy := &jwt.DefaultStrategy{
		Config: config,
		Issuer: jwt.NewDefaultIssuerRS256Unverified(rsaKey),
	}

	strategy := NewCoreStrategy(config, "authelia_%s_", jwtStrategy)

	testCases := []struct {
		name    string
		granted oauth2.AuthorizationDetails
		extra   any
	}{
		{
			name:    "ShouldIncludeGranted",
			granted: oauth2.AuthorizationDetails{{Type: internal.AuthorizationDetailsTypePaymentInitiation, Actions: []string{testRARActionInitiate}}},
		},
		{
			name:    "ShouldOverrideSessionExtra",
			granted: oauth2.AuthorizationDetails{{Type: internal.AuthorizationDetailsTypePaymentInitiation, Actions: []string{testRARActionInitiate}}},
			extra:   testRARExtraSpoofed,
		},
		{
			name:  "ShouldDropSessionExtraWhenNothingGranted",
			extra: testRARExtraSpoofed,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			r := jwtValidCase(oauth2.AccessToken)

			if tc.extra != nil {
				r.GetSession().(*JWTSession).JWTClaims.Extra[consts.ClaimAuthorizationDetails] = tc.extra
			}

			if tc.granted != nil {
				r.GrantedAuthorizationDetails = tc.granted
			}

			token, _, err := strategy.GenerateAccessToken(t.Context(), r)
			require.NoError(t, err)

			parts := strings.Split(token, ".")
			require.Len(t, parts, 3, "%s - %v", token, parts)

			rawPayload, err := base64.RawURLEncoding.DecodeString(parts[1])
			require.NoError(t, err)

			var payload map[string]any
			require.NoError(t, json.Unmarshal(rawPayload, &payload))

			if tc.granted == nil {
				assert.NotContains(t, payload, consts.ClaimAuthorizationDetails)

				return
			}

			raw, err := json.Marshal(payload[consts.ClaimAuthorizationDetails])
			require.NoError(t, err)
			assert.JSONEq(t, `[{"type":"payment_initiation","actions":["initiate"]}]`, string(raw))
		})
	}
}

func TestSplitN(t *testing.T) {
	value1 := "a.b.c"

	split1 := strings.SplitN(value1, ".", 3)

	value2 := "a.b"

	split2 := strings.SplitN(value2, ".", 3)

	value3 := "a.b.c.d"

	split3 := strings.SplitN(value3, ".", 3)

	assert.Len(t, split1, 3)
	assert.Len(t, split2, 2)
	assert.Len(t, split3, 3)
}

// RFC 9068 Section 2.2: the 'client_id' claim is REQUIRED.
func TestGenerateJWTIncludesClientID(t *testing.T) {
	config := &oauth2.Config{
		EnforceJWTProfileAccessTokens: true,
		GlobalSecret:                  []byte("foofoofoofoofoofoofoofoofoofoofoo"),
	}

	jwtStrategy := &jwt.DefaultStrategy{
		Config: config,
		Issuer: jwt.NewDefaultIssuerRS256Unverified(rsaKey),
	}

	strategy := NewCoreStrategy(config, "authelia_%s_", jwtStrategy)

	r := jwtValidCase(oauth2.AccessToken)
	r.Client = &oauth2.DefaultClient{ID: "client-abc"}

	token, _, err := strategy.GenerateAccessToken(t.Context(), r)
	require.NoError(t, err)

	parts := strings.Split(token, ".")
	require.Len(t, parts, 3, "%s - %v", token, parts)

	rawPayload, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)

	var payload map[string]any

	require.NoError(t, json.Unmarshal(rawPayload, &payload))

	assert.Equal(t, "client-abc", payload[consts.ClaimClientIdentifier])
}

func TestGenerateJWTUsesTheClientSigningKeyID(t *testing.T) {
	config := &oauth2.Config{
		EnforceJWTProfileAccessTokens: true,
		GlobalSecret:                  []byte("foofoofoofoofoofoofoofoofoofoofoo"),
	}

	jwks := &jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{Key: rsaKey, KeyID: "a", Use: consts.JSONWebTokenUseSignature, Algorithm: string(jose.RS256)},
			{Key: gen.MustRSAKey(), KeyID: "b", Use: consts.JSONWebTokenUseSignature, Algorithm: string(jose.RS256)},
		},
	}

	strategy := NewCoreStrategy(config, "authelia_%s_", &jwt.DefaultStrategy{
		Config: config,
		Issuer: jwt.NewDefaultIssuerUnverifiedFromJWKS(jwks),
	})

	client := &oauth2.DefaultRegisteredClient{
		DefaultClient:                  &oauth2.DefaultClient{ID: "client-abc"},
		AccessTokenSignedResponseKeyID: "a",
		AccessTokenSignedResponseAlg:   string(jose.RS256),
	}

	r := jwtValidCase(oauth2.AccessToken)
	r.Client = client

	for _, kid := range []string{"a", "b"} {
		client.AccessTokenSignedResponseKeyID = kid

		token, _, err := strategy.GenerateAccessToken(t.Context(), r)
		require.NoError(t, err)

		parsed, err := josejwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.RS256})
		require.NoError(t, err)
		require.Len(t, parsed.Headers, 1)
		assert.Equal(t, kid, parsed.Headers[0].KeyID)
	}

	assert.NotContains(t, r.GetSession().(*JWTSession).JWTHeader.Extra, consts.JSONWebTokenHeaderKeyIdentifier)
}

func TestGenerateJWTDefaultsTheSigningAlgorithm(t *testing.T) {
	config := &oauth2.Config{
		EnforceJWTProfileAccessTokens: true,
		GlobalSecret:                  []byte("foofoofoofoofoofoofoofoofoofoofoo"),
	}

	jwtStrategy := &jwt.DefaultStrategy{
		Config: config,
		Issuer: jwt.NewDefaultIssuerRS256Unverified(rsaKey),
	}

	strategy := NewCoreStrategy(config, "authelia_%s_", jwtStrategy)

	r := jwtValidCase(oauth2.AccessToken)
	r.Client = &oauth2.DefaultRegisteredClient{DefaultClient: &oauth2.DefaultClient{ID: "client-abc"}}

	token, _, err := strategy.GenerateAccessToken(t.Context(), r)
	require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

	parts := strings.Split(token, ".")
	require.Len(t, parts, 3, "%s - %v", token, parts)

	rawHeader, err := base64.RawURLEncoding.DecodeString(parts[0])
	require.NoError(t, err)

	var header map[string]any

	require.NoError(t, json.Unmarshal(rawHeader, &header))

	assert.Equal(t, "RS256", header["alg"])
	assert.NoError(t, strategy.ValidateAccessToken(t.Context(), r, token))
}

func anyInt64ToTime(in any) time.Time {
	return time.Unix(in.(int64), 0)
}
