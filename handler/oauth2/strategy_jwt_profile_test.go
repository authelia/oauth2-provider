// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/gen"
	"authelia.com/provider/oauth2/token/jwt"
)

var rsaKey = gen.MustRSAKey()

// returns a valid JWT type. The JWTClaims.ExpiresAt time is intentionally
// left empty to ensure it is pulled from the session's ExpiresAt map for
// the given oauth2.TokenType.
var jwtValidCase = func(tokenType oauth2.TokenType) *oauth2.Request {
	r := &oauth2.Request{
		Client: &oauth2.DefaultClient{
			ClientSecret: mustNewBCryptClientSecretPlain("foobarfoobarfoobarfoobar"),
		},
		Session: &JWTSession{
			JWTClaims: &jwt.JWTClaims{
				Issuer:    "oauth2",
				Subject:   "peter",
				IssuedAt:  time.Now().UTC(),
				NotBefore: time.Now().UTC(),
				Extra:     map[string]any{"foo": "bar"},
			},
			JWTHeader: &jwt.Headers{
				Extra: make(map[string]any),
			},
			ExpiresAt: map[oauth2.TokenType]time.Time{
				tokenType: time.Now().UTC().Add(time.Hour),
			},
		},
	}
	r.SetRequestedScopes([]string{consts.ScopeEmail, consts.ScopeOffline})
	r.GrantScope(consts.ScopeEmail)
	r.GrantScope(consts.ScopeOffline)
	r.SetRequestedAudience([]string{"group0"})
	r.GrantAudience("group0")
	return r
}

var jwtValidCaseWithZeroRefreshExpiry = func(tokenType oauth2.TokenType) *oauth2.Request {
	r := &oauth2.Request{
		Client: &oauth2.DefaultClient{
			ClientSecret: mustNewBCryptClientSecretPlain("foobarfoobarfoobarfoobar"),
		},
		Session: &JWTSession{
			JWTClaims: &jwt.JWTClaims{
				Issuer:    "oauth2",
				Subject:   "peter",
				IssuedAt:  time.Now().UTC(),
				NotBefore: time.Now().UTC(),
				Extra:     map[string]any{"foo": "bar"},
			},
			JWTHeader: &jwt.Headers{
				Extra: make(map[string]any),
			},
			ExpiresAt: map[oauth2.TokenType]time.Time{
				tokenType:           time.Now().UTC().Add(time.Hour),
				oauth2.RefreshToken: {},
			},
		},
	}
	r.SetRequestedScopes([]string{consts.ScopeEmail, consts.ScopeOffline})
	r.GrantScope(consts.ScopeEmail)
	r.GrantScope(consts.ScopeOffline)
	r.SetRequestedAudience([]string{"group0"})
	r.GrantAudience("group0")
	return r
}

var jwtValidCaseWithRefreshExpiry = func(tokenType oauth2.TokenType) *oauth2.Request {
	r := &oauth2.Request{
		Client: &oauth2.DefaultClient{
			ClientSecret: mustNewBCryptClientSecretPlain("foobarfoobarfoobarfoobar"),
		},
		Session: &JWTSession{
			JWTClaims: &jwt.JWTClaims{
				Issuer:    "oauth2",
				Subject:   "peter",
				IssuedAt:  time.Now().UTC(),
				NotBefore: time.Now().UTC(),
				Extra:     map[string]any{"foo": "bar"},
			},
			JWTHeader: &jwt.Headers{
				Extra: make(map[string]any),
			},
			ExpiresAt: map[oauth2.TokenType]time.Time{
				tokenType:           time.Now().UTC().Add(time.Hour),
				oauth2.RefreshToken: time.Now().UTC().Add(time.Hour * 2).Round(time.Hour),
			},
		},
	}
	r.SetRequestedScopes([]string{consts.ScopeEmail, consts.ScopeOffline})
	r.GrantScope(consts.ScopeEmail)
	r.GrantScope(consts.ScopeOffline)
	r.SetRequestedAudience([]string{"group0"})
	r.GrantAudience("group0")
	return r
}

// returns an expired JWT type. The JWTClaims.ExpiresAt time is intentionally
// left empty to ensure it is pulled from the session's ExpiresAt map for
// the given oauth2.TokenType.
var jwtExpiredCase = func(tokenType oauth2.TokenType) *oauth2.Request {
	r := &oauth2.Request{
		Client: &oauth2.DefaultClient{
			ClientSecret: mustNewBCryptClientSecretPlain("foobarfoobarfoobarfoobar"),
		},
		Session: &JWTSession{
			JWTClaims: &jwt.JWTClaims{
				Issuer:    "oauth2",
				Subject:   "peter",
				IssuedAt:  time.Now().UTC().Add(-time.Minute * 10),
				NotBefore: time.Now().UTC().Add(-time.Minute * 10),
				ExpiresAt: time.Now().UTC().Add(-time.Minute),
				Extra:     map[string]any{"foo": "bar"},
			},
			JWTHeader: &jwt.Headers{
				Extra: make(map[string]any),
			},
			ExpiresAt: map[oauth2.TokenType]time.Time{
				tokenType: time.Now().UTC().Add(-time.Hour),
			},
		},
	}
	r.SetRequestedScopes([]string{consts.ScopeEmail, consts.ScopeOffline})
	r.GrantScope(consts.ScopeEmail)
	r.GrantScope(consts.ScopeOffline)
	r.SetRequestedAudience([]string{"group0"})
	r.GrantAudience("group0")
	return r
}

func TestAccessToken(t *testing.T) {
	for s, scopeField := range []jwt.JWTScopeFieldEnum{
		jwt.JWTScopeFieldList,
		jwt.JWTScopeFieldString,
		jwt.JWTScopeFieldBoth,
	} {
		for k, c := range []struct {
			r    *oauth2.Request
			pass bool
		}{
			{
				r:    jwtValidCase(oauth2.AccessToken),
				pass: true,
			},
			{
				r:    jwtExpiredCase(oauth2.AccessToken),
				pass: false,
			},
			{
				r:    jwtValidCaseWithZeroRefreshExpiry(oauth2.AccessToken),
				pass: true,
			},
			{
				r:    jwtValidCaseWithRefreshExpiry(oauth2.AccessToken),
				pass: true,
			},
		} {
			t.Run(fmt.Sprintf("case=%d/%d", s, k), func(t *testing.T) {
				signer := &jwt.DefaultSigner{
					GetPrivateKey: func(_ context.Context) (any, error) {
						return rsaKey, nil
					},
				}

				config := &oauth2.Config{
					EnforceJWTProfileAccessTokens: true,
					GlobalSecret:                  []byte("foofoofoofoofoofoofoofoofoofoofoo"),
					JWTScopeClaimKey:              scopeField,
				}

				strategy := NewCoreStrategy(config, "authelia_%s_", signer)

				token, signature, err := strategy.GenerateAccessToken(context.TODO(), c.r)
				assert.NoError(t, err)

				parts := strings.Split(token, ".")
				require.Len(t, parts, 3, "%s - %v", token, parts)
				assert.Equal(t, parts[2], signature)

				rawPayload, err := base64.RawURLEncoding.DecodeString(parts[1])
				require.NoError(t, err)

				var payload map[string]any

				require.NoError(t, json.Unmarshal(rawPayload, &payload))

				if scopeField == jwt.JWTScopeFieldList || scopeField == jwt.JWTScopeFieldBoth {
					scope, ok := payload[consts.ClaimScopeNonStandard]
					require.True(t, ok)
					assert.Equal(t, []any{consts.ScopeEmail, consts.ScopeOffline}, scope)
				}
				if scopeField == jwt.JWTScopeFieldString || scopeField == jwt.JWTScopeFieldBoth {
					scope, ok := payload[consts.ClaimScope]
					require.True(t, ok)
					assert.Equal(t, "email offline", scope)
				}

				rawHeader, err := base64.RawURLEncoding.DecodeString(parts[0])
				require.NoError(t, err)
				var header map[string]any

				require.NoError(t, json.Unmarshal(rawHeader, &header))

				assert.Equal(t, consts.JSONWebTokenTypeAccessToken, header[consts.JSONWebTokenHeaderType])

				extraClaimsSession, ok := c.r.GetSession().(oauth2.ExtraClaimsSession)
				require.True(t, ok)
				claims := extraClaimsSession.GetExtraClaims()
				assert.Equal(t, "bar", claims["foo"])
				// Returned, but will be ignored by the introspect handler.
				assert.Equal(t, "peter", claims[consts.ClaimSubject])
				assert.Equal(t, []string{"group0"}, claims[consts.ClaimAudience])
				// Scope field is always a string.
				assert.Equal(t, "email offline", claims[consts.ClaimScope])

				assert.WithinDuration(t, time.Now(), anyInt64ToTime(claims[consts.ClaimIssuedAt]), time.Second)
				assert.WithinDuration(t, time.Now(), anyInt64ToTime(claims[consts.ClaimNotBefore]), time.Second)

				err = strategy.ValidateAccessToken(context.Background(), c.r, token)
				if c.pass {
					assert.NoError(t, err)
				} else {
					assert.Error(t, err)
				}
			})
		}
	}
}

func anyInt64ToTime(in any) time.Time {
	return time.Unix(in.(int64), 0)
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
