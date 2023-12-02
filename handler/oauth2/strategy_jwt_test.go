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

	"github.com/authelia/goauth2"
	"github.com/authelia/goauth2/internal/gen"
	"github.com/authelia/goauth2/token/jwt"
)

var rsaKey = gen.MustRSAKey()

var j = &DefaultJWTStrategy{
	Signer: &jwt.DefaultSigner{
		GetPrivateKey: func(_ context.Context) (any, error) {
			return rsaKey, nil
		},
	},
	Config: &goauth2.Config{},
}

// returns a valid JWT type. The JWTClaims.ExpiresAt time is intentionally
// left empty to ensure it is pulled from the session's ExpiresAt map for
// the given goauth2.TokenType.
var jwtValidCase = func(tokenType goauth2.TokenType) *goauth2.Request {
	r := &goauth2.Request{
		Client: &goauth2.DefaultClient{
			Secret: []byte("foobarfoobarfoobarfoobar"),
		},
		Session: &JWTSession{
			JWTClaims: &jwt.JWTClaims{
				Issuer:    "goauth2",
				Subject:   "peter",
				IssuedAt:  time.Now().UTC(),
				NotBefore: time.Now().UTC(),
				Extra:     map[string]any{"foo": "bar"},
			},
			JWTHeader: &jwt.Headers{
				Extra: make(map[string]any),
			},
			ExpiresAt: map[goauth2.TokenType]time.Time{
				tokenType: time.Now().UTC().Add(time.Hour),
			},
		},
	}
	r.SetRequestedScopes([]string{"email", "offline"})
	r.GrantScope("email")
	r.GrantScope("offline")
	r.SetRequestedAudience([]string{"group0"})
	r.GrantAudience("group0")
	return r
}

var jwtValidCaseWithZeroRefreshExpiry = func(tokenType goauth2.TokenType) *goauth2.Request {
	r := &goauth2.Request{
		Client: &goauth2.DefaultClient{
			Secret: []byte("foobarfoobarfoobarfoobar"),
		},
		Session: &JWTSession{
			JWTClaims: &jwt.JWTClaims{
				Issuer:    "goauth2",
				Subject:   "peter",
				IssuedAt:  time.Now().UTC(),
				NotBefore: time.Now().UTC(),
				Extra:     map[string]any{"foo": "bar"},
			},
			JWTHeader: &jwt.Headers{
				Extra: make(map[string]any),
			},
			ExpiresAt: map[goauth2.TokenType]time.Time{
				tokenType:            time.Now().UTC().Add(time.Hour),
				goauth2.RefreshToken: {},
			},
		},
	}
	r.SetRequestedScopes([]string{"email", "offline"})
	r.GrantScope("email")
	r.GrantScope("offline")
	r.SetRequestedAudience([]string{"group0"})
	r.GrantAudience("group0")
	return r
}

var jwtValidCaseWithRefreshExpiry = func(tokenType goauth2.TokenType) *goauth2.Request {
	r := &goauth2.Request{
		Client: &goauth2.DefaultClient{
			Secret: []byte("foobarfoobarfoobarfoobar"),
		},
		Session: &JWTSession{
			JWTClaims: &jwt.JWTClaims{
				Issuer:    "goauth2",
				Subject:   "peter",
				IssuedAt:  time.Now().UTC(),
				NotBefore: time.Now().UTC(),
				Extra:     map[string]any{"foo": "bar"},
			},
			JWTHeader: &jwt.Headers{
				Extra: make(map[string]any),
			},
			ExpiresAt: map[goauth2.TokenType]time.Time{
				tokenType:            time.Now().UTC().Add(time.Hour),
				goauth2.RefreshToken: time.Now().UTC().Add(time.Hour * 2).Round(time.Hour),
			},
		},
	}
	r.SetRequestedScopes([]string{"email", "offline"})
	r.GrantScope("email")
	r.GrantScope("offline")
	r.SetRequestedAudience([]string{"group0"})
	r.GrantAudience("group0")
	return r
}

// returns an expired JWT type. The JWTClaims.ExpiresAt time is intentionally
// left empty to ensure it is pulled from the session's ExpiresAt map for
// the given goauth2.TokenType.
var jwtExpiredCase = func(tokenType goauth2.TokenType) *goauth2.Request {
	r := &goauth2.Request{
		Client: &goauth2.DefaultClient{
			Secret: []byte("foobarfoobarfoobarfoobar"),
		},
		Session: &JWTSession{
			JWTClaims: &jwt.JWTClaims{
				Issuer:    "goauth2",
				Subject:   "peter",
				IssuedAt:  time.Now().UTC(),
				NotBefore: time.Now().UTC(),
				ExpiresAt: time.Now().UTC().Add(-time.Minute),
				Extra:     map[string]any{"foo": "bar"},
			},
			JWTHeader: &jwt.Headers{
				Extra: make(map[string]any),
			},
			ExpiresAt: map[goauth2.TokenType]time.Time{
				tokenType: time.Now().UTC().Add(-time.Hour),
			},
		},
	}
	r.SetRequestedScopes([]string{"email", "offline"})
	r.GrantScope("email")
	r.GrantScope("offline")
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
			r    *goauth2.Request
			pass bool
		}{
			{
				r:    jwtValidCase(goauth2.AccessToken),
				pass: true,
			},
			{
				r:    jwtExpiredCase(goauth2.AccessToken),
				pass: false,
			},
			{
				r:    jwtValidCaseWithZeroRefreshExpiry(goauth2.AccessToken),
				pass: true,
			},
			{
				r:    jwtValidCaseWithRefreshExpiry(goauth2.AccessToken),
				pass: true,
			},
		} {
			t.Run(fmt.Sprintf("case=%d/%d", s, k), func(t *testing.T) {
				j.Config = &goauth2.Config{
					JWTScopeClaimKey: scopeField,
				}
				token, signature, err := j.GenerateAccessToken(context.Background(), c.r)
				assert.NoError(t, err)

				parts := strings.Split(token, ".")
				require.Len(t, parts, 3, "%s - %v", token, parts)
				assert.Equal(t, parts[2], signature)

				rawPayload, err := base64.RawURLEncoding.DecodeString(parts[1])
				require.NoError(t, err)
				var payload map[string]any
				err = json.Unmarshal(rawPayload, &payload)
				require.NoError(t, err)
				if scopeField == jwt.JWTScopeFieldList || scopeField == jwt.JWTScopeFieldBoth {
					scope, ok := payload["scp"]
					require.True(t, ok)
					assert.Equal(t, []any{"email", "offline"}, scope)
				}
				if scopeField == jwt.JWTScopeFieldString || scopeField == jwt.JWTScopeFieldBoth {
					scope, ok := payload["scope"]
					require.True(t, ok)
					assert.Equal(t, "email offline", scope)
				}

				extraClaimsSession, ok := c.r.GetSession().(goauth2.ExtraClaimsSession)
				require.True(t, ok)
				claims := extraClaimsSession.GetExtraClaims()
				assert.Equal(t, "bar", claims["foo"])
				// Returned, but will be ignored by the introspect handler.
				assert.Equal(t, "peter", claims["sub"])
				assert.Equal(t, []string{"group0"}, claims["aud"])
				// Scope field is always a string.
				assert.Equal(t, "email offline", claims["scope"])

				validate := j.signature(token)
				err = j.ValidateAccessToken(context.Background(), c.r, token)
				if c.pass {
					assert.NoError(t, err)
					assert.Equal(t, signature, validate)
				} else {
					assert.Error(t, err)
				}
			})
		}
	}
}
