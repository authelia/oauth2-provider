// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/gen"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestIntrospectJWT(t *testing.T) {
	config := &oauth2.Config{
		EnforceJWTProfileAccessTokens: true,
		GlobalSecret:                  []byte("foofoofoofoofoofoofoofoofoofoofoo"),
	}

	strategy := &JWTProfileCoreStrategy{
		HMACCoreStrategy: NewHMACCoreStrategy(config, "authelia_%s_"),
		Strategy: &jwt.DefaultStrategy{
			Config: config,
			Issuer: jwt.NewDefaultIssuerRS256Unverified(gen.MustRSAKey()),
		},
		Config: config,
	}

	validator := &StatelessJWTValidator{
		Strategy: strategy,
		Config: &oauth2.Config{
			ScopeStrategy: oauth2.HierarchicScopeStrategy,
		},
	}

	testCases := []struct {
		name     string
		token    func(t *testing.T) string
		err      error
		expected string
		scopes   []string
	}{
		{
			name: "ShouldFailTokenExpired",
			token: func(t *testing.T) string {
				token := jwtExpiredCase(oauth2.AccessToken, time.Unix(1726972738, 0))
				tokenString, _, err := strategy.GenerateAccessToken(context.TODO(), token)
				require.NoError(t, err)

				return tokenString
			},
			err:      oauth2.ErrTokenExpired,
			expected: "Token expired. The token expired. Token expired at 1726969138.",
		},
		{
			name: "ShouldPassScopeGranted",
			token: func(t *testing.T) string {
				token := jwtValidCase(oauth2.AccessToken)
				token.GrantedScope = []string{"foo", "bar"}
				tokenString, _, err := strategy.GenerateAccessToken(context.TODO(), token)

				require.NoError(t, err)

				return tokenString
			},
			scopes: []string{"foo"},
		},
		{
			name: "ShouldFailWrongTyp",
			token: func(t *testing.T) string {
				token := jwtInvalidTypCase(oauth2.AccessToken)
				token.GrantedScope = []string{"foo", "bar"}
				tokenString, _, err := strategy.GenerateAccessToken(context.TODO(), token)

				require.NoError(t, err)

				return tokenString
			},
			scopes:   []string{"foo"},
			err:      oauth2.ErrRequestUnauthorized,
			expected: "The request could not be authorized. Check that you provided valid credentials in the right format. The provided token is not a valid RFC9068 JWT Profile Access Token as it is missing the header 'typ' value of 'at+jwt'.",
		},
		{
			name: "ShouldFailScopeNotGranted",
			token: func(t *testing.T) string {
				token := jwtValidCase(oauth2.AccessToken)
				tokenString, _, err := strategy.GenerateAccessToken(context.TODO(), token)
				require.NoError(t, err)

				return tokenString
			},
			scopes:   []string{"foo"},
			err:      oauth2.ErrInvalidScope,
			expected: "The requested scope is invalid, unknown, or malformed. The request scope 'foo' has not been granted or is not allowed to be requested.",
		},
		{
			name: "ShouldFailInvalidSignature",
			token: func(t *testing.T) string {
				token := jwtValidCase(oauth2.AccessToken)
				tokenString, _, err := strategy.GenerateAccessToken(context.TODO(), token)
				require.NoError(t, err)
				parts := strings.Split(tokenString, ".")
				require.Len(t, parts, 3, "%s - %v", tokenString, parts)
				dec, err := base64.RawURLEncoding.DecodeString(parts[1])
				assert.NoError(t, err)
				s := strings.ReplaceAll(string(dec), "peter", "piper")
				parts[1] = base64.RawURLEncoding.EncodeToString([]byte(s))

				return strings.Join(parts, ".")
			},
			err:      oauth2.ErrTokenSignatureMismatch,
			expected: "Token signature mismatch. Check that you provided a valid token in the right format. Token has an invalid signature.",
		},
		{
			name: "ShouldPass",
			token: func(t *testing.T) string {
				token := jwtValidCase(oauth2.AccessToken)
				tokenString, _, err := strategy.GenerateAccessToken(context.TODO(), token)
				require.NoError(t, err)

				return tokenString
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.scopes == nil {
				tc.scopes = []string{}
			}

			areq := oauth2.NewAccessRequest(nil)
			_, err := validator.IntrospectToken(context.TODO(), tc.token(t), oauth2.AccessToken, areq, tc.scopes)

			if tc.err != nil {
				assert.EqualError(t, err, tc.err.Error())
				assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), tc.expected)
			} else {
				require.NoError(t, err)
				assert.Equal(t, "peter", areq.Session.GetSubject())
			}
		})
	}
}

func BenchmarkIntrospectJWT(b *testing.B) {
	config := &oauth2.Config{}

	strategy := &JWTProfileCoreStrategy{
		Strategy: &jwt.DefaultStrategy{
			Config: config,
			Issuer: jwt.NewDefaultIssuerRS256Unverified(gen.MustRSAKey()),
		},
		Config: config,
	}

	v := &StatelessJWTValidator{
		Strategy: strategy,
	}

	jwt := jwtValidCase(oauth2.AccessToken)
	token, _, err := strategy.GenerateAccessToken(context.TODO(), jwt)
	assert.NoError(b, err)
	areq := oauth2.NewAccessRequest(nil)

	for n := 0; n < b.N; n++ {
		_, err = v.IntrospectToken(context.TODO(), token, oauth2.AccessToken, areq, []string{})
	}

	assert.NoError(b, err)
}
