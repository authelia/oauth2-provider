// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/gen"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestIntrospectJWT(t *testing.T) {
	rsaKey := gen.MustRSAKey()

	config := &oauth2.Config{
		EnforceJWTProfileAccessTokens: true,
		GlobalSecret:                  []byte("foofoofoofoofoofoofoofoofoofoofoo"),
	}

	strategy := &JWTProfileCoreStrategy{
		HMACCoreStrategy: NewHMACCoreStrategy(config, "authelia_%s_"),
		Signer: &jwt.DefaultSigner{
			GetPrivateKey: func(_ context.Context) (any, error) {
				return rsaKey, nil
			},
		},
		Config: config,
	}

	var v = &StatelessJWTValidator{
		Signer: strategy,
		Config: &oauth2.Config{
			ScopeStrategy: oauth2.HierarchicScopeStrategy,
		},
	}

	for k, c := range []struct {
		description string
		token       func() string
		expectErr   error
		scopes      []string
	}{
		{
			description: "should fail because jwt is expired",
			token: func() string {
				jwt := jwtExpiredCase(oauth2.AccessToken)
				token, _, err := strategy.GenerateAccessToken(context.TODO(), jwt)
				assert.NoError(t, err)
				return token
			},
			expectErr: oauth2.ErrTokenExpired,
		},
		{
			description: "should pass because scope was granted",
			token: func() string {
				jwt := jwtValidCase(oauth2.AccessToken)
				jwt.GrantedScope = []string{"foo", "bar"}
				token, _, err := strategy.GenerateAccessToken(context.TODO(), jwt)
				assert.NoError(t, err)
				return token
			},
			scopes: []string{"foo"},
		},
		{
			description: "should fail because scope was not granted",
			token: func() string {
				jwt := jwtValidCase(oauth2.AccessToken)
				token, _, err := strategy.GenerateAccessToken(context.TODO(), jwt)
				assert.NoError(t, err)
				return token
			},
			scopes:    []string{"foo"},
			expectErr: oauth2.ErrInvalidScope,
		},
		{
			description: "should fail because signature is invalid",
			token: func() string {
				jwt := jwtValidCase(oauth2.AccessToken)
				token, _, err := strategy.GenerateAccessToken(context.TODO(), jwt)
				assert.NoError(t, err)
				parts := strings.Split(token, ".")
				require.Len(t, parts, 3, "%s - %v", token, parts)
				dec, err := base64.RawURLEncoding.DecodeString(parts[1])
				assert.NoError(t, err)
				s := strings.ReplaceAll(string(dec), "peter", "piper")
				parts[1] = base64.RawURLEncoding.EncodeToString([]byte(s))
				return strings.Join(parts, ".")
			},
			expectErr: oauth2.ErrTokenSignatureMismatch,
		},
		{
			description: "should pass",
			token: func() string {
				jwt := jwtValidCase(oauth2.AccessToken)
				token, _, err := strategy.GenerateAccessToken(context.TODO(), jwt)
				assert.NoError(t, err)
				return token
			},
		},
	} {
		t.Run(fmt.Sprintf("case=%d:%v", k, c.description), func(t *testing.T) {
			if c.scopes == nil {
				c.scopes = []string{}
			}

			areq := oauth2.NewAccessRequest(nil)
			_, err := v.IntrospectToken(context.TODO(), c.token(), oauth2.AccessToken, areq, c.scopes)

			if c.expectErr != nil {
				require.EqualError(t, err, c.expectErr.Error())
			} else {
				require.NoError(t, err)
				assert.Equal(t, "peter", areq.Session.GetSubject())
			}
		})
	}
}

func BenchmarkIntrospectJWT(b *testing.B) {
	strategy := &JWTProfileCoreStrategy{
		Signer: &jwt.DefaultSigner{GetPrivateKey: func(_ context.Context) (any, error) {
			return gen.MustRSAKey(), nil
		},
		},
		Config: &oauth2.Config{},
	}

	v := &StatelessJWTValidator{
		Signer: strategy,
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
