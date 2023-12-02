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

	"github.com/authelia/goauth2"
	"github.com/authelia/goauth2/internal/gen"
	"github.com/authelia/goauth2/token/jwt"
)

func TestIntrospectJWT(t *testing.T) {
	rsaKey := gen.MustRSAKey()
	strat := &DefaultJWTStrategy{
		Signer: &jwt.DefaultSigner{
			GetPrivateKey: func(_ context.Context) (any, error) {
				return rsaKey, nil
			},
		},
		Config: &goauth2.Config{},
	}

	var v = &StatelessJWTValidator{
		Signer: strat,
		Config: &goauth2.Config{
			ScopeStrategy: goauth2.HierarchicScopeStrategy,
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
				jwt := jwtExpiredCase(goauth2.AccessToken)
				token, _, err := strat.GenerateAccessToken(context.TODO(), jwt)
				assert.NoError(t, err)
				return token
			},
			expectErr: goauth2.ErrTokenExpired,
		},
		{
			description: "should pass because scope was granted",
			token: func() string {
				jwt := jwtValidCase(goauth2.AccessToken)
				jwt.GrantedScope = []string{"foo", "bar"}
				token, _, err := strat.GenerateAccessToken(context.TODO(), jwt)
				assert.NoError(t, err)
				return token
			},
			scopes: []string{"foo"},
		},
		{
			description: "should fail because scope was not granted",
			token: func() string {
				jwt := jwtValidCase(goauth2.AccessToken)
				token, _, err := strat.GenerateAccessToken(context.TODO(), jwt)
				assert.NoError(t, err)
				return token
			},
			scopes:    []string{"foo"},
			expectErr: goauth2.ErrInvalidScope,
		},
		{
			description: "should fail because signature is invalid",
			token: func() string {
				jwt := jwtValidCase(goauth2.AccessToken)
				token, _, err := strat.GenerateAccessToken(context.TODO(), jwt)
				assert.NoError(t, err)
				parts := strings.Split(token, ".")
				require.Len(t, parts, 3, "%s - %v", token, parts)
				dec, err := base64.RawURLEncoding.DecodeString(parts[1])
				assert.NoError(t, err)
				s := strings.Replace(string(dec), "peter", "piper", -1)
				parts[1] = base64.RawURLEncoding.EncodeToString([]byte(s))
				return strings.Join(parts, ".")
			},
			expectErr: goauth2.ErrTokenSignatureMismatch,
		},
		{
			description: "should pass",
			token: func() string {
				jwt := jwtValidCase(goauth2.AccessToken)
				token, _, err := strat.GenerateAccessToken(context.TODO(), jwt)
				assert.NoError(t, err)
				return token
			},
		},
	} {
		t.Run(fmt.Sprintf("case=%d:%v", k, c.description), func(t *testing.T) {
			if c.scopes == nil {
				c.scopes = []string{}
			}

			areq := goauth2.NewAccessRequest(nil)
			_, err := v.IntrospectToken(context.TODO(), c.token(), goauth2.AccessToken, areq, c.scopes)

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
	strat := &DefaultJWTStrategy{
		Signer: &jwt.DefaultSigner{GetPrivateKey: func(_ context.Context) (any, error) {
			return gen.MustRSAKey(), nil
		},
		},
		Config: &goauth2.Config{},
	}

	v := &StatelessJWTValidator{
		Signer: strat,
	}

	jwt := jwtValidCase(goauth2.AccessToken)
	token, _, err := strat.GenerateAccessToken(context.TODO(), jwt)
	assert.NoError(b, err)
	areq := goauth2.NewAccessRequest(nil)

	for n := 0; n < b.N; n++ {
		_, err = v.IntrospectToken(context.TODO(), token, goauth2.AccessToken, areq, []string{})
	}

	assert.NoError(b, err)
}
