// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/authelia/goauth2"
	"github.com/authelia/goauth2/token/hmac"
)

var hmacshaStrategy = HMACSHAStrategy{
	Enigma: &hmac.HMACStrategy{Config: &goauth2.Config{GlobalSecret: []byte("foobarfoobarfoobarfoobarfoobarfoobarfoobarfoobar")}},
	Config: &goauth2.Config{
		AccessTokenLifespan:   time.Hour * 24,
		AuthorizeCodeLifespan: time.Hour * 24,
	},
}

var hmacExpiredCase = goauth2.Request{
	Client: &goauth2.DefaultClient{
		Secret: []byte("foobarfoobarfoobarfoobar"),
	},
	Session: &goauth2.DefaultSession{
		ExpiresAt: map[goauth2.TokenType]time.Time{
			goauth2.AccessToken:   time.Now().UTC().Add(-time.Hour),
			goauth2.AuthorizeCode: time.Now().UTC().Add(-time.Hour),
			goauth2.RefreshToken:  time.Now().UTC().Add(-time.Hour),
		},
	},
}

var hmacValidCase = goauth2.Request{
	Client: &goauth2.DefaultClient{
		Secret: []byte("foobarfoobarfoobarfoobar"),
	},
	Session: &goauth2.DefaultSession{
		ExpiresAt: map[goauth2.TokenType]time.Time{
			goauth2.AccessToken:   time.Now().UTC().Add(time.Hour),
			goauth2.AuthorizeCode: time.Now().UTC().Add(time.Hour),
			goauth2.RefreshToken:  time.Now().UTC().Add(time.Hour),
		},
	},
}

var hmacValidZeroTimeRefreshCase = goauth2.Request{
	Client: &goauth2.DefaultClient{
		Secret: []byte("foobarfoobarfoobarfoobar"),
	},
	Session: &goauth2.DefaultSession{
		ExpiresAt: map[goauth2.TokenType]time.Time{
			goauth2.AccessToken:   time.Now().UTC().Add(time.Hour),
			goauth2.AuthorizeCode: time.Now().UTC().Add(time.Hour),
			goauth2.RefreshToken:  {},
		},
	},
}

func TestHMACAccessToken(t *testing.T) {
	for k, c := range []struct {
		r    goauth2.Request
		pass bool
	}{
		{
			r:    hmacValidCase,
			pass: true,
		},
		{
			r:    hmacExpiredCase,
			pass: false,
		},
	} {
		t.Run(fmt.Sprintf("case=%d", k), func(t *testing.T) {
			token, signature, err := hmacshaStrategy.GenerateAccessToken(nil, &c.r)
			assert.NoError(t, err)
			assert.Equal(t, strings.Split(token, ".")[1], signature)
			assert.Contains(t, token, "ory_at_")

			for k, token := range []string{
				token,
				strings.TrimPrefix(token, "ory_at_"),
			} {
				t.Run(fmt.Sprintf("prefix=%v", k == 0), func(t *testing.T) {
					err = hmacshaStrategy.ValidateAccessToken(nil, &c.r, token)
					if c.pass {
						assert.NoError(t, err)
						validate := hmacshaStrategy.Enigma.Signature(token)
						assert.Equal(t, signature, validate)
					} else {
						assert.Error(t, err)
					}
				})
			}
		})
	}
}

func TestHMACRefreshToken(t *testing.T) {
	for k, c := range []struct {
		r    goauth2.Request
		pass bool
	}{
		{
			r:    hmacValidCase,
			pass: true,
		},
		{
			r:    hmacExpiredCase,
			pass: false,
		},
	} {
		t.Run(fmt.Sprintf("case=%d", k), func(t *testing.T) {
			token, signature, err := hmacshaStrategy.GenerateRefreshToken(nil, &c.r)
			assert.NoError(t, err)
			assert.Equal(t, strings.Split(token, ".")[1], signature)
			assert.Contains(t, token, "ory_rt_")

			for k, token := range []string{
				token,
				strings.TrimPrefix(token, "ory_rt_"),
			} {
				t.Run(fmt.Sprintf("prefix=%v", k == 0), func(t *testing.T) {
					err = hmacshaStrategy.ValidateRefreshToken(nil, &c.r, token)
					if c.pass {
						assert.NoError(t, err)
						validate := hmacshaStrategy.Enigma.Signature(token)
						assert.Equal(t, signature, validate)
					} else {
						assert.Error(t, err)
					}
				})
			}
		})
	}
}

func TestHMACAuthorizeCode(t *testing.T) {
	for k, c := range []struct {
		r    goauth2.Request
		pass bool
	}{
		{
			r:    hmacValidCase,
			pass: true,
		},
		{
			r:    hmacExpiredCase,
			pass: false,
		},
	} {
		t.Run(fmt.Sprintf("case=%d", k), func(t *testing.T) {
			token, signature, err := hmacshaStrategy.GenerateAuthorizeCode(nil, &c.r)
			assert.NoError(t, err)
			assert.Equal(t, strings.Split(token, ".")[1], signature)
			assert.Contains(t, token, "ory_ac_")

			for k, token := range []string{
				token,
				strings.TrimPrefix(token, "ory_ac_"),
			} {
				t.Run(fmt.Sprintf("prefix=%v", k == 0), func(t *testing.T) {
					err = hmacshaStrategy.ValidateAuthorizeCode(nil, &c.r, token)
					if c.pass {
						assert.NoError(t, err)
						validate := hmacshaStrategy.Enigma.Signature(token)
						assert.Equal(t, signature, validate)
					} else {
						assert.Error(t, err)
					}
				})
			}
		})
	}
}
