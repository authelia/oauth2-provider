// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/token/hmac"
)

var hmacshaStrategy = HMACSHAStrategy{
	Enigma: &hmac.HMACStrategy{Config: &oauth2.Config{GlobalSecret: []byte("foobarfoobarfoobarfoobarfoobarfoobarfoobarfoobar")}},
	Config: &oauth2.Config{
		AccessTokenLifespan:   time.Hour * 24,
		AuthorizeCodeLifespan: time.Hour * 24,
	},
	prefix: "authelia_%s_",
}

var hmacExpiredCase = oauth2.Request{
	Client: &oauth2.DefaultClient{
		ClientSecret: mustNewBCryptClientSecretPlain("foobarfoobarfoobarfoobar"),
	},
	Session: &oauth2.DefaultSession{
		ExpiresAt: map[oauth2.TokenType]time.Time{
			oauth2.AccessToken:   time.Now().UTC().Add(-time.Hour),
			oauth2.AuthorizeCode: time.Now().UTC().Add(-time.Hour),
			oauth2.RefreshToken:  time.Now().UTC().Add(-time.Hour),
		},
	},
}

var hmacValidCase = oauth2.Request{
	Client: &oauth2.DefaultClient{
		ClientSecret: mustNewBCryptClientSecretPlain("foobarfoobarfoobarfoobar"),
	},
	Session: &oauth2.DefaultSession{
		ExpiresAt: map[oauth2.TokenType]time.Time{
			oauth2.AccessToken:   time.Now().UTC().Add(time.Hour),
			oauth2.AuthorizeCode: time.Now().UTC().Add(time.Hour),
			oauth2.RefreshToken:  time.Now().UTC().Add(time.Hour),
		},
	},
}

func TestNewHMACSHAStrategy(t *testing.T) {
	testCases := []struct {
		name       string
		have       string
		expectedAT string
		expectedRT string
		expectedAC string
		expected   string
	}{
		{
			"ShouldHandleCustom",
			"example_%s_",
			"example_at_",
			"example_rt_",
			"example_ac_",
			"",
		},
		{
			"ShouldHandleDefault",
			"",
			"",
			"",
			"",
			"",
		},
		{
			"ShouldHandleInvalidPrefix",
			"example_%s_%s_",
			"",
			"",
			"",
			"the prefix must contain a single '%s' but contains 2",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual, err := NewHMACSHAStrategy(nil, tc.have)

			if len(tc.expected) == 0 {
				assert.NoError(t, err)
				require.NotNil(t, actual)
				assert.Equal(t, tc.expectedAT, actual.getPrefix(tokenPartAccessToken))
				assert.Equal(t, tc.expectedRT, actual.getPrefix(tokenPartRefreshToken))
				assert.Equal(t, tc.expectedAC, actual.getPrefix(tokenPartAuthorizeCode))
			} else {
				assert.Nil(t, actual)
				assert.EqualError(t, err, tc.expected)
			}
		})
	}
}

func TestHMACAccessToken(t *testing.T) {
	for k, c := range []struct {
		r    oauth2.Request
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
			assert.Contains(t, token, "authelia_at_")

			for k, token := range []string{
				token,
				strings.TrimPrefix(token, "authelia_at_"),
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
		r    oauth2.Request
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
			assert.Contains(t, token, "authelia_rt_")

			for k, token := range []string{
				token,
				strings.TrimPrefix(token, "authelia_rt_"),
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
		r    oauth2.Request
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
			assert.Contains(t, token, "authelia_ac_")

			for k, token := range []string{
				token,
				strings.TrimPrefix(token, "authelia_ac_"),
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

func mustNewBCryptClientSecretPlain(rawSecret string) *oauth2.BCryptClientSecret {
	if secret, err := oauth2.NewBCryptClientSecretPlain(rawSecret, 10); err != nil {
		panic(err)
	} else {
		return secret
	}
}
