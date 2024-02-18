package rfc8628_test

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"authelia.com/provider/oauth2"
	. "authelia.com/provider/oauth2/handler/rfc8628"
	"authelia.com/provider/oauth2/token/hmac"
)

var hmacshaStrategy = RFC8628HMACSHAStrategy{
	Enigma: &hmac.HMACStrategy{Config: &oauth2.Config{GlobalSecret: []byte("foobarfoobarfoobarfoobarfoobarfoobarfoobarfoobar")}},
	Config: &oauth2.Config{
		AccessTokenLifespan:       time.Minute * 24,
		AuthorizeCodeLifespan:     time.Minute * 24,
		DeviceAndUserCodeLifespan: time.Minute * 24,
	},
}

var hmacExpiredCase = oauth2.Request{
	Client: &oauth2.DefaultClient{
		Secret: []byte("foobarfoobarfoobarfoobar"),
	},
	Session: &oauth2.DefaultSession{
		ExpiresAt: map[oauth2.TokenType]time.Time{
			oauth2.UserCode:   time.Now().UTC().Add(-time.Hour),
			oauth2.DeviceCode: time.Now().UTC().Add(-time.Hour),
		},
	},
}

var hmacValidCase = oauth2.Request{
	Client: &oauth2.DefaultClient{
		Secret: []byte("foobarfoobarfoobarfoobar"),
	},
	Session: &oauth2.DefaultSession{
		ExpiresAt: map[oauth2.TokenType]time.Time{
			oauth2.UserCode:   time.Now().UTC().Add(time.Hour),
			oauth2.DeviceCode: time.Now().UTC().Add(time.Hour),
		},
	},
}

var hmacValidZeroTimeRefreshCase = oauth2.Request{
	Client: &oauth2.DefaultClient{
		Secret: []byte("foobarfoobarfoobarfoobar"),
	},
	RequestedAt: time.Now().UTC().Add(-time.Hour * 48),
	Session: &oauth2.DefaultSession{
		ExpiresAt: map[oauth2.TokenType]time.Time{
			oauth2.UserCode:   {},
			oauth2.DeviceCode: {},
		},
	},
}

func TestHMACUserCode(t *testing.T) {
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
		{
			r:    hmacValidZeroTimeRefreshCase,
			pass: false,
		},
	} {
		t.Run(fmt.Sprintf("case=%d", k), func(t *testing.T) {
			userCode, signature, err := hmacshaStrategy.GenerateUserCode(context.TODO())
			assert.NoError(t, err)
			regex := regexp.MustCompile("[BCDFGHJKLMNPQRSTVWXZ]{8}")
			assert.Equal(t, len(regex.FindString(userCode)), len(userCode))

			err = hmacshaStrategy.ValidateUserCode(context.TODO(), &c.r, userCode)
			if c.pass {
				assert.NoError(t, err)
				validate, _ := hmacshaStrategy.Enigma.GenerateHMACForString(context.TODO(), userCode)
				assert.Equal(t, signature, validate)
				testSign, err := hmacshaStrategy.UserCodeSignature(context.TODO(), userCode)
				assert.NoError(t, err)
				assert.Equal(t, testSign, signature)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

func TestHMACDeviceCode(t *testing.T) {
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
		{
			r:    hmacValidZeroTimeRefreshCase,
			pass: false,
		},
	} {
		t.Run(fmt.Sprintf("case=%d", k), func(t *testing.T) {
			strategy := NewRFC8628HMACSHAStrategy(&hmac.HMACStrategy{Config: &oauth2.Config{GlobalSecret: []byte("foobarfoobarfoobarfoobarfoobarfoobarfoobarfoobar")}},
				&oauth2.Config{
					AccessTokenLifespan:       time.Minute * 24,
					AuthorizeCodeLifespan:     time.Minute * 24,
					DeviceAndUserCodeLifespan: time.Minute * 24,
				}, "authelia_%s_")

			token, signature, err := strategy.GenerateDeviceCode(context.TODO())
			assert.NoError(t, err)
			assert.Equal(t, strings.Split(token, ".")[1], signature)
			assert.Contains(t, token, "authelia_dc_")

			for k, token := range []string{
				token,
				strings.TrimPrefix(token, "authelia_dc_"),
			} {
				t.Run(fmt.Sprintf("prefix=%v", k == 0), func(t *testing.T) {
					err = strategy.ValidateDeviceCode(context.TODO(), &c.r, token)
					if c.pass {
						assert.NoError(t, err)
						validate := strategy.Enigma.Signature(token)
						assert.Equal(t, signature, validate)
						testSign, err := strategy.DeviceCodeSignature(context.TODO(), token)
						assert.NoError(t, err)
						assert.Equal(t, testSign, signature)
					} else {
						assert.Error(t, err)
					}
				})
			}
		})
	}
}
