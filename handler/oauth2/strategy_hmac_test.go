// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/token/hmac"
)

var hmacshaStrategy = HMACCoreStrategy{
	Enigma: &hmac.HMACStrategy{Config: &oauth2.Config{GlobalSecret: []byte("foobarfoobarfoobarfoobarfoobarfoobarfoobarfoobar")}},
	Config: &oauth2.Config{
		AccessTokenLifespan:   time.Hour * 24,
		AuthorizeCodeLifespan: time.Hour * 24,
	},
	usePrefix: true,
	prefix:    "authelia_%s_",
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
			actual := NewHMACCoreStrategy(nil, tc.have)

			require.NotNil(t, actual)
			assert.Equal(t, tc.expectedAT, actual.getPrefix(tokenPrefixPartAccessToken))
			assert.Equal(t, tc.expectedRT, actual.getPrefix(tokenPrefixPartRefreshToken))
			assert.Equal(t, tc.expectedAC, actual.getPrefix(tokenPrefixPartAuthorizeCode))
		})
	}
}

func TestHMACAccessToken(t *testing.T) {
	testCases := []struct {
		name   string
		have   oauth2.Requester
		setup  func(t *testing.T, r oauth2.Requester, strategy CoreStrategy) (token, signature string)
		err    error
		errStr string
	}{
		{
			"ShouldPassStillValid",
			&oauth2.Request{
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
			},
			func(t *testing.T, r oauth2.Requester, strategy CoreStrategy) (token, signature string) {
				var err error

				token, signature, err = strategy.GenerateAccessToken(t.Context(), r)

				require.NoError(t, err)

				return
			},
			nil,
			"",
		},
		{
			"ShouldFailExpired",
			&oauth2.Request{
				Client: &oauth2.DefaultClient{
					ClientSecret: mustNewBCryptClientSecretPlain("foobarfoobarfoobarfoobar"),
				},
				Session: &oauth2.DefaultSession{
					ExpiresAt: map[oauth2.TokenType]time.Time{
						oauth2.AccessToken:   time.Unix(90000000, 0).UTC(),
						oauth2.AuthorizeCode: time.Unix(90000000, 0).UTC(),
						oauth2.RefreshToken:  time.Unix(90000000, 0).UTC(),
					},
				},
			},
			func(t *testing.T, r oauth2.Requester, strategy CoreStrategy) (token, signature string) {
				var err error

				token, signature, err = strategy.GenerateAccessToken(t.Context(), r)

				require.NoError(t, err)

				return
			},
			oauth2.ErrTokenExpired,
			"Token expired. Access Token expired at '1972-11-07 16:00:00 +0000 UTC'.",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			strategy := &HMACCoreStrategy{
				Enigma: &hmac.HMACStrategy{Config: &oauth2.Config{GlobalSecret: []byte("foobarfoobarfoobarfoobarfoobarfoobarfoobarfoobar")}},
				Config: &oauth2.Config{
					AccessTokenLifespan:   time.Hour * 24,
					AuthorizeCodeLifespan: time.Hour * 24,
				},
				usePrefix: true,
				prefix:    "authelia_%s_",
			}

			token, signature, err := strategy.GenerateAccessToken(t.Context(), tc.have)
			require.NoError(t, err)
			assert.Equal(t, strings.Split(token, ".")[1], signature)
			assert.Contains(t, token, "authelia_at_")

			if tc.err == nil {
				assert.NoError(t, strategy.ValidateAccessToken(t.Context(), tc.have, token))
				assert.True(t, strategy.IsOpaqueAccessToken(t.Context(), token))

				trimmed := strings.TrimPrefix(token, "authelia_at_")

				assert.False(t, strategy.IsOpaqueAccessToken(t.Context(), trimmed))
				assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(strategy.ValidateAccessToken(t.Context(), tc.have, trimmed)), "Invalid token format. Provided Token does not appear to be an Access Token.")
			} else {
				err = strategy.ValidateAccessToken(t.Context(), tc.have, token)

				assert.EqualError(t, err, tc.err.Error())
				assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), tc.errStr)
			}
		})
	}
}

func TestHMACRefreshToken(t *testing.T) {
	testCases := []struct {
		name   string
		have   oauth2.Requester
		setup  func(t *testing.T, r oauth2.Requester, strategy CoreStrategy) (token, signature string)
		err    error
		errStr string
	}{
		{
			"ShouldPassValid",
			&oauth2.Request{
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
			},
			func(t *testing.T, r oauth2.Requester, strategy CoreStrategy) (token, signature string) {
				var err error

				token, signature, err = strategy.GenerateAccessToken(t.Context(), r)

				require.NoError(t, err)

				return
			},
			nil,
			"",
		},
		{
			"ShouldFailExpired",
			&oauth2.Request{
				Client: &oauth2.DefaultClient{
					ClientSecret: mustNewBCryptClientSecretPlain("foobarfoobarfoobarfoobar"),
				},
				Session: &oauth2.DefaultSession{
					ExpiresAt: map[oauth2.TokenType]time.Time{
						oauth2.AccessToken:   time.Unix(90000000, 0).UTC(),
						oauth2.AuthorizeCode: time.Unix(90000000, 0).UTC(),
						oauth2.RefreshToken:  time.Unix(90000000, 0).UTC(),
					},
				},
			},
			func(t *testing.T, r oauth2.Requester, strategy CoreStrategy) (token, signature string) {
				var err error

				token, signature, err = strategy.GenerateAccessToken(t.Context(), r)

				require.NoError(t, err)

				return
			},
			oauth2.ErrTokenExpired,
			"Token expired. Refresh Token expired at '1972-11-07 16:00:00 +0000 UTC'.",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			strategy := &HMACCoreStrategy{
				Enigma: &hmac.HMACStrategy{Config: &oauth2.Config{GlobalSecret: []byte("foobarfoobarfoobarfoobarfoobarfoobarfoobarfoobar")}},
				Config: &oauth2.Config{
					AccessTokenLifespan:   time.Hour * 24,
					AuthorizeCodeLifespan: time.Hour * 24,
				},
				usePrefix: true,
				prefix:    "authelia_%s_",
			}

			token, signature, err := strategy.GenerateRefreshToken(t.Context(), tc.have)
			require.NoError(t, err)
			assert.Equal(t, strings.Split(token, ".")[1], signature)
			assert.Contains(t, token, "authelia_rt_")

			if tc.err == nil {
				assert.NoError(t, strategy.ValidateRefreshToken(t.Context(), tc.have, token))
				assert.True(t, strategy.IsOpaqueRefreshToken(t.Context(), token))

				trimmed := strings.TrimPrefix(token, "authelia_rt_")

				assert.False(t, strategy.IsOpaqueRefreshToken(t.Context(), trimmed))
				assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(strategy.ValidateRefreshToken(t.Context(), tc.have, trimmed)), "Invalid token format. Provided Token does not appear to be a Refresh Token.")
			} else {
				err = strategy.ValidateRefreshToken(t.Context(), tc.have, token)

				assert.EqualError(t, err, tc.err.Error())
				assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), tc.errStr)
			}
		})
	}
}

func TestHMACAuthorizeCode(t *testing.T) {
	testCases := []struct {
		name   string
		have   oauth2.Requester
		err    error
		errStr string
	}{
		{
			"ShouldPassValid",
			&oauth2.Request{
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
			},
			nil,
			"",
		},
		{
			"ShouldFailExpired",
			&oauth2.Request{
				Client: &oauth2.DefaultClient{
					ClientSecret: mustNewBCryptClientSecretPlain("foobarfoobarfoobarfoobar"),
				},
				Session: &oauth2.DefaultSession{
					ExpiresAt: map[oauth2.TokenType]time.Time{
						oauth2.AccessToken:   time.Unix(90000000, 0).UTC(),
						oauth2.AuthorizeCode: time.Unix(90000000, 0).UTC(),
						oauth2.RefreshToken:  time.Unix(90000000, 0).UTC(),
					},
				},
			},
			oauth2.ErrTokenExpired,
			"Token expired. Authorize Code expired at '1972-11-07 16:00:00 +0000 UTC'.",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			strategy := &HMACCoreStrategy{
				Enigma: &hmac.HMACStrategy{Config: &oauth2.Config{GlobalSecret: []byte("foobarfoobarfoobarfoobarfoobarfoobarfoobarfoobar")}},
				Config: &oauth2.Config{
					AccessTokenLifespan:   time.Hour * 24,
					AuthorizeCodeLifespan: time.Hour * 24,
				},
				usePrefix: true,
				prefix:    "authelia_%s_",
			}

			token, signature, err := strategy.GenerateAuthorizeCode(t.Context(), tc.have)
			require.NoError(t, err)
			assert.Equal(t, strings.Split(token, ".")[1], signature)
			assert.Contains(t, token, "authelia_ac_")

			if tc.err == nil {
				assert.NoError(t, strategy.ValidateAuthorizeCode(t.Context(), tc.have, token))
				assert.True(t, strategy.IsOpaqueAuthorizeCode(t.Context(), token))

				trimmed := strings.TrimPrefix(token, "authelia_ac_")

				assert.False(t, strategy.IsOpaqueAuthorizeCode(t.Context(), trimmed))
				assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(strategy.ValidateAuthorizeCode(t.Context(), tc.have, trimmed)), "Invalid token format. Provided Token does not appear to be an Authorization Code.")
			} else {
				err = strategy.ValidateAuthorizeCode(t.Context(), tc.have, token)

				assert.EqualError(t, err, tc.err.Error())
				assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), tc.errStr)
			}
		})
	}
}

func mustNewBCryptClientSecretPlain(rawSecret string) *oauth2.BCryptClientSecret {
	if secret, err := oauth2.NewBCryptClientSecretPlain(rawSecret, 4); err != nil {
		panic(err)
	} else {
		return secret
	}
}
