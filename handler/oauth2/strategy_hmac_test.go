// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/token/hmac"
)

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
				assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(strategy.ValidateAccessToken(t.Context(), tc.have, trimmed)), "The token provided is expired, revoked, malformed, or invalid for other reasons. Provided Token does not appear to be an Access Token.")
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
				assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(strategy.ValidateRefreshToken(t.Context(), tc.have, trimmed)), "The token provided is expired, revoked, malformed, or invalid for other reasons. Provided Token does not appear to be a Refresh Token.")
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
				assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(strategy.ValidateAuthorizeCode(t.Context(), tc.have, trimmed)), "The token provided is expired, revoked, malformed, or invalid for other reasons. Provided Token does not appear to be an Authorization Code.")
			} else {
				err = strategy.ValidateAuthorizeCode(t.Context(), tc.have, token)

				assert.EqualError(t, err, tc.err.Error())
				assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), tc.errStr)
			}
		})
	}
}

func TestHMACCoreStrategyClientRegistrationToken(t *testing.T) {
	ctx := context.Background()
	strategy := NewHMACCoreStrategy(&oauth2.Config{
		GlobalSecret:                          []byte("super-duper-secret-that-is-at-least-32-bytes"),
		RFC7591ClientRegistrationGlobalSecret: []byte("a-completely-different-secret-at-least-32b"),
	}, "authelia_%s_")

	request := oauth2.NewRequest()
	request.Session = &oauth2.DefaultSession{
		ExpiresAt: map[oauth2.TokenType]time.Time{oauth2.AccessToken: time.Now().UTC().Add(time.Hour)},
	}

	token, signature, err := strategy.GenerateClientRegistrationToken(ctx, request)
	require.NoError(t, err)

	assert.True(t, strings.HasPrefix(token, "authelia_cr_"), "got %q", token)
	assert.Equal(t, signature, strategy.ClientRegistrationTokenSignature(ctx, token))
	assert.NoError(t, strategy.ValidateClientRegistrationToken(ctx, request, token))

	assert.Empty(t, strategy.AccessTokenSignature(ctx, token))
	assert.Error(t, strategy.ValidateAccessToken(ctx, request, token))

	accessToken, _, err := strategy.GenerateAccessToken(ctx, request)
	require.NoError(t, err)

	assert.Empty(t, strategy.ClientRegistrationTokenSignature(ctx, accessToken))
	assert.Error(t, strategy.ValidateClientRegistrationToken(ctx, request, accessToken))
}

func TestHMACCoreStrategyClientRegistrationTokenExpiry(t *testing.T) {
	ctx := context.Background()
	strategy := NewHMACCoreStrategy(&oauth2.Config{
		GlobalSecret:                          []byte("super-duper-secret-that-is-at-least-32-bytes"),
		RFC7591ClientRegistrationGlobalSecret: []byte("a-completely-different-secret-at-least-32b"),
	}, "authelia_%s_")

	expired := oauth2.NewRequest()
	expired.Session = &oauth2.DefaultSession{
		ExpiresAt: map[oauth2.TokenType]time.Time{oauth2.AccessToken: time.Now().UTC().Add(-time.Minute)},
	}

	token, _, err := strategy.GenerateClientRegistrationToken(ctx, expired)
	require.NoError(t, err)
	assert.ErrorIs(t, strategy.ValidateClientRegistrationToken(ctx, expired, token), oauth2.ErrTokenExpired)

	zero := oauth2.NewRequest()
	zero.Session = &oauth2.DefaultSession{}

	zeroToken, _, err := strategy.GenerateClientRegistrationToken(ctx, zero)
	require.NoError(t, err)
	assert.Error(t, strategy.ValidateClientRegistrationToken(ctx, zero, zeroToken))
}

func TestJWTProfileCoreStrategyClientRegistrationTokenIsAlwaysOpaque(t *testing.T) {
	ctx := context.Background()

	config := &oauth2.Config{
		GlobalSecret:                          []byte("super-duper-secret-that-is-at-least-32-bytes"),
		RFC7591ClientRegistrationGlobalSecret: []byte("a-completely-different-secret-at-least-32b"),
		EnforceJWTProfileAccessTokens:         true,
	}

	hmac := NewHMACCoreStrategy(config, "authelia_%s_")
	strategy := &JWTProfileCoreStrategy{HMACCoreStrategy: hmac, Config: config}

	request := oauth2.NewRequest()
	request.Session = &oauth2.DefaultSession{
		ExpiresAt: map[oauth2.TokenType]time.Time{oauth2.AccessToken: time.Now().UTC().Add(time.Hour)},
	}

	token, signature, err := strategy.GenerateClientRegistrationToken(ctx, request)
	require.NoError(t, err)

	assert.True(t, strings.HasPrefix(token, "authelia_cr_"), "got %q", token)
	assert.Equal(t, signature, strategy.ClientRegistrationTokenSignature(ctx, token))
	assert.NoError(t, strategy.ValidateClientRegistrationToken(ctx, request, token))
}

func TestClientRegistrationTokenUsesItsOwnSecret(t *testing.T) {
	ctx := context.Background()

	config := &oauth2.Config{
		GlobalSecret:                          []byte("super-duper-secret-that-is-at-least-32-bytes"),
		RFC7591ClientRegistrationGlobalSecret: []byte("a-completely-different-secret-at-least-32b"),
	}

	strategy := NewHMACCoreStrategy(config, "authelia_%s_")

	request := oauth2.NewRequest()
	request.Session = &oauth2.DefaultSession{
		ExpiresAt: map[oauth2.TokenType]time.Time{oauth2.AccessToken: time.Now().UTC().Add(time.Hour)},
	}

	token, _, err := strategy.GenerateClientRegistrationToken(ctx, request)
	require.NoError(t, err)
	require.NoError(t, strategy.ValidateClientRegistrationToken(ctx, request, token))

	config.GlobalSecret = []byte("an-entirely-new-global-secret-at-least-32b")
	assert.NoError(t, strategy.ValidateClientRegistrationToken(ctx, request, token))

	config.RFC7591ClientRegistrationGlobalSecret = []byte("yet-another-registration-secret-32-bytes!")
	assert.Error(t, strategy.ValidateClientRegistrationToken(ctx, request, token))

	config.RFC7591ClientRegistrationRotatedGlobalSecrets = [][]byte{[]byte("a-completely-different-secret-at-least-32b")}
	assert.NoError(t, strategy.ValidateClientRegistrationToken(ctx, request, token))
}

func TestHMACCoreStrategyRejectsClientRegistrationTokenOpsWithoutNewHMACCoreStrategy(t *testing.T) {
	ctx := context.Background()

	strategy := &HMACCoreStrategy{
		Enigma: &hmac.HMACStrategy{Config: &oauth2.Config{GlobalSecret: []byte("super-duper-secret-that-is-at-least-32-bytes")}},
		Config: &oauth2.Config{},
	}

	request := oauth2.NewRequest()
	request.Session = &oauth2.DefaultSession{
		ExpiresAt: map[oauth2.TokenType]time.Time{oauth2.AccessToken: time.Now().UTC().Add(time.Hour)},
	}

	_, _, err := strategy.GenerateClientRegistrationToken(ctx, request)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "NewHMACCoreStrategy")

	err = strategy.ValidateClientRegistrationToken(ctx, request, "irrelevant-token")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "NewHMACCoreStrategy")

	assert.Empty(t, strategy.ClientRegistrationTokenSignature(ctx, "irrelevant-token"))
}

func mustNewBCryptClientSecretPlain(rawSecret string) *oauth2.BCryptClientSecret {
	if secret, err := oauth2.NewBCryptClientSecretPlain(rawSecret, 4); err != nil {
		panic(err)
	} else {
		return secret
	}
}

var hmacshaStrategy = HMACCoreStrategy{
	Enigma: &hmac.HMACStrategy{Config: &oauth2.Config{GlobalSecret: []byte("foobarfoobarfoobarfoobarfoobarfoobarfoobarfoobar")}},
	Config: &oauth2.Config{
		AccessTokenLifespan:   time.Hour * 24,
		AuthorizeCodeLifespan: time.Hour * 24,
	},
	usePrefix: true,
	prefix:    "authelia_%s_",
}
