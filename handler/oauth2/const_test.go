// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"time"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/gen"
	"authelia.com/provider/oauth2/token/hmac"
	"authelia.com/provider/oauth2/token/jwt"
)

const (
	testRARActionInitiate       = "initiate"
	testRARActionStatus         = "status"
	testRARActionCancel         = "cancel"
	testRARIdentifierEnriched   = "enriched"
	testRARExtraSpoofed         = "spoofed"
	testRARHintTypeNotAllowed   = "The OAuth 2.0 Client is not allowed to request authorization details type 'payment_initiation'."
	testRARHintTypeNotSupported = "The authorization details type 'payment_initiation' is not supported."
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

var rsaKey = gen.MustRSAKey()

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

var jwtInvalidTypCase = func(tokenType oauth2.TokenType) *oauth2.Request {
	r := &oauth2.Request{
		Client: &oauth2.DefaultClient{
			ClientSecret: mustNewBCryptClientSecretPlain("xfoobarfoobarfoobarfoobar"),
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
				Extra: map[string]any{consts.JSONWebTokenHeaderType: consts.JSONWebTokenTypeJWT},
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
				oauth2.RefreshToken: time.Now().UTC().Add(time.Hour * 2).Truncate(time.Hour),
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

var jwtExpiredCase = func(tokenType oauth2.TokenType, now time.Time) *oauth2.Request {
	r := &oauth2.Request{
		Client: &oauth2.DefaultClient{
			ClientSecret: mustNewBCryptClientSecretPlain("foobarfoobarfoobarfoobar"),
		},
		Session: &JWTSession{
			JWTClaims: &jwt.JWTClaims{
				Issuer:    "oauth2",
				Subject:   "peter",
				IssuedAt:  now.UTC().Add(-time.Minute * 10),
				NotBefore: now.UTC().Add(-time.Minute * 10),
				ExpiresAt: now.UTC().Add(-time.Minute),
				Extra:     map[string]any{"foo": "bar"},
			},
			JWTHeader: &jwt.Headers{
				Extra: make(map[string]any),
			},
			ExpiresAt: map[oauth2.TokenType]time.Time{
				tokenType: now.UTC().Add(-time.Hour),
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
