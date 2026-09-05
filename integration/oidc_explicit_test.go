// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package integration_test

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	xoauth2 "golang.org/x/oauth2"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/compose"
	"authelia.com/provider/oauth2/handler/openid"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/gen"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestOpenIDConnectExplicitFlow(t *testing.T) {
	f := compose.ComposeAllEnabled(&oauth2.Config{
		GlobalSecret:                          []byte("some-secret-thats-random-some-secret-thats-random-"),
		RFC7591ClientRegistrationGlobalSecret: []byte("a-completely-different-secret-at-least-32b"),
	}, store, gen.MustRSAKey())

	testCases := []struct {
		name           string
		setup          func(oauthClient *xoauth2.Config) string
		authStatusCode int
		authCodeURL    string
		session        *defaultSession
		expectAuthErr  string
		expectTokenErr string
	}{
		{
			session: newIDSession(&jwt.IDTokenClaims{Subject: "peter"}),
			name:    "should pass",
			setup: func(oauthClient *xoauth2.Config) string {
				oauthClient.Scopes = []string{consts.ScopeOpenID}
				return oauthClient.AuthCodeURL(testState) + "&nonce=11234123"
			},
			authStatusCode: http.StatusOK,
		},
		{
			session: newIDSession(&jwt.IDTokenClaims{Subject: "peter"}),
			name:    "should fail registered single redirect uri but no redirect uri in request",
			setup: func(oauthClient *xoauth2.Config) string {
				oauthClient.Scopes = []string{"openid"}
				oauthClient.RedirectURL = ""

				return oauthClient.AuthCodeURL(testState) + "&nonce=11234123"
			},
			authStatusCode: http.StatusBadRequest,
			expectAuthErr:  `{"error":"invalid_request","error_description":"The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The 'redirect_uri' parameter is required when using OpenID Connect 1.0."}`,
		},
		{
			session: newIDSession(&jwt.IDTokenClaims{Subject: "peter"}),
			name:    "should fail registered single redirect uri but no redirect uri in request",
			setup: func(oauthClient *xoauth2.Config) string {
				oauthClient.Scopes = []string{"openid"}
				oauthClient.RedirectURL = ""

				return oauthClient.AuthCodeURL(testState) + "&nonce=11234123"
			},
			authStatusCode: http.StatusBadRequest,
			expectAuthErr:  `{"error":"invalid_request","error_description":"The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The 'redirect_uri' parameter is required when using OpenID Connect 1.0."}`,
		},
		{
			session: newIDSession(&jwt.IDTokenClaims{Subject: "peter"}),
			name:    "should fail registered single redirect uri but no redirect uri in request",
			setup: func(oauthClient *xoauth2.Config) string {
				oauthClient.Scopes = []string{consts.ScopeOpenID}
				oauthClient.RedirectURL = ""

				return oauthClient.AuthCodeURL(testState) + "&nonce=11234123"
			},
			authStatusCode: http.StatusBadRequest,
			expectAuthErr:  `{"error":"invalid_request","error_description":"The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The 'redirect_uri' parameter is required when using OpenID Connect 1.0."}`,
		},
		{
			session: newIDSession(&jwt.IDTokenClaims{Subject: "peter"}),
			name:    "should fail because nonce is not long enough",
			setup: func(oauthClient *xoauth2.Config) string {
				oauthClient.Scopes = []string{consts.ScopeOpenID}
				return oauthClient.AuthCodeURL(testState) + "&nonce=1"
			},
			authStatusCode: http.StatusOK,
			expectTokenErr: "insufficient_entropy",
		},
		{
			session: newIDSession(&jwt.IDTokenClaims{
				Subject:  "peter",
				AuthTime: jwt.NewNumericDate(time.Now().Add(time.Second)),
			}),
			name: "should not pass missing redirect uri",
			setup: func(oauthClient *xoauth2.Config) string {
				oauthClient.RedirectURL = ""
				oauthClient.Scopes = []string{"openid"}
				return oauthClient.AuthCodeURL(testState) + "&nonce=1234567890&prompt=login"
			},
			expectAuthErr:  `{"error":"invalid_request","error_description":"The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The 'redirect_uri' parameter is required when using OpenID Connect 1.0."}`,
			authStatusCode: http.StatusBadRequest,
		},
		{
			session: newIDSession(&jwt.IDTokenClaims{Subject: "peter"}),
			name:    "should fail because state is not long enough",
			setup: func(oauthClient *xoauth2.Config) string {
				oauthClient.Scopes = []string{consts.ScopeOpenID}
				return oauthClient.AuthCodeURL("123") + "&nonce=1234567890"
			},
			expectAuthErr:  "invalid_state",
			authStatusCode: http.StatusNotAcceptable, // code from internal test callback handler when error occurs
		},
		{
			session: newIDSession(&jwt.IDTokenClaims{
				Subject:  "peter",
				AuthTime: jwt.NewNumericDate(time.Now().Add(time.Second)),
			}),
			name: "should pass",
			setup: func(oauthClient *xoauth2.Config) string {
				oauthClient.Scopes = []string{consts.ScopeOpenID}

				return oauthClient.AuthCodeURL(testState) + "&nonce=1234567890&prompt=login"
			},
			authStatusCode: http.StatusOK,
		},
		{
			session: newIDSession(&jwt.IDTokenClaims{
				Subject:  "peter",
				AuthTime: jwt.NewNumericDate(time.Now().Add(time.Second)),
			}),
			name: "should not pass missing redirect uri",
			setup: func(oauthClient *xoauth2.Config) string {
				oauthClient.RedirectURL = ""
				oauthClient.Scopes = []string{consts.ScopeOpenID}
				return oauthClient.AuthCodeURL(testState) + "&nonce=1234567890&prompt=login"
			},
			expectAuthErr:  `{"error":"invalid_request","error_description":"The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The 'redirect_uri' parameter is required when using OpenID Connect 1.0."}`,
			authStatusCode: http.StatusBadRequest,
		},
		{
			session: newIDSession(&jwt.IDTokenClaims{
				Subject:  "peter",
				AuthTime: jwt.NewNumericDate(time.Now().Add(time.Second)),
			}),
			name: "should not pass missing redirect uri",
			setup: func(oauthClient *xoauth2.Config) string {
				oauthClient.RedirectURL = ""
				oauthClient.Scopes = []string{"openid"}
				return oauthClient.AuthCodeURL(testState) + "&nonce=1234567890&prompt=login"
			},
			expectAuthErr:  `{"error":"invalid_request","error_description":"The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The 'redirect_uri' parameter is required when using OpenID Connect 1.0."}`,
			authStatusCode: http.StatusBadRequest,
		},
		{
			session: newIDSession(&jwt.IDTokenClaims{
				Subject:  "peter",
				AuthTime: jwt.NewNumericDate(time.Now().Add(-time.Minute)),
			}),
			name: "should fail because authentication was in the past",
			setup: func(oauthClient *xoauth2.Config) string {
				oauthClient.Scopes = []string{consts.ScopeOpenID}
				return oauthClient.AuthCodeURL(testState) + "&nonce=1234567890&prompt=login"
			},
			authStatusCode: http.StatusNotAcceptable, // code from internal test callback handler when error occurs
			expectAuthErr:  "login_required",
		},
		{
			session: newIDSession(&jwt.IDTokenClaims{
				Subject:  "peter",
				AuthTime: jwt.NewNumericDate(time.Now().Add(-time.Minute)),
			}),
			name: "should pass because authorization was in the past and no login was required",
			setup: func(oauthClient *xoauth2.Config) string {
				oauthClient.Scopes = []string{consts.ScopeOpenID}
				return oauthClient.AuthCodeURL(testState) + "&nonce=1234567890&prompt=none"
			},
			authStatusCode: http.StatusOK,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ts := mockServer(t, f, tc.session)
			defer ts.Close()

			oauthClient := newOAuth2Client(ts)
			store.Clients["my-client"].(*oauth2.DefaultClient).RedirectURIs = []string{ts.URL + "/callback"}

			resp, err := http.Get(tc.setup(oauthClient))
			require.NoError(t, err)
			defer resp.Body.Close()

			body, _ := io.ReadAll(resp.Body)
			require.Equal(t, tc.authStatusCode, resp.StatusCode, "Got response: %s", body)
			if resp.StatusCode >= 400 {
				assert.Equal(t, tc.expectAuthErr, strings.Replace(string(body), "error: ", "", 1))
			}

			if tc.expectAuthErr != "" {
				assert.Empty(t, resp.Request.URL.Query().Get("code"))
			}

			if resp.StatusCode == http.StatusOK {
				time.Sleep(time.Second)

				token, err := oauthClient.Exchange(t.Context(), resp.Request.URL.Query().Get("code"))
				if tc.expectTokenErr != "" {
					require.Error(t, err)
					assert.True(t, strings.Contains(err.Error(), tc.expectTokenErr), err.Error())
				} else {
					require.NoError(t, err)
					assert.NotEmpty(t, token.AccessToken)
					assert.NotEmpty(t, token.Extra("id_token"))
				}
			}
		})
	}
}

func newIDSession(j *jwt.IDTokenClaims) *defaultSession {
	return &defaultSession{
		DefaultSession: &openid.DefaultSession{
			Claims:      j,
			Headers:     &jwt.Headers{},
			Subject:     j.Subject,
			RequestedAt: time.Now().UTC(),
		},
	}
}
