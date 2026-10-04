// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package integration_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	xoauth2 "golang.org/x/oauth2"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/compose"
	"authelia.com/provider/oauth2/handler/openid"
	"authelia.com/provider/oauth2/internal"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/storage"
)

func TestAuthorizeCodeFlowWithAuthorizationDetails(t *testing.T) {
	stores := []struct {
		name string
		new  func() (any, map[string]oauth2.Client)
	}{
		{name: "MemoryStore", new: func() (any, map[string]oauth2.Client) {
			s := storage.NewMemoryStore()
			return s, s.Clients
		}},
		{name: "HydratingMemoryStore", new: func() (any, map[string]oauth2.Client) {
			s := storage.NewHydratingMemoryStore()
			return s, s.Clients
		}},
	}

	for _, st := range stores {
		t.Run(st.name, func(t *testing.T) {
			s, clients := st.new()

			config := &oauth2.Config{
				AuthorizationDetailsTypeHandlers: []oauth2.AuthorizationDetailsTypeHandler{internal.PaymentInitiationTypeHandler{}},
			}

			f := compose.Compose(config, s, hmacStrategy, compose.OAuth2AuthorizeExplicitFactory, compose.OAuth2RefreshTokenGrantFactory, compose.OAuth2TokenIntrospectionFactory)
			ts := mockServer(t, f, &openid.DefaultSession{Subject: testSubject})
			defer ts.Close()

			clients[testClientIDRAR] = &oauth2.DefaultClient{
				ID:            testClientIDRAR,
				ClientSecret:  oauth2.NewBCryptClientSecret(`$2a$04$6i/O2OM9CcEVTRLq9uFDtOze4AtISH79iYkZeEUsos4WzWtCnJ52y`), // = "foobar"
				RedirectURIs:  []string{ts.URL + "/callback"},
				ResponseTypes: []string{consts.ResponseTypeAuthorizationCodeFlow},
				GrantTypes:    []string{consts.GrantTypeAuthorizationCode, consts.GrantTypeRefreshToken},
				Scopes:        []string{testScopeOAuth2, consts.ScopeOffline},
			}

			client := &xoauth2.Config{
				ClientID:     testClientIDRAR,
				ClientSecret: testClientSecret,
				RedirectURL:  ts.URL + "/callback",
				Scopes:       []string{testScopeOAuth2, consts.ScopeOffline},
				Endpoint: xoauth2.Endpoint{
					TokenURL:  ts.URL + tokenRelativePath,
					AuthURL:   ts.URL + "/auth",
					AuthStyle: xoauth2.AuthStyleInHeader,
				},
			}

			const requested = `[{"type":"payment_initiation","actions":["initiate","status"],"instructedAmount":{"currency":"EUR","amount":"123.50"}}]`

			t.Run("ShouldRejectUnknownTypeAtAuthorize", func(t *testing.T) {
				resp, err := http.Get(client.AuthCodeURL(testState, xoauth2.SetAuthURLParam("authorization_details", `[{"type":"account_information"}]`)))
				require.NoError(t, err)
				defer resp.Body.Close()

				assert.Equal(t, http.StatusNotAcceptable, resp.StatusCode)
				assert.Equal(t, "invalid_authorization_details", resp.Request.URL.Query().Get("error"))
			})

			resp, err := http.Get(client.AuthCodeURL(testState, xoauth2.SetAuthURLParam("authorization_details", requested)))
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, resp.StatusCode)

			token, err := client.Exchange(t.Context(), resp.Request.URL.Query().Get(consts.FormParameterAuthorizationCode))
			resp.Body.Close()
			require.NoError(t, err)

			encoded, err := json.Marshal(token.Extra("authorization_details"))
			require.NoError(t, err)
			assert.JSONEq(t, requested, string(encoded))

			introspected := introspectAuthorizationDetails(t, ts, token.AccessToken)
			assert.JSONEq(t, requested, introspected)

			narrowed := refreshWithAuthorizationDetails(t, ts, token.RefreshToken, `[{"type":"payment_initiation","actions":["status"]}]`)
			assert.JSONEq(t, `[{"type":"payment_initiation","actions":["status"]}]`, string(narrowed["authorization_details"]))

			var next string
			require.NoError(t, json.Unmarshal(narrowed["refresh_token"], &next))

			restored := refreshWithAuthorizationDetails(t, ts, next, "")
			assert.JSONEq(t, requested, string(restored["authorization_details"]))

			var last string
			require.NoError(t, json.Unmarshal(restored["refresh_token"], &last))

			rejected := refreshWithAuthorizationDetails(t, ts, last, `[{"type":"payment_initiation","actions":["cancel"]}]`)
			assert.JSONEq(t, `"invalid_authorization_details"`, string(rejected["error"]))
		})
	}
}

func refreshWithAuthorizationDetails(t *testing.T, ts *httptest.Server, refreshToken, details string) map[string]json.RawMessage {
	t.Helper()

	form := url.Values{
		consts.FormParameterGrantType:    {consts.GrantTypeRefreshToken},
		consts.FormParameterRefreshToken: {refreshToken},
	}

	if details != "" {
		form.Set("authorization_details", details)
	}

	return postTokenEndpoint(t, ts, form)
}

func postTokenEndpoint(t *testing.T, ts *httptest.Server, form url.Values) map[string]json.RawMessage {
	t.Helper()

	req, err := http.NewRequest(http.MethodPost, ts.URL+tokenRelativePath, strings.NewReader(form.Encode()))
	require.NoError(t, err)

	req.Header.Set(consts.HeaderContentType, "application/x-www-form-urlencoded")
	req.SetBasicAuth(testClientIDRAR, testClientSecret)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)

	defer resp.Body.Close()

	body := map[string]json.RawMessage{}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))

	return body
}

func introspectAuthorizationDetails(t *testing.T, ts *httptest.Server, token string) string {
	t.Helper()

	req, err := http.NewRequest(http.MethodPost, ts.URL+"/introspect", strings.NewReader(url.Values{consts.FormParameterToken: {token}}.Encode()))
	require.NoError(t, err)

	req.Header.Set(consts.HeaderContentType, "application/x-www-form-urlencoded")
	req.SetBasicAuth(testClientIDRAR, testClientSecret)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)

	defer resp.Body.Close()

	body := map[string]json.RawMessage{}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))

	return string(body["authorization_details"])
}
