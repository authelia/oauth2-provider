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

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/compose"
	"authelia.com/provider/oauth2/handler/openid"
	"authelia.com/provider/oauth2/internal"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/storage"
)

func TestDeviceFlowWithAuthorizationDetails(t *testing.T) {
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

	const (
		requested = `[{"type":"payment_initiation","actions":["initiate","status"],"instructedAmount":{"currency":"EUR","amount":"123.50"}}]`
		narrow    = `[{"type":"payment_initiation","actions":["status"]}]`
		narrowed  = `[{"type":"payment_initiation","actions":["status"],"instructedAmount":{"currency":"EUR","amount":"123.50"}}]`
	)

	for _, st := range stores {
		t.Run(st.name, func(t *testing.T) {
			s, clients := st.new()

			config := &oauth2.Config{
				AuthorizationDetailsTypeHandlers: []oauth2.AuthorizationDetailsTypeHandler{internal.PaymentInitiationTypeHandler{}},
				RFC8628UserVerificationURL:       "https://www.authelia.com/device",
			}

			f := compose.Compose(config, s, hmacStrategy,
				compose.RFC8628DeviceAuthorizeFactory,
				compose.RFC8628UserAuthorizeFactory,
				compose.RFC8628DeviceAuthorizeTokenFactory,
				compose.OAuth2RefreshTokenGrantFactory,
				compose.OAuth2TokenIntrospectionFactory,
			)

			ts := deviceFlowServer(t, f, &openid.DefaultSession{Subject: testSubject})
			defer ts.Close()

			clients[testClientIDRAR] = &oauth2.DefaultClient{
				ID:           testClientIDRAR,
				ClientSecret: oauth2.NewBCryptClientSecret(`$2a$04$6i/O2OM9CcEVTRLq9uFDtOze4AtISH79iYkZeEUsos4WzWtCnJ52y`),
				GrantTypes:   []string{consts.GrantTypeOAuthDeviceCode, consts.GrantTypeRefreshToken},
				Scopes:       []string{testScopeOAuth2, consts.ScopeOffline},
			}

			t.Run("ShouldRejectUnknownTypeAtDeviceAuthorization", func(t *testing.T) {
				status, body := postDeviceAuthorization(t, ts, `[{"type":"account_information"}]`)

				assert.Equal(t, http.StatusBadRequest, status)
				assert.JSONEq(t, `"invalid_authorization_details"`, string(body["error"]))
			})

			t.Run("ShouldIssueGrantedDetails", func(t *testing.T) {
				token := postTokenEndpoint(t, ts, deviceCodeForm(approveDevice(t, ts, requested), ""))
				assert.JSONEq(t, requested, string(token["authorization_details"]))

				var access, refresh string

				require.NoError(t, json.Unmarshal(token["access_token"], &access))
				require.NoError(t, json.Unmarshal(token["refresh_token"], &refresh))

				assert.JSONEq(t, requested, introspectAuthorizationDetails(t, ts, access))

				refreshed := refreshWithAuthorizationDetails(t, ts, refresh, "")
				assert.JSONEq(t, requested, string(refreshed["authorization_details"]))
			})

			t.Run("ShouldIssueNarrowedDetailsAndKeepTheGrant", func(t *testing.T) {
				token := postTokenEndpoint(t, ts, deviceCodeForm(approveDevice(t, ts, requested), narrow))
				assert.JSONEq(t, narrowed, string(token["authorization_details"]))

				var refresh string

				require.NoError(t, json.Unmarshal(token["refresh_token"], &refresh))

				refreshed := refreshWithAuthorizationDetails(t, ts, refresh, "")
				assert.JSONEq(t, requested, string(refreshed["authorization_details"]))
			})

			t.Run("ShouldRejectDetailsNotGranted", func(t *testing.T) {
				token := postTokenEndpoint(t, ts, deviceCodeForm(approveDevice(t, ts, requested), `[{"type":"payment_initiation","actions":["cancel"]}]`))
				assert.JSONEq(t, `"invalid_authorization_details"`, string(token["error"]))
			})

			t.Run("ShouldRejectDetailsWhenNoneGranted", func(t *testing.T) {
				token := postTokenEndpoint(t, ts, deviceCodeForm(approveDevice(t, ts, ""), narrow))
				assert.JSONEq(t, `"invalid_authorization_details"`, string(token["error"]))
			})
		})
	}
}

func deviceFlowServer(t *testing.T, provider oauth2.Provider, session oauth2.Session) *httptest.Server {
	t.Helper()

	router := http.NewServeMux()

	router.HandleFunc("/device_authorization", func(rw http.ResponseWriter, req *http.Request) {
		ctx := oauth2.NewContext()

		ar, err := provider.NewRFC862DeviceAuthorizeRequest(ctx, req)
		if err != nil {
			writeDeviceAuthorizationError(rw, err)
			return
		}

		response, err := provider.NewRFC862DeviceAuthorizeResponse(ctx, ar, session)
		if err != nil {
			writeDeviceAuthorizationError(rw, err)
			return
		}

		provider.WriteRFC862DeviceAuthorizeResponse(ctx, rw, ar, response)
	})

	router.HandleFunc("/device/verify", func(rw http.ResponseWriter, req *http.Request) {
		ctx := oauth2.NewContext()

		ar, err := provider.NewRFC8628UserAuthorizeRequest(ctx, req, session)
		if err != nil {
			provider.WriteRFC8628UserAuthorizeError(ctx, rw, ar, err)
			return
		}

		for _, scope := range ar.GetRequestedScopes() {
			ar.GrantScope(scope)
		}

		ar.SetGrantedAuthorizationDetails(ar.GetRequestedAuthorizationDetails())
		ar.SetStatus(oauth2.DeviceAuthorizeStatusApproved)

		response, err := provider.NewRFC8628UserAuthorizeResponse(ctx, ar, session)
		if err != nil {
			provider.WriteRFC8628UserAuthorizeError(ctx, rw, ar, err)
			return
		}

		provider.WriteRFC8628UserAuthorizeResponse(ctx, rw, ar, response)
	})

	router.HandleFunc(tokenRelativePath, tokenEndpointHandler(t, provider))
	router.HandleFunc("/introspect", tokenIntrospectionHandler(t, provider, session))

	return httptest.NewServer(router)
}

func writeDeviceAuthorizationError(rw http.ResponseWriter, err error) {
	rfc := oauth2.ErrorToRFC6749Error(err)

	rw.Header().Set(consts.HeaderContentType, "application/json")
	rw.WriteHeader(rfc.CodeField)

	_ = json.NewEncoder(rw).Encode(map[string]string{"error": rfc.ErrorField})
}

func postDeviceAuthorization(t *testing.T, ts *httptest.Server, details string) (int, map[string]json.RawMessage) {
	t.Helper()

	form := url.Values{consts.FormParameterScope: {testScopeOAuth2 + " " + consts.ScopeOffline}}

	if details != "" {
		form.Set("authorization_details", details)
	}

	req, err := http.NewRequest(http.MethodPost, ts.URL+"/device_authorization", strings.NewReader(form.Encode()))
	require.NoError(t, err)

	req.Header.Set(consts.HeaderContentType, "application/x-www-form-urlencoded")
	req.SetBasicAuth(testClientIDRAR, testClientSecret)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)

	defer resp.Body.Close()

	body := map[string]json.RawMessage{}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))

	return resp.StatusCode, body
}

func approveDevice(t *testing.T, ts *httptest.Server, details string) string {
	t.Helper()

	status, body := postDeviceAuthorization(t, ts, details)
	require.Equal(t, http.StatusOK, status)

	var deviceCode, userCode string

	require.NoError(t, json.Unmarshal(body["device_code"], &deviceCode))
	require.NoError(t, json.Unmarshal(body["user_code"], &userCode))

	resp, err := http.PostForm(ts.URL+"/device/verify", url.Values{consts.FormParameterUserCode: {userCode}})
	require.NoError(t, err)

	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)

	return deviceCode
}

func deviceCodeForm(deviceCode, details string) url.Values {
	form := url.Values{
		consts.FormParameterGrantType:  {consts.GrantTypeOAuthDeviceCode},
		consts.FormParameterDeviceCode: {deviceCode},
	}

	if details != "" {
		form.Set("authorization_details", details)
	}

	return form
}
