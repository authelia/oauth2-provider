// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package integration_test

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/compose"
	"authelia.com/provider/oauth2/handler/openid"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/gen"
	"authelia.com/provider/oauth2/storage"
)

func TestDeviceFlowNonceEntropy(t *testing.T) {
	s := storage.NewMemoryStore()

	f := compose.ComposeAllEnabled(&oauth2.Config{
		GlobalSecret:                          []byte("some-secret-thats-random-some-secret-thats-random-"),
		RFC7591ClientRegistrationGlobalSecret: []byte("a-completely-different-secret-at-least-32b"),
		RFC8628UserVerificationURL:            "https://www.authelia.com/device",
	}, s, gen.MustRSAKey())

	ts := deviceFlowServer(t, f, &openid.DefaultSession{Subject: testSubject})
	defer ts.Close()

	s.Clients[testClientIDRAR] = &oauth2.DefaultClient{
		ID:           testClientIDRAR,
		ClientSecret: oauth2.NewBCryptClientSecret(`$2a$04$6i/O2OM9CcEVTRLq9uFDtOze4AtISH79iYkZeEUsos4WzWtCnJ52y`),
		GrantTypes:   []string{consts.GrantTypeOAuthDeviceCode},
		Scopes:       []string{consts.ScopeOpenID},
	}

	testCases := []struct {
		name   string
		nonce  string
		status int
		err    string
	}{
		{name: "ShouldPassSufficientNonce", nonce: "1234567890", status: http.StatusOK},
		{name: "ShouldFailShortNonce", nonce: "abc", status: http.StatusBadRequest, err: "insufficient_entropy"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			form := url.Values{
				consts.FormParameterScope: {consts.ScopeOpenID},
				consts.FormParameterNonce: {tc.nonce},
			}

			req, err := http.NewRequest(http.MethodPost, ts.URL+"/device_authorization", strings.NewReader(form.Encode()))
			require.NoError(t, err)

			req.Header.Set(consts.HeaderContentType, "application/x-www-form-urlencoded")
			req.SetBasicAuth(testClientIDRAR, testClientSecret)

			resp, err := http.DefaultClient.Do(req)
			require.NoError(t, err)

			defer resp.Body.Close()

			body := struct {
				Error string `json:"error"`
			}{}
			require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))

			assert.Equal(t, tc.status, resp.StatusCode)
			assert.Equal(t, tc.err, body.Error)
		})
	}
}
