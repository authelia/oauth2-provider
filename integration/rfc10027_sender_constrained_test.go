// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package integration_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/compose"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/handler/openid"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/token/jwt"
)

// RFC 10027 Section 6.1.12.
func TestDeviceFlowSenderConstrainedAccessTokens(t *testing.T) {
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

	testCases := []struct {
		name      string
		enforce   bool
		client    bool
		proof     bool
		status    int
		tokenType string
		err       string
	}{
		{name: "ShouldIssueABearerTokenByDefault", status: http.StatusOK, tokenType: oauth2.BearerAccessToken},
		{name: "ShouldBindTheDPoPProofByDefault", proof: true, status: http.StatusOK, tokenType: oauth2.DPoPAccessToken},
		{name: "ShouldRejectAPollWithoutKeyMaterialWhenEnforced", enforce: true, status: http.StatusBadRequest, err: "invalid_request"},
		{name: "ShouldBindTheDPoPProofWhenEnforced", enforce: true, proof: true, status: http.StatusOK, tokenType: oauth2.DPoPAccessToken},
		{name: "ShouldRejectAPollWithoutKeyMaterialWhenTheClientEnforces", client: true, status: http.StatusBadRequest, err: "invalid_request"},
		{name: "ShouldBindTheDPoPProofWhenTheClientEnforces", client: true, proof: true, status: http.StatusOK, tokenType: oauth2.DPoPAccessToken},
	}

	for _, st := range stores {
		for _, tc := range testCases {
			t.Run(st.name+"/"+tc.name, func(t *testing.T) {
				s, clients := st.new()

				config := &oauth2.Config{
					GlobalSecret:                []byte("some-super-cool-secret-that-nobody-knows"),
					DPoPEnabled:                 true,
					RFC8628UserVerificationURL:  "https://www.authelia.com/device",
					RFC8628TokenPollingInterval: time.Nanosecond,

					RFC8628EnforceSenderConstrainedAccessTokens: tc.enforce,
				}

				f := compose.Compose(config, s, hmacStrategy,
					compose.RFC8628DeviceAuthorizeFactory,
					compose.RFC8628UserAuthorizeFactory,
					compose.RFC8628DeviceAuthorizeTokenFactory,
					compose.DPoPDeviceAuthorizeFactory,
					compose.DPoPTokenFactory,
					compose.OAuth2TokenIntrospectionFactory,
				)

				ts := deviceFlowServer(t, f, &openid.DefaultSession{Subject: testSubject})
				defer ts.Close()

				clients[testClientIDRAR] = &oauth2.DefaultRegisteredClient{
					DefaultClient: &oauth2.DefaultClient{
						ID:           testClientIDRAR,
						ClientSecret: oauth2.NewBCryptClientSecret(`$2a$04$6i/O2OM9CcEVTRLq9uFDtOze4AtISH79iYkZeEUsos4WzWtCnJ52y`),
						GrantTypes:   []string{consts.GrantTypeOAuthDeviceCode},
						Scopes:       []string{testScopeOAuth2, consts.ScopeOffline},
					},
					TokenEndpointAuthMethod:                     consts.ClientAuthMethodClientSecretBasic,
					RFC8628EnforceSenderConstrainedAccessTokens: tc.client,
				}

				var proof, jkt string

				if tc.proof {
					key := newDPoPProofKey(t)
					pub := key.Public()

					var err error

					jkt, err = jwt.ThumbprintJWK(&pub)
					require.NoError(t, err)

					proof = signDPoPProof(t, key, ts.URL+tokenRelativePath, nil)
				}

				status, body := postDeviceToken(t, ts, deviceCodeForm(approveDevice(t, ts, ""), ""), proof)

				require.Equal(t, tc.status, status, "token response: %v", body)

				if tc.err != "" {
					assert.JSONEq(t, `"`+tc.err+`"`, string(body["error"]))
					assert.Contains(t, string(body["error_description"]), "sender-constrained access token")

					return
				}

				var tokenType, accessToken string

				require.NoError(t, json.Unmarshal(body["token_type"], &tokenType))
				assert.True(t, strings.EqualFold(tc.tokenType, tokenType), "token type %q", tokenType)

				require.NoError(t, json.Unmarshal(body["access_token"], &accessToken))

				_, requester, err := f.IntrospectToken(context.Background(), accessToken, oauth2.AccessToken, &hoauth2.JWTSession{})
				require.NoError(t, err)

				session, ok := requester.GetSession().(oauth2.DPoPBoundSession)
				require.True(t, ok)
				assert.Equal(t, jkt, session.GetDPoPJWKThumbprint())
			})
		}
	}
}

func postDeviceToken(t *testing.T, ts *httptest.Server, form url.Values, proof string) (status int, body map[string]json.RawMessage) {
	t.Helper()

	req, err := http.NewRequest(http.MethodPost, ts.URL+tokenRelativePath, strings.NewReader(form.Encode()))
	require.NoError(t, err)

	req.Header.Set(consts.HeaderContentType, consts.ContentTypeApplicationURLEncodedForm)
	req.SetBasicAuth(testClientIDRAR, testClientSecret)

	if proof != "" {
		req.Header.Set(consts.HeaderDPoP, proof)
	}

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)

	defer resp.Body.Close()

	body = map[string]json.RawMessage{}

	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))

	return resp.StatusCode, body
}
