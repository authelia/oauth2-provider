// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package authzen_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
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
	"authelia.com/provider/oauth2/handler/authzen"
	"authelia.com/provider/oauth2/handler/openid"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/storage"
)

func TestPolicyAgainstAPolicyDecisionPoint(t *testing.T) {
	testCases := []struct {
		name     string
		pdp      http.HandlerFunc
		status   int
		scope    string
		lifetime int64
	}{
		{name: "ShouldShapeTheToken", pdp: evaluations(func(e authzen.Evaluation) map[string]any {
			switch e.Action.Name {
			case "b":
				return map[string]any{"decision": false}
			case "issue:access_token:client_credentials":
				return map[string]any{"decision": true, "context": map[string]any{"issuance": map[string]any{"token_lifetime": 60}}}
			default:
				return map[string]any{"decision": true}
			}
		}), status: http.StatusOK, scope: "a", lifetime: 60},
		{name: "ShouldDenyOnAGateDenial", pdp: evaluations(func(e authzen.Evaluation) map[string]any {
			return map[string]any{"decision": !strings.HasPrefix(e.Action.Name, "issue:")}
		}), status: http.StatusForbidden},
		{name: "ShouldFailClosedWhenThePDPFails", pdp: func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}, status: http.StatusServiceUnavailable},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(tc.pdp)
			defer server.Close()

			key, err := rsa.GenerateKey(rand.Reader, 2048)
			require.NoError(t, err)

			store := storage.NewMemoryStore()
			store.Clients["svc"] = &oauth2.DefaultClient{ID: "svc", ClientSecret: oauth2.NewPlainTextClientSecret("secret"), GrantTypes: []string{consts.GrantTypeClientCredentials}, Scopes: []string{"a", "b"}}

			provider := compose.ComposeAllEnabled(&oauth2.Config{
				GlobalSecret:                                []byte("some-secret-that-is-32-bytes-long"),
				RFC7591ClientRegistrationGlobalSecret:       []byte("another-secret-that-is-32-bytes-long"),
				ClientCredentialsFlowImplicitGrantRequested: true,
				IssuancePolicy:                              &authzen.Policy{Evaluator: &authzen.HTTPEvaluator{Endpoint: server.URL}, DefaultTarget: "https://api.example"},
			}, store, key)

			body := url.Values{consts.FormParameterGrantType: {consts.GrantTypeClientCredentials}, consts.FormParameterScope: {"a b"}}
			r := httptest.NewRequest(http.MethodPost, "https://as.example/token", strings.NewReader(body.Encode()))
			r.Header.Set(consts.HeaderContentType, consts.ContentTypeApplicationURLEncodedForm)
			r.SetBasicAuth("svc", "secret")

			ctx := context.Background()
			recorder := httptest.NewRecorder()

			request, err := provider.NewAccessRequest(ctx, r, &openid.DefaultSession{})
			require.NoError(t, err)

			response, err := provider.NewAccessResponse(ctx, request)
			if err != nil {
				provider.WriteAccessError(ctx, recorder, request, err)
				assert.Equal(t, tc.status, recorder.Code)

				return
			}

			require.Equal(t, http.StatusOK, tc.status)
			assert.Equal(t, tc.scope, response.GetExtra(consts.AccessResponseScope))
			assert.LessOrEqual(t, response.GetExtra(consts.AccessResponseExpiresIn), tc.lifetime)
		})
	}
}

func evaluations(decide func(e authzen.Evaluation) map[string]any) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var request authzen.EvaluationsRequest

		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			w.WriteHeader(http.StatusBadRequest)

			return
		}

		out := make([]map[string]any, 0, len(request.Evaluations))

		for _, e := range request.Evaluations {
			out = append(out, decide(e))
		}

		_ = json.NewEncoder(w).Encode(map[string]any{"evaluations": out})
	}
}
