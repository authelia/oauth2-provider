// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	. "authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/handler/rfc9449"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/gen"
	"authelia.com/provider/oauth2/storage"
)

func TestWriteBackChannelAuthenticationResponse(t *testing.T) {
	testCases := []struct {
		name     string
		response *BackChannelAuthenticationResponse
		keys     []string
	}{
		{
			name:     "ShouldWriteInterval",
			response: &BackChannelAuthenticationResponse{AuthRequestID: "id", ExpiresIn: 300, Interval: 5},
			keys:     []string{"auth_req_id", "expires_in", "interval"},
		},
		{
			name:     "ShouldOmitZeroInterval",
			response: &BackChannelAuthenticationResponse{AuthRequestID: "id", ExpiresIn: 300},
			keys:     []string{"auth_req_id", "expires_in"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			provider := &Fosite{Config: &Config{}}
			rw := httptest.NewRecorder()

			provider.WriteBackChannelAuthenticationResponse(t.Context(), rw, NewBackChannelAuthenticationRequest(), tc.response)

			assert.Equal(t, http.StatusOK, rw.Code)
			assert.Equal(t, consts.ContentTypeApplicationJSON, rw.Header().Get(consts.HeaderContentType))
			assert.Equal(t, "no-store", rw.Header().Get(consts.HeaderCacheControl))

			body := map[string]any{}

			require.NoError(t, json.Unmarshal(rw.Body.Bytes(), &body))

			keys := make([]string, 0, len(body))

			for k := range body {
				keys = append(keys, k)
			}

			assert.ElementsMatch(t, tc.keys, keys)
			assert.Equal(t, "id", body["auth_req_id"])
			assert.EqualValues(t, 300, body["expires_in"])
		})
	}
}

func TestWriteBackChannelAuthenticationResponseDPoPNonce(t *testing.T) {
	testCases := []struct {
		name      string
		stateless bool
		required  bool
		bound     bool
		expected  bool
	}{
		{name: "ShouldSendAStoredNonceToABoundRequest", required: true, bound: true, expected: true},
		{name: "ShouldSendAStatelessNonceToABoundRequest", stateless: true, required: true, bound: true, expected: true},
		{name: "ShouldNotSendANonceToAnUnboundRequest", required: true},
		{name: "ShouldNotSendANonceWhenNotRequired", bound: true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			store := storage.NewMemoryStore()
			config := &Config{
				GlobalSecret:       []byte("foobarfoobarfoobarfoobarfoobarfoobarfoobarfoobar"),
				DPoPEnabled:        true,
				DPoPNonceRequired:  tc.required,
				DPoPNonceStateless: tc.stateless,
			}
			config.DPoPStrategy = rfc9449.NewDefaultStrategy(config, store)

			provider := &Fosite{Config: config}

			request := NewBackChannelAuthenticationRequest()
			session := &DefaultSession{}

			if tc.bound {
				session.SetDPoPJWKThumbprint("some-thumbprint")
			}

			request.Session = session

			rw := httptest.NewRecorder()

			provider.WriteBackChannelAuthenticationResponse(t.Context(), rw, request, &BackChannelAuthenticationResponse{AuthRequestID: "id", ExpiresIn: 300})

			require.Equal(t, http.StatusOK, rw.Code)

			nonce := rw.Header().Get(consts.HeaderDPoPNonce)

			if !tc.expected {
				assert.Empty(t, nonce)
				assert.Empty(t, store.DPoPNonces)

				return
			}

			require.NotEmpty(t, nonce)
			assert.NoError(t, config.DPoPStrategy.ValidateDPoPNonce(t.Context(), nonce))
			assert.Equal(t, !tc.stateless, len(store.DPoPNonces) == 1)
		})
	}
}

func TestWriteBackChannelAuthenticationError(t *testing.T) {
	_, provider, _ := newCIBATestProvider(gen.MustRSAKey(), gen.MustRSAKey())

	// An authenticated-client failure carries the WWW-Authenticate challenge.
	_, challenged := provider.NewBackChannelAuthenticationRequest(t.Context(), newCIBATestRequest(t, nil, "", cibaTestClientPoll, "wrong", "scope=openid&login_hint=alice"), &DefaultSession{})
	require.Error(t, challenged)

	testCases := []struct {
		name      string
		err       error
		status    int
		code      string
		challenge bool
		desc      string
	}{
		{name: "ShouldWriteUnknownUserID", err: ErrUnknownUserID, status: http.StatusBadRequest, code: "unknown_user_id"},
		{name: "ShouldWriteInvalidClientWithChallenge", err: challenged, status: http.StatusUnauthorized, code: "invalid_client", challenge: true},
		{name: "ShouldWriteInvalidClientAsUnauthorized", err: ErrInvalidClient.WithCode(http.StatusBadRequest), status: http.StatusUnauthorized, code: "invalid_client"},
		{name: "ShouldWriteAccessDeniedAsForbidden", err: ErrAccessDenied.WithCode(http.StatusBadRequest), status: http.StatusForbidden, code: "access_denied"},
		{name: "ShouldSanitizeDescription", err: ErrInvalidRequest.WithDescription("a \"quoted\" \\ value"), status: http.StatusBadRequest, code: "invalid_request", desc: "a 'quoted'   value"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rw := httptest.NewRecorder()

			provider.WriteBackChannelAuthenticationError(t.Context(), rw, NewBackChannelAuthenticationRequest(), tc.err)

			assert.Equal(t, tc.status, rw.Code)
			assert.Equal(t, consts.ContentTypeApplicationJSON, rw.Header().Get(consts.HeaderContentType))
			assert.Equal(t, "no-store", rw.Header().Get(consts.HeaderCacheControl))

			if tc.challenge {
				assert.NotEmpty(t, rw.Header().Get(consts.HeaderWWWAuthenticate))
			} else {
				assert.Empty(t, rw.Header().Get(consts.HeaderWWWAuthenticate))
			}

			body := map[string]any{}

			require.NoError(t, json.Unmarshal(rw.Body.Bytes(), &body))
			assert.Equal(t, tc.code, body["error"])

			if tc.desc != "" {
				assert.True(t, strings.HasPrefix(body["error_description"].(string), tc.desc), "%v", body["error_description"])
				assert.NotContains(t, body["error_description"], "\"")
				assert.NotContains(t, body["error_description"], "\\")
			}
		})
	}
}
