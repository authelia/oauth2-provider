// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	. "authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
)

func TestWriteOpenIDCIBAResponse(t *testing.T) {
	testCases := []struct {
		name     string
		setup    func() *CIBAResponse
		expected map[string]any
		headers  http.Header
	}{
		{
			name: "ShouldWriteAllFieldsWhenSet",
			setup: func() *CIBAResponse {
				resp := NewCIBAResponse()
				resp.SetAuthRequestID("auth_req_id_value")
				resp.SetExpiresIn(600)
				resp.SetInterval(5)
				return resp
			},
			expected: map[string]any{
				consts.CIBAResponseAuthRequestID: "auth_req_id_value",
				consts.CIBAResponseExpiresIn:     float64(600),
				consts.CIBAResponseInterval:      float64(5),
			},
			headers: http.Header{
				consts.HeaderContentType:  []string{consts.ContentTypeApplicationJSON},
				consts.HeaderCacheControl: []string{consts.CacheControlNoStore},
				consts.HeaderPragma:       []string{consts.PragmaNoCache},
			},
		},
		{
			name: "ShouldOmitIntervalWhenZero",
			setup: func() *CIBAResponse {
				resp := NewCIBAResponse()
				resp.SetAuthRequestID("auth_req_id_value")
				resp.SetExpiresIn(600)
				return resp
			},
			expected: map[string]any{
				consts.CIBAResponseAuthRequestID: "auth_req_id_value",
				consts.CIBAResponseExpiresIn:     float64(600),
			},
		},
		{
			name: "ShouldCopyCustomHeadersFromResponder",
			setup: func() *CIBAResponse {
				resp := NewCIBAResponse()
				resp.SetAuthRequestID("abc")
				resp.SetExpiresIn(600)
				resp.AddHeader("X-Custom-Header", "custom-value")
				return resp
			},
			headers: http.Header{
				"X-Custom-Header":         []string{"custom-value"},
				consts.HeaderContentType:  []string{consts.ContentTypeApplicationJSON},
				consts.HeaderCacheControl: []string{consts.CacheControlNoStore},
				consts.HeaderPragma:       []string{consts.PragmaNoCache},
			},
		},
		{
			name: "ShouldNotAllowResponderHeaderToOverrideContentType",
			setup: func() *CIBAResponse {
				resp := NewCIBAResponse()
				resp.SetAuthRequestID("abc")
				resp.SetExpiresIn(600)
				resp.AddHeader(consts.HeaderContentType, "text/plain")
				return resp
			},
			headers: http.Header{
				consts.HeaderContentType:  []string{consts.ContentTypeApplicationJSON},
				consts.HeaderCacheControl: []string{consts.CacheControlNoStore},
				consts.HeaderPragma:       []string{consts.PragmaNoCache},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			provider := &Fosite{Config: &Config{}}
			rw := httptest.NewRecorder()
			cr := &CIBARequest{}

			provider.WriteOpenIDCIBAResponse(context.Background(), rw, cr, tc.setup())

			assert.Equal(t, http.StatusOK, rw.Code)

			for key, values := range tc.headers {
				assert.Equal(t, values, rw.Header().Values(key), "header %s", key)
			}

			if tc.expected != nil {
				actual := map[string]any{}
				require.NoError(t, json.NewDecoder(rw.Body).Decode(&actual))

				for k, v := range tc.expected {
					assert.Equal(t, v, actual[k], "field %s", k)
				}
			}
		})
	}
}

func TestWriteOpenIDCIBAResponseMarshalError(t *testing.T) {
	provider := &Fosite{Config: &Config{SendDebugMessagesToClients: true}}
	rw := httptest.NewRecorder()
	cr := &CIBARequest{}

	resp := NewCIBAResponse()
	resp.SetAuthRequestID("abc")
	// A channel cannot be JSON-marshalled and triggers the fallback path.
	resp.SetExtra("bad", make(chan int))

	provider.WriteOpenIDCIBAResponse(context.Background(), rw, cr, resp)

	assert.Equal(t, http.StatusInternalServerError, rw.Code)
	assert.Contains(t, rw.Body.String(), "json: unsupported type")
}

func TestWriteOpenIDCIBAError(t *testing.T) {
	testCases := []struct {
		name       string
		err        error
		debug      bool
		statusCode int
		bodyKey    string
		bodyValue  string
	}{
		{
			name:       "ShouldWriteInvalidRequest",
			err:        ErrInvalidRequest.WithHint("Missing parameter."),
			statusCode: http.StatusBadRequest,
			bodyKey:    consts.FormParameterError,
			bodyValue:  "invalid_request",
		},
		{
			name:       "ShouldWriteInvalidClient",
			err:        ErrInvalidClient.WithHint("Bad client."),
			statusCode: http.StatusUnauthorized,
			bodyKey:    consts.FormParameterError,
			bodyValue:  "invalid_client",
		},
		{
			name:       "ShouldWriteServerErrorForUnknownErrors",
			err:        errors.New("boom"),
			statusCode: http.StatusInternalServerError,
			bodyKey:    consts.FormParameterError,
			bodyValue:  "error",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			provider := &Fosite{Config: &Config{SendDebugMessagesToClients: tc.debug}}
			rw := httptest.NewRecorder()
			cr := &CIBARequest{}

			provider.WriteOpenIDCIBAError(context.Background(), rw, cr, tc.err)

			assert.Equal(t, tc.statusCode, rw.Code)
			assert.Equal(t, consts.ContentTypeApplicationJSON, rw.Header().Get(consts.HeaderContentType))
			assert.Equal(t, consts.CacheControlNoStore, rw.Header().Get(consts.HeaderCacheControl))
			assert.Equal(t, consts.PragmaNoCache, rw.Header().Get(consts.HeaderPragma))

			body := map[string]any{}
			require.NoError(t, json.NewDecoder(rw.Body).Decode(&body))
			assert.Equal(t, tc.bodyValue, body[tc.bodyKey])
		})
	}
}
