// Copyright © 2026 Authelia
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
	"authelia.com/provider/oauth2/x/errorsx"
)

func TestFosite_WriteRFC8628UserAuthorizeResponse(t *testing.T) {
	testCases := []struct {
		name     string
		setup    func() *RFC8628UserAuthorizeResponse
		expected map[string]any
		headers  http.Header
	}{
		{
			name: "ShouldWriteResponseWithStatus",
			setup: func() *RFC8628UserAuthorizeResponse {
				responder := NewRFC8628UserAuthorizeResponse()
				responder.SetStatus(DeviceAuthorizeStatusToString(DeviceAuthorizeStatusApproved))
				return responder
			},
			expected: map[string]any{
				consts.DeviceCodeResponseStatus: DeviceAuthorizeStatusToString(DeviceAuthorizeStatusApproved),
			},
			headers: http.Header{
				consts.HeaderContentType:  []string{consts.ContentTypeApplicationJSON},
				consts.HeaderCacheControl: []string{consts.CacheControlNoStore},
				consts.HeaderPragma:       []string{consts.PragmaNoCache},
			},
		},
		{
			name: "ShouldCopyCustomHeadersFromResponder",
			setup: func() *RFC8628UserAuthorizeResponse {
				responder := NewRFC8628UserAuthorizeResponse()
				responder.SetStatus(DeviceAuthorizeStatusToString(DeviceAuthorizeStatusDenied))
				responder.AddHeader("X-Custom-Header", "custom-value")
				return responder
			},
			expected: map[string]any{
				consts.DeviceCodeResponseStatus: DeviceAuthorizeStatusToString(DeviceAuthorizeStatusDenied),
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
			setup: func() *RFC8628UserAuthorizeResponse {
				responder := NewRFC8628UserAuthorizeResponse()
				responder.SetStatus(DeviceAuthorizeStatusToString(DeviceAuthorizeStatusNew))
				responder.AddHeader(consts.HeaderContentType, "text/plain")
				return responder
			},
			expected: map[string]any{
				consts.DeviceCodeResponseStatus: DeviceAuthorizeStatusToString(DeviceAuthorizeStatusNew),
			},
			headers: http.Header{
				consts.HeaderContentType:  []string{consts.ContentTypeApplicationJSON},
				consts.HeaderCacheControl: []string{consts.CacheControlNoStore},
				consts.HeaderPragma:       []string{consts.PragmaNoCache},
			},
		},
		{
			name: "ShouldIncludeExtraClaimsInResponse",
			setup: func() *RFC8628UserAuthorizeResponse {
				responder := NewRFC8628UserAuthorizeResponse()
				responder.SetStatus(DeviceAuthorizeStatusToString(DeviceAuthorizeStatusApproved))
				responder.SetExtra("custom_field", "custom_value")
				return responder
			},
			expected: map[string]any{
				consts.DeviceCodeResponseStatus: DeviceAuthorizeStatusToString(DeviceAuthorizeStatusApproved),
				"custom_field":                  "custom_value",
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
			requester := &DeviceAuthorizeRequest{}

			provider.WriteRFC8628UserAuthorizeResponse(context.Background(), rw, requester, tc.setup())

			assert.Equal(t, http.StatusOK, rw.Code)
			assert.Equal(t, tc.headers, rw.Header())

			actual := map[string]any{}
			require.NoError(t, json.NewDecoder(rw.Body).Decode(&actual))
			assert.Equal(t, tc.expected, actual)
		})
	}
}

func TestFosite_WriteRFC8628UserAuthorizeResponseMarshalError(t *testing.T) {
	testCases := []struct {
		name     string
		setup    func() *RFC8628UserAuthorizeResponse
		contains string
	}{
		{
			name: "ShouldRespondInternalServerErrorWhenToMapNotMarshalable",
			setup: func() *RFC8628UserAuthorizeResponse {
				responder := NewRFC8628UserAuthorizeResponse()
				// channels cannot be marshaled to JSON
				responder.SetExtra("bad", make(chan int))
				return responder
			},
			contains: "json: unsupported type",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			provider := &Fosite{Config: &Config{}}
			rw := httptest.NewRecorder()
			requester := &DeviceAuthorizeRequest{}

			provider.WriteRFC8628UserAuthorizeResponse(context.Background(), rw, requester, tc.setup())

			assert.Equal(t, http.StatusInternalServerError, rw.Code)
			assert.Contains(t, rw.Body.String(), tc.contains)
		})
	}
}

func TestFosite_WriteRFC8628UserAuthorizeError(t *testing.T) {
	testCases := []struct {
		name     string
		err      error
		debug    bool
		expected string
		code     int
		body     string
	}{
		{
			name:     "ShouldWriteInvalidGrantError",
			err:      ErrInvalidGrant.WithDescription("invalid grant message."),
			expected: "invalid grant message.",
			code:     http.StatusBadRequest,
			body:     `{"error":"invalid_grant","error_description":"invalid grant message."}`,
		},
		{
			name:     "ShouldWriteInvalidRequestError",
			err:      errorsx.WithStack(ErrInvalidRequest),
			expected: "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Make sure that the various parameters are correct, be aware of case sensitivity and trim your parameters. Make sure that the client you are using has exactly whitelisted the redirect_uri you specified.",
			code:     http.StatusBadRequest,
			body:     `{"error":"invalid_request","error_description":"The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Make sure that the various parameters are correct, be aware of case sensitivity and trim your parameters. Make sure that the client you are using has exactly whitelisted the redirect_uri you specified."}`,
		},
		{
			name:     "ShouldExposeDebugDetailsWhenEnabled",
			err:      errorsx.WithStack(ErrInvalidRequest.WithDebug("debug detail")),
			debug:    true,
			expected: "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Make sure that the various parameters are correct, be aware of case sensitivity and trim your parameters. Make sure that the client you are using has exactly whitelisted the redirect_uri you specified. debug detail",
			code:     http.StatusBadRequest,
			body:     `{"error":"invalid_request","error_description":"The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Make sure that the various parameters are correct, be aware of case sensitivity and trim your parameters. Make sure that the client you are using has exactly whitelisted the redirect_uri you specified. debug detail"}`,
		},
		{
			name:     "ShouldWriteUnrecognizedErrorWithoutDebug",
			err:      errors.New("some other error"),
			expected: "some other error",
			code:     http.StatusInternalServerError,
			body:     `{"error":"error","error_description":"The error is unrecognizable"}`,
		},
		{
			name:     "ShouldWriteUnrecognizedErrorWithDebug",
			err:      errors.New("some other error"),
			debug:    true,
			expected: "some other error",
			code:     http.StatusInternalServerError,
			body:     `{"error":"error","error_description":"The error is unrecognizable some other error"}`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			provider := &Fosite{Config: &Config{
				SendDebugMessagesToClients: tc.debug,
			}}

			rw := httptest.NewRecorder()
			requester := &DeviceAuthorizeRequest{}

			provider.WriteRFC8628UserAuthorizeError(context.Background(), rw, requester, tc.err)

			assert.EqualError(t, ErrorToDebugRFC6749Error(tc.err), tc.expected)
			assert.Equal(t, tc.code, rw.Code)
			assert.JSONEq(t, tc.body, rw.Body.String())
			assert.Equal(t, consts.ContentTypeApplicationJSON, rw.Header().Get(consts.HeaderContentType))
			assert.Equal(t, consts.CacheControlNoStore, rw.Header().Get(consts.HeaderCacheControl))
			assert.Equal(t, consts.PragmaNoCache, rw.Header().Get(consts.HeaderPragma))
		})
	}
}
