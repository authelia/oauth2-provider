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
	"go.uber.org/mock/gomock"

	. "authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/testing/mock"
	"authelia.com/provider/oauth2/x/errorsx"
)

func TestNewPushedAuthorizeResponse(t *testing.T) {
	handlerErr := errors.New("handler failed")

	testCases := []struct {
		name     string
		mock     func(handler *mock.MockPushedAuthorizeEndpointHandler, ar *mock.MockAuthorizeRequester)
		expected string
	}{
		{
			name: "ShouldFailWhenHandlerReturnsError",
			mock: func(handler *mock.MockPushedAuthorizeEndpointHandler, ar *mock.MockAuthorizeRequester) {
				ar.EXPECT().SetSession(gomock.Eq(new(DefaultSession)))
				handler.EXPECT().HandlePushedAuthorizeEndpointRequest(gomock.Any(), gomock.Eq(ar), gomock.Any()).Return(handlerErr)
			},
			expected: "handler failed",
		},
		{
			name: "ShouldFailWhenHandlerReturnsRFC6749Error",
			mock: func(handler *mock.MockPushedAuthorizeEndpointHandler, ar *mock.MockAuthorizeRequester) {
				ar.EXPECT().SetSession(gomock.Eq(new(DefaultSession)))
				handler.EXPECT().HandlePushedAuthorizeEndpointRequest(gomock.Any(), gomock.Eq(ar), gomock.Any()).Return(errorsx.WithStack(ErrInvalidRequest.WithHint("PAR request was invalid.")))
			},
			expected: "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. PAR request was invalid.",
		},
		{
			name: "ShouldStopAtFirstHandlerError",
			mock: func(handler *mock.MockPushedAuthorizeEndpointHandler, ar *mock.MockAuthorizeRequester) {
				ar.EXPECT().SetSession(gomock.Eq(new(DefaultSession)))
				handler.EXPECT().HandlePushedAuthorizeEndpointRequest(gomock.Any(), gomock.Eq(ar), gomock.Any()).Return(handlerErr)
			},
			expected: "handler failed",
		},
		{
			name: "ShouldPassWhenHandlerSucceeds",
			mock: func(handler *mock.MockPushedAuthorizeEndpointHandler, ar *mock.MockAuthorizeRequester) {
				ar.EXPECT().SetSession(gomock.Eq(new(DefaultSession)))
				handler.EXPECT().HandlePushedAuthorizeEndpointRequest(gomock.Any(), gomock.Eq(ar), gomock.Any()).Return(nil)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			handler := mock.NewMockPushedAuthorizeEndpointHandler(ctrl)
			ar := mock.NewMockAuthorizeRequester(ctrl)

			provider := &Fosite{
				Config: &Config{
					PushedAuthorizeEndpointHandlers: PushedAuthorizeEndpointHandlers{handler},
				},
			}

			tc.mock(handler, ar)

			responder, err := provider.NewPushedAuthorizeResponse(context.Background(), ar, new(DefaultSession))

			if tc.expected != "" {
				assert.Nil(t, responder)
				assert.EqualError(t, ErrorToDebugRFC6749Error(err), tc.expected)

				return
			}

			require.NoError(t, ErrorToDebugRFC6749Error(err))
			require.NotNil(t, responder)
			assert.NotNil(t, responder.GetHeader())
		})
	}
}

func TestWritePushedAuthorizeResponse(t *testing.T) {
	testCases := []struct {
		name      string
		responder PushedAuthorizeResponder
		expected  map[string]any
		headers   http.Header
	}{
		{
			name: "ShouldWriteResponseWithRequestURIAndExpiresIn",
			responder: &PushedAuthorizeResponse{
				RequestURI: "urn:ietf:params:oauth:request_uri:abc123",
				ExpiresIn:  60,
				Header:     http.Header{},
				Extra:      map[string]any{},
			},
			expected: map[string]any{
				consts.FormParameterRequestURI: "urn:ietf:params:oauth:request_uri:abc123",
				consts.AccessResponseExpiresIn: float64(60),
			},
			headers: http.Header{
				consts.HeaderContentType:  []string{consts.ContentTypeApplicationJSON},
				consts.HeaderCacheControl: []string{consts.CacheControlNoStore},
				consts.HeaderPragma:       []string{consts.PragmaNoCache},
			},
		},
		{
			name: "ShouldIncludeExtraFieldsInResponse",
			responder: &PushedAuthorizeResponse{
				RequestURI: "urn:ietf:params:oauth:request_uri:xyz",
				ExpiresIn:  120,
				Header:     http.Header{},
				Extra: map[string]any{
					"custom_field": "custom_value",
				},
			},
			expected: map[string]any{
				consts.FormParameterRequestURI: "urn:ietf:params:oauth:request_uri:xyz",
				consts.AccessResponseExpiresIn: float64(120),
				"custom_field":                 "custom_value",
			},
			headers: http.Header{
				consts.HeaderContentType:  []string{consts.ContentTypeApplicationJSON},
				consts.HeaderCacheControl: []string{consts.CacheControlNoStore},
				consts.HeaderPragma:       []string{consts.PragmaNoCache},
			},
		},
		{
			name: "ShouldCopyCustomHeadersFromResponder",
			responder: &PushedAuthorizeResponse{
				RequestURI: "urn:ietf:params:oauth:request_uri:custom",
				ExpiresIn:  90,
				Header: http.Header{
					"X-Custom-Header": []string{"custom-value"},
				},
				Extra: map[string]any{},
			},
			expected: map[string]any{
				consts.FormParameterRequestURI: "urn:ietf:params:oauth:request_uri:custom",
				consts.AccessResponseExpiresIn: float64(90),
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
			responder: &PushedAuthorizeResponse{
				RequestURI: "urn:ietf:params:oauth:request_uri:abc",
				ExpiresIn:  30,
				Header: http.Header{
					consts.HeaderContentType: []string{"text/plain"},
				},
				Extra: map[string]any{},
			},
			expected: map[string]any{
				consts.FormParameterRequestURI: "urn:ietf:params:oauth:request_uri:abc",
				consts.AccessResponseExpiresIn: float64(30),
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
			provider := &Fosite{Config: new(Config)}
			rw := httptest.NewRecorder()

			provider.WritePushedAuthorizeResponse(context.Background(), rw, nil, tc.responder)

			assert.Equal(t, http.StatusCreated, rw.Code)
			assert.Equal(t, tc.headers, rw.Header())

			actual := map[string]any{}
			require.NoError(t, json.NewDecoder(rw.Body).Decode(&actual))
			assert.Equal(t, tc.expected, actual)
		})
	}
}

func TestWritePushedAuthorizeResponseMarshalError(t *testing.T) {
	testCases := []struct {
		name      string
		responder PushedAuthorizeResponder
	}{
		{
			name: "ShouldRespondInternalServerErrorWhenToMapNotMarshalable",
			responder: &PushedAuthorizeResponse{
				RequestURI: "urn:ietf:params:oauth:request_uri:abc",
				ExpiresIn:  60,
				Header:     http.Header{},
				Extra: map[string]any{
					// channels cannot be marshaled to JSON
					"bad": make(chan int),
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			provider := &Fosite{Config: new(Config)}
			rw := httptest.NewRecorder()

			provider.WritePushedAuthorizeResponse(context.Background(), rw, nil, tc.responder)

			assert.Equal(t, http.StatusInternalServerError, rw.Code)
			assert.Contains(t, rw.Body.String(), "json: unsupported type")
		})
	}
}

func TestWritePushedAuthorizeError(t *testing.T) {
	testCases := []struct {
		name     string
		err      error
		debug    bool
		legacy   bool
		expected string
		code     int
		body     string
	}{
		{
			name:     "ShouldWriteInvalidRequestError",
			err:      errorsx.WithStack(ErrInvalidRequest),
			expected: "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Make sure that the various parameters are correct, be aware of case sensitivity and trim your parameters. Make sure that the client you are using has exactly whitelisted the redirect_uri you specified.",
			code:     http.StatusBadRequest,
			body:     `{"error":"invalid_request","error_description":"The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Make sure that the various parameters are correct, be aware of case sensitivity and trim your parameters. Make sure that the client you are using has exactly whitelisted the redirect_uri you specified."}`,
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
		{
			name:     "ShouldExposeDebugDetailsWhenEnabled",
			err:      errorsx.WithStack(ErrInvalidRequest.WithDebug("debug detail")),
			debug:    true,
			expected: "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Make sure that the various parameters are correct, be aware of case sensitivity and trim your parameters. Make sure that the client you are using has exactly whitelisted the redirect_uri you specified. debug detail",
			code:     http.StatusBadRequest,
			body:     `{"error":"invalid_request","error_description":"The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Make sure that the various parameters are correct, be aware of case sensitivity and trim your parameters. Make sure that the client you are using has exactly whitelisted the redirect_uri you specified. debug detail"}`,
		},
		{
			name:     "ShouldEmitLegacyFormatWhenEnabled",
			err:      errorsx.WithStack(ErrInvalidRequest),
			legacy:   true,
			expected: "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Make sure that the various parameters are correct, be aware of case sensitivity and trim your parameters. Make sure that the client you are using has exactly whitelisted the redirect_uri you specified.",
			code:     http.StatusBadRequest,
			body:     `{"error":"invalid_request","error_description":"The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed.","error_hint":"Make sure that the various parameters are correct, be aware of case sensitivity and trim your parameters. Make sure that the client you are using has exactly whitelisted the redirect_uri you specified.","status_code":400}`,
		},
		{
			name:     "ShouldEmitLegacyFormatWithDebugWhenEnabled",
			err:      errorsx.WithStack(ErrInvalidRequest.WithDebug("debug detail")),
			legacy:   true,
			debug:    true,
			expected: "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Make sure that the various parameters are correct, be aware of case sensitivity and trim your parameters. Make sure that the client you are using has exactly whitelisted the redirect_uri you specified. debug detail",
			code:     http.StatusBadRequest,
			body:     `{"error":"invalid_request","error_description":"The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed.","error_hint":"Make sure that the various parameters are correct, be aware of case sensitivity and trim your parameters. Make sure that the client you are using has exactly whitelisted the redirect_uri you specified.","error_debug":"debug detail","status_code":400}`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			provider := &Fosite{Config: &Config{
				SendDebugMessagesToClients: tc.debug,
				UseLegacyErrorFormat:       tc.legacy,
			}}

			rw := httptest.NewRecorder()
			provider.WritePushedAuthorizeError(context.Background(), rw, nil, tc.err)

			assert.EqualError(t, ErrorToDebugRFC6749Error(tc.err), tc.expected)
			assert.Equal(t, tc.code, rw.Code)
			assert.JSONEq(t, tc.body, rw.Body.String())
			assert.Equal(t, consts.ContentTypeApplicationJSON, rw.Header().Get(consts.HeaderContentType))
			assert.Equal(t, consts.CacheControlNoStore, rw.Header().Get(consts.HeaderCacheControl))
			assert.Equal(t, consts.PragmaNoCache, rw.Header().Get(consts.HeaderPragma))
		})
	}
}
