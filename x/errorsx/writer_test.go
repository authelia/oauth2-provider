// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package errorsx_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2/x/errorsx"
)

func TestWriteJSONError(t *testing.T) {
	testCases := []struct {
		name         string
		have         error
		expectedCode int
		expectedBody string
	}{
		{
			name:         "ShouldUseStatusCodeFromStatusCodeCarrier",
			have:         &rfc6750Error{ErrorField: "invalid_token", DescriptionField: "The access token expired.", CodeField: http.StatusUnauthorized},
			expectedCode: http.StatusUnauthorized,
			expectedBody: "{\"error\":\"invalid_token\",\"error_description\":\"The access token expired.\"}\n",
		},
		{
			name:         "ShouldDefaultToInternalServerErrorWhenErrorHasNoStatusCode",
			have:         errPlain("something failed"),
			expectedCode: http.StatusInternalServerError,
			expectedBody: "\"something failed\"\n",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, "/", nil)

			errorsx.WriteJSONError(w, r, tc.have)

			assert.Equal(t, tc.expectedCode, w.Code)
			assert.Equal(t, "application/json; charset=utf-8", w.Header().Get("Content-Type"))
			assert.Equal(t, tc.expectedBody, w.Body.String())
		})
	}
}

func TestWriteJSONErrorCode(t *testing.T) {
	testCases := []struct {
		name         string
		code         int
		canceled     bool
		have         error
		expectedCode int
		expectedBody string
	}{
		{
			name:         "ShouldWriteProvidedStatusCode",
			code:         http.StatusBadRequest,
			have:         errPlain("bad request"),
			expectedCode: http.StatusBadRequest,
			expectedBody: "\"bad request\"\n",
		},
		{
			name:         "ShouldDefaultToInternalServerErrorWhenCodeIsZero",
			code:         0,
			have:         errPlain("no code"),
			expectedCode: http.StatusInternalServerError,
			expectedBody: "\"no code\"\n",
		},
		{
			name:         "ShouldOverrideStatusCodeWith499WhenRequestContextCanceled",
			code:         http.StatusBadRequest,
			canceled:     true,
			have:         errPlain("client gone"),
			expectedCode: 499,
			expectedBody: "\"client gone\"\n",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, "/", nil)

			if tc.canceled {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()

				r = r.WithContext(ctx)
			}

			errorsx.WriteJSONErrorCode(w, r, tc.code, tc.have)

			assert.Equal(t, tc.expectedCode, w.Code)
			assert.Equal(t, "application/json; charset=utf-8", w.Header().Get("Content-Type"))
			assert.Equal(t, tc.expectedBody, w.Body.String())
		})
	}
}

func TestEncodeRFC6750(t *testing.T) {
	testCases := []struct {
		name     string
		have     errorsx.Fields
		expected string
	}{
		{
			name:     "ShouldReturnBearerPrefixOnlyWhenEmpty",
			have:     errorsx.Fields{},
			expected: "Bearer ",
		},
		{
			name:     "ShouldEncodeSingleField",
			have:     errorsx.Fields{"error": "invalid_token"},
			expected: `Bearer error="invalid_token"`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.have.EncodeRFC6750())
		})
	}
}

func TestWriteRFC6750Error(t *testing.T) {
	testCases := []struct {
		name           string
		have           any
		extra          errorsx.Fields
		expectedCode   int
		expectedHeader errorsx.Fields
		expectedBody   string
	}{
		{
			name:           "ShouldEncodeRFCErrorWithAllFields",
			have:           &rfc6750Error{ErrorField: "invalid_token", DescriptionField: "The access token expired.", ReasonField: "token expired", CodeField: http.StatusUnauthorized},
			expectedCode:   http.StatusUnauthorized,
			expectedHeader: errorsx.Fields{"error": "invalid_token", "error_description": "The access token expired.", "error_hint": "token expired"},
			expectedBody:   "{\"error\":\"invalid_token\",\"error_description\":\"The access token expired.\"}\n",
		},
		{
			name:           "ShouldOmitEmptyRFCErrorFields",
			have:           &rfc6750Error{ErrorField: "invalid_token", CodeField: http.StatusForbidden},
			expectedCode:   http.StatusForbidden,
			expectedHeader: errorsx.Fields{"error": "invalid_token"},
			expectedBody:   "{\"error\":\"invalid_token\"}\n",
		},
		{
			name:           "ShouldClampStatusCodeBelowBadRequestToBadRequest",
			have:           &rfc6750Error{ErrorField: "invalid_token", CodeField: http.StatusOK},
			expectedCode:   http.StatusBadRequest,
			expectedHeader: errorsx.Fields{"error": "invalid_token"},
			expectedBody:   "{\"error\":\"invalid_token\"}\n",
		},
		{
			name:           "ShouldClampStatusCodeAboveForbiddenToBadRequest",
			have:           &rfc6750Error{ErrorField: "server_error", CodeField: http.StatusInternalServerError},
			expectedCode:   http.StatusBadRequest,
			expectedHeader: errorsx.Fields{"error": "server_error"},
			expectedBody:   "{\"error\":\"server_error\"}\n",
		},
		{
			name:           "ShouldEncodePlainErrorAsErrorField",
			have:           errPlain("plain failure"),
			expectedCode:   http.StatusBadRequest,
			expectedHeader: errorsx.Fields{"error": "plain failure"},
			expectedBody:   "\"plain failure\"\n",
		},
		{
			name:           "ShouldEncodeFieldsFromMapWithStatusCode",
			have:           map[string]any{"status_code": http.StatusForbidden, "error": "invalid_request", "error_description": "The request is missing a token."},
			expectedCode:   http.StatusForbidden,
			expectedHeader: errorsx.Fields{"error": "invalid_request", "error_description": "The request is missing a token."},
			expectedBody:   "{}\n",
		},
		{
			name:           "ShouldDeriveErrorFromMapErrorFieldWhenNoDescription",
			have:           map[string]any{"error": "invalid_request"},
			expectedCode:   http.StatusBadRequest,
			expectedHeader: errorsx.Fields{"error": "invalid_request"},
			expectedBody:   "{}\n",
		},
		{
			name:           "ShouldUseErrorValueFromMapField",
			have:           map[string]any{"error_description": errPlain("typed map error")},
			expectedCode:   http.StatusBadRequest,
			expectedHeader: errorsx.Fields{"error_description": "typed map error"},
			expectedBody:   "\"typed map error\"\n",
		},
		{
			name:           "ShouldNotOverrideErrorOnceDerivedFromMapField",
			have:           map[string]any{"error": errPlain("conflict"), "error_description": errPlain("conflict")},
			expectedCode:   http.StatusBadRequest,
			expectedHeader: errorsx.Fields{"error": "conflict", "error_description": "conflict"},
			expectedBody:   "\"conflict\"\n",
		},
		{
			name:           "ShouldNotWriteBodyWhenErrorIsNil",
			have:           nil,
			expectedCode:   http.StatusBadRequest,
			expectedHeader: errorsx.Fields{},
			expectedBody:   "",
		},
		{
			name:           "ShouldWriteInvalidRequestForUnsupportedType",
			have:           "an unexpected value",
			expectedCode:   http.StatusBadRequest,
			expectedHeader: errorsx.Fields{"error": "invalid_request", "error_description": "an unexpected value"},
			expectedBody:   "{}\n",
		},
		{
			name:           "ShouldMergeExtraFieldsWithoutOverridingExisting",
			have:           &rfc6750Error{ErrorField: "invalid_token", CodeField: http.StatusUnauthorized},
			extra:          errorsx.Fields{"error": "SHOULD_NOT_OVERRIDE", "scope": "profile email"},
			expectedCode:   http.StatusUnauthorized,
			expectedHeader: errorsx.Fields{"error": "invalid_token", "scope": "profile email"},
			expectedBody:   "{\"error\":\"invalid_token\"}\n",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()

			errorsx.WriteRFC6750Error(w, tc.have, tc.extra)

			assert.Equal(t, tc.expectedCode, w.Code)
			assert.Equal(t, "application/json; charset=utf-8", w.Header().Get("Content-Type"))
			assert.Equal(t, tc.expectedHeader, decodeRFC6750Header(t, w.Header().Get("WWW-Authenticate")))
			assert.Equal(t, tc.expectedBody, w.Body.String())
		})
	}
}

// decodeRFC6750Header parses a 'Bearer key="value", ...' header into its fields so the
// result can be compared independently of the non-deterministic map iteration order.
func decodeRFC6750Header(t *testing.T, header string) errorsx.Fields {
	t.Helper()

	fields := errorsx.Fields{}

	rest, ok := strings.CutPrefix(header, "Bearer ")
	require.True(t, ok, "header %q must start with 'Bearer '", header)

	if rest == "" {
		return fields
	}

	for item := range strings.SplitSeq(rest, ", ") {
		key, value, found := strings.Cut(item, "=")
		require.True(t, found, "malformed field %q", item)

		fields[key] = strings.Trim(value, `"`)
	}

	return fields
}

// rfc6750Error is a test error implementing the errorsx.RFCError and StatusCodeCarrier
// interfaces so it can drive both the RFC6750 and JSON writer branches.
type rfc6750Error struct {
	ErrorField       string `json:"error,omitempty"`
	DescriptionField string `json:"error_description,omitempty"`
	ReasonField      string `json:"-"`
	CodeField        int    `json:"-"`
}

func (e *rfc6750Error) Error() string          { return e.ErrorField }
func (e *rfc6750Error) GetDescription() string { return e.DescriptionField }
func (e *rfc6750Error) Reason() string         { return e.ReasonField }
func (e *rfc6750Error) StatusCode() int        { return e.CodeField }
