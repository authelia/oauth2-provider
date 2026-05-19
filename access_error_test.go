// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	. "authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/testing/mock"
)

func TestWriteAccessError(t *testing.T) {
	testCases := []struct {
		name      string
		err       error
		requester AccessRequester
		code      int
	}{
		{
			name:      "ShouldWriteInvalidRequest",
			err:       ErrInvalidRequest,
			requester: nil,
			code:      http.StatusBadRequest,
		},
		{
			name:      "ShouldWriteServerError",
			err:       ErrServerError,
			requester: nil,
			code:      http.StatusInternalServerError,
		},
		{
			name: "ShouldUseRequesterForLocalization",
			err:  ErrInvalidRequest,
			requester: func() AccessRequester {
				ar := NewAccessRequest(new(DefaultSession))
				return ar
			}(),
			code: http.StatusBadRequest,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			header := http.Header{}
			rw := mock.NewMockResponseWriter(ctrl)
			rw.EXPECT().Header().AnyTimes().Return(header)
			rw.EXPECT().WriteHeader(tc.code)
			rw.EXPECT().Write(gomock.Any())

			provider := &Fosite{Config: new(Config)}
			provider.WriteAccessError(t.Context(), rw, tc.requester, tc.err)

			assert.Equal(t, consts.ContentTypeApplicationJSON, header.Get(consts.HeaderContentType))
			assert.Equal(t, consts.CacheControlNoStore, header.Get(consts.HeaderCacheControl))
			assert.Equal(t, consts.PragmaNoCache, header.Get(consts.HeaderPragma))
		})
	}
}

func TestWriteAccessErrorRFC6749(t *testing.T) {
	testCases := []struct {
		name          string
		err           *RFC6749Error
		code          string
		debug         bool
		expectedDebug string
		legacyFormat  bool
	}{
		{
			name:          "ShouldReturnInvalidRequestWithDebugAndExtraFields",
			err:           ErrInvalidRequest.WithDebug("some-debug"),
			code:          "invalid_request",
			debug:         true,
			expectedDebug: "some-debug",
			legacyFormat:  true,
		},
		{
			name:          "ShouldReturnInvalidRequestWithDebugfAndExtraFields",
			err:           ErrInvalidRequest.WithDebugf("some-debug-%d", 1234),
			code:          "invalid_request",
			debug:         true,
			expectedDebug: "some-debug-1234",
			legacyFormat:  true,
		},
		{
			name:          "ShouldReturnInvalidRequestWithoutDebugWithExtraFields",
			err:           ErrInvalidRequest.WithDebug("some-debug"),
			code:          "invalid_request",
			debug:         false,
			expectedDebug: "some-debug",
			legacyFormat:  true,
		},
		{
			name:          "ShouldReturnInvalidClientWithoutDebugWithExtraFields",
			err:           ErrInvalidClient.WithDebug("some-debug"),
			code:          "invalid_client",
			debug:         false,
			expectedDebug: "some-debug",
			legacyFormat:  true,
		},
		{
			name:          "ShouldReturnInvalidGrantWithoutDebugWithExtraFields",
			err:           ErrInvalidGrant.WithDebug("some-debug"),
			code:          "invalid_grant",
			debug:         false,
			expectedDebug: "some-debug",
			legacyFormat:  true,
		},
		{
			name:          "ShouldReturnInvalidScopeWithoutDebugWithExtraFields",
			err:           ErrInvalidScope.WithDebug("some-debug"),
			code:          "invalid_scope",
			debug:         false,
			expectedDebug: "some-debug",
			legacyFormat:  true,
		},
		{
			name:          "ShouldReturnUnauthorizedClientWithoutDebugWithExtraFields",
			err:           ErrUnauthorizedClient.WithDebug("some-debug"),
			code:          "unauthorized_client",
			debug:         false,
			expectedDebug: "some-debug",
			legacyFormat:  true,
		},
		{
			name:          "ShouldReturnUnsupportedGrantTypeWithoutDebugWithExtraFields",
			err:           ErrUnsupportedGrantType.WithDebug("some-debug"),
			code:          "unsupported_grant_type",
			debug:         false,
			expectedDebug: "some-debug",
			legacyFormat:  true,
		},
		{
			name:          "ShouldReturnUnsupportedGrantTypeWithoutDebugWithoutExtraFields",
			err:           ErrUnsupportedGrantType.WithDebug("some-debug"),
			code:          "unsupported_grant_type",
			debug:         false,
			expectedDebug: "some-debug",
			legacyFormat:  false,
		},
		{
			name:          "ShouldReturnUnsupportedGrantTypeWithDebugWithoutExtraFields",
			err:           ErrUnsupportedGrantType.WithDebug("some-debug"),
			code:          "unsupported_grant_type",
			debug:         true,
			expectedDebug: "some-debug",
			legacyFormat:  false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			provider := &Fosite{Config: &Config{
				SendDebugMessagesToClients: tc.debug,
				UseLegacyErrorFormat:       tc.legacyFormat,
			}}

			rw := httptest.NewRecorder()
			provider.WriteAccessError(t.Context(), rw, nil, tc.err)

			var actual struct {
				Error       string `json:"error"`
				Description string `json:"error_description"`
				Debug       string `json:"error_debug"`
				Hint        string `json:"error_hint"`
			}

			require.NotNil(t, rw.Body)
			require.NoError(t, json.NewDecoder(rw.Body).Decode(&actual))

			assert.Equal(t, tc.code, actual.Error)

			if !tc.legacyFormat {
				assert.Empty(t, actual.Debug)
				assert.Empty(t, actual.Hint)
				assert.Contains(t, actual.Description, tc.err.DescriptionField)
				assert.Contains(t, actual.Description, tc.err.HintField)

				if tc.debug {
					assert.Contains(t, actual.Description, tc.err.DebugField)
				} else {
					assert.NotContains(t, actual.Description, tc.err.DebugField)
				}

				return
			}

			assert.EqualValues(t, tc.err.DescriptionField, actual.Description)
			assert.EqualValues(t, tc.err.HintField, actual.Hint)

			if !tc.debug {
				assert.Empty(t, actual.Debug)
				return
			}

			assert.EqualValues(t, tc.err.DebugField, actual.Debug)
		})
	}
}
