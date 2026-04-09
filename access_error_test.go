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
	"authelia.com/provider/oauth2/testing/mock"
)

func TestWriteAccessError(t *testing.T) {
	provider := &Fosite{Config: new(Config)}
	header := http.Header{}
	ctrl := gomock.NewController(t)
	rw := mock.NewMockResponseWriter(ctrl)
	defer ctrl.Finish()

	rw.EXPECT().Header().AnyTimes().Return(header)
	rw.EXPECT().WriteHeader(http.StatusBadRequest)
	rw.EXPECT().Write(gomock.Any())

	provider.WriteAccessError(t.Context(), rw, nil, ErrInvalidRequest)
}

func TestWriteAccessError_RFC6749(t *testing.T) {
	testCases := []struct {
		name               string
		err                *RFC6749Error
		code               string
		debug              bool
		expectDebugMessage string
		includeExtraFields bool
	}{
		{"ShouldReturnInvalidRequestWithDebugAndExtraFields", ErrInvalidRequest.WithDebug("some-debug"), "invalid_request", true, "some-debug", true},
		{"ShouldReturnInvalidRequestWithDebugfAndExtraFields", ErrInvalidRequest.WithDebugf("some-debug-%d", 1234), "invalid_request", true, "some-debug-1234", true},
		{"ShouldReturnInvalidRequestWithoutDebugWithExtraFields", ErrInvalidRequest.WithDebug("some-debug"), "invalid_request", false, "some-debug", true},
		{"ShouldReturnInvalidClientWithoutDebugWithExtraFields", ErrInvalidClient.WithDebug("some-debug"), "invalid_client", false, "some-debug", true},
		{"ShouldReturnInvalidGrantWithoutDebugWithExtraFields", ErrInvalidGrant.WithDebug("some-debug"), "invalid_grant", false, "some-debug", true},
		{"ShouldReturnInvalidScopeWithoutDebugWithExtraFields", ErrInvalidScope.WithDebug("some-debug"), "invalid_scope", false, "some-debug", true},
		{"ShouldReturnUnauthorizedClientWithoutDebugWithExtraFields", ErrUnauthorizedClient.WithDebug("some-debug"), "unauthorized_client", false, "some-debug", true},
		{"ShouldReturnUnsupportedGrantTypeWithoutDebugWithExtraFields", ErrUnsupportedGrantType.WithDebug("some-debug"), "unsupported_grant_type", false, "some-debug", true},
		{"ShouldReturnUnsupportedGrantTypeWithoutDebugWithoutExtraFields", ErrUnsupportedGrantType.WithDebug("some-debug"), "unsupported_grant_type", false, "some-debug", false},
		{"ShouldReturnUnsupportedGrantTypeWithDebugWithoutExtraFields", ErrUnsupportedGrantType.WithDebug("some-debug"), "unsupported_grant_type", true, "some-debug", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := new(Config)
			provider := &Fosite{Config: config}
			config.SendDebugMessagesToClients = tc.debug
			config.UseLegacyErrorFormat = tc.includeExtraFields

			rw := httptest.NewRecorder()
			provider.WriteAccessError(t.Context(), rw, nil, tc.err)

			var params struct {
				Error       string `json:"error"`             // specified by RFC, required
				Description string `json:"error_description"` // specified by RFC, optional
				Debug       string `json:"error_debug"`
				Hint        string `json:"error_hint"`
			}

			require.NotNil(t, rw.Body)
			err := json.NewDecoder(rw.Body).Decode(&params)
			require.NoError(t, err)

			assert.Equal(t, tc.code, params.Error)
			if !tc.includeExtraFields {
				assert.Empty(t, params.Debug)
				assert.Empty(t, params.Hint)
				assert.Contains(t, params.Description, tc.err.DescriptionField)
				assert.Contains(t, params.Description, tc.err.HintField)

				if tc.debug {
					assert.Contains(t, params.Description, tc.err.DebugField)
				} else {
					assert.NotContains(t, params.Description, tc.err.DebugField)
				}
			} else {
				assert.EqualValues(t, tc.err.DescriptionField, params.Description)
				assert.EqualValues(t, tc.err.HintField, params.Hint)

				if !tc.debug {
					assert.Empty(t, params.Debug)
				} else {
					assert.EqualValues(t, tc.err.DebugField, params.Debug)
				}
			}
		})
	}
}
