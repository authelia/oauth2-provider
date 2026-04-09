// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	. "authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/testing/mock"
)

func TestNewAccessResponse(t *testing.T) {
	testCases := []struct {
		name         string
		emptyHandler bool
		mock         func(handler *mock.MockTokenEndpointHandler)
		err          string
		expect       AccessResponder
	}{
		{
			name:         "ShouldFailNoHandlers",
			emptyHandler: true,
			mock:         func(handler *mock.MockTokenEndpointHandler) {},
			err:          "The authorization server encountered an unexpected condition that prevented it from fulfilling the request. An internal server occurred while trying to complete the request. Access token or token type not set by TokenEndpointHandlers.",
		},
		{
			name: "ShouldFailHandlerReturnsError",
			mock: func(handler *mock.MockTokenEndpointHandler) {
				handler.EXPECT().PopulateTokenEndpointResponse(gomock.Any(), gomock.Any(), gomock.Any()).Return(ErrServerError)
			},
			err: "The authorization server encountered an unexpected condition that prevented it from fulfilling the request.",
		},
		{
			name: "ShouldFailHandlerSetsNoToken",
			mock: func(handler *mock.MockTokenEndpointHandler) {
				handler.EXPECT().PopulateTokenEndpointResponse(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
			},
			err: "The authorization server encountered an unexpected condition that prevented it from fulfilling the request. An internal server occurred while trying to complete the request. Access token or token type not set by TokenEndpointHandlers.",
		},
		{
			name: "ShouldFailHandlerSetsOnlyAccessToken",
			mock: func(handler *mock.MockTokenEndpointHandler) {
				handler.EXPECT().PopulateTokenEndpointResponse(gomock.Any(), gomock.Any(), gomock.Any()).Do(func(_ context.Context, _ AccessRequester, responder AccessResponder) {
					responder.SetAccessToken("foo")
				}).Return(nil)
			},
			err: "The authorization server encountered an unexpected condition that prevented it from fulfilling the request. An internal server occurred while trying to complete the request. Access token or token type not set by TokenEndpointHandlers.",
		},
		{
			name: "ShouldPass",
			mock: func(handler *mock.MockTokenEndpointHandler) {
				handler.EXPECT().PopulateTokenEndpointResponse(gomock.Any(), gomock.Any(), gomock.Any()).Do(func(_ context.Context, _ AccessRequester, responder AccessResponder) {
					responder.SetAccessToken("foo")
					responder.SetTokenType("bar")
				}).Return(nil)
			},
			expect: &AccessResponse{
				Extra:       map[string]any{},
				AccessToken: "foo",
				TokenType:   "bar",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			handler := mock.NewMockTokenEndpointHandler(ctrl)

			config := &Config{}
			if tc.emptyHandler {
				config.TokenEndpointHandlers = TokenEndpointHandlers{}
			} else {
				config.TokenEndpointHandlers = TokenEndpointHandlers{handler}
			}
			provider := &Fosite{Config: config}

			tc.mock(handler)
			ar, err := provider.NewAccessResponse(t.Context(), nil)

			if tc.err != "" {
				assert.EqualError(t, ErrorToDebugRFC6749Error(err), tc.err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, ar, tc.expect)
			}
		})
	}
}
