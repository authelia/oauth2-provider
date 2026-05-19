// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"context"
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	. "authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/testing/mock"
	"authelia.com/provider/oauth2/x/errorsx"
)

func TestFosite_NewRFC8628UserAuthorizeResponse(t *testing.T) {
	handlerErr := errors.New("handler failed")

	testCases := []struct {
		name     string
		handlers int
		mock     func(handlers []*mock.MockRFC8628UserAuthorizeEndpointHandler, dar *mock.MockDeviceAuthorizeRequester)
		expected string
	}{
		{
			name:     "ShouldPassWithSingleHandler",
			handlers: 1,
			mock: func(handlers []*mock.MockRFC8628UserAuthorizeEndpointHandler, dar *mock.MockDeviceAuthorizeRequester) {
				dar.EXPECT().SetSession(gomock.Any())
				handlers[0].EXPECT().PopulateRFC8628UserAuthorizeEndpointResponse(gomock.Any(), gomock.Eq(dar), gomock.Any()).Return(nil)
			},
		},
		{
			name:     "ShouldFailWhenHandlerReturnsError",
			handlers: 1,
			mock: func(handlers []*mock.MockRFC8628UserAuthorizeEndpointHandler, dar *mock.MockDeviceAuthorizeRequester) {
				dar.EXPECT().SetSession(gomock.Any())
				handlers[0].EXPECT().PopulateRFC8628UserAuthorizeEndpointResponse(gomock.Any(), gomock.Eq(dar), gomock.Any()).Return(handlerErr)
			},
			expected: "handler failed",
		},
		{
			name:     "ShouldFailWhenHandlerReturnsRFC6749Error",
			handlers: 1,
			mock: func(handlers []*mock.MockRFC8628UserAuthorizeEndpointHandler, dar *mock.MockDeviceAuthorizeRequester) {
				dar.EXPECT().SetSession(gomock.Any())
				handlers[0].EXPECT().PopulateRFC8628UserAuthorizeEndpointResponse(gomock.Any(), gomock.Eq(dar), gomock.Any()).Return(errorsx.WithStack(ErrInvalidRequest.WithHint("User authorize response failed.")))
			},
			expected: "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. User authorize response failed.",
		},
		{
			name:     "ShouldPassWithMultipleHandlers",
			handlers: 2,
			mock: func(handlers []*mock.MockRFC8628UserAuthorizeEndpointHandler, dar *mock.MockDeviceAuthorizeRequester) {
				dar.EXPECT().SetSession(gomock.Any())
				handlers[0].EXPECT().PopulateRFC8628UserAuthorizeEndpointResponse(gomock.Any(), gomock.Eq(dar), gomock.Any()).Return(nil)
				handlers[1].EXPECT().PopulateRFC8628UserAuthorizeEndpointResponse(gomock.Any(), gomock.Eq(dar), gomock.Any()).Return(nil)
			},
		},
		{
			name:     "ShouldFailWhenSecondHandlerReturnsError",
			handlers: 2,
			mock: func(handlers []*mock.MockRFC8628UserAuthorizeEndpointHandler, dar *mock.MockDeviceAuthorizeRequester) {
				dar.EXPECT().SetSession(gomock.Any())
				handlers[0].EXPECT().PopulateRFC8628UserAuthorizeEndpointResponse(gomock.Any(), gomock.Eq(dar), gomock.Any()).Return(nil)
				handlers[1].EXPECT().PopulateRFC8628UserAuthorizeEndpointResponse(gomock.Any(), gomock.Eq(dar), gomock.Any()).Return(handlerErr)
			},
			expected: "handler failed",
		},
		{
			name:     "ShouldPassWithNoHandlers",
			handlers: 0,
			mock: func(handlers []*mock.MockRFC8628UserAuthorizeEndpointHandler, dar *mock.MockDeviceAuthorizeRequester) {
				dar.EXPECT().SetSession(gomock.Any())
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			dar := mock.NewMockDeviceAuthorizeRequester(ctrl)

			handlers := make([]*mock.MockRFC8628UserAuthorizeEndpointHandler, tc.handlers)
			endpointHandlers := make(RFC8628UserAuthorizeEndpointHandlers, tc.handlers)
			for i := 0; i < tc.handlers; i++ {
				handlers[i] = mock.NewMockRFC8628UserAuthorizeEndpointHandler(ctrl)
				endpointHandlers[i] = handlers[i]
			}

			provider := &Fosite{Config: &Config{
				RFC8628UserAuthorizeEndpointHandlers: endpointHandlers,
			}}

			tc.mock(handlers, dar)

			actual, err := provider.NewRFC8628UserAuthorizeResponse(context.Background(), dar, new(DefaultSession))

			if tc.expected != "" {
				assert.Nil(t, actual)
				assert.EqualError(t, ErrorToDebugRFC6749Error(err), tc.expected)

				return
			}

			require.NoError(t, ErrorToDebugRFC6749Error(err))
			require.NotNil(t, actual)
		})
	}
}
