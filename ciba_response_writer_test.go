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

func TestNewOpenIDCIBAResponse(t *testing.T) {
	handlerErr := errors.New("handler failed")

	testCases := []struct {
		name     string
		handlers int
		mock     func(handlers []*mock.MockOpenIDCIBAEndpointHandler, cr *mock.MockCIBARequester)
		expected string
	}{
		{
			name:     "ShouldFailWhenHandlerReturnsError",
			handlers: 1,
			mock: func(handlers []*mock.MockOpenIDCIBAEndpointHandler, cr *mock.MockCIBARequester) {
				cr.EXPECT().SetSession(gomock.Eq(new(DefaultSession)))
				handlers[0].EXPECT().HandleOpenIDCIBAEndpointRequest(gomock.Any(), gomock.Eq(cr), gomock.Any()).Return(handlerErr)
			},
			expected: "handler failed",
		},
		{
			name:     "ShouldFailWhenHandlerReturnsRFC6749Error",
			handlers: 1,
			mock: func(handlers []*mock.MockOpenIDCIBAEndpointHandler, cr *mock.MockCIBARequester) {
				cr.EXPECT().SetSession(gomock.Eq(new(DefaultSession)))
				handlers[0].EXPECT().HandleOpenIDCIBAEndpointRequest(gomock.Any(), gomock.Eq(cr), gomock.Any()).Return(errorsx.WithStack(ErrInvalidRequest.WithHint("CIBA request was invalid.")))
			},
			expected: "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. CIBA request was invalid.",
		},
		{
			name:     "ShouldPassWithSingleHandler",
			handlers: 1,
			mock: func(handlers []*mock.MockOpenIDCIBAEndpointHandler, cr *mock.MockCIBARequester) {
				cr.EXPECT().SetSession(gomock.Eq(new(DefaultSession)))
				handlers[0].EXPECT().HandleOpenIDCIBAEndpointRequest(gomock.Any(), gomock.Eq(cr), gomock.Any()).Return(nil)
			},
		},
		{
			name:     "ShouldPassWithMultipleHandlers",
			handlers: 2,
			mock: func(handlers []*mock.MockOpenIDCIBAEndpointHandler, cr *mock.MockCIBARequester) {
				cr.EXPECT().SetSession(gomock.Eq(new(DefaultSession)))
				handlers[0].EXPECT().HandleOpenIDCIBAEndpointRequest(gomock.Any(), gomock.Eq(cr), gomock.Any()).Return(nil)
				handlers[1].EXPECT().HandleOpenIDCIBAEndpointRequest(gomock.Any(), gomock.Eq(cr), gomock.Any()).Return(nil)
			},
		},
		{
			name:     "ShouldFailWhenSecondHandlerReturnsError",
			handlers: 2,
			mock: func(handlers []*mock.MockOpenIDCIBAEndpointHandler, cr *mock.MockCIBARequester) {
				cr.EXPECT().SetSession(gomock.Eq(new(DefaultSession)))
				handlers[0].EXPECT().HandleOpenIDCIBAEndpointRequest(gomock.Any(), gomock.Eq(cr), gomock.Any()).Return(nil)
				handlers[1].EXPECT().HandleOpenIDCIBAEndpointRequest(gomock.Any(), gomock.Eq(cr), gomock.Any()).Return(handlerErr)
			},
			expected: "handler failed",
		},
		{
			name:     "ShouldPassWithNoHandlers",
			handlers: 0,
			mock: func(handlers []*mock.MockOpenIDCIBAEndpointHandler, cr *mock.MockCIBARequester) {
				cr.EXPECT().SetSession(gomock.Eq(new(DefaultSession)))
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			cr := mock.NewMockCIBARequester(ctrl)

			handlers := make([]*mock.MockOpenIDCIBAEndpointHandler, tc.handlers)
			endpointHandlers := make(OpenIDCIBAEndpointHandlers, tc.handlers)
			for i := 0; i < tc.handlers; i++ {
				handlers[i] = mock.NewMockOpenIDCIBAEndpointHandler(ctrl)
				endpointHandlers[i] = handlers[i]
			}

			provider := &Fosite{Config: &Config{
				OpenIDCIBAEndpointHandlers: endpointHandlers,
			}}

			tc.mock(handlers, cr)

			actual, err := provider.NewOpenIDCIBAResponse(context.Background(), cr, new(DefaultSession))

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
