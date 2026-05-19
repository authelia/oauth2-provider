// Copyright © 2023 Ory Corp
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

func TestNewAuthorizeResponse(t *testing.T) {
	handlerErr := errors.New("handler failed")

	testCases := []struct {
		name     string
		handlers int
		mock     func(handlers []*mock.MockAuthorizeEndpointHandler, ar *mock.MockAuthorizeRequester)
		expected string
	}{
		{
			name:     "ShouldFailWhenHandlerReturnsError",
			handlers: 1,
			mock: func(handlers []*mock.MockAuthorizeEndpointHandler, ar *mock.MockAuthorizeRequester) {
				ar.EXPECT().SetSession(gomock.Eq(new(DefaultSession)))
				handlers[0].EXPECT().HandleAuthorizeEndpointRequest(gomock.Any(), gomock.Eq(ar), gomock.Any()).Return(handlerErr)
			},
			expected: "handler failed",
		},
		{
			name:     "ShouldFailWhenHandlerReturnsRFC6749Error",
			handlers: 1,
			mock: func(handlers []*mock.MockAuthorizeEndpointHandler, ar *mock.MockAuthorizeRequester) {
				ar.EXPECT().SetSession(gomock.Eq(new(DefaultSession)))
				handlers[0].EXPECT().HandleAuthorizeEndpointRequest(gomock.Any(), gomock.Eq(ar), gomock.Any()).Return(errorsx.WithStack(ErrInvalidRequest.WithHint("Authorize endpoint request was invalid.")))
			},
			expected: "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Authorize endpoint request was invalid.",
		},
		{
			name:     "ShouldPassWithSingleHandler",
			handlers: 1,
			mock: func(handlers []*mock.MockAuthorizeEndpointHandler, ar *mock.MockAuthorizeRequester) {
				ar.EXPECT().SetSession(gomock.Eq(new(DefaultSession)))
				handlers[0].EXPECT().HandleAuthorizeEndpointRequest(gomock.Any(), gomock.Eq(ar), gomock.Any()).Return(nil)
				ar.EXPECT().DidHandleAllResponseTypes().Return(true)
				ar.EXPECT().GetDefaultResponseMode().Return(ResponseModeFragment)
				ar.EXPECT().GetResponseMode().Return(ResponseModeDefault)
			},
		},
		{
			name:     "ShouldPassWithMultipleHandlers",
			handlers: 2,
			mock: func(handlers []*mock.MockAuthorizeEndpointHandler, ar *mock.MockAuthorizeRequester) {
				ar.EXPECT().SetSession(gomock.Eq(new(DefaultSession)))
				handlers[0].EXPECT().HandleAuthorizeEndpointRequest(gomock.Any(), gomock.Eq(ar), gomock.Any()).Return(nil)
				handlers[1].EXPECT().HandleAuthorizeEndpointRequest(gomock.Any(), gomock.Eq(ar), gomock.Any()).Return(nil)
				ar.EXPECT().DidHandleAllResponseTypes().Return(true)
				ar.EXPECT().GetDefaultResponseMode().Return(ResponseModeFragment)
				ar.EXPECT().GetResponseMode().Return(ResponseModeDefault)
			},
		},
		{
			name:     "ShouldFailWhenSecondHandlerReturnsError",
			handlers: 2,
			mock: func(handlers []*mock.MockAuthorizeEndpointHandler, ar *mock.MockAuthorizeRequester) {
				ar.EXPECT().SetSession(gomock.Eq(new(DefaultSession)))
				handlers[0].EXPECT().HandleAuthorizeEndpointRequest(gomock.Any(), gomock.Eq(ar), gomock.Any()).Return(nil)
				handlers[1].EXPECT().HandleAuthorizeEndpointRequest(gomock.Any(), gomock.Eq(ar), gomock.Any()).Return(handlerErr)
			},
			expected: "handler failed",
		},
		{
			name:     "ShouldFailWhenNotAllResponseTypesHandled",
			handlers: 1,
			mock: func(handlers []*mock.MockAuthorizeEndpointHandler, ar *mock.MockAuthorizeRequester) {
				ar.EXPECT().SetSession(gomock.Eq(new(DefaultSession)))
				handlers[0].EXPECT().HandleAuthorizeEndpointRequest(gomock.Any(), gomock.Eq(ar), gomock.Any()).Return(nil)
				ar.EXPECT().DidHandleAllResponseTypes().Return(false)
			},
			expected: "The authorization server does not support obtaining a token using this method.",
		},
		{
			name:     "ShouldFailWhenInsecureQueryModeForFragmentDefault",
			handlers: 2,
			mock: func(handlers []*mock.MockAuthorizeEndpointHandler, ar *mock.MockAuthorizeRequester) {
				ar.EXPECT().SetSession(gomock.Eq(new(DefaultSession)))
				handlers[0].EXPECT().HandleAuthorizeEndpointRequest(gomock.Any(), gomock.Eq(ar), gomock.Any()).Return(nil)
				handlers[1].EXPECT().HandleAuthorizeEndpointRequest(gomock.Any(), gomock.Eq(ar), gomock.Any()).Return(nil)
				ar.EXPECT().DidHandleAllResponseTypes().Return(true)
				ar.EXPECT().GetDefaultResponseMode().Return(ResponseModeFragment)
				ar.EXPECT().GetResponseMode().Return(ResponseModeQuery).Times(2)
				ar.EXPECT().GetResponseTypes().Return(Arguments{"token", "code"})
			},
			expected: "The authorization server does not support obtaining a response using this response mode. Insecure response_mode 'query' for the response_type '[token code]'.",
		},
		{
			name:     "ShouldPassWithNoHandlers",
			handlers: 0,
			mock: func(handlers []*mock.MockAuthorizeEndpointHandler, ar *mock.MockAuthorizeRequester) {
				ar.EXPECT().SetSession(gomock.Eq(new(DefaultSession)))
				ar.EXPECT().DidHandleAllResponseTypes().Return(true)
				ar.EXPECT().GetDefaultResponseMode().Return(ResponseModeFragment)
				ar.EXPECT().GetResponseMode().Return(ResponseModeDefault)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			ar := mock.NewMockAuthorizeRequester(ctrl)

			handlers := make([]*mock.MockAuthorizeEndpointHandler, tc.handlers)
			endpointHandlers := make(AuthorizeEndpointHandlers, tc.handlers)
			for i := 0; i < tc.handlers; i++ {
				handlers[i] = mock.NewMockAuthorizeEndpointHandler(ctrl)
				endpointHandlers[i] = handlers[i]
			}

			provider := &Fosite{Config: &Config{
				AuthorizeEndpointHandlers: endpointHandlers,
			}}

			tc.mock(handlers, ar)

			actual, err := provider.NewAuthorizeResponse(context.Background(), ar, new(DefaultSession))

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
