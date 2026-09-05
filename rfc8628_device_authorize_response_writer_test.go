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

func TestNewRFC862DeviceAuthorizeResponse(t *testing.T) {
	handlerErr := errors.New("handler failed")

	testCases := []struct {
		name     string
		handlers int
		mock     func(handlers []*mock.MockRFC8628DeviceAuthorizeEndpointHandler, dar *mock.MockDeviceAuthorizeRequester)
		expected string
	}{
		{
			name:     "ShouldFailWhenHandlerReturnsError",
			handlers: 1,
			mock: func(handlers []*mock.MockRFC8628DeviceAuthorizeEndpointHandler, dar *mock.MockDeviceAuthorizeRequester) {
				dar.EXPECT().SetSession(gomock.Eq(new(DefaultSession)))
				handlers[0].EXPECT().HandleRFC8628DeviceAuthorizeEndpointRequest(gomock.Any(), gomock.Eq(dar), gomock.Any()).Return(handlerErr)
			},
			expected: "handler failed",
		},
		{
			name:     "ShouldFailWhenHandlerReturnsRFC6749Error",
			handlers: 1,
			mock: func(handlers []*mock.MockRFC8628DeviceAuthorizeEndpointHandler, dar *mock.MockDeviceAuthorizeRequester) {
				dar.EXPECT().SetSession(gomock.Eq(new(DefaultSession)))
				handlers[0].EXPECT().HandleRFC8628DeviceAuthorizeEndpointRequest(gomock.Any(), gomock.Eq(dar), gomock.Any()).Return(errorsx.WithStack(ErrInvalidRequest.WithHint("Device authorize request was invalid.")))
			},
			expected: "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Device authorize request was invalid.",
		},
		{
			name:     "ShouldPassWithSingleHandler",
			handlers: 1,
			mock: func(handlers []*mock.MockRFC8628DeviceAuthorizeEndpointHandler, dar *mock.MockDeviceAuthorizeRequester) {
				dar.EXPECT().SetSession(gomock.Eq(new(DefaultSession)))
				handlers[0].EXPECT().HandleRFC8628DeviceAuthorizeEndpointRequest(gomock.Any(), gomock.Eq(dar), gomock.Any()).Return(nil)
			},
		},
		{
			name:     "ShouldPassWithMultipleHandlers",
			handlers: 2,
			mock: func(handlers []*mock.MockRFC8628DeviceAuthorizeEndpointHandler, dar *mock.MockDeviceAuthorizeRequester) {
				dar.EXPECT().SetSession(gomock.Eq(new(DefaultSession)))
				handlers[0].EXPECT().HandleRFC8628DeviceAuthorizeEndpointRequest(gomock.Any(), gomock.Eq(dar), gomock.Any()).Return(nil)
				handlers[1].EXPECT().HandleRFC8628DeviceAuthorizeEndpointRequest(gomock.Any(), gomock.Eq(dar), gomock.Any()).Return(nil)
			},
		},
		{
			name:     "ShouldFailWhenSecondHandlerReturnsError",
			handlers: 2,
			mock: func(handlers []*mock.MockRFC8628DeviceAuthorizeEndpointHandler, dar *mock.MockDeviceAuthorizeRequester) {
				dar.EXPECT().SetSession(gomock.Eq(new(DefaultSession)))
				handlers[0].EXPECT().HandleRFC8628DeviceAuthorizeEndpointRequest(gomock.Any(), gomock.Eq(dar), gomock.Any()).Return(nil)
				handlers[1].EXPECT().HandleRFC8628DeviceAuthorizeEndpointRequest(gomock.Any(), gomock.Eq(dar), gomock.Any()).Return(handlerErr)
			},
			expected: "handler failed",
		},
		{
			name:     "ShouldPassWithNoHandlers",
			handlers: 0,
			mock: func(handlers []*mock.MockRFC8628DeviceAuthorizeEndpointHandler, dar *mock.MockDeviceAuthorizeRequester) {
				dar.EXPECT().SetSession(gomock.Eq(new(DefaultSession)))
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			dar := mock.NewMockDeviceAuthorizeRequester(ctrl)

			handlers := make([]*mock.MockRFC8628DeviceAuthorizeEndpointHandler, tc.handlers)
			endpointHandlers := make(RFC8628DeviceAuthorizeEndpointHandlers, tc.handlers)
			for i := 0; i < tc.handlers; i++ {
				handlers[i] = mock.NewMockRFC8628DeviceAuthorizeEndpointHandler(ctrl)
				endpointHandlers[i] = handlers[i]
			}

			provider := &Fosite{Config: &Config{
				RFC8628DeviceAuthorizeEndpointHandlers: endpointHandlers,
			}}

			tc.mock(handlers, dar)

			actual, err := provider.NewRFC862DeviceAuthorizeResponse(context.Background(), dar, new(DefaultSession))

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

func TestNewRFC862DeviceAuthorizeResponse_DispatchesBindingHandlers(t *testing.T) {
	t.Run("ShouldRunBeforeEndpointHandlers", func(t *testing.T) {
		binding := &testDeviceBindingHandler{}
		endpoint := &testDeviceEndpointHandler{}

		config := &Config{
			RFC8628DeviceAuthorizeEndpointBindingHandlers: RFC8628DeviceAuthorizeEndpointBindingHandlers{binding},
			RFC8628DeviceAuthorizeEndpointHandlers:        RFC8628DeviceAuthorizeEndpointHandlers{endpoint},
		}
		provider := &Fosite{Config: config}

		session := &DefaultSession{}
		request := NewDeviceAuthorizeRequest()

		_, err := provider.NewRFC862DeviceAuthorizeResponse(t.Context(), request, session)
		require.NoError(t, err)

		assert.True(t, binding.called)
		assert.Equal(t, "recorded", session.GetDPoPJWKThumbprint())
		assert.Equal(t, "recorded", endpoint.sawThumbprint)
	})

	t.Run("ShouldPropagateBindingError", func(t *testing.T) {
		binding := &testDeviceBindingHandler{err: ErrInvalidRequest}

		config := &Config{RFC8628DeviceAuthorizeEndpointBindingHandlers: RFC8628DeviceAuthorizeEndpointBindingHandlers{binding}}
		provider := &Fosite{Config: config}

		_, err := provider.NewRFC862DeviceAuthorizeResponse(t.Context(), NewDeviceAuthorizeRequest(), &DefaultSession{})

		assert.ErrorIs(t, err, ErrInvalidRequest)
	})
}

type testDeviceBindingHandler struct {
	called bool
	err    error
}

func (h *testDeviceBindingHandler) BindRFC8628DeviceAuthorizeRequest(ctx context.Context, request DeviceAuthorizeRequester) (err error) {
	h.called = true

	if h.err != nil {
		return h.err
	}

	request.GetSession().(*DefaultSession).SetDPoPJWKThumbprint("recorded")

	return nil
}

type testDeviceEndpointHandler struct {
	sawThumbprint string
}

func (h *testDeviceEndpointHandler) HandleRFC8628DeviceAuthorizeEndpointRequest(ctx context.Context, request DeviceAuthorizeRequester, response DeviceAuthorizeResponder) (err error) {
	h.sawThumbprint = request.GetSession().(*DefaultSession).GetDPoPJWKThumbprint()

	return nil
}
