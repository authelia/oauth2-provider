// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"context"
	"net/http"
	"net/url"
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

func TestFosite_NewRFC8628UserAuthorizeRequest(t *testing.T) {
	handlerErr := errors.New("handler failed")

	testCases := []struct {
		name     string
		req      *http.Request
		handlers int
		mock     func(handlers []*mock.MockRFC8628UserAuthorizeEndpointHandler)
		expected string
	}{
		{
			name: "ShouldPassWithSingleHandler",
			req: &http.Request{
				Form: url.Values{
					consts.FormParameterUserCode: {"A1B2C3D4"},
				},
			},
			handlers: 1,
			mock: func(handlers []*mock.MockRFC8628UserAuthorizeEndpointHandler) {
				handlers[0].EXPECT().HandleRFC8628UserAuthorizeEndpointRequest(gomock.Any(), gomock.Any()).Return(nil)
			},
		},
		{
			name: "ShouldFailWhenHandlerReturnsError",
			req: &http.Request{
				Form: url.Values{
					consts.FormParameterUserCode: {"A1B2C3D4"},
				},
			},
			handlers: 1,
			mock: func(handlers []*mock.MockRFC8628UserAuthorizeEndpointHandler) {
				handlers[0].EXPECT().HandleRFC8628UserAuthorizeEndpointRequest(gomock.Any(), gomock.Any()).Return(handlerErr)
			},
			expected: "handler failed",
		},
		{
			name: "ShouldFailWhenHandlerReturnsRFC6749Error",
			req: &http.Request{
				Form: url.Values{
					consts.FormParameterUserCode: {"A1B2C3D4"},
				},
			},
			handlers: 1,
			mock: func(handlers []*mock.MockRFC8628UserAuthorizeEndpointHandler) {
				handlers[0].EXPECT().HandleRFC8628UserAuthorizeEndpointRequest(gomock.Any(), gomock.Any()).Return(errorsx.WithStack(ErrInvalidRequest.WithHint("User code is invalid.")))
			},
			expected: "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. User code is invalid.",
		},
		{
			name: "ShouldPassWithMultipleHandlers",
			req: &http.Request{
				Form: url.Values{
					consts.FormParameterUserCode: {"A1B2C3D4"},
				},
			},
			handlers: 2,
			mock: func(handlers []*mock.MockRFC8628UserAuthorizeEndpointHandler) {
				handlers[0].EXPECT().HandleRFC8628UserAuthorizeEndpointRequest(gomock.Any(), gomock.Any()).Return(nil)
				handlers[1].EXPECT().HandleRFC8628UserAuthorizeEndpointRequest(gomock.Any(), gomock.Any()).Return(nil)
			},
		},
		{
			name: "ShouldFailWhenSecondHandlerReturnsError",
			req: &http.Request{
				Form: url.Values{
					consts.FormParameterUserCode: {"A1B2C3D4"},
				},
			},
			handlers: 2,
			mock: func(handlers []*mock.MockRFC8628UserAuthorizeEndpointHandler) {
				handlers[0].EXPECT().HandleRFC8628UserAuthorizeEndpointRequest(gomock.Any(), gomock.Any()).Return(nil)
				handlers[1].EXPECT().HandleRFC8628UserAuthorizeEndpointRequest(gomock.Any(), gomock.Any()).Return(handlerErr)
			},
			expected: "handler failed",
		},
		{
			name: "ShouldContinueWhenHandlerReturnsErrUnknownRequest",
			req: &http.Request{
				Form: url.Values{
					consts.FormParameterUserCode: {"A1B2C3D4"},
				},
			},
			handlers: 2,
			mock: func(handlers []*mock.MockRFC8628UserAuthorizeEndpointHandler) {
				handlers[0].EXPECT().HandleRFC8628UserAuthorizeEndpointRequest(gomock.Any(), gomock.Any()).Return(errorsx.WithStack(ErrUnknownRequest))
				handlers[1].EXPECT().HandleRFC8628UserAuthorizeEndpointRequest(gomock.Any(), gomock.Any()).Return(nil)
			},
		},
		{
			name: "ShouldFailWhenParseFormErrors",
			req: &http.Request{
				Header: http.Header{
					consts.HeaderContentType: {"multipart/form-data"},
				},
			},
			handlers: 1,
			mock:     func(handlers []*mock.MockRFC8628UserAuthorizeEndpointHandler) {},
			expected: "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Unable to parse HTTP body, make sure to send a properly formatted form request body. missing form body",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			handlers := make([]*mock.MockRFC8628UserAuthorizeEndpointHandler, tc.handlers)
			endpointHandlers := make(RFC8628UserAuthorizeEndpointHandlers, tc.handlers)
			for i := 0; i < tc.handlers; i++ {
				handlers[i] = mock.NewMockRFC8628UserAuthorizeEndpointHandler(ctrl)
				endpointHandlers[i] = handlers[i]
			}

			provider := &Fosite{Config: &Config{
				RFC8628UserAuthorizeEndpointHandlers: endpointHandlers,
			}}

			tc.mock(handlers)

			actual, err := provider.NewRFC8628UserAuthorizeRequest(context.Background(), tc.req)

			if tc.expected != "" {
				assert.Nil(t, actual)
				assert.EqualError(t, ErrorToDebugRFC6749Error(err), tc.expected)

				return
			}

			require.NoError(t, ErrorToDebugRFC6749Error(err))
			require.NotNil(t, actual)
			assert.Equal(t, tc.req.Form, actual.GetRequestForm())
		})
	}
}
