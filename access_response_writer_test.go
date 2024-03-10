// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	. "authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/testing/mock"
)

func TestNewAccessResponse(t *testing.T) {
	ctrl := gomock.NewController(t)
	handler := mock.NewMockTokenEndpointHandler(ctrl)
	defer ctrl.Finish()

	config := &Config{}
	provider := &Fosite{Config: config}
	for k, c := range []struct {
		handlers  TokenEndpointHandlers
		mock      func()
		expectErr error
		expect    AccessResponder
	}{
		{
			mock:      func() {},
			handlers:  TokenEndpointHandlers{},
			expectErr: ErrServerError,
		},
		{
			mock: func() {
				handler.EXPECT().PopulateTokenEndpointResponse(gomock.Any(), gomock.Any(), gomock.Any()).Return(ErrServerError)
			},
			handlers:  TokenEndpointHandlers{handler},
			expectErr: ErrServerError,
		},
		{
			mock: func() {
				handler.EXPECT().PopulateTokenEndpointResponse(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
			},
			handlers:  TokenEndpointHandlers{handler},
			expectErr: ErrServerError,
		},
		{
			mock: func() {
				handler.EXPECT().PopulateTokenEndpointResponse(gomock.Any(), gomock.Any(), gomock.Any()).Do(func(_ context.Context, _ AccessRequester, resp AccessResponder) {
					resp.SetAccessToken("foo")
				}).Return(nil)
			},
			handlers:  TokenEndpointHandlers{handler},
			expectErr: ErrServerError,
		},
		{
			mock: func() {
				handler.EXPECT().PopulateTokenEndpointResponse(gomock.Any(), gomock.Any(), gomock.Any()).Do(func(_ context.Context, _ AccessRequester, resp AccessResponder) {
					resp.SetAccessToken("foo")
					resp.SetTokenType("bar")
				}).Return(nil)
			},
			handlers: TokenEndpointHandlers{handler},
			expect: &AccessResponse{
				Extra:       map[string]any{},
				AccessToken: "foo",
				TokenType:   "bar",
			},
		},
	} {
		t.Run(fmt.Sprintf("case=%d", k), func(t *testing.T) {
			config.TokenEndpointHandlers = c.handlers
			c.mock()
			ar, err := provider.NewAccessResponse(context.TODO(), nil)

			if c.expectErr != nil {
				assert.EqualError(t, err, c.expectErr.Error())
			} else {
				require.NoError(t, err)
				assert.Equal(t, ar, c.expect)
			}
		})
	}
}
