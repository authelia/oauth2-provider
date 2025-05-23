// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	. "authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/compose"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/testing/mock"
)

func TestAccessTokenFromRequestNoToken(t *testing.T) {
	req, _ := http.NewRequest("GET", "http://example.com/test", nil)

	assert.Equal(t, AccessTokenFromRequest(req), "", "No token should produce an empty string")
}

func TestAccessTokenFromRequestHeader(t *testing.T) {
	token := "TokenFromHeader"

	req, _ := http.NewRequest("GET", "http://example.com/test", nil)
	req.Header.Add(consts.HeaderAuthorization, "Bearer "+token)

	assert.Equal(t, AccessTokenFromRequest(req), token, "Token should be obtainable from header")
}

func TestAccessTokenFromRequestQuery(t *testing.T) {
	token := "TokenFromQueryParam"

	req, _ := http.NewRequest("GET", "http://example.com/test?access_token="+token, nil)

	assert.Equal(t, AccessTokenFromRequest(req), token, "Token should be obtainable from access_token query parameter")
}

func TestIntrospect(t *testing.T) {
	ctrl := gomock.NewController(t)
	validator := mock.NewMockTokenIntrospector(ctrl)
	defer ctrl.Finish()

	config := new(Config)
	provider := compose.ComposeAllEnabled(config, storage.NewMemoryStore(), nil).(*Fosite)

	req, _ := http.NewRequest("GET", "http://example.com/test", nil)
	req.Header.Add(consts.HeaderAuthorization, "bearer some-token")

	for k, c := range []struct {
		description string
		scopes      []string
		setup       func()
		expectErr   error
	}{
		{
			description: "should fail",
			scopes:      []string{},
			setup: func() {
			},
			expectErr: ErrRequestUnauthorized,
		},
		{
			description: "should fail",
			scopes:      []string{"foo"},
			setup: func() {
				config.TokenIntrospectionHandlers = TokenIntrospectionHandlers{validator}
				validator.EXPECT().IntrospectToken(t.Context(), "some-token", gomock.Any(), gomock.Any(), gomock.Any()).Return(TokenUse(""), ErrUnknownRequest)
			},
			expectErr: ErrRequestUnauthorized,
		},
		{
			description: "should fail",
			scopes:      []string{"foo"},
			setup: func() {
				validator.EXPECT().IntrospectToken(t.Context(), "some-token", gomock.Any(), gomock.Any(), gomock.Any()).Return(TokenUse(""), ErrInvalidClient)
			},
			expectErr: ErrInvalidClient,
		},
		{
			description: "should pass",
			setup: func() {
				validator.EXPECT().IntrospectToken(t.Context(), "some-token", gomock.Any(), gomock.Any(), gomock.Any()).Do(func(ctx context.Context, _ string, _ TokenUse, requester AccessRequester, _ []string) {
					requester.(*AccessRequest).GrantedScope = []string{"bar"}
				}).Return(TokenUse(""), nil)
			},
		},
		{
			description: "should pass",
			scopes:      []string{"bar"},
			setup: func() {
				validator.EXPECT().IntrospectToken(t.Context(), "some-token", gomock.Any(), gomock.Any(), gomock.Any()).Do(func(ctx context.Context, _ string, _ TokenType, requester AccessRequester, _ []string) {
					requester.(*AccessRequest).GrantedScope = []string{"bar"}
				}).Return(TokenUse(""), nil)
			},
		},
	} {
		t.Run(fmt.Sprintf("case=%d", k), func(t *testing.T) {
			c.setup()
			_, _, err := provider.IntrospectToken(t.Context(), AccessTokenFromRequest(req), AccessToken, nil, c.scopes...)
			if c.expectErr != nil {
				assert.EqualError(t, err, c.expectErr.Error())
			} else {
				require.NoError(t, err)
			}
		})
	}
}
