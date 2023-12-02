// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/ory/x/errorsx"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/authelia/goauth2"
	"github.com/authelia/goauth2/internal"
)

func TestIntrospectToken(t *testing.T) {
	ctrl := gomock.NewController(t)
	store := internal.NewMockCoreStorage(ctrl)
	chgen := internal.NewMockCoreStrategy(ctrl)
	areq := goauth2.NewAccessRequest(nil)
	defer ctrl.Finish()

	config := &goauth2.Config{}
	v := &CoreValidator{
		CoreStrategy: chgen,
		CoreStorage:  store,
		Config:       config,
	}
	httpreq := &http.Request{Header: http.Header{}}

	for k, c := range []struct {
		description string
		setup       func()
		expectErr   error
		expectTU    goauth2.TokenUse
	}{
		{
			description: "should fail because no bearer token set",
			setup: func() {
				httpreq.Header.Set("Authorization", "bearer")
				chgen.EXPECT().AccessTokenSignature(gomock.Any(), "").Return("")
				store.EXPECT().GetAccessTokenSession(nil, "", nil).Return(nil, errors.New(""))
				chgen.EXPECT().RefreshTokenSignature(gomock.Any(), "").Return("")
				store.EXPECT().GetRefreshTokenSession(nil, "", nil).Return(nil, errors.New(""))
			},
			expectErr: goauth2.ErrRequestUnauthorized,
		},
		{
			description: "should fail because retrieval fails",
			setup: func() {
				httpreq.Header.Set("Authorization", "bearer 1234")
				chgen.EXPECT().AccessTokenSignature(gomock.Any(), "1234").AnyTimes().Return("asdf")
				store.EXPECT().GetAccessTokenSession(nil, "asdf", nil).Return(nil, errors.New(""))
				chgen.EXPECT().RefreshTokenSignature(gomock.Any(), "1234").Return("asdf")
				store.EXPECT().GetRefreshTokenSession(nil, "asdf", nil).Return(nil, errors.New(""))
			},
			expectErr: goauth2.ErrRequestUnauthorized,
		},
		{
			description: "should fail because validation fails",
			setup: func() {
				store.EXPECT().GetAccessTokenSession(nil, "asdf", nil).AnyTimes().Return(areq, nil)
				chgen.EXPECT().ValidateAccessToken(nil, areq, "1234").Return(errorsx.WithStack(goauth2.ErrTokenExpired))
				chgen.EXPECT().RefreshTokenSignature(gomock.Any(), "1234").Return("asdf")
				store.EXPECT().GetRefreshTokenSession(nil, "asdf", nil).Return(nil, errors.New(""))
			},
			expectErr: goauth2.ErrTokenExpired,
		},
		{
			description: "should fail because access token invalid",
			setup: func() {
				config.DisableRefreshTokenValidation = true
				chgen.EXPECT().ValidateAccessToken(nil, areq, "1234").Return(errorsx.WithStack(goauth2.ErrInvalidTokenFormat))
			},
			expectErr: goauth2.ErrInvalidTokenFormat,
		},
		{
			description: "should pass",
			setup: func() {
				chgen.EXPECT().ValidateAccessToken(nil, areq, "1234").Return(nil)
			},
			expectTU: goauth2.AccessToken,
		},
	} {
		t.Run(fmt.Sprintf("case=%d", k), func(t *testing.T) {
			c.setup()
			tu, err := v.IntrospectToken(nil, goauth2.AccessTokenFromRequest(httpreq), goauth2.AccessToken, areq, []string{})

			if c.expectErr != nil {
				require.EqualError(t, err, c.expectErr.Error())
			} else {
				require.NoError(t, err)
				assert.Equal(t, c.expectTU, tu)
			}
		})
	}
}
