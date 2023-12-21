// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/errorsx"
)

func TestIntrospectToken(t *testing.T) {
	ctrl := gomock.NewController(t)
	store := internal.NewMockCoreStorage(ctrl)
	chgen := internal.NewMockCoreStrategy(ctrl)
	areq := oauth2.NewAccessRequest(nil)

	defer ctrl.Finish()

	config := &oauth2.Config{}
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
		expectTU    oauth2.TokenUse
	}{
		{
			description: "should fail because no bearer token set",
			setup: func() {
				httpreq.Header.Set(consts.HeaderAuthorization, "bearer")
				chgen.EXPECT().AccessTokenSignature(gomock.Any(), "").Return("")
				store.EXPECT().GetAccessTokenSession(context.TODO(), "", nil).Return(nil, errors.New(""))
				chgen.EXPECT().RefreshTokenSignature(gomock.Any(), "").Return("")
				store.EXPECT().GetRefreshTokenSession(context.TODO(), "", nil).Return(nil, errors.New(""))
			},
			expectErr: oauth2.ErrRequestUnauthorized,
		},
		{
			description: "should fail because retrieval fails",
			setup: func() {
				httpreq.Header.Set(consts.HeaderAuthorization, "bearer 1234")
				chgen.EXPECT().AccessTokenSignature(gomock.Any(), "1234").AnyTimes().Return("asdf")
				store.EXPECT().GetAccessTokenSession(context.TODO(), "asdf", nil).Return(nil, errors.New(""))
				chgen.EXPECT().RefreshTokenSignature(gomock.Any(), "1234").Return("asdf")
				store.EXPECT().GetRefreshTokenSession(context.TODO(), "asdf", nil).Return(nil, errors.New(""))
			},
			expectErr: oauth2.ErrRequestUnauthorized,
		},
		{
			description: "should fail because validation fails",
			setup: func() {
				store.EXPECT().GetAccessTokenSession(context.TODO(), "asdf", nil).AnyTimes().Return(areq, nil)
				chgen.EXPECT().ValidateAccessToken(context.TODO(), areq, "1234").Return(errorsx.WithStack(oauth2.ErrTokenExpired))
				chgen.EXPECT().RefreshTokenSignature(gomock.Any(), "1234").Return("asdf")
				store.EXPECT().GetRefreshTokenSession(context.TODO(), "asdf", nil).Return(nil, errors.New(""))
			},
			expectErr: oauth2.ErrTokenExpired,
		},
		{
			description: "should fail because access token invalid",
			setup: func() {
				config.DisableRefreshTokenValidation = true
				chgen.EXPECT().ValidateAccessToken(context.TODO(), areq, "1234").Return(errorsx.WithStack(oauth2.ErrInvalidTokenFormat))
			},
			expectErr: oauth2.ErrInvalidTokenFormat,
		},
		{
			description: "should pass",
			setup: func() {
				chgen.EXPECT().ValidateAccessToken(context.TODO(), areq, "1234").Return(nil)
			},
			expectTU: oauth2.AccessToken,
		},
	} {
		t.Run(fmt.Sprintf("case=%d", k), func(t *testing.T) {
			c.setup()
			tu, err := v.IntrospectToken(context.TODO(), oauth2.AccessTokenFromRequest(httpreq), oauth2.AccessToken, areq, []string{})

			if c.expectErr != nil {
				require.EqualError(t, err, c.expectErr.Error())
			} else {
				require.NoError(t, err)
				assert.Equal(t, c.expectTU, tu)
			}
		})
	}
}
