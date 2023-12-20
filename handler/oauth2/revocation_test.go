// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal"
)

func TestRevokeToken(t *testing.T) {
	ctrl := gomock.NewController(t)
	store := internal.NewMockTokenRevocationStorage(ctrl)
	atStrat := internal.NewMockAccessTokenStrategy(ctrl)
	rtStrat := internal.NewMockRefreshTokenStrategy(ctrl)
	ar := internal.NewMockAccessRequester(ctrl)

	defer ctrl.Finish()

	h := TokenRevocationHandler{
		TokenRevocationStorage: store,
		RefreshTokenStrategy:   rtStrat,
		AccessTokenStrategy:    atStrat,
	}

	var (
		token     string
		tokenType oauth2.TokenType
	)

	for k, c := range []struct {
		description string
		mock        func()
		expectErr   error
		client      oauth2.Client
	}{
		{
			description: "should fail - token was issued to another client",
			expectErr:   oauth2.ErrUnauthorizedClient,
			client:      &oauth2.DefaultClient{ID: "bar"},
			mock: func() {
				token = "foo"
				tokenType = oauth2.RefreshToken
				rtStrat.EXPECT().RefreshTokenSignature(gomock.Any(), token)
				store.EXPECT().GetRefreshTokenSession(gomock.Any(), gomock.Any(), gomock.Any()).Return(ar, nil)
				ar.EXPECT().GetClient().Return(&oauth2.DefaultClient{ID: "foo"})
			},
		},
		{
			description: "should pass - refresh token discovery first; refresh token found",
			expectErr:   nil,
			client:      &oauth2.DefaultClient{ID: "bar"},
			mock: func() {
				token = "foo"
				tokenType = oauth2.RefreshToken
				rtStrat.EXPECT().RefreshTokenSignature(gomock.Any(), token)
				store.EXPECT().GetRefreshTokenSession(gomock.Any(), gomock.Any(), gomock.Any()).Return(ar, nil)
				ar.EXPECT().GetID()
				ar.EXPECT().GetClient().Return(&oauth2.DefaultClient{ID: "bar"})
				store.EXPECT().RevokeRefreshToken(gomock.Any(), gomock.Any())
				store.EXPECT().RevokeAccessToken(gomock.Any(), gomock.Any())
			},
		},
		{
			description: "should pass - access token discovery first; access token found",
			expectErr:   nil,
			client:      &oauth2.DefaultClient{ID: "bar"},
			mock: func() {
				token = "foo"
				tokenType = oauth2.AccessToken
				atStrat.EXPECT().AccessTokenSignature(gomock.Any(), token)
				store.EXPECT().GetAccessTokenSession(gomock.Any(), gomock.Any(), gomock.Any()).Return(ar, nil)
				ar.EXPECT().GetID()
				ar.EXPECT().GetClient().Return(&oauth2.DefaultClient{ID: "bar"})
				store.EXPECT().RevokeRefreshToken(gomock.Any(), gomock.Any())
				store.EXPECT().RevokeAccessToken(gomock.Any(), gomock.Any())
			},
		},
		{
			description: "should pass - refresh token discovery first; refresh token not found",
			expectErr:   nil,
			client:      &oauth2.DefaultClient{ID: "bar"},
			mock: func() {
				token = "foo"
				tokenType = oauth2.AccessToken
				atStrat.EXPECT().AccessTokenSignature(gomock.Any(), token)
				store.EXPECT().GetAccessTokenSession(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, oauth2.ErrNotFound)

				rtStrat.EXPECT().RefreshTokenSignature(gomock.Any(), token)
				store.EXPECT().GetRefreshTokenSession(gomock.Any(), gomock.Any(), gomock.Any()).Return(ar, nil)
				ar.EXPECT().GetID()
				ar.EXPECT().GetClient().Return(&oauth2.DefaultClient{ID: "bar"})
				store.EXPECT().RevokeRefreshToken(gomock.Any(), gomock.Any())
				store.EXPECT().RevokeAccessToken(gomock.Any(), gomock.Any())
			},
		},
		{
			description: "should pass - access token discovery first; access token not found",
			expectErr:   nil,
			client:      &oauth2.DefaultClient{ID: "bar"},
			mock: func() {
				token = "foo"
				tokenType = oauth2.RefreshToken
				rtStrat.EXPECT().RefreshTokenSignature(gomock.Any(), token)
				store.EXPECT().GetRefreshTokenSession(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, oauth2.ErrNotFound)

				atStrat.EXPECT().AccessTokenSignature(gomock.Any(), token)
				store.EXPECT().GetAccessTokenSession(gomock.Any(), gomock.Any(), gomock.Any()).Return(ar, nil)
				ar.EXPECT().GetID()
				ar.EXPECT().GetClient().Return(&oauth2.DefaultClient{ID: "bar"})
				store.EXPECT().RevokeRefreshToken(gomock.Any(), gomock.Any())
				store.EXPECT().RevokeAccessToken(gomock.Any(), gomock.Any())
			},
		},
		{
			description: "should pass - refresh token discovery first; both tokens not found",
			expectErr:   nil,
			client:      &oauth2.DefaultClient{ID: "bar"},
			mock: func() {
				token = "foo"
				tokenType = oauth2.RefreshToken
				rtStrat.EXPECT().RefreshTokenSignature(gomock.Any(), token)
				store.EXPECT().GetRefreshTokenSession(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, oauth2.ErrNotFound)

				atStrat.EXPECT().AccessTokenSignature(gomock.Any(), token)
				store.EXPECT().GetAccessTokenSession(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, oauth2.ErrNotFound)
			},
		},
		{
			description: "should pass - access token discovery first; both tokens not found",
			expectErr:   nil,
			client:      &oauth2.DefaultClient{ID: "bar"},
			mock: func() {
				token = "foo"
				tokenType = oauth2.AccessToken
				atStrat.EXPECT().AccessTokenSignature(gomock.Any(), token)
				store.EXPECT().GetAccessTokenSession(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, oauth2.ErrNotFound)

				rtStrat.EXPECT().RefreshTokenSignature(gomock.Any(), token)
				store.EXPECT().GetRefreshTokenSession(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, oauth2.ErrNotFound)
			},
		},
		{

			description: "should pass - refresh token discovery first; refresh token is inactive",
			expectErr:   nil,
			client:      &oauth2.DefaultClient{ID: "bar"},
			mock: func() {
				token = "foo"
				tokenType = oauth2.RefreshToken
				rtStrat.EXPECT().RefreshTokenSignature(gomock.Any(), token)
				store.EXPECT().GetRefreshTokenSession(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, oauth2.ErrInactiveToken)

				atStrat.EXPECT().AccessTokenSignature(gomock.Any(), token)
				store.EXPECT().GetAccessTokenSession(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, oauth2.ErrNotFound)
			},
		},
		{
			description: "should pass - access token discovery first; refresh token is inactive",
			expectErr:   nil,
			client:      &oauth2.DefaultClient{ID: "bar"},
			mock: func() {
				token = "foo"
				tokenType = oauth2.AccessToken
				atStrat.EXPECT().AccessTokenSignature(gomock.Any(), token)
				store.EXPECT().GetAccessTokenSession(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, oauth2.ErrNotFound)

				rtStrat.EXPECT().RefreshTokenSignature(gomock.Any(), token)
				store.EXPECT().GetRefreshTokenSession(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, oauth2.ErrInactiveToken)
			},
		},
		{
			description: "should fail - store error for access token get",
			expectErr:   oauth2.ErrTemporarilyUnavailable,
			client:      &oauth2.DefaultClient{ID: "bar"},
			mock: func() {
				token = "foo"
				tokenType = oauth2.AccessToken
				atStrat.EXPECT().AccessTokenSignature(gomock.Any(), token)
				store.EXPECT().GetAccessTokenSession(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, fmt.Errorf("random error"))

				rtStrat.EXPECT().RefreshTokenSignature(gomock.Any(), token)
				store.EXPECT().GetRefreshTokenSession(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, oauth2.ErrNotFound)
			},
		},
		{
			description: "should fail - store error for refresh token get",
			expectErr:   oauth2.ErrTemporarilyUnavailable,
			client:      &oauth2.DefaultClient{ID: "bar"},
			mock: func() {
				token = "foo"
				tokenType = oauth2.RefreshToken
				atStrat.EXPECT().AccessTokenSignature(gomock.Any(), token)
				store.EXPECT().GetAccessTokenSession(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, oauth2.ErrNotFound)

				rtStrat.EXPECT().RefreshTokenSignature(gomock.Any(), token)
				store.EXPECT().GetRefreshTokenSession(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, fmt.Errorf("random error"))
			},
		},
		{
			description: "should fail - store error for access token revoke",
			expectErr:   oauth2.ErrTemporarilyUnavailable,
			client:      &oauth2.DefaultClient{ID: "bar"},
			mock: func() {
				token = "foo"
				tokenType = oauth2.AccessToken
				atStrat.EXPECT().AccessTokenSignature(gomock.Any(), token)
				store.EXPECT().GetAccessTokenSession(gomock.Any(), gomock.Any(), gomock.Any()).Return(ar, nil)

				ar.EXPECT().GetID()
				ar.EXPECT().GetClient().Return(&oauth2.DefaultClient{ID: "bar"})
				store.EXPECT().RevokeRefreshToken(gomock.Any(), gomock.Any()).Return(oauth2.ErrNotFound)
				store.EXPECT().RevokeAccessToken(gomock.Any(), gomock.Any()).Return(fmt.Errorf("random error"))
			},
		},
		{
			description: "should fail - store error for refresh token revoke",
			expectErr:   oauth2.ErrTemporarilyUnavailable,
			client:      &oauth2.DefaultClient{ID: "bar"},
			mock: func() {
				token = "foo"
				tokenType = oauth2.RefreshToken
				rtStrat.EXPECT().RefreshTokenSignature(gomock.Any(), token)
				store.EXPECT().GetRefreshTokenSession(gomock.Any(), gomock.Any(), gomock.Any()).Return(ar, nil)

				ar.EXPECT().GetID()
				ar.EXPECT().GetClient().Return(&oauth2.DefaultClient{ID: "bar"})
				store.EXPECT().RevokeRefreshToken(gomock.Any(), gomock.Any()).Return(fmt.Errorf("random error"))
				store.EXPECT().RevokeAccessToken(gomock.Any(), gomock.Any()).Return(oauth2.ErrNotFound)
			},
		},
	} {
		t.Run(fmt.Sprintf("case=%d/description=%s", k, c.description), func(t *testing.T) {
			c.mock()
			err := h.RevokeToken(context.TODO(), token, tokenType, c.client)

			if c.expectErr != nil {
				require.EqualError(t, err, c.expectErr.Error())
			} else {
				require.NoError(t, err)
			}
		})
	}
}
