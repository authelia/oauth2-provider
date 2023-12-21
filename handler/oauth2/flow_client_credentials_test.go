// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal"
	"authelia.com/provider/oauth2/internal/consts"
)

func TestClientCredentials_HandleTokenEndpointRequest(t *testing.T) {
	ctrl := gomock.NewController(t)
	store := internal.NewMockClientCredentialsGrantStorage(ctrl)
	chgen := internal.NewMockAccessTokenStrategy(ctrl)
	areq := internal.NewMockAccessRequester(ctrl)
	defer ctrl.Finish()

	h := ClientCredentialsGrantHandler{
		HandleHelper: &HandleHelper{
			AccessTokenStorage:  store,
			AccessTokenStrategy: chgen,
			Config: &oauth2.Config{
				AccessTokenLifespan: time.Hour,
			},
		},
		Config: &oauth2.Config{
			ScopeStrategy:            oauth2.HierarchicScopeStrategy,
			AudienceMatchingStrategy: oauth2.DefaultAudienceMatchingStrategy,
		},
	}
	for k, c := range []struct {
		description string
		mock        func()
		req         *http.Request
		expectErr   error
	}{
		{
			description: "should fail because not responsible",
			expectErr:   oauth2.ErrUnknownRequest,
			mock: func() {
				areq.EXPECT().GetGrantTypes().Return(oauth2.Arguments{""})
			},
		},
		{
			description: "should fail because audience not valid",
			expectErr:   oauth2.ErrInvalidRequest,
			mock: func() {
				areq.EXPECT().GetGrantTypes().Return(oauth2.Arguments{consts.GrantTypeClientCredentials})
				areq.EXPECT().GetRequestedScopes().Return([]string{})
				areq.EXPECT().GetRequestedAudience().Return([]string{"https://www.authelia.com/not-api"})
				areq.EXPECT().GetClient().Return(&oauth2.DefaultClient{
					GrantTypes: oauth2.Arguments{consts.GrantTypeClientCredentials},
					Audience:   []string{"https://www.authelia.com/api"},
				})
			},
		},
		{
			description: "should fail because scope not valid",
			expectErr:   oauth2.ErrInvalidScope,
			mock: func() {
				areq.EXPECT().GetGrantTypes().Return(oauth2.Arguments{consts.GrantTypeClientCredentials})
				areq.EXPECT().GetRequestedScopes().Return([]string{"foo", "bar", "baz.bar"})
				areq.EXPECT().GetClient().Return(&oauth2.DefaultClient{
					GrantTypes: oauth2.Arguments{consts.GrantTypeClientCredentials},
					Scopes:     []string{"foo"},
				})
			},
		},
		{
			description: "should pass",
			mock: func() {
				areq.EXPECT().GetSession().Return(new(oauth2.DefaultSession))
				areq.EXPECT().GetGrantTypes().Return(oauth2.Arguments{consts.GrantTypeClientCredentials})
				areq.EXPECT().GetRequestedScopes().Return([]string{"foo", "bar", "baz.bar"})
				areq.EXPECT().GetRequestedAudience().Return([]string{})
				areq.EXPECT().GetClient().Return(&oauth2.DefaultClient{
					GrantTypes: oauth2.Arguments{consts.GrantTypeClientCredentials},
					Scopes:     []string{"foo", "bar", "baz"},
				})
			},
		},
	} {
		t.Run(fmt.Sprintf("case=%d", k), func(t *testing.T) {
			c.mock()
			err := h.HandleTokenEndpointRequest(context.TODO(), areq)
			if c.expectErr != nil {
				require.EqualError(t, err, c.expectErr.Error())
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestClientCredentials_PopulateTokenEndpointResponse(t *testing.T) {
	ctrl := gomock.NewController(t)
	store := internal.NewMockClientCredentialsGrantStorage(ctrl)
	chgen := internal.NewMockAccessTokenStrategy(ctrl)
	areq := oauth2.NewAccessRequest(new(oauth2.DefaultSession))
	aresp := oauth2.NewAccessResponse()
	defer ctrl.Finish()

	h := ClientCredentialsGrantHandler{
		HandleHelper: &HandleHelper{
			AccessTokenStorage:  store,
			AccessTokenStrategy: chgen,
			Config: &oauth2.Config{
				AccessTokenLifespan: time.Hour,
			},
		},
		Config: &oauth2.Config{
			ScopeStrategy: oauth2.HierarchicScopeStrategy,
		},
	}
	for k, c := range []struct {
		description string
		mock        func()
		req         *http.Request
		expectErr   error
	}{
		{
			description: "should fail because not responsible",
			expectErr:   oauth2.ErrUnknownRequest,
			mock: func() {
				areq.GrantTypes = oauth2.Arguments{""}
			},
		},
		{
			description: "should fail because grant_type not allowed",
			expectErr:   oauth2.ErrUnauthorizedClient,
			mock: func() {
				areq.GrantTypes = oauth2.Arguments{consts.GrantTypeClientCredentials}
				areq.Client = &oauth2.DefaultClient{GrantTypes: oauth2.Arguments{consts.GrantTypeAuthorizationCode}}
			},
		},
		{
			description: "should pass",
			mock: func() {
				areq.GrantTypes = oauth2.Arguments{consts.GrantTypeClientCredentials}
				areq.Session = &oauth2.DefaultSession{}
				areq.Client = &oauth2.DefaultClient{GrantTypes: oauth2.Arguments{consts.GrantTypeClientCredentials}}
				chgen.EXPECT().GenerateAccessToken(context.TODO(), areq).Return("tokenfoo.bar", "bar", nil)
				store.EXPECT().CreateAccessTokenSession(context.TODO(), "bar", gomock.Eq(areq.Sanitize([]string{}))).Return(nil)
			},
		},
	} {
		t.Run(fmt.Sprintf("case=%d", k), func(t *testing.T) {
			c.mock()
			err := h.PopulateTokenEndpointResponse(context.TODO(), areq, aresp)
			if c.expectErr != nil {
				require.EqualError(t, err, c.expectErr.Error())
			} else {
				require.NoError(t, err)
			}
		})
	}
}
