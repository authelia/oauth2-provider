// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/testing/mock"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestResourceOwnerFlow_HandleTokenEndpointRequest(t *testing.T) {
	ctrl := gomock.NewController(t)
	store := mock.NewMockResourceOwnerPasswordCredentialsGrantStorage(ctrl)
	defer ctrl.Finish()

	areq := oauth2.NewAccessRequest(new(oauth2.DefaultSession))
	areq.Form = url.Values{}
	for k, c := range []struct {
		description string
		setup       func(config *oauth2.Config)
		expectErr   error
		check       func(areq *oauth2.AccessRequest)
	}{
		{
			description: "should fail because not responsible",
			expectErr:   oauth2.ErrUnknownRequest,
			setup: func(config *oauth2.Config) {
				areq.GrantTypes = oauth2.Arguments{"123"}
			},
		},
		{
			description: "should fail because scope missing",
			setup: func(config *oauth2.Config) {
				areq.GrantTypes = oauth2.Arguments{consts.GrantTypeResourceOwnerPasswordCredentials}
				areq.Client = &oauth2.DefaultClient{GrantTypes: oauth2.Arguments{consts.GrantTypeResourceOwnerPasswordCredentials}, Scopes: []string{}}
				areq.RequestedScope = []string{"foo-scope"}
			},
			expectErr: oauth2.ErrInvalidScope,
		},
		{
			description: "should fail because audience missing",
			setup: func(config *oauth2.Config) {
				areq.RequestedAudience = oauth2.Arguments{"https://www.authelia.com/api"}
				areq.Client = &oauth2.DefaultClient{GrantTypes: oauth2.Arguments{consts.GrantTypeResourceOwnerPasswordCredentials}, Scopes: []string{"foo-scope"}}
			},
			expectErr: oauth2.ErrInvalidRequest,
		},
		{
			description: "should fail because invalid grant_type specified",
			setup: func(config *oauth2.Config) {
				areq.GrantTypes = oauth2.Arguments{consts.GrantTypeResourceOwnerPasswordCredentials}
				areq.Client = &oauth2.DefaultClient{GrantTypes: oauth2.Arguments{consts.GrantTypeAuthorizationCode}, Scopes: []string{"foo-scope"}}
			},
			expectErr: oauth2.ErrUnauthorizedClient,
		},
		{
			description: "should fail because invalid credentials",
			setup: func(config *oauth2.Config) {
				areq.Form.Set(consts.FormParameterUsername, "peter")
				areq.Form.Set(consts.FormParameterPassword, "pan")
				areq.Client = &oauth2.DefaultClient{GrantTypes: oauth2.Arguments{consts.GrantTypeResourceOwnerPasswordCredentials}, Scopes: []string{"foo-scope"}, Audience: []string{"https://www.authelia.com/api"}}

				store.EXPECT().Authenticate(context.TODO(), "peter", "pan").Return(oauth2.ErrNotFound)
			},
			expectErr: oauth2.ErrInvalidGrant,
		},
		{
			description: "should fail because error on lookup",
			setup: func(config *oauth2.Config) {
				store.EXPECT().Authenticate(context.TODO(), "peter", "pan").Return(errors.New(""))
			},
			expectErr: oauth2.ErrServerError,
		},
		{
			description: "should pass",
			setup: func(config *oauth2.Config) {
				store.EXPECT().Authenticate(context.TODO(), "peter", "pan").Return(nil)
			},
			check: func(areq *oauth2.AccessRequest) {
				assert.Equal(t, time.Now().Add(time.Hour).UTC().Truncate(jwt.TimePrecision), areq.GetSession().GetExpiresAt(oauth2.AccessToken))
				assert.Equal(t, time.Now().Add(time.Hour).UTC().Truncate(jwt.TimePrecision), areq.GetSession().GetExpiresAt(oauth2.RefreshToken))
			},
		},
	} {
		t.Run(fmt.Sprintf("case=%d/description=%s", k, c.description), func(t *testing.T) {
			config := &oauth2.Config{
				AccessTokenLifespan:      time.Hour,
				RefreshTokenLifespan:     time.Hour,
				ScopeStrategy:            oauth2.HierarchicScopeStrategy,
				AudienceMatchingStrategy: oauth2.DefaultAudienceMatchingStrategy,
			}
			h := ResourceOwnerPasswordCredentialsGrantHandler{
				ResourceOwnerPasswordCredentialsGrantStorage: store,
				HandleHelper: &HandleHelper{
					AccessTokenStorage: store,
					Config:             config,
				},
				Config: config,
			}
			c.setup(config)
			err := h.HandleTokenEndpointRequest(context.TODO(), areq)

			if c.expectErr != nil {
				require.EqualError(t, err, c.expectErr.Error())
			} else {
				require.NoError(t, err)
				if c.check != nil {
					c.check(areq)
				}
			}
		})
	}
}

func TestResourceOwnerFlow_PopulateTokenEndpointResponse(t *testing.T) {
	ctrl := gomock.NewController(t)
	store := mock.NewMockResourceOwnerPasswordCredentialsGrantStorage(ctrl)
	chgen := mock.NewMockAccessTokenStrategy(ctrl)
	rtstr := mock.NewMockRefreshTokenStrategy(ctrl)
	mockAT := "accesstoken.foo.bar"
	mockRT := "refreshtoken.bar.foo"
	defer ctrl.Finish()

	var areq *oauth2.AccessRequest
	var aresp *oauth2.AccessResponse
	config := &oauth2.Config{}
	var h ResourceOwnerPasswordCredentialsGrantHandler
	h.Config = config

	for k, c := range []struct {
		description string
		setup       func(*oauth2.Config)
		expectErr   error
		expect      func()
	}{
		{
			description: "should fail because not responsible",
			expectErr:   oauth2.ErrUnknownRequest,
			setup: func(config *oauth2.Config) {
				areq.GrantTypes = oauth2.Arguments{""}
			},
		},
		{
			description: "should pass",
			setup: func(config *oauth2.Config) {
				areq.GrantTypes = oauth2.Arguments{consts.GrantTypeResourceOwnerPasswordCredentials}
				chgen.EXPECT().GenerateAccessToken(context.TODO(), areq).Return(mockAT, "bar", nil)
				store.EXPECT().CreateAccessTokenSession(context.TODO(), "bar", gomock.Eq(areq.Sanitize([]string{}))).Return(nil)
			},
			expect: func() {
				assert.Nil(t, aresp.GetExtra(consts.AccessResponseRefreshToken), "unexpected refresh token")
			},
		},
		{
			description: "should pass - offline scope",
			setup: func(config *oauth2.Config) {
				areq.GrantTypes = oauth2.Arguments{consts.GrantTypeResourceOwnerPasswordCredentials}
				areq.GrantScope(consts.ScopeOffline)
				rtstr.EXPECT().GenerateRefreshToken(context.TODO(), areq).Return(mockRT, "bar", nil)
				store.EXPECT().CreateRefreshTokenSession(context.TODO(), "bar", gomock.Eq(areq.Sanitize([]string{}))).Return(nil)
				chgen.EXPECT().GenerateAccessToken(context.TODO(), areq).Return(mockAT, "bar", nil)
				store.EXPECT().CreateAccessTokenSession(context.TODO(), "bar", gomock.Eq(areq.Sanitize([]string{}))).Return(nil)
			},
			expect: func() {
				assert.NotNil(t, aresp.GetExtra(consts.AccessResponseRefreshToken), "expected refresh token")
			},
		},
		{
			description: "should pass - refresh token without offline scope",
			setup: func(config *oauth2.Config) {
				config.RefreshTokenScopes = []string{}
				areq.GrantTypes = oauth2.Arguments{consts.GrantTypeResourceOwnerPasswordCredentials}
				rtstr.EXPECT().GenerateRefreshToken(context.TODO(), areq).Return(mockRT, "bar", nil)
				store.EXPECT().CreateRefreshTokenSession(context.TODO(), "bar", gomock.Eq(areq.Sanitize([]string{}))).Return(nil)
				chgen.EXPECT().GenerateAccessToken(context.TODO(), areq).Return(mockAT, "bar", nil)
				store.EXPECT().CreateAccessTokenSession(context.TODO(), "bar", gomock.Eq(areq.Sanitize([]string{}))).Return(nil)
			},
			expect: func() {
				assert.NotNil(t, aresp.GetExtra(consts.AccessResponseRefreshToken), "expected refresh token")
			},
		},
	} {
		t.Run(fmt.Sprintf("case=%d", k), func(t *testing.T) {
			areq = oauth2.NewAccessRequest(nil)
			aresp = oauth2.NewAccessResponse()
			areq.Session = &oauth2.DefaultSession{}
			config := &oauth2.Config{
				RefreshTokenScopes:  []string{consts.ScopeOffline},
				AccessTokenLifespan: time.Hour,
			}
			h = ResourceOwnerPasswordCredentialsGrantHandler{
				ResourceOwnerPasswordCredentialsGrantStorage: store,
				HandleHelper: &HandleHelper{
					AccessTokenStorage:  store,
					AccessTokenStrategy: chgen, Config: config,
				},
				RefreshTokenStrategy: rtstr, Config: config,
			}
			c.setup(config)
			err := h.PopulateTokenEndpointResponse(context.TODO(), areq, aresp)
			if c.expectErr != nil {
				require.EqualError(t, err, c.expectErr.Error())
			} else {
				require.NoError(t, err)
				if c.expect != nil {
					c.expect()
				}
			}
		})
	}
}
