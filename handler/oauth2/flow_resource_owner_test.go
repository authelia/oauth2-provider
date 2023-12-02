// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/authelia/goauth2"
	"github.com/authelia/goauth2/internal"
)

func TestResourceOwnerFlow_HandleTokenEndpointRequest(t *testing.T) {
	ctrl := gomock.NewController(t)
	store := internal.NewMockResourceOwnerPasswordCredentialsGrantStorage(ctrl)
	defer ctrl.Finish()

	areq := goauth2.NewAccessRequest(new(goauth2.DefaultSession))
	areq.Form = url.Values{}
	for k, c := range []struct {
		description string
		setup       func(config *goauth2.Config)
		expectErr   error
		check       func(areq *goauth2.AccessRequest)
	}{
		{
			description: "should fail because not responsible",
			expectErr:   goauth2.ErrUnknownRequest,
			setup: func(config *goauth2.Config) {
				areq.GrantTypes = goauth2.Arguments{"123"}
			},
		},
		{
			description: "should fail because scope missing",
			setup: func(config *goauth2.Config) {
				areq.GrantTypes = goauth2.Arguments{"password"}
				areq.Client = &goauth2.DefaultClient{GrantTypes: goauth2.Arguments{"password"}, Scopes: []string{}}
				areq.RequestedScope = []string{"foo-scope"}
			},
			expectErr: goauth2.ErrInvalidScope,
		},
		{
			description: "should fail because audience missing",
			setup: func(config *goauth2.Config) {
				areq.RequestedAudience = goauth2.Arguments{"https://www.ory.sh/api"}
				areq.Client = &goauth2.DefaultClient{GrantTypes: goauth2.Arguments{"password"}, Scopes: []string{"foo-scope"}}
			},
			expectErr: goauth2.ErrInvalidRequest,
		},
		{
			description: "should fail because invalid grant_type specified",
			setup: func(config *goauth2.Config) {
				areq.GrantTypes = goauth2.Arguments{"password"}
				areq.Client = &goauth2.DefaultClient{GrantTypes: goauth2.Arguments{"authorization_code"}, Scopes: []string{"foo-scope"}}
			},
			expectErr: goauth2.ErrUnauthorizedClient,
		},
		{
			description: "should fail because invalid credentials",
			setup: func(config *goauth2.Config) {
				areq.Form.Set("username", "peter")
				areq.Form.Set("password", "pan")
				areq.Client = &goauth2.DefaultClient{GrantTypes: goauth2.Arguments{"password"}, Scopes: []string{"foo-scope"}, Audience: []string{"https://www.ory.sh/api"}}

				store.EXPECT().Authenticate(nil, "peter", "pan").Return(goauth2.ErrNotFound)
			},
			expectErr: goauth2.ErrInvalidGrant,
		},
		{
			description: "should fail because error on lookup",
			setup: func(config *goauth2.Config) {
				store.EXPECT().Authenticate(nil, "peter", "pan").Return(errors.New(""))
			},
			expectErr: goauth2.ErrServerError,
		},
		{
			description: "should pass",
			setup: func(config *goauth2.Config) {
				store.EXPECT().Authenticate(nil, "peter", "pan").Return(nil)
			},
			check: func(areq *goauth2.AccessRequest) {
				//assert.NotEmpty(t, areq.GetSession().GetExpiresAt(goauth2.AccessToken))
				assert.Equal(t, time.Now().Add(time.Hour).UTC().Round(time.Second), areq.GetSession().GetExpiresAt(goauth2.AccessToken))
				assert.Equal(t, time.Now().Add(time.Hour).UTC().Round(time.Second), areq.GetSession().GetExpiresAt(goauth2.RefreshToken))
			},
		},
	} {
		t.Run(fmt.Sprintf("case=%d/description=%s", k, c.description), func(t *testing.T) {
			config := &goauth2.Config{
				AccessTokenLifespan:      time.Hour,
				RefreshTokenLifespan:     time.Hour,
				ScopeStrategy:            goauth2.HierarchicScopeStrategy,
				AudienceMatchingStrategy: goauth2.DefaultAudienceMatchingStrategy,
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
			err := h.HandleTokenEndpointRequest(nil, areq)

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
	store := internal.NewMockResourceOwnerPasswordCredentialsGrantStorage(ctrl)
	chgen := internal.NewMockAccessTokenStrategy(ctrl)
	rtstr := internal.NewMockRefreshTokenStrategy(ctrl)
	mockAT := "accesstoken.foo.bar"
	mockRT := "refreshtoken.bar.foo"
	defer ctrl.Finish()

	var areq *goauth2.AccessRequest
	var aresp *goauth2.AccessResponse
	config := &goauth2.Config{}
	var h ResourceOwnerPasswordCredentialsGrantHandler
	h.Config = config

	for k, c := range []struct {
		description string
		setup       func(*goauth2.Config)
		expectErr   error
		expect      func()
	}{
		{
			description: "should fail because not responsible",
			expectErr:   goauth2.ErrUnknownRequest,
			setup: func(config *goauth2.Config) {
				areq.GrantTypes = goauth2.Arguments{""}
			},
		},
		{
			description: "should pass",
			setup: func(config *goauth2.Config) {
				areq.GrantTypes = goauth2.Arguments{"password"}
				chgen.EXPECT().GenerateAccessToken(nil, areq).Return(mockAT, "bar", nil)
				store.EXPECT().CreateAccessTokenSession(nil, "bar", gomock.Eq(areq.Sanitize([]string{}))).Return(nil)
			},
			expect: func() {
				assert.Nil(t, aresp.GetExtra("refresh_token"), "unexpected refresh token")
			},
		},
		{
			description: "should pass - offline scope",
			setup: func(config *goauth2.Config) {
				areq.GrantTypes = goauth2.Arguments{"password"}
				areq.GrantScope("offline")
				rtstr.EXPECT().GenerateRefreshToken(nil, areq).Return(mockRT, "bar", nil)
				store.EXPECT().CreateRefreshTokenSession(nil, "bar", gomock.Eq(areq.Sanitize([]string{}))).Return(nil)
				chgen.EXPECT().GenerateAccessToken(nil, areq).Return(mockAT, "bar", nil)
				store.EXPECT().CreateAccessTokenSession(nil, "bar", gomock.Eq(areq.Sanitize([]string{}))).Return(nil)
			},
			expect: func() {
				assert.NotNil(t, aresp.GetExtra("refresh_token"), "expected refresh token")
			},
		},
		{
			description: "should pass - refresh token without offline scope",
			setup: func(config *goauth2.Config) {
				config.RefreshTokenScopes = []string{}
				areq.GrantTypes = goauth2.Arguments{"password"}
				rtstr.EXPECT().GenerateRefreshToken(nil, areq).Return(mockRT, "bar", nil)
				store.EXPECT().CreateRefreshTokenSession(nil, "bar", gomock.Eq(areq.Sanitize([]string{}))).Return(nil)
				chgen.EXPECT().GenerateAccessToken(nil, areq).Return(mockAT, "bar", nil)
				store.EXPECT().CreateAccessTokenSession(nil, "bar", gomock.Eq(areq.Sanitize([]string{}))).Return(nil)
			},
			expect: func() {
				assert.NotNil(t, aresp.GetExtra("refresh_token"), "expected refresh token")
			},
		},
	} {
		t.Run(fmt.Sprintf("case=%d", k), func(t *testing.T) {
			areq = goauth2.NewAccessRequest(nil)
			aresp = goauth2.NewAccessResponse()
			areq.Session = &goauth2.DefaultSession{}
			config := &goauth2.Config{
				RefreshTokenScopes:  []string{"offline"},
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
			err := h.PopulateTokenEndpointResponse(nil, areq, aresp)
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
