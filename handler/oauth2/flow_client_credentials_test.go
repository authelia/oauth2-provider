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

	"github.com/authelia/goauth2"
	"github.com/authelia/goauth2/internal"
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
			Config: &goauth2.Config{
				AccessTokenLifespan: time.Hour,
			},
		},
		Config: &goauth2.Config{
			ScopeStrategy:            goauth2.HierarchicScopeStrategy,
			AudienceMatchingStrategy: goauth2.DefaultAudienceMatchingStrategy,
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
			expectErr:   goauth2.ErrUnknownRequest,
			mock: func() {
				areq.EXPECT().GetGrantTypes().Return(goauth2.Arguments{""})
			},
		},
		{
			description: "should fail because audience not valid",
			expectErr:   goauth2.ErrInvalidRequest,
			mock: func() {
				areq.EXPECT().GetGrantTypes().Return(goauth2.Arguments{"client_credentials"})
				areq.EXPECT().GetRequestedScopes().Return([]string{})
				areq.EXPECT().GetRequestedAudience().Return([]string{"https://www.ory.sh/not-api"})
				areq.EXPECT().GetClient().Return(&goauth2.DefaultClient{
					GrantTypes: goauth2.Arguments{"client_credentials"},
					Audience:   []string{"https://www.ory.sh/api"},
				})
			},
		},
		{
			description: "should fail because scope not valid",
			expectErr:   goauth2.ErrInvalidScope,
			mock: func() {
				areq.EXPECT().GetGrantTypes().Return(goauth2.Arguments{"client_credentials"})
				areq.EXPECT().GetRequestedScopes().Return([]string{"foo", "bar", "baz.bar"})
				areq.EXPECT().GetClient().Return(&goauth2.DefaultClient{
					GrantTypes: goauth2.Arguments{"client_credentials"},
					Scopes:     []string{"foo"},
				})
			},
		},
		{
			description: "should pass",
			mock: func() {
				areq.EXPECT().GetSession().Return(new(goauth2.DefaultSession))
				areq.EXPECT().GetGrantTypes().Return(goauth2.Arguments{"client_credentials"})
				areq.EXPECT().GetRequestedScopes().Return([]string{"foo", "bar", "baz.bar"})
				areq.EXPECT().GetRequestedAudience().Return([]string{})
				areq.EXPECT().GetClient().Return(&goauth2.DefaultClient{
					GrantTypes: goauth2.Arguments{"client_credentials"},
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
	areq := goauth2.NewAccessRequest(new(goauth2.DefaultSession))
	aresp := goauth2.NewAccessResponse()
	defer ctrl.Finish()

	h := ClientCredentialsGrantHandler{
		HandleHelper: &HandleHelper{
			AccessTokenStorage:  store,
			AccessTokenStrategy: chgen,
			Config: &goauth2.Config{
				AccessTokenLifespan: time.Hour,
			},
		},
		Config: &goauth2.Config{
			ScopeStrategy: goauth2.HierarchicScopeStrategy,
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
			expectErr:   goauth2.ErrUnknownRequest,
			mock: func() {
				areq.GrantTypes = goauth2.Arguments{""}
			},
		},
		{
			description: "should fail because grant_type not allowed",
			expectErr:   goauth2.ErrUnauthorizedClient,
			mock: func() {
				areq.GrantTypes = goauth2.Arguments{"client_credentials"}
				areq.Client = &goauth2.DefaultClient{GrantTypes: goauth2.Arguments{"authorization_code"}}
			},
		},
		{
			description: "should pass",
			mock: func() {
				areq.GrantTypes = goauth2.Arguments{"client_credentials"}
				areq.Session = &goauth2.DefaultSession{}
				areq.Client = &goauth2.DefaultClient{GrantTypes: goauth2.Arguments{"client_credentials"}}
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
