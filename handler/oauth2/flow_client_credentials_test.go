// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/testing/mock"
)

func TestClientCredentials_HandleTokenEndpointRequest(t *testing.T) {
	ctrl := gomock.NewController(t)
	store := mock.NewMockClientCredentialsGrantStorage(ctrl)
	chgen := mock.NewMockAccessTokenStrategy(ctrl)
	areq := mock.NewMockAccessRequester(ctrl)
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
				areq.EXPECT().GetRequestedAudience().Return([]string{"https://www.authelia.com/not-api"}).Times(2)
				areq.EXPECT().GetClient().Return(&oauth2.DefaultClient{
					GrantTypes: oauth2.Arguments{consts.GrantTypeClientCredentials},
					Audience:   []string{"https://www.authelia.com/api"},
				})
				areq.EXPECT().GetRequestForm().Return(url.Values{})
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
				areq.EXPECT().GetRequestForm().Return(url.Values{})
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
	store := mock.NewMockClientCredentialsGrantStorage(ctrl)
	chgen := mock.NewMockAccessTokenStrategy(ctrl)
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

func TestClientCredentialsGrantHandler_HandleTokenEndpointRequest(t *testing.T) {
	testCases := []struct {
		name     string
		have     oauth2.AccessRequester
		expected oauth2.AccessRequester
		err      string
	}{
		{
			"ShouldSuccessfullyNotGrantAnyAudience",
			&oauth2.AccessRequest{
				GrantTypes: oauth2.Arguments{consts.GrantTypeClientCredentials},
				Request: oauth2.Request{
					Session: &oauth2.DefaultSession{},
					Client: &TestRequestedAudienceClient{
						DefaultClient: &oauth2.DefaultClient{
							ID:         "test",
							GrantTypes: []string{consts.GrantTypeClientCredentials},
							Audience:   []string{"https://example.com"},
							Scopes:     []string{"openid"},
						},
					},
				},
			},
			&oauth2.AccessRequest{
				GrantTypes: oauth2.Arguments{consts.GrantTypeClientCredentials},
				Request:    oauth2.Request{},
			},
			"",
		},
		{
			"ShouldSuccessfullyRequestNoAudienceUnsupportedClient",
			&oauth2.AccessRequest{
				GrantTypes: oauth2.Arguments{consts.GrantTypeClientCredentials},
				Request: oauth2.Request{
					Session: &oauth2.DefaultSession{},
					Client: &oauth2.DefaultClient{
						ID:         "test",
						GrantTypes: []string{consts.GrantTypeClientCredentials},
						Audience:   []string{"https://example.com"},
						Scopes:     []string{"openid"},
					},
				},
			},
			&oauth2.AccessRequest{
				GrantTypes: oauth2.Arguments{consts.GrantTypeClientCredentials},
				Request:    oauth2.Request{},
			},
			"",
		},
		{
			"ShouldSuccessfullyGrantAllAudience",
			&oauth2.AccessRequest{
				GrantTypes: oauth2.Arguments{consts.GrantTypeClientCredentials},
				Request: oauth2.Request{
					Session: &oauth2.DefaultSession{},
					Client: &TestRequestedAudienceClient{
						DefaultClient: &oauth2.DefaultClient{
							ID:         "test",
							GrantTypes: []string{consts.GrantTypeClientCredentials},
							Audience:   []string{"https://example.com"},
							Scopes:     []string{"openid"},
						},
						audience: true,
					},
				},
			},
			&oauth2.AccessRequest{
				GrantTypes: oauth2.Arguments{consts.GrantTypeClientCredentials},
				Request: oauth2.Request{
					RequestedAudience: []string{"https://example.com"},
					GrantedAudience:   []string{"https://example.com"},
				},
			},
			"",
		},
		{
			"ShouldSuccessfullyGrantAllScopes",
			&oauth2.AccessRequest{
				GrantTypes: oauth2.Arguments{consts.GrantTypeClientCredentials},
				Request: oauth2.Request{
					Session: &oauth2.DefaultSession{},
					Client: &TestRequestedAudienceClient{
						DefaultClient: &oauth2.DefaultClient{
							ID:         "test",
							GrantTypes: []string{consts.GrantTypeClientCredentials},
							Audience:   []string{"https://exmaple.com"},
							Scopes:     []string{"openid"},
						},
						scopes: true,
					},
				},
			},
			&oauth2.AccessRequest{
				GrantTypes: oauth2.Arguments{consts.GrantTypeClientCredentials},
				Request: oauth2.Request{
					RequestedScope: []string{"openid"},
					GrantedScope:   []string{"openid"},
				},
			},
			"",
		},
		{
			"ShouldSuccessfullyGrantAllScopesAndAudiences",
			&oauth2.AccessRequest{
				GrantTypes: oauth2.Arguments{consts.GrantTypeClientCredentials},
				Request: oauth2.Request{
					Session: &oauth2.DefaultSession{},
					Client: &TestRequestedAudienceClient{
						DefaultClient: &oauth2.DefaultClient{
							ID:         "test",
							GrantTypes: []string{consts.GrantTypeClientCredentials},
							Audience:   []string{"https://exmaple.com"},
							Scopes:     []string{"openid"},
						},
						scopes:   true,
						audience: true,
					},
				},
			},
			&oauth2.AccessRequest{
				GrantTypes: oauth2.Arguments{consts.GrantTypeClientCredentials},
				Request: oauth2.Request{
					RequestedScope:    []string{"openid"},
					RequestedAudience: []string{"https://exmaple.com"},
					GrantedScope:      []string{"openid"},
					GrantedAudience:   []string{"https://exmaple.com"},
				},
			},
			"",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)

			defer ctrl.Finish()

			store := mock.NewMockClientCredentialsGrantStorage(ctrl)
			strategy := mock.NewMockAccessTokenStrategy(ctrl)

			strategy.EXPECT().GenerateAccessToken(context.Background(), gomock.Any()).Return("abc123.abc", "abc", nil)
			store.EXPECT().CreateAccessTokenSession(context.Background(), gomock.Any(), gomock.Any()).Return(nil)

			config := &oauth2.Config{
				AccessTokenLifespan:                         time.Hour,
				ClientCredentialsFlowImplicitGrantRequested: true,
				ScopeStrategy:                               oauth2.HierarchicScopeStrategy,
			}

			handler := ClientCredentialsGrantHandler{
				HandleHelper: &HandleHelper{
					AccessTokenStorage:  store,
					AccessTokenStrategy: strategy,
					Config:              config,
				},
				Config: config,
			}

			err := handler.HandleTokenEndpointRequest(context.TODO(), tc.have)

			assert.Equal(t, tc.expected.GetRequestedScopes(), tc.have.GetRequestedScopes())
			assert.Equal(t, tc.expected.GetRequestedAudience(), tc.have.GetRequestedAudience())
			assert.Equal(t, oauth2.Arguments(nil), tc.have.GetGrantedScopes())
			assert.Equal(t, oauth2.Arguments(nil), tc.have.GetGrantedAudience())

			if len(tc.err) == 0 {
				assert.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
			} else {
				assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), tc.err)
			}

			response := oauth2.NewAccessResponse()

			err = handler.PopulateTokenEndpointResponse(context.Background(), tc.have, response)

			assert.NoError(t, err)

			assert.Equal(t, tc.expected.GetGrantedScopes(), tc.have.GetGrantedScopes())
			assert.Equal(t, tc.expected.GetGrantedAudience(), tc.have.GetGrantedAudience())
		})
	}
}

type TestRequestedAudienceClient struct {
	*oauth2.DefaultClient

	audience bool
	scopes   bool
}

func (c *TestRequestedAudienceClient) GetRequestedAudienceImplicit() bool {
	return c.audience
}

func (c *TestRequestedAudienceClient) GetClientCredentialsFlowRequestedScopeImplicit() bool {
	return c.scopes
}
