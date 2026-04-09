// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
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
	testCases := []struct {
		name string
		mock func(areq *mock.MockAccessRequester)
		err  string
	}{
		{
			name: "ShouldFailNotResponsible",
			err:  "The handler is not responsible for this request.",
			mock: func(areq *mock.MockAccessRequester) {
				areq.EXPECT().GetGrantTypes().Return(oauth2.Arguments{""})
			},
		},
		{
			name: "ShouldFailAudienceNotValid",
			err:  "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Requested audience 'https://www.authelia.com/not-api' has not been whitelisted by the OAuth 2.0 Client.",
			mock: func(areq *mock.MockAccessRequester) {
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
			name: "ShouldFailScopeNotValid",
			err:  "The requested scope is invalid, unknown, or malformed. The OAuth 2.0 Client is not allowed to request scope 'bar'.",
			mock: func(areq *mock.MockAccessRequester) {
				areq.EXPECT().GetGrantTypes().Return(oauth2.Arguments{consts.GrantTypeClientCredentials})
				areq.EXPECT().GetRequestedScopes().Return([]string{"foo", "bar", "baz.bar"})
				areq.EXPECT().GetClient().Return(&oauth2.DefaultClient{
					GrantTypes: oauth2.Arguments{consts.GrantTypeClientCredentials},
					Scopes:     []string{"foo"},
				})
			},
		},
		{
			name: "ShouldPass",
			mock: func(areq *mock.MockAccessRequester) {
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
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tc.mock(areq)
			err := h.HandleTokenEndpointRequest(t.Context(), areq)
			if tc.err != "" {
				require.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), tc.err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestClientCredentials_PopulateTokenEndpointResponse(t *testing.T) {
	testCases := []struct {
		name string
		mock func(areq *oauth2.AccessRequest, store *mock.MockClientCredentialsGrantStorage, chgen *mock.MockAccessTokenStrategy)
		err  string
	}{
		{
			name: "ShouldFailNotResponsible",
			err:  "The handler is not responsible for this request.",
			mock: func(areq *oauth2.AccessRequest, store *mock.MockClientCredentialsGrantStorage, chgen *mock.MockAccessTokenStrategy) {
				areq.GrantTypes = oauth2.Arguments{""}
			},
		},
		{
			name: "ShouldFailGrantTypeNotAllowed",
			err:  "The client is not authorized to request a token using this method. The OAuth 2.0 Client is not allowed to use authorization grant 'client_credentials'.",
			mock: func(areq *oauth2.AccessRequest, store *mock.MockClientCredentialsGrantStorage, chgen *mock.MockAccessTokenStrategy) {
				areq.GrantTypes = oauth2.Arguments{consts.GrantTypeClientCredentials}
				areq.Client = &oauth2.DefaultClient{GrantTypes: oauth2.Arguments{consts.GrantTypeAuthorizationCode}}
			},
		},
		{
			name: "ShouldPass",
			mock: func(areq *oauth2.AccessRequest, store *mock.MockClientCredentialsGrantStorage, chgen *mock.MockAccessTokenStrategy) {
				areq.GrantTypes = oauth2.Arguments{consts.GrantTypeClientCredentials}
				areq.Session = &oauth2.DefaultSession{}
				areq.Client = &oauth2.DefaultClient{GrantTypes: oauth2.Arguments{consts.GrantTypeClientCredentials}}
				chgen.EXPECT().GenerateAccessToken(gomock.Any(), areq).Return("tokenfoo.bar", "bar", nil)
				store.EXPECT().CreateAccessTokenSession(gomock.Any(), "bar", gomock.Eq(areq.Sanitize([]string{}))).Return(nil)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			store := mock.NewMockClientCredentialsGrantStorage(ctrl)
			chgen := mock.NewMockAccessTokenStrategy(ctrl)
			areq := oauth2.NewAccessRequest(new(oauth2.DefaultSession))
			aresp := oauth2.NewAccessResponse()

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

			tc.mock(areq, store, chgen)
			err := h.PopulateTokenEndpointResponse(t.Context(), areq, aresp)
			if tc.err != "" {
				require.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), tc.err)
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

			err := handler.HandleTokenEndpointRequest(t.Context(), tc.have)

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
