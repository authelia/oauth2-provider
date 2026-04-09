// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
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
	testCases := []struct {
		name  string
		setup func(areq *oauth2.AccessRequest, store *mock.MockResourceOwnerPasswordCredentialsGrantStorage, config *oauth2.Config)
		err   string
		check func(t *testing.T, areq *oauth2.AccessRequest)
	}{
		{
			name: "ShouldFailNotResponsible",
			err:  "The handler is not responsible for this request.",
			setup: func(areq *oauth2.AccessRequest, store *mock.MockResourceOwnerPasswordCredentialsGrantStorage, config *oauth2.Config) {
				areq.GrantTypes = oauth2.Arguments{"123"}
			},
		},
		{
			name: "ShouldFailScopeMissing",
			setup: func(areq *oauth2.AccessRequest, store *mock.MockResourceOwnerPasswordCredentialsGrantStorage, config *oauth2.Config) {
				areq.GrantTypes = oauth2.Arguments{consts.GrantTypeResourceOwnerPasswordCredentials}
				areq.Client = &oauth2.DefaultClient{GrantTypes: oauth2.Arguments{consts.GrantTypeResourceOwnerPasswordCredentials}, Scopes: []string{}}
				areq.RequestedScope = []string{"foo-scope"}
			},
			err: "The requested scope is invalid, unknown, or malformed. The OAuth 2.0 Client is not allowed to request scope 'foo-scope'.",
		},
		{
			name: "ShouldFailAudienceMissing",
			setup: func(areq *oauth2.AccessRequest, store *mock.MockResourceOwnerPasswordCredentialsGrantStorage, config *oauth2.Config) {
				areq.GrantTypes = oauth2.Arguments{consts.GrantTypeResourceOwnerPasswordCredentials}
				areq.RequestedAudience = oauth2.Arguments{"https://www.authelia.com/api"}
				areq.Client = &oauth2.DefaultClient{GrantTypes: oauth2.Arguments{consts.GrantTypeResourceOwnerPasswordCredentials}, Scopes: []string{"foo-scope"}}
			},
			err: "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Requested audience 'https://www.authelia.com/api' has not been whitelisted by the OAuth 2.0 Client.",
		},
		{
			name: "ShouldFailInvalidGrantTypeSpecified",
			setup: func(areq *oauth2.AccessRequest, store *mock.MockResourceOwnerPasswordCredentialsGrantStorage, config *oauth2.Config) {
				areq.GrantTypes = oauth2.Arguments{consts.GrantTypeResourceOwnerPasswordCredentials}
				areq.Client = &oauth2.DefaultClient{GrantTypes: oauth2.Arguments{consts.GrantTypeAuthorizationCode}, Scopes: []string{"foo-scope"}}
			},
			err: "The client is not authorized to request a token using this method. The client is not allowed to use authorization grant 'password'.",
		},
		{
			name: "ShouldFailInvalidCredentials",
			setup: func(areq *oauth2.AccessRequest, store *mock.MockResourceOwnerPasswordCredentialsGrantStorage, config *oauth2.Config) {
				areq.GrantTypes = oauth2.Arguments{consts.GrantTypeResourceOwnerPasswordCredentials}
				areq.Form.Set(consts.FormParameterUsername, "peter")
				areq.Form.Set(consts.FormParameterPassword, "pan")
				areq.Client = &oauth2.DefaultClient{GrantTypes: oauth2.Arguments{consts.GrantTypeResourceOwnerPasswordCredentials}, Scopes: []string{"foo-scope"}, Audience: []string{"https://www.authelia.com/api"}}

				store.EXPECT().Authenticate(gomock.Any(), "peter", "pan").Return(oauth2.ErrNotFound)
			},
			err: "The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client. Unable to authenticate the provided username and password credentials. Could not find the requested resource(s).",
		},
		{
			name: "ShouldFailErrorOnLookup",
			setup: func(areq *oauth2.AccessRequest, store *mock.MockResourceOwnerPasswordCredentialsGrantStorage, config *oauth2.Config) {
				areq.GrantTypes = oauth2.Arguments{consts.GrantTypeResourceOwnerPasswordCredentials}
				areq.Form.Set(consts.FormParameterUsername, "peter")
				areq.Form.Set(consts.FormParameterPassword, "pan")
				areq.Client = &oauth2.DefaultClient{GrantTypes: oauth2.Arguments{consts.GrantTypeResourceOwnerPasswordCredentials}, Scopes: []string{"foo-scope"}, Audience: []string{"https://www.authelia.com/api"}}

				store.EXPECT().Authenticate(gomock.Any(), "peter", "pan").Return(errors.New(""))
			},
			err: "The authorization server encountered an unexpected condition that prevented it from fulfilling the request.",
		},
		{
			name: "ShouldPass",
			setup: func(areq *oauth2.AccessRequest, store *mock.MockResourceOwnerPasswordCredentialsGrantStorage, config *oauth2.Config) {
				areq.GrantTypes = oauth2.Arguments{consts.GrantTypeResourceOwnerPasswordCredentials}
				areq.Form.Set(consts.FormParameterUsername, "peter")
				areq.Form.Set(consts.FormParameterPassword, "pan")
				areq.Client = &oauth2.DefaultClient{GrantTypes: oauth2.Arguments{consts.GrantTypeResourceOwnerPasswordCredentials}, Scopes: []string{"foo-scope"}, Audience: []string{"https://www.authelia.com/api"}}

				store.EXPECT().Authenticate(gomock.Any(), "peter", "pan").Return(nil)
			},
			check: func(t *testing.T, areq *oauth2.AccessRequest) {
				assert.Equal(t, time.Now().Add(time.Hour).UTC().Truncate(jwt.TimePrecision), areq.GetSession().GetExpiresAt(oauth2.AccessToken))
				assert.Equal(t, time.Now().Add(time.Hour).UTC().Truncate(jwt.TimePrecision), areq.GetSession().GetExpiresAt(oauth2.RefreshToken))
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			store := mock.NewMockResourceOwnerPasswordCredentialsGrantStorage(ctrl)

			areq := oauth2.NewAccessRequest(new(oauth2.DefaultSession))
			areq.Form = url.Values{}

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
			tc.setup(areq, store, config)
			err := h.HandleTokenEndpointRequest(t.Context(), areq)

			if tc.err != "" {
				require.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), tc.err)
			} else {
				require.NoError(t, err)
				if tc.check != nil {
					tc.check(t, areq)
				}
			}
		})
	}
}

func TestResourceOwnerFlow_PopulateTokenEndpointResponse(t *testing.T) {
	mockAT := "accesstoken.foo.bar"
	mockRT := "refreshtoken.bar.foo"

	testCases := []struct {
		name   string
		setup  func(areq *oauth2.AccessRequest, store *mock.MockResourceOwnerPasswordCredentialsGrantStorage, chgen *mock.MockAccessTokenStrategy, rtstr *mock.MockRefreshTokenStrategy, config *oauth2.Config)
		err    string
		expect func(t *testing.T, aresp *oauth2.AccessResponse)
	}{
		{
			name: "ShouldFailNotResponsible",
			err:  "The handler is not responsible for this request.",
			setup: func(areq *oauth2.AccessRequest, store *mock.MockResourceOwnerPasswordCredentialsGrantStorage, chgen *mock.MockAccessTokenStrategy, rtstr *mock.MockRefreshTokenStrategy, config *oauth2.Config) {
				areq.GrantTypes = oauth2.Arguments{""}
			},
		},
		{
			name: "ShouldPass",
			setup: func(areq *oauth2.AccessRequest, store *mock.MockResourceOwnerPasswordCredentialsGrantStorage, chgen *mock.MockAccessTokenStrategy, rtstr *mock.MockRefreshTokenStrategy, config *oauth2.Config) {
				areq.GrantTypes = oauth2.Arguments{consts.GrantTypeResourceOwnerPasswordCredentials}
				chgen.EXPECT().GenerateAccessToken(t.Context(), areq).Return(mockAT, "bar", nil)
				store.EXPECT().CreateAccessTokenSession(t.Context(), "bar", gomock.Eq(areq.Sanitize([]string{}))).Return(nil)
			},
			expect: func(t *testing.T, aresp *oauth2.AccessResponse) {
				assert.Nil(t, aresp.GetExtra(consts.AccessResponseRefreshToken), "unexpected refresh token")
			},
		},
		{
			name: "ShouldPassOfflineScope",
			setup: func(areq *oauth2.AccessRequest, store *mock.MockResourceOwnerPasswordCredentialsGrantStorage, chgen *mock.MockAccessTokenStrategy, rtstr *mock.MockRefreshTokenStrategy, config *oauth2.Config) {
				areq.GrantTypes = oauth2.Arguments{consts.GrantTypeResourceOwnerPasswordCredentials}
				areq.GrantScope(consts.ScopeOffline)
				rtstr.EXPECT().GenerateRefreshToken(t.Context(), areq).Return(mockRT, "bar", nil)
				store.EXPECT().CreateRefreshTokenSession(t.Context(), "bar", gomock.Eq(areq.Sanitize([]string{}))).Return(nil)
				chgen.EXPECT().GenerateAccessToken(t.Context(), areq).Return(mockAT, "bar", nil)
				store.EXPECT().CreateAccessTokenSession(t.Context(), "bar", gomock.Eq(areq.Sanitize([]string{}))).Return(nil)
			},
			expect: func(t *testing.T, aresp *oauth2.AccessResponse) {
				assert.NotNil(t, aresp.GetExtra(consts.AccessResponseRefreshToken), "expected refresh token")
			},
		},
		{
			name: "ShouldPassRefreshTokenWithoutOfflineScope",
			setup: func(areq *oauth2.AccessRequest, store *mock.MockResourceOwnerPasswordCredentialsGrantStorage, chgen *mock.MockAccessTokenStrategy, rtstr *mock.MockRefreshTokenStrategy, config *oauth2.Config) {
				config.RefreshTokenScopes = []string{}
				areq.GrantTypes = oauth2.Arguments{consts.GrantTypeResourceOwnerPasswordCredentials}
				rtstr.EXPECT().GenerateRefreshToken(t.Context(), areq).Return(mockRT, "bar", nil)
				store.EXPECT().CreateRefreshTokenSession(t.Context(), "bar", gomock.Eq(areq.Sanitize([]string{}))).Return(nil)
				chgen.EXPECT().GenerateAccessToken(t.Context(), areq).Return(mockAT, "bar", nil)
				store.EXPECT().CreateAccessTokenSession(t.Context(), "bar", gomock.Eq(areq.Sanitize([]string{}))).Return(nil)
			},
			expect: func(t *testing.T, aresp *oauth2.AccessResponse) {
				assert.NotNil(t, aresp.GetExtra(consts.AccessResponseRefreshToken), "expected refresh token")
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			store := mock.NewMockResourceOwnerPasswordCredentialsGrantStorage(ctrl)
			chgen := mock.NewMockAccessTokenStrategy(ctrl)
			rtstr := mock.NewMockRefreshTokenStrategy(ctrl)

			areq := oauth2.NewAccessRequest(nil)
			aresp := oauth2.NewAccessResponse()
			areq.Session = &oauth2.DefaultSession{}
			config := &oauth2.Config{
				RefreshTokenScopes:  []string{consts.ScopeOffline},
				AccessTokenLifespan: time.Hour,
			}
			h := ResourceOwnerPasswordCredentialsGrantHandler{
				ResourceOwnerPasswordCredentialsGrantStorage: store,
				HandleHelper: &HandleHelper{
					AccessTokenStorage:  store,
					AccessTokenStrategy: chgen, Config: config,
				},
				RefreshTokenStrategy: rtstr, Config: config,
			}
			tc.setup(areq, store, chgen, rtstr, config)
			err := h.PopulateTokenEndpointResponse(t.Context(), areq, aresp)
			if tc.err != "" {
				assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), tc.err)
			} else {
				assert.NoError(t, err)
				if tc.expect != nil {
					tc.expect(t, aresp)
				}
			}
		})
	}
}
