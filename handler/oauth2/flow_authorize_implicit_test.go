// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/testing/mock"
)

func TestAuthorizeImplicit_EndpointHandler(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	areq := oauth2.NewAuthorizeRequest()
	areq.Session = new(oauth2.DefaultSession)
	h, store, chgen, aresp := makeAuthorizeImplicitGrantTypeHandler(ctrl)

	testCases := []struct {
		name  string
		setup func(areq *oauth2.AuthorizeRequest, store *mock.MockAccessTokenStorage, chgen *mock.MockAccessTokenStrategy, aresp *mock.MockAuthorizeResponder)
		err   string
	}{
		{
			name: "ShouldPassNotResponsibleForResponseType",
			setup: func(areq *oauth2.AuthorizeRequest, store *mock.MockAccessTokenStorage, chgen *mock.MockAccessTokenStrategy, aresp *mock.MockAuthorizeResponder) {
				areq.ResponseTypes = oauth2.Arguments{"a"}
			},
		},
		{
			name: "ShouldFailAccessTokenGenerationFailed",
			setup: func(areq *oauth2.AuthorizeRequest, store *mock.MockAccessTokenStorage, chgen *mock.MockAccessTokenStrategy, aresp *mock.MockAuthorizeResponder) {
				areq.ResponseTypes = oauth2.Arguments{consts.ResponseTypeImplicitFlowToken}
				areq.Client = &oauth2.DefaultClient{
					GrantTypes:    oauth2.Arguments{consts.GrantTypeImplicit},
					ResponseTypes: oauth2.Arguments{consts.ResponseTypeImplicitFlowToken},
				}
				chgen.EXPECT().GenerateAccessToken(t.Context(), areq).Return("", "", errors.New(""))
			},
			err: "The authorization server encountered an unexpected condition that prevented it from fulfilling the request.",
		},
		{
			name: "ShouldFailScopeInvalid",
			setup: func(areq *oauth2.AuthorizeRequest, store *mock.MockAccessTokenStorage, chgen *mock.MockAccessTokenStrategy, aresp *mock.MockAuthorizeResponder) {
				areq.ResponseTypes = oauth2.Arguments{consts.ResponseTypeImplicitFlowToken}
				areq.RequestedScope = oauth2.Arguments{"scope"}
				areq.Client = &oauth2.DefaultClient{
					GrantTypes:    oauth2.Arguments{consts.GrantTypeImplicit},
					ResponseTypes: oauth2.Arguments{consts.ResponseTypeImplicitFlowToken},
				}
			},
			err: "The requested scope is invalid, unknown, or malformed. The OAuth 2.0 Client is not allowed to request scope 'scope'.",
		},
		{
			name: "ShouldFailAudienceInvalid",
			setup: func(areq *oauth2.AuthorizeRequest, store *mock.MockAccessTokenStorage, chgen *mock.MockAccessTokenStrategy, aresp *mock.MockAuthorizeResponder) {
				areq.ResponseTypes = oauth2.Arguments{consts.ResponseTypeImplicitFlowToken}
				areq.RequestedScope = oauth2.Arguments{"scope"}
				areq.RequestedAudience = oauth2.Arguments{"https://www.authelia.com/not-api"}
				areq.Client = &oauth2.DefaultClient{
					GrantTypes:    oauth2.Arguments{consts.GrantTypeImplicit},
					ResponseTypes: oauth2.Arguments{consts.ResponseTypeImplicitFlowToken},
					Scopes:        []string{"scope"},
					Audience:      []string{"https://www.authelia.com/api"},
				}
			},
			err: "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Requested audience 'https://www.authelia.com/not-api' has not been whitelisted by the OAuth 2.0 Client.",
		},
		{
			name: "ShouldFailPersistenceFailed",
			setup: func(areq *oauth2.AuthorizeRequest, store *mock.MockAccessTokenStorage, chgen *mock.MockAccessTokenStrategy, aresp *mock.MockAuthorizeResponder) {
				areq.RequestedAudience = oauth2.Arguments{"https://www.authelia.com/api"}
				chgen.EXPECT().GenerateAccessToken(t.Context(), areq).AnyTimes().Return("access.ats", "ats", nil)
				store.EXPECT().CreateAccessTokenSession(t.Context(), "ats", gomock.Eq(areq.Sanitize([]string{}))).Return(errors.New(""))
			},
			err: "The authorization server encountered an unexpected condition that prevented it from fulfilling the request.",
		},
		{
			name: "ShouldPass",
			setup: func(areq *oauth2.AuthorizeRequest, store *mock.MockAccessTokenStorage, chgen *mock.MockAccessTokenStrategy, aresp *mock.MockAuthorizeResponder) {
				areq.State = "state"
				areq.GrantedScope = oauth2.Arguments{"scope"}

				store.EXPECT().CreateAccessTokenSession(t.Context(), "ats", gomock.Eq(areq.Sanitize([]string{}))).AnyTimes().Return(nil)

				aresp.EXPECT().AddParameter(consts.AccessResponseAccessToken, "access.ats")
				aresp.EXPECT().AddParameter(consts.AccessResponseExpiresIn, gomock.Any())
				aresp.EXPECT().AddParameter(consts.AccessResponseTokenType, oauth2.BearerAccessToken)
				aresp.EXPECT().AddParameter(consts.FormParameterState, "state")
				aresp.EXPECT().AddParameter(consts.FormParameterScope, "scope")
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tc.setup(areq, store, chgen, aresp)
			err := h.HandleAuthorizeEndpointRequest(t.Context(), areq, aresp)
			if tc.err != "" {
				require.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), tc.err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func makeAuthorizeImplicitGrantTypeHandler(ctrl *gomock.Controller) (AuthorizeImplicitGrantTypeHandler,
	*mock.MockAccessTokenStorage, *mock.MockAccessTokenStrategy, *mock.MockAuthorizeResponder) {
	store := mock.NewMockAccessTokenStorage(ctrl)
	chgen := mock.NewMockAccessTokenStrategy(ctrl)
	aresp := mock.NewMockAuthorizeResponder(ctrl)

	h := AuthorizeImplicitGrantTypeHandler{
		AccessTokenStorage:  store,
		AccessTokenStrategy: chgen,
		Config: &oauth2.Config{
			AccessTokenLifespan:      time.Hour,
			ScopeStrategy:            oauth2.HierarchicScopeStrategy,
			AudienceMatchingStrategy: oauth2.DefaultAudienceMatchingStrategy,
		},
	}

	return h, store, chgen, aresp
}

func TestDefaultResponseMode_AuthorizeImplicit_EndpointHandler(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	areq := oauth2.NewAuthorizeRequest()
	areq.Session = new(oauth2.DefaultSession)
	h, store, chgen, aresp := makeAuthorizeImplicitGrantTypeHandler(ctrl)

	areq.State = "state"
	areq.GrantedScope = oauth2.Arguments{"scope"}
	areq.ResponseTypes = oauth2.Arguments{consts.ResponseTypeImplicitFlowToken}
	areq.Client = &oauth2.DefaultClientWithCustomTokenLifespans{
		DefaultClient: &oauth2.DefaultClient{
			GrantTypes:    oauth2.Arguments{consts.GrantTypeImplicit},
			ResponseTypes: oauth2.Arguments{consts.ResponseTypeImplicitFlowToken},
		},
		TokenLifespans: &internal.TestLifespans,
	}

	store.EXPECT().CreateAccessTokenSession(t.Context(), "ats", gomock.Eq(areq.Sanitize([]string{}))).AnyTimes().Return(nil)
	aresp.EXPECT().AddParameter(consts.AccessResponseAccessToken, "access.ats")
	aresp.EXPECT().AddParameter(consts.AccessResponseExpiresIn, gomock.Any())
	aresp.EXPECT().AddParameter(consts.AccessResponseTokenType, oauth2.BearerAccessToken)
	aresp.EXPECT().AddParameter(consts.FormParameterState, "state")
	aresp.EXPECT().AddParameter(consts.FormParameterScope, "scope")
	chgen.EXPECT().GenerateAccessToken(t.Context(), areq).AnyTimes().Return("access.ats", "ats", nil)

	err := h.HandleAuthorizeEndpointRequest(t.Context(), areq, aresp)
	assert.NoError(t, err)
	assert.Equal(t, oauth2.ResponseModeFragment, areq.GetResponseMode())

	internal.RequireEqualTime(t, time.Now().UTC().Add(*internal.TestLifespans.ImplicitGrantAccessTokenLifespan), areq.Session.GetExpiresAt(oauth2.AccessToken), time.Minute)
}
