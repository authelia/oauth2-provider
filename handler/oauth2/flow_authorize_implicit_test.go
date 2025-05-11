// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"fmt"
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

	for k, c := range []struct {
		description string
		setup       func()
		expectErr   error
	}{
		{
			description: "should pass because not responsible for handling the response type",
			setup: func() {
				areq.ResponseTypes = oauth2.Arguments{"a"}
			},
		},
		{
			description: "should fail because access token generation failed",
			setup: func() {
				areq.ResponseTypes = oauth2.Arguments{consts.ResponseTypeImplicitFlowToken}
				areq.Client = &oauth2.DefaultClient{
					GrantTypes:    oauth2.Arguments{consts.GrantTypeImplicit},
					ResponseTypes: oauth2.Arguments{consts.ResponseTypeImplicitFlowToken},
				}
				chgen.EXPECT().GenerateAccessToken(t.Context(), areq).Return("", "", errors.New(""))
			},
			expectErr: oauth2.ErrServerError,
		},
		{
			description: "should fail because scope invalid",
			setup: func() {
				areq.ResponseTypes = oauth2.Arguments{consts.ResponseTypeImplicitFlowToken}
				areq.RequestedScope = oauth2.Arguments{"scope"}
				areq.Client = &oauth2.DefaultClient{
					GrantTypes:    oauth2.Arguments{consts.GrantTypeImplicit},
					ResponseTypes: oauth2.Arguments{consts.ResponseTypeImplicitFlowToken},
				}
			},
			expectErr: oauth2.ErrInvalidScope,
		},
		{
			description: "should fail because audience invalid",
			setup: func() {
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
			expectErr: oauth2.ErrInvalidRequest,
		},
		{
			description: "should fail because persistence failed",
			setup: func() {
				areq.RequestedAudience = oauth2.Arguments{"https://www.authelia.com/api"}
				chgen.EXPECT().GenerateAccessToken(t.Context(), areq).AnyTimes().Return("access.ats", "ats", nil)
				store.EXPECT().CreateAccessTokenSession(t.Context(), "ats", gomock.Eq(areq.Sanitize([]string{}))).Return(errors.New(""))
			},
			expectErr: oauth2.ErrServerError,
		},
		{
			description: "should pass",
			setup: func() {
				areq.State = "state"
				areq.GrantedScope = oauth2.Arguments{"scope"}

				store.EXPECT().CreateAccessTokenSession(t.Context(), "ats", gomock.Eq(areq.Sanitize([]string{}))).AnyTimes().Return(nil)

				aresp.EXPECT().AddParameter(consts.AccessResponseAccessToken, "access.ats")
				aresp.EXPECT().AddParameter(consts.AccessResponseExpiresIn, gomock.Any())
				aresp.EXPECT().AddParameter(consts.AccessResponseTokenType, oauth2.BearerAccessToken)
				aresp.EXPECT().AddParameter(consts.FormParameterState, "state")
				aresp.EXPECT().AddParameter(consts.FormParameterScope, "scope")
			},
			expectErr: nil,
		},
	} {
		t.Run(fmt.Sprintf("case=%d", k), func(t *testing.T) {
			c.setup()
			err := h.HandleAuthorizeEndpointRequest(t.Context(), areq, aresp)
			if c.expectErr != nil {
				require.EqualError(t, err, c.expectErr.Error())
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
