// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/authelia/goauth2"
	"github.com/authelia/goauth2/internal"
)

func TestAuthorizeImplicit_EndpointHandler(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	areq := goauth2.NewAuthorizeRequest()
	areq.Session = new(goauth2.DefaultSession)
	h, store, chgen, aresp := makeAuthorizeImplicitGrantTypeHandler(ctrl)

	for k, c := range []struct {
		description string
		setup       func()
		expectErr   error
	}{
		{
			description: "should pass because not responsible for handling the response type",
			setup: func() {
				areq.ResponseTypes = goauth2.Arguments{"a"}
			},
		},
		{
			description: "should fail because access token generation failed",
			setup: func() {
				areq.ResponseTypes = goauth2.Arguments{"token"}
				areq.Client = &goauth2.DefaultClient{
					GrantTypes:    goauth2.Arguments{"implicit"},
					ResponseTypes: goauth2.Arguments{"token"},
				}
				chgen.EXPECT().GenerateAccessToken(context.TODO(), areq).Return("", "", errors.New(""))
			},
			expectErr: goauth2.ErrServerError,
		},
		{
			description: "should fail because scope invalid",
			setup: func() {
				areq.ResponseTypes = goauth2.Arguments{"token"}
				areq.RequestedScope = goauth2.Arguments{"scope"}
				areq.Client = &goauth2.DefaultClient{
					GrantTypes:    goauth2.Arguments{"implicit"},
					ResponseTypes: goauth2.Arguments{"token"},
				}
			},
			expectErr: goauth2.ErrInvalidScope,
		},
		{
			description: "should fail because audience invalid",
			setup: func() {
				areq.ResponseTypes = goauth2.Arguments{"token"}
				areq.RequestedScope = goauth2.Arguments{"scope"}
				areq.RequestedAudience = goauth2.Arguments{"https://www.ory.sh/not-api"}
				areq.Client = &goauth2.DefaultClient{
					GrantTypes:    goauth2.Arguments{"implicit"},
					ResponseTypes: goauth2.Arguments{"token"},
					Scopes:        []string{"scope"},
					Audience:      []string{"https://www.ory.sh/api"},
				}
			},
			expectErr: goauth2.ErrInvalidRequest,
		},
		{
			description: "should fail because persistence failed",
			setup: func() {
				areq.RequestedAudience = goauth2.Arguments{"https://www.ory.sh/api"}
				chgen.EXPECT().GenerateAccessToken(context.TODO(), areq).AnyTimes().Return("access.ats", "ats", nil)
				store.EXPECT().CreateAccessTokenSession(context.TODO(), "ats", gomock.Eq(areq.Sanitize([]string{}))).Return(errors.New(""))
			},
			expectErr: goauth2.ErrServerError,
		},
		{
			description: "should pass",
			setup: func() {
				areq.State = "state"
				areq.GrantedScope = goauth2.Arguments{"scope"}

				store.EXPECT().CreateAccessTokenSession(context.TODO(), "ats", gomock.Eq(areq.Sanitize([]string{}))).AnyTimes().Return(nil)

				aresp.EXPECT().AddParameter("access_token", "access.ats")
				aresp.EXPECT().AddParameter("expires_in", gomock.Any())
				aresp.EXPECT().AddParameter("token_type", "bearer")
				aresp.EXPECT().AddParameter("state", "state")
				aresp.EXPECT().AddParameter("scope", "scope")
			},
			expectErr: nil,
		},
	} {
		t.Run(fmt.Sprintf("case=%d", k), func(t *testing.T) {
			c.setup()
			err := h.HandleAuthorizeEndpointRequest(context.TODO(), areq, aresp)
			if c.expectErr != nil {
				require.EqualError(t, err, c.expectErr.Error())
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func makeAuthorizeImplicitGrantTypeHandler(ctrl *gomock.Controller) (AuthorizeImplicitGrantTypeHandler,
	*internal.MockAccessTokenStorage, *internal.MockAccessTokenStrategy, *internal.MockAuthorizeResponder) {
	store := internal.NewMockAccessTokenStorage(ctrl)
	chgen := internal.NewMockAccessTokenStrategy(ctrl)
	aresp := internal.NewMockAuthorizeResponder(ctrl)

	h := AuthorizeImplicitGrantTypeHandler{
		AccessTokenStorage:  store,
		AccessTokenStrategy: chgen,
		Config: &goauth2.Config{
			AccessTokenLifespan:      time.Hour,
			ScopeStrategy:            goauth2.HierarchicScopeStrategy,
			AudienceMatchingStrategy: goauth2.DefaultAudienceMatchingStrategy,
		},
	}

	return h, store, chgen, aresp
}

func TestDefaultResponseMode_AuthorizeImplicit_EndpointHandler(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	areq := goauth2.NewAuthorizeRequest()
	areq.Session = new(goauth2.DefaultSession)
	h, store, chgen, aresp := makeAuthorizeImplicitGrantTypeHandler(ctrl)

	areq.State = "state"
	areq.GrantedScope = goauth2.Arguments{"scope"}
	areq.ResponseTypes = goauth2.Arguments{"token"}
	areq.Client = &goauth2.DefaultClientWithCustomTokenLifespans{
		DefaultClient: &goauth2.DefaultClient{
			GrantTypes:    goauth2.Arguments{"implicit"},
			ResponseTypes: goauth2.Arguments{"token"},
		},
		TokenLifespans: &internal.TestLifespans,
	}

	store.EXPECT().CreateAccessTokenSession(context.TODO(), "ats", gomock.Eq(areq.Sanitize([]string{}))).AnyTimes().Return(nil)

	aresp.EXPECT().AddParameter("access_token", "access.ats")
	aresp.EXPECT().AddParameter("expires_in", gomock.Any())
	aresp.EXPECT().AddParameter("token_type", "bearer")
	aresp.EXPECT().AddParameter("state", "state")
	aresp.EXPECT().AddParameter("scope", "scope")
	chgen.EXPECT().GenerateAccessToken(context.TODO(), areq).AnyTimes().Return("access.ats", "ats", nil)

	err := h.HandleAuthorizeEndpointRequest(context.TODO(), areq, aresp)
	assert.NoError(t, err)
	assert.Equal(t, goauth2.ResponseModeFragment, areq.GetResponseMode())

	internal.RequireEqualTime(t, time.Now().UTC().Add(*internal.TestLifespans.ImplicitGrantAccessTokenLifespan), areq.Session.GetExpiresAt(goauth2.AccessToken), time.Minute)
}
