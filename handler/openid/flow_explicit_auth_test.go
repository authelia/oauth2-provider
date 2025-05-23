// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package openid

import (
	"fmt"
	"net/url"
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/gen"
	"authelia.com/provider/oauth2/testing/mock"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestExplicit_HandleAuthorizeEndpointRequest(t *testing.T) {
	ctrl := gomock.NewController(t)
	aresp := mock.NewMockAuthorizeResponder(ctrl)
	defer ctrl.Finish()

	areq := oauth2.NewAuthorizeRequest()

	session := NewDefaultSession()
	session.Claims.Subject = "foo"
	areq.Session = session
	areq.Form = url.Values{
		"redirect_uri": {"https://example.com"},
	}

	for k, c := range []struct {
		description string
		setup       func() OpenIDConnectExplicitHandler
		expectErr   error
	}{
		{
			description: "should pass because not responsible for handling an empty response type",
			setup: func() OpenIDConnectExplicitHandler {
				h, _ := makeOpenIDConnectExplicitHandler(ctrl, oauth2.MinParameterEntropy)
				areq.ResponseTypes = oauth2.Arguments{""}
				return h
			},
		},
		{
			description: "should pass because scope openid is not set",
			setup: func() OpenIDConnectExplicitHandler {
				h, _ := makeOpenIDConnectExplicitHandler(ctrl, oauth2.MinParameterEntropy)
				areq.ResponseTypes = oauth2.Arguments{"code"}
				areq.Client = &oauth2.DefaultClient{
					ResponseTypes: oauth2.Arguments{"code"},
				}
				areq.RequestedScope = oauth2.Arguments{""}
				return h
			},
		},
		{
			description: "should fail because no code set",
			setup: func() OpenIDConnectExplicitHandler {
				h, _ := makeOpenIDConnectExplicitHandler(ctrl, oauth2.MinParameterEntropy)
				areq.GrantedScope = oauth2.Arguments{consts.ScopeOpenID}
				areq.Form.Set("nonce", "11111111111111111111111111111")
				aresp.EXPECT().GetCode().Return("")
				return h
			},
			expectErr: oauth2.ErrMisconfiguration,
		},
		{
			description: "should fail because lookup fails",
			setup: func() OpenIDConnectExplicitHandler {
				h, store := makeOpenIDConnectExplicitHandler(ctrl, oauth2.MinParameterEntropy)
				aresp.EXPECT().GetCode().AnyTimes().Return("codeexample")
				store.EXPECT().CreateOpenIDConnectSession(t.Context(), "codeexample", gomock.Eq(areq.Sanitize(oidcParameters))).Return(errors.New(""))
				return h
			},
			expectErr: oauth2.ErrServerError,
		},
		{
			description: "should pass",
			setup: func() OpenIDConnectExplicitHandler {
				h, store := makeOpenIDConnectExplicitHandler(ctrl, oauth2.MinParameterEntropy)
				store.EXPECT().CreateOpenIDConnectSession(t.Context(), "codeexample", gomock.Eq(areq.Sanitize(oidcParameters))).AnyTimes().Return(nil)
				return h
			},
		},
		{
			description: "should fail because redirect url is missing",
			setup: func() OpenIDConnectExplicitHandler {
				areq.Form.Del(consts.FormParameterRedirectURI)
				h, store := makeOpenIDConnectExplicitHandler(ctrl, oauth2.MinParameterEntropy)
				store.EXPECT().CreateOpenIDConnectSession(gomock.Any(), "codeexample", gomock.Eq(areq.Sanitize(oidcParameters))).AnyTimes().Return(nil)
				return h
			},
			expectErr: oauth2.ErrInvalidRequest,
		},
	} {
		t.Run(fmt.Sprintf("case=%d", k), func(t *testing.T) {
			h := c.setup()
			err := h.HandleAuthorizeEndpointRequest(t.Context(), areq, aresp)

			if c.expectErr != nil {
				require.EqualError(t, err, c.expectErr.Error())
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// expose key to verify id_token
var key = gen.MustRSAKey()

//nolint:unparam
func makeOpenIDConnectExplicitHandler(ctrl *gomock.Controller, minParameterEntropy int) (OpenIDConnectExplicitHandler, *mock.MockOpenIDConnectRequestStorage) {
	store := mock.NewMockOpenIDConnectRequestStorage(ctrl)
	config := &oauth2.Config{MinParameterEntropy: minParameterEntropy}

	jwtStrategy := &jwt.DefaultStrategy{
		Config: config,
		Issuer: jwt.NewDefaultIssuerRS256Unverified(key),
	}

	var j = &DefaultStrategy{
		Strategy: jwtStrategy,
		Config:   config,
	}

	return OpenIDConnectExplicitHandler{
		OpenIDConnectRequestStorage: store,
		IDTokenHandleHelper: &IDTokenHandleHelper{
			IDTokenStrategy: j,
		},
		OpenIDConnectRequestValidator: NewOpenIDConnectRequestValidator(j.Strategy, config),
		Config:                        config,
	}, store
}
