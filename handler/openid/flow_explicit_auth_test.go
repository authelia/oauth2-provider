// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package openid

import (
	"context"
	"fmt"
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal"
	"authelia.com/provider/oauth2/internal/gen"
	"authelia.com/provider/oauth2/token/jwt"
)

// expose key to verify id_token
var key = gen.MustRSAKey()

func makeOpenIDConnectExplicitHandler(ctrl *gomock.Controller, minParameterEntropy int) (OpenIDConnectExplicitHandler, *internal.MockOpenIDConnectRequestStorage) {
	store := internal.NewMockOpenIDConnectRequestStorage(ctrl)
	config := &oauth2.Config{MinParameterEntropy: minParameterEntropy}

	var j = &DefaultStrategy{
		Signer: &jwt.DefaultSigner{
			GetPrivateKey: func(ctx context.Context) (any, error) {
				return key, nil
			},
		},
		Config: config,
	}

	return OpenIDConnectExplicitHandler{
		OpenIDConnectRequestStorage: store,
		IDTokenHandleHelper: &IDTokenHandleHelper{
			IDTokenStrategy: j,
		},
		OpenIDConnectRequestValidator: NewOpenIDConnectRequestValidator(j.Signer, config),
		Config:                        config,
	}, store
}

func TestExplicit_HandleAuthorizeEndpointRequest(t *testing.T) {
	ctrl := gomock.NewController(t)
	aresp := internal.NewMockAuthorizeResponder(ctrl)
	defer ctrl.Finish()

	areq := oauth2.NewAuthorizeRequest()

	session := NewDefaultSession()
	session.Claims.Subject = "foo"
	areq.Session = session

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
				areq.GrantedScope = oauth2.Arguments{"openid"}
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
				store.EXPECT().CreateOpenIDConnectSession(context.TODO(), "codeexample", gomock.Eq(areq.Sanitize(oidcParameters))).Return(errors.New(""))
				return h
			},
			expectErr: oauth2.ErrServerError,
		},
		{
			description: "should pass",
			setup: func() OpenIDConnectExplicitHandler {
				h, store := makeOpenIDConnectExplicitHandler(ctrl, oauth2.MinParameterEntropy)
				store.EXPECT().CreateOpenIDConnectSession(context.TODO(), "codeexample", gomock.Eq(areq.Sanitize(oidcParameters))).AnyTimes().Return(nil)
				return h
			},
		},
	} {
		t.Run(fmt.Sprintf("case=%d", k), func(t *testing.T) {
			h := c.setup()
			err := h.HandleAuthorizeEndpointRequest(context.TODO(), areq, aresp)

			if c.expectErr != nil {
				require.EqualError(t, err, c.expectErr.Error())
			} else {
				require.NoError(t, err)
			}
		})
	}
}
