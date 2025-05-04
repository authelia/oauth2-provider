// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package openid

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/testing/mock"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestOpenIDConnectDeviceAuthorizeHandler_PopulateRFC8628UserAuthorizeEndpointResponse(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	config := &oauth2.Config{
		AccessTokenLifespan:   time.Minute * 24,
		AuthorizeCodeLifespan: time.Minute * 24,
		RFC8628CodeLifespan:   time.Minute * 24,
	}

	jwtStrategy := &jwt.DefaultStrategy{
		Config: config,
		Issuer: jwt.NewDefaultIssuerRS256Unverified(key),
	}

	j := &DefaultStrategy{
		Strategy: jwtStrategy,
		Config:   config,
	}

	oidcStore := mock.NewMockOpenIDConnectRequestStorage(ctrl)
	tokenHandler := mock.NewMockCodeTokenEndpointHandler(ctrl)

	handler := &OpenIDConnectDeviceAuthorizeHandler{
		OpenIDConnectRequestStorage:   oidcStore,
		OpenIDConnectRequestValidator: NewOpenIDConnectRequestValidator(j.Strategy, config),
		CodeTokenEndpointHandler:      tokenHandler,
		Config:                        config,
		IDTokenHandleHelper: &IDTokenHandleHelper{
			IDTokenStrategy: j,
		},
	}
	req := oauth2.NewDeviceAuthorizeRequest()
	resp := oauth2.NewRFC8628UserAuthorizeResponse()

	for k, c := range []struct {
		description string
		setup       func()
		expectErr   error
	}{
		{
			description: "Success",
			setup: func() {
				req.GrantedScope = []string{consts.ScopeOpenID}
				req.Client = &oauth2.DefaultClient{
					GrantTypes: []string{string(oauth2.GrantTypeDeviceCode), string(oauth2.GrantTypeAuthorizationCode)},
				}
				req.SetDeviceCodeSignature("foobar")
				oidcStore.EXPECT().CreateOpenIDConnectSession(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
			},
		},
		{
			description: "Success - no openid scope",
			setup: func() {
				req.GrantedScope = []string{"foobar"}
			},
		},
		{
			description: "Success - client does not support device code grant type",
			setup: func() {
				req.GrantedScope = []string{consts.ScopeOpenID, "foobar"}
				req.Client = &oauth2.DefaultClient{
					GrantTypes: []string{string(oauth2.GrantTypeImplicit)},
				}
			},
		},
		{
			description: "Fail - request does not have device signature",
			setup: func() {
				req.GrantedScope = []string{consts.ScopeOpenID, "foobar"}
				req.Client = &oauth2.DefaultClient{
					GrantTypes: []string{string(oauth2.GrantTypeDeviceCode)},
				}
				req.SetDeviceCodeSignature("")
			},
			expectErr: oauth2.ErrMisconfiguration.WithDebug("The device code has not been issued yet, indicating a broken code configuration."),
		},
		{
			description: "Fail - failed to create OIDC session",
			setup: func() {
				req.GrantedScope = []string{consts.ScopeOpenID}
				req.Client = &oauth2.DefaultClient{
					GrantTypes: []string{string(oauth2.GrantTypeDeviceCode), string(oauth2.GrantTypeAuthorizationCode)},
				}
				req.SetDeviceCodeSignature("foobar")
				oidcStore.EXPECT().CreateOpenIDConnectSession(gomock.Any(), gomock.Any(), gomock.Any()).Return(errors.New("foobar"))
			},
			expectErr: oauth2.ErrServerError.WithDebug("foobar"),
		},
	} {
		t.Run(fmt.Sprintf("case=%d", k), func(t *testing.T) {
			c.setup()
			err := handler.PopulateRFC8628UserAuthorizeEndpointResponse(context.TODO(), req, resp)

			if c.expectErr != nil {
				require.EqualError(t, err, c.expectErr.Error())
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestOpenIDConnectDeviceAuthorizeHandler_PopulateTokenEndpointResponse(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	config := &oauth2.Config{
		AccessTokenLifespan:   time.Minute * 24,
		AuthorizeCodeLifespan: time.Minute * 24,
		RFC8628CodeLifespan:   time.Minute * 24,
	}

	jwtStrategy := &jwt.DefaultStrategy{
		Config: config,
		Issuer: jwt.NewDefaultIssuerRS256Unverified(key),
	}

	j := &DefaultStrategy{
		Strategy: jwtStrategy,
		Config:   config,
	}

	oidcStore := mock.NewMockOpenIDConnectRequestStorage(ctrl)
	tokenHandler := mock.NewMockCodeTokenEndpointHandler(ctrl)

	handler := &OpenIDConnectDeviceAuthorizeHandler{
		OpenIDConnectRequestStorage:   oidcStore,
		OpenIDConnectRequestValidator: NewOpenIDConnectRequestValidator(j.Strategy, config),
		CodeTokenEndpointHandler:      tokenHandler,
		Config:                        config,
		IDTokenHandleHelper: &IDTokenHandleHelper{
			IDTokenStrategy: j,
		},
	}
	var (
		req     *oauth2.AccessRequest
		resp    *oauth2.AccessResponse
		authReq *oauth2.AuthorizeRequest
	)

	for k, c := range []struct {
		description string
		setup       func()
		expectErr   error
	}{
		{
			description: "Success",
			setup: func() {
				sess := &DefaultSession{
					Claims: &jwt.IDTokenClaims{
						Subject: "foobar",
					},
					Headers:     &jwt.Headers{},
					RequestedAt: time.Now(),
				}

				req = oauth2.NewAccessRequest(nil)
				req.GrantedScope = []string{consts.ScopeOpenID}
				req.GrantTypes = []string{string(oauth2.GrantTypeDeviceCode)}
				req.Session = sess
				req.Client = &oauth2.DefaultClient{
					GrantTypes: []string{string(oauth2.GrantTypeDeviceCode), string(oauth2.GrantTypeAuthorizationCode)},
				}

				resp = oauth2.NewAccessResponse()

				authReq = oauth2.NewAuthorizeRequest()
				authReq.GrantedScope = []string{consts.ScopeOpenID}
				authReq.Session = sess

				tokenHandler.EXPECT().DeviceCodeSignature(gomock.Any(), gomock.Any()).Return("foobar", nil)
				oidcStore.EXPECT().GetOpenIDConnectSession(gomock.Any(), "foobar", req).Return(authReq, nil)
				oidcStore.EXPECT().DeleteOpenIDConnectSession(gomock.Any(), "foobar").Return(nil)
			},
		},
		{
			description: "Failed - request has no device code grant type ",
			setup: func() {
				req = oauth2.NewAccessRequest(nil)
				req.GrantedScope = []string{consts.ScopeOpenID}
				req.GrantTypes = []string{string(oauth2.GrantTypeAuthorizationCode)}
			},
			expectErr: oauth2.ErrUnknownRequest,
		},
		{
			description: "Failed - no device code",
			setup: func() {
				req = oauth2.NewAccessRequest(nil)
				req.GrantTypes = []string{string(oauth2.GrantTypeDeviceCode)}

				tokenHandler.EXPECT().DeviceCodeSignature(gomock.Any(), gomock.Any()).Return("", errors.New(""))
			},
			expectErr: oauth2.ErrServerError,
		},
		{
			description: "Failed - get OIDC session ErrNoSessionFound",
			setup: func() {
				req = oauth2.NewAccessRequest(nil)
				req.GrantTypes = []string{string(oauth2.GrantTypeDeviceCode)}

				tokenHandler.EXPECT().DeviceCodeSignature(gomock.Any(), gomock.Any()).Return("foobar", nil)
				oidcStore.EXPECT().GetOpenIDConnectSession(gomock.Any(), "foobar", req).Return(nil, ErrNoSessionFound)
			},
			expectErr: oauth2.ErrUnknownRequest,
		},
		{
			description: "Failed - get OIDC session other error",
			setup: func() {
				req = oauth2.NewAccessRequest(nil)
				req.GrantTypes = []string{string(oauth2.GrantTypeDeviceCode)}

				tokenHandler.EXPECT().DeviceCodeSignature(gomock.Any(), gomock.Any()).Return("foobar", nil)
				oidcStore.EXPECT().GetOpenIDConnectSession(gomock.Any(), "foobar", req).Return(nil, errors.New(""))
			},
			expectErr: oauth2.ErrServerError,
		},
		{
			description: "Failed - auth request has no openid scope granted",
			setup: func() {
				req = oauth2.NewAccessRequest(nil)
				req.GrantTypes = []string{string(oauth2.GrantTypeDeviceCode)}

				resp = oauth2.NewAccessResponse()

				authReq = oauth2.NewAuthorizeRequest()
				authReq.GrantedScope = []string{"foobar"}

				tokenHandler.EXPECT().DeviceCodeSignature(gomock.Any(), gomock.Any()).Return("foobar", nil)
				oidcStore.EXPECT().GetOpenIDConnectSession(gomock.Any(), "foobar", req).Return(authReq, nil)
			},
			expectErr: oauth2.ErrMisconfiguration,
		},
		{
			description: "Failed - client has no device code grant type",
			setup: func() {
				req = oauth2.NewAccessRequest(nil)
				req.GrantedScope = []string{consts.ScopeOpenID}
				req.GrantTypes = []string{string(oauth2.GrantTypeDeviceCode)}
				req.Client = &oauth2.DefaultClient{
					GrantTypes: []string{string(oauth2.GrantTypeAuthorizationCode)},
				}

				resp = oauth2.NewAccessResponse()

				authReq = oauth2.NewAuthorizeRequest()
				authReq.GrantedScope = []string{consts.ScopeOpenID}

				tokenHandler.EXPECT().DeviceCodeSignature(gomock.Any(), gomock.Any()).Return("foobar", nil)
				oidcStore.EXPECT().GetOpenIDConnectSession(gomock.Any(), "foobar", req).Return(authReq, nil)
			},
			expectErr: oauth2.ErrUnauthorizedClient,
		},
		{
			description: "Failed - no session",
			setup: func() {
				req = oauth2.NewAccessRequest(nil)
				req.GrantedScope = []string{consts.ScopeOpenID}
				req.GrantTypes = []string{string(oauth2.GrantTypeDeviceCode)}
				req.Session = nil
				req.Client = &oauth2.DefaultClient{
					GrantTypes: []string{string(oauth2.GrantTypeDeviceCode), string(oauth2.GrantTypeAuthorizationCode)},
				}

				resp = oauth2.NewAccessResponse()

				authReq = oauth2.NewAuthorizeRequest()
				authReq.GrantedScope = []string{consts.ScopeOpenID}
				authReq.Session = nil

				tokenHandler.EXPECT().DeviceCodeSignature(gomock.Any(), gomock.Any()).Return("foobar", nil)
				oidcStore.EXPECT().GetOpenIDConnectSession(gomock.Any(), "foobar", req).Return(authReq, nil)
			},
			expectErr: oauth2.ErrServerError,
		},
		{
			description: "Failed - ID Token Claim has no subject",
			setup: func() {
				sess := &DefaultSession{
					Claims: &jwt.IDTokenClaims{
						Subject: "",
					},
					Headers:     &jwt.Headers{},
					RequestedAt: time.Now(),
				}

				req = oauth2.NewAccessRequest(nil)
				req.GrantedScope = []string{consts.ScopeOpenID}
				req.GrantTypes = []string{string(oauth2.GrantTypeDeviceCode)}
				req.Session = sess
				req.Client = &oauth2.DefaultClient{
					GrantTypes: []string{string(oauth2.GrantTypeDeviceCode), string(oauth2.GrantTypeAuthorizationCode)},
				}

				resp = oauth2.NewAccessResponse()

				authReq = oauth2.NewAuthorizeRequest()
				authReq.GrantedScope = []string{consts.ScopeOpenID}
				authReq.Session = sess

				tokenHandler.EXPECT().DeviceCodeSignature(gomock.Any(), gomock.Any()).Return("foobar", nil)
				oidcStore.EXPECT().GetOpenIDConnectSession(gomock.Any(), "foobar", req).Return(authReq, nil)
			},
			expectErr: oauth2.ErrServerError,
		},
	} {
		t.Run(fmt.Sprintf("case=%d", k), func(t *testing.T) {
			c.setup()
			err := handler.PopulateTokenEndpointResponse(context.TODO(), req, resp)

			if c.expectErr != nil {
				require.EqualError(t, err, c.expectErr.Error())
			} else {
				require.NoError(t, err)
			}
		})
	}
}
