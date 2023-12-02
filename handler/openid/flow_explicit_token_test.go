// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package openid

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
	"github.com/authelia/goauth2/token/jwt"
)

func TestHandleTokenEndpointRequest(t *testing.T) {
	h := &OpenIDConnectExplicitHandler{Config: &goauth2.Config{}}
	areq := goauth2.NewAccessRequest(nil)
	areq.Client = &goauth2.DefaultClient{
		//ResponseTypes: goauth2.Arguments{"id_token"},
	}
	assert.EqualError(t, h.HandleTokenEndpointRequest(context.TODO(), areq), goauth2.ErrUnknownRequest.Error())
}

func TestExplicit_PopulateTokenEndpointResponse(t *testing.T) {
	for k, c := range []struct {
		description string
		setup       func(store *internal.MockOpenIDConnectRequestStorage, req *goauth2.AccessRequest)
		expectErr   error
		check       func(t *testing.T, aresp *goauth2.AccessResponse)
	}{
		{
			description: "should fail because current request has invalid grant type",
			setup: func(store *internal.MockOpenIDConnectRequestStorage, req *goauth2.AccessRequest) {
				req.GrantTypes = goauth2.Arguments{"some_other_grant_type"}
			},
			expectErr: goauth2.ErrUnknownRequest,
		},
		{
			description: "should fail because storage lookup returns not found",
			setup: func(store *internal.MockOpenIDConnectRequestStorage, req *goauth2.AccessRequest) {
				req.GrantTypes = goauth2.Arguments{"authorization_code"}
				req.Form.Set("code", "foobar")
				store.EXPECT().GetOpenIDConnectSession(context.TODO(), "foobar", req).Return(nil, ErrNoSessionFound)
			},
			expectErr: goauth2.ErrUnknownRequest,
		},
		{
			description: "should fail because storage lookup fails",
			setup: func(store *internal.MockOpenIDConnectRequestStorage, req *goauth2.AccessRequest) {
				req.GrantTypes = goauth2.Arguments{"authorization_code"}
				req.Form.Set("code", "foobar")
				store.EXPECT().GetOpenIDConnectSession(context.TODO(), "foobar", req).Return(nil, errors.New(""))
			},
			expectErr: goauth2.ErrServerError,
		},
		{
			description: "should fail because stored request is missing openid scope",
			setup: func(store *internal.MockOpenIDConnectRequestStorage, req *goauth2.AccessRequest) {
				req.GrantTypes = goauth2.Arguments{"authorization_code"}
				req.Form.Set("code", "foobar")
				store.EXPECT().GetOpenIDConnectSession(context.TODO(), "foobar", req).Return(goauth2.NewAuthorizeRequest(), nil)
			},
			expectErr: goauth2.ErrMisconfiguration,
		},
		{
			description: "should fail because current request's client does not have authorization_code grant type",
			setup: func(store *internal.MockOpenIDConnectRequestStorage, req *goauth2.AccessRequest) {
				req.Client = &goauth2.DefaultClient{
					GrantTypes: goauth2.Arguments{"some_other_grant_type"},
				}
				req.GrantTypes = goauth2.Arguments{"authorization_code"}
				req.Form.Set("code", "foobar")
				storedReq := goauth2.NewAuthorizeRequest()
				storedReq.GrantedScope = goauth2.Arguments{"openid"}
				store.EXPECT().GetOpenIDConnectSession(context.TODO(), "foobar", req).Return(storedReq, nil)
			},
			expectErr: goauth2.ErrUnauthorizedClient,
		},
		{
			description: "should pass with custom client lifespans",
			setup: func(store *internal.MockOpenIDConnectRequestStorage, req *goauth2.AccessRequest) {
				req.Client = &goauth2.DefaultClientWithCustomTokenLifespans{
					DefaultClient: &goauth2.DefaultClient{
						GrantTypes: goauth2.Arguments{"authorization_code"},
					},
					TokenLifespans: &internal.TestLifespans,
				}
				req.GrantTypes = goauth2.Arguments{"authorization_code"}
				req.Form.Set("code", "foobar")
				storedSession := &DefaultSession{
					Claims: &jwt.IDTokenClaims{Subject: "peter"},
				}
				storedReq := goauth2.NewAuthorizeRequest()
				storedReq.Session = storedSession
				storedReq.GrantedScope = goauth2.Arguments{"openid"}
				storedReq.Form.Set("nonce", "1111111111111111")
				store.EXPECT().GetOpenIDConnectSession(context.TODO(), "foobar", req).Return(storedReq, nil)
			},
			check: func(t *testing.T, aresp *goauth2.AccessResponse) {
				assert.NotEmpty(t, aresp.GetExtra("id_token"))
				idToken, _ := aresp.GetExtra("id_token").(string)
				decodedIdToken, err := jwt.Parse(idToken, func(token *jwt.Token) (interface{}, error) {
					return key.PublicKey, nil
				})
				require.NoError(t, err)
				claims := decodedIdToken.Claims
				assert.NotEmpty(t, claims["at_hash"])
				idTokenExp := internal.ExtractJwtExpClaim(t, idToken)
				internal.RequireEqualTime(t, time.Now().Add(*internal.TestLifespans.AuthorizationCodeGrantIDTokenLifespan).UTC(), *idTokenExp, time.Minute)
			},
		},
		{
			description: "should pass",
			setup: func(store *internal.MockOpenIDConnectRequestStorage, req *goauth2.AccessRequest) {
				req.Client = &goauth2.DefaultClient{
					GrantTypes: goauth2.Arguments{"authorization_code"},
				}
				req.GrantTypes = goauth2.Arguments{"authorization_code"}
				req.Form.Set("code", "foobar")
				storedSession := &DefaultSession{
					Claims: &jwt.IDTokenClaims{Subject: "peter"},
				}
				storedReq := goauth2.NewAuthorizeRequest()
				storedReq.Session = storedSession
				storedReq.GrantedScope = goauth2.Arguments{"openid"}
				storedReq.Form.Set("nonce", "1111111111111111")
				store.EXPECT().GetOpenIDConnectSession(context.TODO(), "foobar", req).Return(storedReq, nil)
			},
			check: func(t *testing.T, aresp *goauth2.AccessResponse) {
				assert.NotEmpty(t, aresp.GetExtra("id_token"))
				idToken, _ := aresp.GetExtra("id_token").(string)
				decodedIdToken, err := jwt.Parse(idToken, func(token *jwt.Token) (interface{}, error) {
					return key.PublicKey, nil
				})
				require.NoError(t, err)
				claims := decodedIdToken.Claims
				assert.NotEmpty(t, claims["at_hash"])
				idTokenExp := internal.ExtractJwtExpClaim(t, idToken)
				internal.RequireEqualTime(t, time.Now().Add(time.Hour), *idTokenExp, time.Minute)
			},
		},
		{
			description: "should fail because stored request's session is missing subject claim",
			setup: func(store *internal.MockOpenIDConnectRequestStorage, req *goauth2.AccessRequest) {
				req.GrantTypes = goauth2.Arguments{"authorization_code"}
				req.Form.Set("code", "foobar")
				storedSession := &DefaultSession{
					Claims: &jwt.IDTokenClaims{Subject: ""},
				}
				storedReq := goauth2.NewAuthorizeRequest()
				storedReq.Session = storedSession
				storedReq.GrantedScope = goauth2.Arguments{"openid"}
				store.EXPECT().GetOpenIDConnectSession(context.TODO(), "foobar", req).Return(storedReq, nil)
			},
			expectErr: goauth2.ErrServerError,
		},
		{
			description: "should fail because stored request is missing session",
			setup: func(store *internal.MockOpenIDConnectRequestStorage, req *goauth2.AccessRequest) {
				req.GrantTypes = goauth2.Arguments{"authorization_code"}
				req.Form.Set("code", "foobar")
				storedReq := goauth2.NewAuthorizeRequest()
				storedReq.Session = nil
				storedReq.GrantScope("openid")
				store.EXPECT().GetOpenIDConnectSession(context.TODO(), "foobar", req).Return(storedReq, nil)
			},
			expectErr: goauth2.ErrServerError,
		},
	} {
		t.Run(fmt.Sprintf("case=%d/description=%s", k, c.description), func(t *testing.T) {
			ctrl := gomock.NewController(t)
			store := internal.NewMockOpenIDConnectRequestStorage(ctrl)
			defer ctrl.Finish()

			session := &DefaultSession{
				Claims: &jwt.IDTokenClaims{
					Subject: "peter",
				},
				Headers: &jwt.Headers{},
			}
			aresp := goauth2.NewAccessResponse()
			areq := goauth2.NewAccessRequest(session)

			var j = &DefaultStrategy{
				Signer: &jwt.DefaultSigner{
					GetPrivateKey: func(ctx context.Context) (interface{}, error) {
						return key, nil
					},
				},
				Config: &goauth2.Config{
					MinParameterEntropy: goauth2.MinParameterEntropy,
				},
			}

			h := &OpenIDConnectExplicitHandler{
				OpenIDConnectRequestStorage: store,
				IDTokenHandleHelper: &IDTokenHandleHelper{
					IDTokenStrategy: j,
				},
				Config: &goauth2.Config{},
			}

			c.setup(store, areq)
			err := h.PopulateTokenEndpointResponse(context.TODO(), areq, aresp)

			if c.expectErr != nil {
				require.EqualError(t, err, c.expectErr.Error())
			} else {
				require.NoError(t, err)
			}
			if c.check != nil {
				c.check(t, aresp)
			}
		})
	}
}
