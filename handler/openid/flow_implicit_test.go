// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package openid

import (
	"context"
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"

	"github.com/authelia/goauth2"
	"github.com/authelia/goauth2/handler/oauth2"
	"github.com/authelia/goauth2/internal"
	"github.com/authelia/goauth2/internal/gen"
	"github.com/authelia/goauth2/storage"
	"github.com/authelia/goauth2/token/jwt"
)

func makeOpenIDConnectImplicitHandler(minParameterEntropy int) OpenIDConnectImplicitHandler {
	config := &goauth2.Config{
		MinParameterEntropy: minParameterEntropy,
		AccessTokenLifespan: time.Hour,
		ScopeStrategy:       goauth2.HierarchicScopeStrategy,
	}

	var idStrategy = &DefaultStrategy{
		Signer: &jwt.DefaultSigner{
			GetPrivateKey: func(ctx context.Context) (any, error) {
				return gen.MustRSAKey(), nil
			},
		},
		Config: config,
	}

	var j = &DefaultStrategy{
		Signer: &jwt.DefaultSigner{
			GetPrivateKey: func(ctx context.Context) (any, error) {
				return key, nil
			},
		},
		Config: config,
	}

	return OpenIDConnectImplicitHandler{
		AuthorizeImplicitGrantTypeHandler: &oauth2.AuthorizeImplicitGrantTypeHandler{
			Config:              config,
			AccessTokenStrategy: hmacStrategy,
			AccessTokenStorage:  storage.NewMemoryStore(),
		},
		IDTokenHandleHelper: &IDTokenHandleHelper{
			IDTokenStrategy: idStrategy,
		},
		OpenIDConnectRequestValidator: NewOpenIDConnectRequestValidator(j.Signer, config),
		Config:                        config,
	}
}

func TestImplicit_HandleAuthorizeEndpointRequest(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	aresp := goauth2.NewAuthorizeResponse()
	areq := goauth2.NewAuthorizeRequest()
	areq.Session = new(goauth2.DefaultSession)

	for k, c := range []struct {
		description string
		setup       func() OpenIDConnectImplicitHandler
		expectErr   error
		check       func()
	}{
		{
			description: "should not do anything because request requirements are not met",
			setup: func() OpenIDConnectImplicitHandler {
				return makeOpenIDConnectImplicitHandler(goauth2.MinParameterEntropy)
			},
		},
		{
			description: "should not do anything because request requirements are not met",
			setup: func() OpenIDConnectImplicitHandler {
				areq.ResponseTypes = goauth2.Arguments{"id_token"}
				areq.State = "foostate"
				return makeOpenIDConnectImplicitHandler(goauth2.MinParameterEntropy)
			},
		},
		{
			description: "should not do anything because request requirements are not met",
			setup: func() OpenIDConnectImplicitHandler {
				areq.ResponseTypes = goauth2.Arguments{"token", "id_token"}
				return makeOpenIDConnectImplicitHandler(goauth2.MinParameterEntropy)
			},
		},
		{
			description: "should not do anything because request requirements are not met",
			setup: func() OpenIDConnectImplicitHandler {
				areq.ResponseTypes = goauth2.Arguments{}
				areq.GrantedScope = goauth2.Arguments{"openid"}
				return makeOpenIDConnectImplicitHandler(goauth2.MinParameterEntropy)
			},
		},
		{
			description: "should not do anything because request requirements are not met",
			setup: func() OpenIDConnectImplicitHandler {
				areq.ResponseTypes = goauth2.Arguments{"token", "id_token"}
				areq.RequestedScope = goauth2.Arguments{"openid"}
				areq.Client = &goauth2.DefaultClient{
					GrantTypes:    goauth2.Arguments{},
					ResponseTypes: goauth2.Arguments{},
					Scopes:        []string{"openid", "goauth2"},
				}
				return makeOpenIDConnectImplicitHandler(goauth2.MinParameterEntropy)
			},
			expectErr: goauth2.ErrInvalidGrant,
		},
		// Disabled because this is already handled at the authorize_request_handler
		//{
		//	description: "should not do anything because request requirements are not met",
		//	setup: func() OpenIDConnectImplicitHandler {
		//		areq.ResponseTypes = goauth2.Arguments{"token", "id_token"}
		//		areq.RequestedScope = goauth2.Arguments{"openid"}
		//		areq.Client = &goauth2.DefaultClient{
		//			GrantTypes:    goauth2.Arguments{"implicit"},
		//			ResponseTypes: goauth2.Arguments{},
		//			RequestedScope:        []string{"openid", "goauth2"},
		//		}
		//		return makeOpenIDConnectImplicitHandler(goauth2.MinParameterEntropy)
		//	},
		//	expectErr: goauth2.ErrInvalidGrant,
		//},
		{
			description: "should not do anything because request requirements are not met",
			setup: func() OpenIDConnectImplicitHandler {
				areq.ResponseTypes = goauth2.Arguments{"id_token"}
				areq.RequestedScope = goauth2.Arguments{"openid"}
				areq.Client = &goauth2.DefaultClient{
					GrantTypes: goauth2.Arguments{"implicit"},
					//ResponseTypes: goauth2.Arguments{"token", "id_token"},
					Scopes: []string{"openid", "goauth2"},
				}
				return makeOpenIDConnectImplicitHandler(goauth2.MinParameterEntropy)
			},
			expectErr: goauth2.ErrInvalidRequest,
		},
		{
			description: "should not do anything because request requirements are not met",
			setup: func() OpenIDConnectImplicitHandler {
				areq.Form = url.Values{"nonce": {"short"}}
				areq.ResponseTypes = goauth2.Arguments{"id_token"}
				areq.RequestedScope = goauth2.Arguments{"openid"}
				areq.Client = &goauth2.DefaultClient{
					GrantTypes:    goauth2.Arguments{"implicit"},
					ResponseTypes: goauth2.Arguments{"token", "id_token"},
					Scopes:        []string{"openid", "goauth2"},
				}
				return makeOpenIDConnectImplicitHandler(goauth2.MinParameterEntropy)
			},
			expectErr: goauth2.ErrInsufficientEntropy,
		},
		{
			description: "should fail because session not set",
			setup: func() OpenIDConnectImplicitHandler {
				areq.Form = url.Values{"nonce": {"long-enough"}}
				areq.ResponseTypes = goauth2.Arguments{"id_token"}
				areq.RequestedScope = goauth2.Arguments{"openid"}
				areq.Client = &goauth2.DefaultClient{
					GrantTypes:    goauth2.Arguments{"implicit"},
					ResponseTypes: goauth2.Arguments{"token", "id_token"},
					Scopes:        []string{"openid", "goauth2"},
				}
				return makeOpenIDConnectImplicitHandler(goauth2.MinParameterEntropy)
			},
			expectErr: ErrInvalidSession,
		},
		{
			description: "should pass because nonce set",
			setup: func() OpenIDConnectImplicitHandler {
				areq.Session = &DefaultSession{
					Claims: &jwt.IDTokenClaims{
						Subject: "peter",
					},
					Headers: &jwt.Headers{},
					Subject: "peter",
				}
				areq.Form.Add("nonce", "some-random-foo-nonce-wow")
				return makeOpenIDConnectImplicitHandler(goauth2.MinParameterEntropy)
			},
		},
		{
			description: "should pass",
			setup: func() OpenIDConnectImplicitHandler {
				areq.ResponseTypes = goauth2.Arguments{"id_token"}
				return makeOpenIDConnectImplicitHandler(goauth2.MinParameterEntropy)
			},
			check: func() {
				assert.NotEmpty(t, aresp.GetParameters().Get("state"))
				assert.Empty(t, aresp.GetParameters().Get("access_token"))

				idToken := aresp.GetParameters().Get("id_token")
				assert.NotEmpty(t, idToken)
				idTokenExp := internal.ExtractJwtExpClaim(t, idToken)
				internal.RequireEqualTime(t, time.Now().Add(time.Hour), *idTokenExp, time.Minute)
			},
		},
		{
			description: "should pass with nondefault id token lifespan",
			setup: func() OpenIDConnectImplicitHandler {
				aresp = goauth2.NewAuthorizeResponse()
				areq.Session = &DefaultSession{
					Claims: &jwt.IDTokenClaims{
						Subject: "peter",
					},
					Headers: &jwt.Headers{},
					Subject: "peter",
				}
				areq.ResponseTypes = goauth2.Arguments{"id_token"}
				areq.Client = &goauth2.DefaultClientWithCustomTokenLifespans{
					DefaultClient: &goauth2.DefaultClient{
						GrantTypes:    goauth2.Arguments{"implicit"},
						ResponseTypes: goauth2.Arguments{"token", "id_token"},
						Scopes:        []string{"openid", "goauth2"},
					},
				}
				areq.Client.(*goauth2.DefaultClientWithCustomTokenLifespans).SetTokenLifespans(&internal.TestLifespans)
				return makeOpenIDConnectImplicitHandler(goauth2.MinParameterEntropy)
			},
			check: func() {
				idToken := aresp.GetParameters().Get("id_token")
				assert.NotEmpty(t, idToken)
				assert.NotEmpty(t, aresp.GetParameters().Get("state"))
				assert.Empty(t, aresp.GetParameters().Get("access_token"))
				idTokenExp := internal.ExtractJwtExpClaim(t, idToken)
				internal.RequireEqualTime(t, time.Now().Add(*internal.TestLifespans.ImplicitGrantIDTokenLifespan), *idTokenExp, time.Minute)
			},
		},
		{
			description: "should pass",
			setup: func() OpenIDConnectImplicitHandler {
				aresp = goauth2.NewAuthorizeResponse()
				areq.ResponseTypes = goauth2.Arguments{"token", "id_token"}
				return makeOpenIDConnectImplicitHandler(goauth2.MinParameterEntropy)
			},
			check: func() {
				assert.NotEmpty(t, aresp.GetParameters().Get("state"))

				idToken := aresp.GetParameters().Get("id_token")
				assert.NotEmpty(t, idToken)
				internal.RequireEqualTime(t, time.Now().Add(*internal.TestLifespans.ImplicitGrantIDTokenLifespan).UTC(), *internal.ExtractJwtExpClaim(t, idToken), time.Minute)

				assert.NotEmpty(t, aresp.GetParameters().Get("access_token"))
				internal.RequireEqualTime(t, time.Now().Add(*internal.TestLifespans.ImplicitGrantAccessTokenLifespan).UTC(), areq.Session.GetExpiresAt(goauth2.AccessToken), time.Minute)
			},
		},
		{
			description: "should pass",
			setup: func() OpenIDConnectImplicitHandler {
				areq.ResponseTypes = goauth2.Arguments{"id_token", "token"}
				areq.RequestedScope = goauth2.Arguments{"goauth2", "openid"}
				return makeOpenIDConnectImplicitHandler(goauth2.MinParameterEntropy)
			},
			check: func() {
				assert.NotEmpty(t, aresp.GetParameters().Get("id_token"))
				assert.NotEmpty(t, aresp.GetParameters().Get("state"))
				assert.NotEmpty(t, aresp.GetParameters().Get("access_token"))
				assert.Equal(t, goauth2.ResponseModeFragment, areq.GetResponseMode())
			},
		},
		{
			description: "should pass with low min entropy",
			setup: func() OpenIDConnectImplicitHandler {
				areq.Form.Set("nonce", "short")
				return makeOpenIDConnectImplicitHandler(4)
			},
			check: func() {
				assert.NotEmpty(t, aresp.GetParameters().Get("id_token"))
				assert.NotEmpty(t, aresp.GetParameters().Get("state"))
				assert.NotEmpty(t, aresp.GetParameters().Get("access_token"))
			},
		},
	} {
		t.Run(fmt.Sprintf("case=%d", k), func(t *testing.T) {
			h := c.setup()
			err := h.HandleAuthorizeEndpointRequest(context.TODO(), areq, aresp)

			if c.expectErr != nil {
				assert.EqualError(t, err, c.expectErr.Error())
			} else {
				assert.NoError(t, err)
				if c.check != nil {
					c.check()
				}
			}
		})
	}
}
