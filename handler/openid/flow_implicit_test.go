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

	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/internal"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/gen"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/token/jwt"
)

func makeOpenIDConnectImplicitHandler(minParameterEntropy int) OpenIDConnectImplicitHandler {
	config := &oauth2.Config{
		MinParameterEntropy: minParameterEntropy,
		AccessTokenLifespan: time.Hour,
		ScopeStrategy:       oauth2.HierarchicScopeStrategy,
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
		AuthorizeImplicitGrantTypeHandler: &hoauth2.AuthorizeImplicitGrantTypeHandler{
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

	aresp := oauth2.NewAuthorizeResponse()
	areq := oauth2.NewAuthorizeRequest()
	areq.Session = new(oauth2.DefaultSession)

	for k, c := range []struct {
		description string
		setup       func() OpenIDConnectImplicitHandler
		expectErr   error
		check       func()
	}{
		{
			description: "should not do anything because request requirements are not met",
			setup: func() OpenIDConnectImplicitHandler {
				return makeOpenIDConnectImplicitHandler(oauth2.MinParameterEntropy)
			},
		},
		{
			description: "should not do anything because request requirements are not met",
			setup: func() OpenIDConnectImplicitHandler {
				areq.ResponseTypes = oauth2.Arguments{consts.ResponseTypeImplicitFlowIDToken}
				areq.State = "foostate"
				return makeOpenIDConnectImplicitHandler(oauth2.MinParameterEntropy)
			},
		},
		{
			description: "should not do anything because request requirements are not met",
			setup: func() OpenIDConnectImplicitHandler {
				areq.ResponseTypes = oauth2.Arguments{consts.ResponseTypeImplicitFlowToken, consts.ResponseTypeImplicitFlowIDToken}
				return makeOpenIDConnectImplicitHandler(oauth2.MinParameterEntropy)
			},
		},
		{
			description: "should not do anything because request requirements are not met",
			setup: func() OpenIDConnectImplicitHandler {
				areq.ResponseTypes = oauth2.Arguments{}
				areq.GrantedScope = oauth2.Arguments{consts.ScopeOpenID}
				return makeOpenIDConnectImplicitHandler(oauth2.MinParameterEntropy)
			},
		},
		{
			description: "should not do anything because request requirements are not met",
			setup: func() OpenIDConnectImplicitHandler {
				areq.ResponseTypes = oauth2.Arguments{consts.ResponseTypeImplicitFlowToken, consts.ResponseTypeImplicitFlowIDToken}
				areq.RequestedScope = oauth2.Arguments{consts.ScopeOpenID}
				areq.Client = &oauth2.DefaultClient{
					GrantTypes:    oauth2.Arguments{},
					ResponseTypes: oauth2.Arguments{},
					Scopes:        []string{consts.ScopeOpenID, "oauth2"},
				}
				return makeOpenIDConnectImplicitHandler(oauth2.MinParameterEntropy)
			},
			expectErr: oauth2.ErrInvalidGrant,
		},
		{
			description: "should not do anything because request requirements are not met",
			setup: func() OpenIDConnectImplicitHandler {
				areq.ResponseTypes = oauth2.Arguments{consts.ResponseTypeImplicitFlowIDToken}
				areq.RequestedScope = oauth2.Arguments{consts.ScopeOpenID}
				areq.Client = &oauth2.DefaultClient{
					GrantTypes: oauth2.Arguments{consts.GrantTypeImplicit},
					//ResponseTypes: oauth2.Arguments{consts.ResponseTypeImplicitFlowToken, consts.ResponseTypeImplicitFlowIDToken},
					Scopes: []string{consts.ScopeOpenID, "oauth2"},
				}
				return makeOpenIDConnectImplicitHandler(oauth2.MinParameterEntropy)
			},
			expectErr: oauth2.ErrInvalidRequest,
		},
		{
			description: "should not do anything because request requirements are not met",
			setup: func() OpenIDConnectImplicitHandler {
				areq.Form = url.Values{consts.FormParameterNonce: {"short"}, consts.FormParameterRedirectURI: {"https://example.com"}}
				areq.ResponseTypes = oauth2.Arguments{consts.ResponseTypeImplicitFlowIDToken}
				areq.RequestedScope = oauth2.Arguments{consts.ScopeOpenID}
				areq.Client = &oauth2.DefaultClient{
					GrantTypes:    oauth2.Arguments{consts.GrantTypeImplicit},
					ResponseTypes: oauth2.Arguments{consts.ResponseTypeImplicitFlowToken, consts.ResponseTypeImplicitFlowIDToken},
					Scopes:        []string{consts.ScopeOpenID, "oauth2"},
				}
				return makeOpenIDConnectImplicitHandler(oauth2.MinParameterEntropy)
			},
			expectErr: oauth2.ErrInsufficientEntropy,
		},
		{
			description: "should fail because session not set",
			setup: func() OpenIDConnectImplicitHandler {
				areq.Form = url.Values{consts.FormParameterNonce: {"long-enough"}, consts.FormParameterRedirectURI: {"https://example.com"}}
				areq.ResponseTypes = oauth2.Arguments{consts.ResponseTypeImplicitFlowIDToken}
				areq.RequestedScope = oauth2.Arguments{consts.ScopeOpenID}
				areq.Client = &oauth2.DefaultClient{
					GrantTypes:    oauth2.Arguments{consts.GrantTypeImplicit},
					ResponseTypes: oauth2.Arguments{consts.ResponseTypeImplicitFlowToken, consts.ResponseTypeImplicitFlowIDToken},
					Scopes:        []string{consts.ScopeOpenID, "oauth2"},
				}
				return makeOpenIDConnectImplicitHandler(oauth2.MinParameterEntropy)
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
				areq.Form.Add(consts.FormParameterNonce, "some-random-foo-nonce-wow")
				areq.Form.Add(consts.FormParameterRedirectURI, "https://example.com")
				return makeOpenIDConnectImplicitHandler(oauth2.MinParameterEntropy)
			},
		},
		{
			description: "should pass",
			setup: func() OpenIDConnectImplicitHandler {
				areq.ResponseTypes = oauth2.Arguments{consts.ResponseTypeImplicitFlowIDToken}
				return makeOpenIDConnectImplicitHandler(oauth2.MinParameterEntropy)
			},
			check: func() {
				assert.NotEmpty(t, aresp.GetParameters().Get(consts.FormParameterState))
				assert.Empty(t, aresp.GetParameters().Get(consts.AccessResponseAccessToken))

				idToken := aresp.GetParameters().Get(consts.AccessResponseIDToken)
				assert.NotEmpty(t, idToken)
				idTokenExp := internal.ExtractJwtExpClaim(t, idToken)
				internal.RequireEqualTime(t, time.Now().Add(time.Hour), *idTokenExp, time.Minute)
			},
		},
		{
			description: "should pass with nondefault id token lifespan",
			setup: func() OpenIDConnectImplicitHandler {
				aresp = oauth2.NewAuthorizeResponse()
				areq.Session = &DefaultSession{
					Claims: &jwt.IDTokenClaims{
						Subject: "peter",
					},
					Headers: &jwt.Headers{},
					Subject: "peter",
				}
				areq.ResponseTypes = oauth2.Arguments{consts.ResponseTypeImplicitFlowIDToken}
				areq.Client = &oauth2.DefaultClientWithCustomTokenLifespans{
					DefaultClient: &oauth2.DefaultClient{
						GrantTypes:    oauth2.Arguments{consts.GrantTypeImplicit},
						ResponseTypes: oauth2.Arguments{consts.ResponseTypeImplicitFlowToken, consts.ResponseTypeImplicitFlowIDToken},
						Scopes:        []string{consts.ScopeOpenID, "oauth2"},
					},
				}
				areq.Client.(*oauth2.DefaultClientWithCustomTokenLifespans).SetTokenLifespans(&internal.TestLifespans)
				return makeOpenIDConnectImplicitHandler(oauth2.MinParameterEntropy)
			},
			check: func() {
				idToken := aresp.GetParameters().Get(consts.AccessResponseIDToken)
				assert.NotEmpty(t, idToken)
				assert.NotEmpty(t, aresp.GetParameters().Get(consts.FormParameterState))
				assert.Empty(t, aresp.GetParameters().Get(consts.AccessResponseAccessToken))
				idTokenExp := internal.ExtractJwtExpClaim(t, idToken)
				internal.RequireEqualTime(t, time.Now().Add(*internal.TestLifespans.ImplicitGrantIDTokenLifespan), *idTokenExp, time.Minute)
			},
		},
		{
			description: "should pass",
			setup: func() OpenIDConnectImplicitHandler {
				aresp = oauth2.NewAuthorizeResponse()
				areq.ResponseTypes = oauth2.Arguments{consts.ResponseTypeImplicitFlowToken, consts.ResponseTypeImplicitFlowIDToken}
				return makeOpenIDConnectImplicitHandler(oauth2.MinParameterEntropy)
			},
			check: func() {
				assert.NotEmpty(t, aresp.GetParameters().Get(consts.FormParameterState))

				idToken := aresp.GetParameters().Get(consts.AccessResponseIDToken)
				assert.NotEmpty(t, idToken)
				internal.RequireEqualTime(t, time.Now().Add(*internal.TestLifespans.ImplicitGrantIDTokenLifespan).UTC(), *internal.ExtractJwtExpClaim(t, idToken), time.Minute)

				assert.NotEmpty(t, aresp.GetParameters().Get(consts.AccessResponseAccessToken))
				internal.RequireEqualTime(t, time.Now().Add(*internal.TestLifespans.ImplicitGrantAccessTokenLifespan).UTC(), areq.Session.GetExpiresAt(oauth2.AccessToken), time.Minute)
			},
		},
		{
			description: "should pass",
			setup: func() OpenIDConnectImplicitHandler {
				areq.ResponseTypes = oauth2.Arguments{consts.ResponseTypeImplicitFlowIDToken, consts.ResponseTypeImplicitFlowToken}
				areq.RequestedScope = oauth2.Arguments{"oauth2", consts.ScopeOpenID}
				return makeOpenIDConnectImplicitHandler(oauth2.MinParameterEntropy)
			},
			check: func() {
				assert.NotEmpty(t, aresp.GetParameters().Get(consts.AccessResponseIDToken))
				assert.NotEmpty(t, aresp.GetParameters().Get(consts.FormParameterState))
				assert.NotEmpty(t, aresp.GetParameters().Get(consts.AccessResponseAccessToken))
				assert.Equal(t, oauth2.ResponseModeFragment, areq.GetResponseMode())
			},
		},
		{
			description: "should pass with low min entropy",
			setup: func() OpenIDConnectImplicitHandler {
				areq.Form.Set(consts.FormParameterNonce, "short")
				return makeOpenIDConnectImplicitHandler(4)
			},
			check: func() {
				assert.NotEmpty(t, aresp.GetParameters().Get(consts.AccessResponseIDToken))
				assert.NotEmpty(t, aresp.GetParameters().Get(consts.FormParameterState))
				assert.NotEmpty(t, aresp.GetParameters().Get(consts.AccessResponseAccessToken))
			},
		},
		{
			description: "should fail without redirect_uri",
			setup: func() OpenIDConnectImplicitHandler {
				areq.Form.Del("redirect_uri")
				return makeOpenIDConnectImplicitHandler(4)
			},
			expectErr: oauth2.ErrInvalidRequest,
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
