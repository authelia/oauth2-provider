// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package openid

import (
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
		Strategy: &jwt.DefaultStrategy{
			Config: config,
			Issuer: jwt.NewDefaultIssuerRS256Unverified(key),
		},
		Config: config,
	}

	var j = &DefaultStrategy{
		Strategy: &jwt.DefaultStrategy{
			Config: config,
			Issuer: jwt.NewDefaultIssuerRS256Unverified(key),
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
		OpenIDConnectRequestValidator: NewOpenIDConnectRequestValidator(j.Strategy, config),
		Config:                        config,
	}
}

func TestImplicit_HandleAuthorizeEndpointRequest(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	responder := oauth2.NewAuthorizeResponse()
	requester := oauth2.NewAuthorizeRequest()
	requester.Session = new(oauth2.DefaultSession)

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
				requester.ResponseTypes = oauth2.Arguments{consts.ResponseTypeImplicitFlowIDToken}
				requester.State = "foostate"
				return makeOpenIDConnectImplicitHandler(oauth2.MinParameterEntropy)
			},
		},
		{
			description: "should not do anything because request requirements are not met",
			setup: func() OpenIDConnectImplicitHandler {
				requester.ResponseTypes = oauth2.Arguments{consts.ResponseTypeImplicitFlowToken, consts.ResponseTypeImplicitFlowIDToken}
				return makeOpenIDConnectImplicitHandler(oauth2.MinParameterEntropy)
			},
		},
		{
			description: "should not do anything because request requirements are not met",
			setup: func() OpenIDConnectImplicitHandler {
				requester.ResponseTypes = oauth2.Arguments{}
				requester.GrantedScope = oauth2.Arguments{consts.ScopeOpenID}
				return makeOpenIDConnectImplicitHandler(oauth2.MinParameterEntropy)
			},
		},
		{
			description: "should not do anything because request requirements are not met",
			setup: func() OpenIDConnectImplicitHandler {
				requester.ResponseTypes = oauth2.Arguments{consts.ResponseTypeImplicitFlowToken, consts.ResponseTypeImplicitFlowIDToken}
				requester.RequestedScope = oauth2.Arguments{consts.ScopeOpenID}
				requester.Client = &oauth2.DefaultClient{
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
				requester.ResponseTypes = oauth2.Arguments{consts.ResponseTypeImplicitFlowIDToken}
				requester.RequestedScope = oauth2.Arguments{consts.ScopeOpenID}
				requester.Client = &oauth2.DefaultClient{
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
				requester.Form = url.Values{consts.FormParameterNonce: {"short"}, consts.FormParameterRedirectURI: {"https://example.com"}}
				requester.ResponseTypes = oauth2.Arguments{consts.ResponseTypeImplicitFlowIDToken}
				requester.RequestedScope = oauth2.Arguments{consts.ScopeOpenID}
				requester.Client = &oauth2.DefaultClient{
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
				requester.Form = url.Values{consts.FormParameterNonce: {"long-enough"}, consts.FormParameterRedirectURI: {"https://example.com"}}
				requester.ResponseTypes = oauth2.Arguments{consts.ResponseTypeImplicitFlowIDToken}
				requester.RequestedScope = oauth2.Arguments{consts.ScopeOpenID}
				requester.Client = &oauth2.DefaultClient{
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
				requester.Session = &DefaultSession{
					Claims: &jwt.IDTokenClaims{
						Subject: testSubjectPeter,
					},
					Headers: &jwt.Headers{},
					Subject: testSubjectPeter,
				}
				requester.Form.Add(consts.FormParameterNonce, "some-random-foo-nonce-wow")
				requester.Form.Add(consts.FormParameterRedirectURI, "https://example.com")
				return makeOpenIDConnectImplicitHandler(oauth2.MinParameterEntropy)
			},
		},
		{
			description: "should pass",
			setup: func() OpenIDConnectImplicitHandler {
				requester.ResponseTypes = oauth2.Arguments{consts.ResponseTypeImplicitFlowIDToken}
				return makeOpenIDConnectImplicitHandler(oauth2.MinParameterEntropy)
			},
			check: func() {
				assert.NotEmpty(t, responder.GetParameters().Get(consts.FormParameterState))
				assert.Empty(t, responder.GetParameters().Get(consts.AccessResponseAccessToken))

				idToken := responder.GetParameters().Get(consts.AccessResponseIDToken)
				assert.NotEmpty(t, idToken)
				idTokenExp := internal.ExtractJwtExpClaim(t, idToken)
				internal.RequireEqualTime(t, time.Now().Add(time.Hour), *idTokenExp, time.Minute)
			},
		},
		{
			description: "should pass with nondefault id token lifespan",
			setup: func() OpenIDConnectImplicitHandler {
				responder = oauth2.NewAuthorizeResponse()
				requester.Session = &DefaultSession{
					Claims: &jwt.IDTokenClaims{
						Subject: testSubjectPeter,
					},
					Headers: &jwt.Headers{},
					Subject: testSubjectPeter,
				}
				requester.ResponseTypes = oauth2.Arguments{consts.ResponseTypeImplicitFlowIDToken}
				requester.Client = &oauth2.DefaultClientWithCustomTokenLifespans{
					DefaultClient: &oauth2.DefaultClient{
						GrantTypes:    oauth2.Arguments{consts.GrantTypeImplicit},
						ResponseTypes: oauth2.Arguments{consts.ResponseTypeImplicitFlowToken, consts.ResponseTypeImplicitFlowIDToken},
						Scopes:        []string{consts.ScopeOpenID, "oauth2"},
					},
				}
				requester.Client.(*oauth2.DefaultClientWithCustomTokenLifespans).SetTokenLifespans(&internal.TestLifespans)
				return makeOpenIDConnectImplicitHandler(oauth2.MinParameterEntropy)
			},
			check: func() {
				idToken := responder.GetParameters().Get(consts.AccessResponseIDToken)
				assert.NotEmpty(t, idToken)
				assert.NotEmpty(t, responder.GetParameters().Get(consts.FormParameterState))
				assert.Empty(t, responder.GetParameters().Get(consts.AccessResponseAccessToken))
				idTokenExp := internal.ExtractJwtExpClaim(t, idToken)
				internal.RequireEqualTime(t, time.Now().Add(*internal.TestLifespans.ImplicitGrantIDTokenLifespan), *idTokenExp, time.Minute)
			},
		},
		{
			description: "should pass",
			setup: func() OpenIDConnectImplicitHandler {
				responder = oauth2.NewAuthorizeResponse()
				requester.ResponseTypes = oauth2.Arguments{consts.ResponseTypeImplicitFlowToken, consts.ResponseTypeImplicitFlowIDToken}
				return makeOpenIDConnectImplicitHandler(oauth2.MinParameterEntropy)
			},
			check: func() {
				assert.NotEmpty(t, responder.GetParameters().Get(consts.FormParameterState))

				idToken := responder.GetParameters().Get(consts.AccessResponseIDToken)
				assert.NotEmpty(t, idToken)
				internal.RequireEqualTime(t, time.Now().Add(*internal.TestLifespans.ImplicitGrantIDTokenLifespan).UTC(), *internal.ExtractJwtExpClaim(t, idToken), time.Minute)

				assert.NotEmpty(t, responder.GetParameters().Get(consts.AccessResponseAccessToken))
				internal.RequireEqualTime(t, time.Now().Add(*internal.TestLifespans.ImplicitGrantAccessTokenLifespan).UTC(), requester.Session.GetExpiresAt(oauth2.AccessToken), time.Minute)
			},
		},
		{
			description: "should pass",
			setup: func() OpenIDConnectImplicitHandler {
				requester.ResponseTypes = oauth2.Arguments{consts.ResponseTypeImplicitFlowIDToken, consts.ResponseTypeImplicitFlowToken}
				requester.RequestedScope = oauth2.Arguments{"oauth2", consts.ScopeOpenID}
				return makeOpenIDConnectImplicitHandler(oauth2.MinParameterEntropy)
			},
			check: func() {
				assert.NotEmpty(t, responder.GetParameters().Get(consts.AccessResponseIDToken))
				assert.NotEmpty(t, responder.GetParameters().Get(consts.FormParameterState))
				assert.NotEmpty(t, responder.GetParameters().Get(consts.AccessResponseAccessToken))
				assert.Equal(t, oauth2.ResponseModeFragment, requester.GetResponseMode())
			},
		},
		{
			description: "should pass with low min entropy",
			setup: func() OpenIDConnectImplicitHandler {
				requester.Form.Set(consts.FormParameterNonce, "short")
				return makeOpenIDConnectImplicitHandler(4)
			},
			check: func() {
				assert.NotEmpty(t, responder.GetParameters().Get(consts.AccessResponseIDToken))
				assert.NotEmpty(t, responder.GetParameters().Get(consts.FormParameterState))
				assert.NotEmpty(t, responder.GetParameters().Get(consts.AccessResponseAccessToken))
			},
		},
		{
			description: "should fail without redirect_uri",
			setup: func() OpenIDConnectImplicitHandler {
				requester.Form.Del(consts.FormParameterRedirectURI)
				return makeOpenIDConnectImplicitHandler(4)
			},
			expectErr: oauth2.ErrInvalidRequest,
		},
	} {
		t.Run(fmt.Sprintf("case=%d", k), func(t *testing.T) {
			h := c.setup()
			err := h.HandleAuthorizeEndpointRequest(t.Context(), requester, responder)

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
