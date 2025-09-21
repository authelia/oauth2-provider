// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package openid

import (
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/internal"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestImplicit_HandleAuthorizeEndpointRequest(t *testing.T) {
	testCases := []struct {
		name          string
		setup         func(requester *oauth2.AuthorizeRequest, responder *oauth2.AuthorizeResponse) (handler OpenIDConnectImplicitHandler)
		expected      string
		expectedField string
		check         func(t *testing.T, requester *oauth2.AuthorizeRequest, responder *oauth2.AuthorizeResponse)
	}{
		{
			name: "ShouldPassBecauseHandlerNotResponsibleOAuth2EmptyFlow",
			setup: func(requester *oauth2.AuthorizeRequest, responder *oauth2.AuthorizeResponse) (handler OpenIDConnectImplicitHandler) {
				return makeOpenIDConnectImplicitHandler(oauth2.MinParameterEntropy)
			},
		},
		{
			name: "ShouldPassBecauseHandlerNotResponsibleForOAuth2AuthorizeCodeFlow",
			setup: func(requester *oauth2.AuthorizeRequest, responder *oauth2.AuthorizeResponse) (handler OpenIDConnectImplicitHandler) {
				requester.ResponseTypes = oauth2.Arguments{consts.ResponseTypeImplicitFlowIDToken}
				requester.State = "foostate"
				return makeOpenIDConnectImplicitHandler(oauth2.MinParameterEntropy)
			},
		},
		{
			name: "ShouldPassBecauseHandlerNotResponsibleForOAuth2ImplicitFlow",
			setup: func(requester *oauth2.AuthorizeRequest, responder *oauth2.AuthorizeResponse) (handler OpenIDConnectImplicitHandler) {
				requester.ResponseTypes = oauth2.Arguments{consts.ResponseTypeImplicitFlowToken, consts.ResponseTypeImplicitFlowIDToken}
				return makeOpenIDConnectImplicitHandler(oauth2.MinParameterEntropy)
			},
		},
		{
			name: "ShouldPassBecauseHandlerNotResponsibleForOpenIDEmptyFlow",
			setup: func(requester *oauth2.AuthorizeRequest, responder *oauth2.AuthorizeResponse) (handler OpenIDConnectImplicitHandler) {
				requester.ResponseTypes = oauth2.Arguments{}
				requester.GrantedScope = oauth2.Arguments{consts.ScopeOpenID}
				return makeOpenIDConnectImplicitHandler(oauth2.MinParameterEntropy)
			},
		},
		{
			name: "ShouldPassBecauseHandlerNotResponsibleForOpenIDImplicitFlowTokenIDToken",
			setup: func(requester *oauth2.AuthorizeRequest, responder *oauth2.AuthorizeResponse) (handler OpenIDConnectImplicitHandler) {
				requester.ResponseTypes = oauth2.Arguments{consts.ResponseTypeImplicitFlowToken, consts.ResponseTypeImplicitFlowIDToken}
				requester.RequestedScope = oauth2.Arguments{consts.ScopeOpenID}
				requester.Client = &oauth2.DefaultClient{
					GrantTypes:    oauth2.Arguments{},
					ResponseTypes: oauth2.Arguments{},
					Scopes:        []string{consts.ScopeOpenID, "oauth2"},
				}
				return makeOpenIDConnectImplicitHandler(oauth2.MinParameterEntropy)
			},
			expected:      "The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client. The OAuth 2.0 Client is not allowed to use the authorization grant 'implicit'.",
			expectedField: "invalid_grant",
		},
		{
			name: "ShouldPassBecauseHandlerNotResponsibleForOpenIDImplicitFlowIDToken",
			setup: func(requester *oauth2.AuthorizeRequest, responder *oauth2.AuthorizeResponse) (handler OpenIDConnectImplicitHandler) {
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
			expected:      "The request used a security parameter (e.g., anti-replay, anti-csrf) with insufficient entropy. Parameter 'nonce' is set but does not satisfy the minimum entropy of 8 characters.",
			expectedField: "insufficient_entropy",
		},
		{
			name: "ShouldFailBecauseSessionNotSet",
			setup: func(requester *oauth2.AuthorizeRequest, responder *oauth2.AuthorizeResponse) (handler OpenIDConnectImplicitHandler) {
				requester.Form = url.Values{consts.FormParameterNonce: {"long-enough"}, consts.FormParameterRedirectURI: {"https://example.com"}}
				requester.ResponseTypes = oauth2.Arguments{consts.ResponseTypeImplicitFlowIDToken}
				requester.RequestedScope = oauth2.Arguments{consts.ScopeOpenID}
				requester.Client = &oauth2.DefaultClient{
					GrantTypes:    oauth2.Arguments{consts.GrantTypeImplicit},
					ResponseTypes: oauth2.Arguments{consts.ResponseTypeImplicitFlowToken, consts.ResponseTypeImplicitFlowIDToken},
					Scopes:        []string{consts.ScopeOpenID, "oauth2"},
				}

				requester.Session = nil

				return makeOpenIDConnectImplicitHandler(oauth2.MinParameterEntropy)
			},
			expected:      "The authorization server encountered an unexpected condition that prevented it from fulfilling the request. Failed to validate OpenID Connect 1.0 request because the session is not of type 'openid.Session' which is required.",
			expectedField: "server_error",
		},
		{
			name: "should pass because nonce set",
			setup: func(requester *oauth2.AuthorizeRequest, responder *oauth2.AuthorizeResponse) (handler OpenIDConnectImplicitHandler) {
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
			name: "ShouldPassImplicitFlowIDToken",
			setup: func(requester *oauth2.AuthorizeRequest, responder *oauth2.AuthorizeResponse) (handler OpenIDConnectImplicitHandler) {
				requester.ResponseTypes = oauth2.Arguments{consts.ResponseTypeImplicitFlowIDToken}
				return makeOpenIDConnectImplicitHandler(oauth2.MinParameterEntropy)
			},
			check: func(t *testing.T, requester *oauth2.AuthorizeRequest, responder *oauth2.AuthorizeResponse) {
				assert.Empty(t, responder.GetParameters().Get(consts.FormParameterState))
				assert.Empty(t, responder.GetParameters().Get(consts.AccessResponseAccessToken))
				require.NotEmpty(t, responder.GetParameters().Get(consts.AccessResponseIDToken))

				exp := internal.ExtractJwtExpClaim(t, responder.GetParameters().Get(consts.AccessResponseIDToken))
				internal.RequireEqualTime(t, time.Now().Add(time.Hour), *exp, time.Minute)
			},
		},
		{
			name: "ShouldPassWithCustomLifespan",
			setup: func(requester *oauth2.AuthorizeRequest, responder *oauth2.AuthorizeResponse) (handler OpenIDConnectImplicitHandler) {
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
			check: func(t *testing.T, requester *oauth2.AuthorizeRequest, responder *oauth2.AuthorizeResponse) {
				idToken := responder.GetParameters().Get(consts.AccessResponseIDToken)
				assert.NotEmpty(t, idToken)
				assert.Empty(t, responder.GetParameters().Get(consts.FormParameterState))
				assert.Empty(t, responder.GetParameters().Get(consts.AccessResponseAccessToken))
				idTokenExp := internal.ExtractJwtExpClaim(t, idToken)
				internal.RequireEqualTime(t, time.Now().Add(*internal.TestLifespans.ImplicitGrantIDTokenLifespan), *idTokenExp, time.Minute)
			},
		},
		{
			name: "should pass",
			setup: func(requester *oauth2.AuthorizeRequest, responder *oauth2.AuthorizeResponse) (handler OpenIDConnectImplicitHandler) {
				responder = oauth2.NewAuthorizeResponse()
				requester.ResponseTypes = oauth2.Arguments{consts.ResponseTypeImplicitFlowToken, consts.ResponseTypeImplicitFlowIDToken}

				requester.Client.(*oauth2.DefaultClientWithCustomTokenLifespans).SetTokenLifespans(&internal.TestLifespans)

				return makeOpenIDConnectImplicitHandler(oauth2.MinParameterEntropy)
			},
			check: func(t *testing.T, requester *oauth2.AuthorizeRequest, responder *oauth2.AuthorizeResponse) {
				assert.Empty(t, responder.GetParameters().Get(consts.FormParameterState))

				idToken := responder.GetParameters().Get(consts.AccessResponseIDToken)
				assert.NotEmpty(t, idToken)
				internal.RequireEqualTime(t, time.Now().Add(*internal.TestLifespans.ImplicitGrantIDTokenLifespan).UTC(), *internal.ExtractJwtExpClaim(t, idToken), time.Minute)

				assert.NotEmpty(t, responder.GetParameters().Get(consts.AccessResponseAccessToken))
				internal.RequireEqualTime(t, time.Now().Add(*internal.TestLifespans.ImplicitGrantAccessTokenLifespan).UTC(), requester.Session.GetExpiresAt(oauth2.AccessToken), time.Minute)
			},
		},
		{
			name: "ShouldPassDefaultValues",
			setup: func(requester *oauth2.AuthorizeRequest, responder *oauth2.AuthorizeResponse) (handler OpenIDConnectImplicitHandler) {
				return makeOpenIDConnectImplicitHandler(oauth2.MinParameterEntropy)
			},
			check: func(t *testing.T, requester *oauth2.AuthorizeRequest, responder *oauth2.AuthorizeResponse) {
				assert.NotEmpty(t, responder.GetParameters().Get(consts.AccessResponseIDToken))
				assert.NotEmpty(t, responder.GetParameters().Get(consts.AccessResponseAccessToken))
				assert.Empty(t, responder.GetParameters().Get(consts.FormParameterNonce))

				assert.Equal(t, oauth2.ResponseModeFragment, requester.GetResponseMode())
			},
		},
		{
			name: "ShouldPassWithLowMinEntropy",
			setup: func(requester *oauth2.AuthorizeRequest, responder *oauth2.AuthorizeResponse) (handler OpenIDConnectImplicitHandler) {
				requester.Form.Set(consts.FormParameterNonce, "short")

				return makeOpenIDConnectImplicitHandler(4)
			},
			check: func(t *testing.T, requester *oauth2.AuthorizeRequest, responder *oauth2.AuthorizeResponse) {
				assert.NotEmpty(t, responder.GetParameters().Get(consts.AccessResponseIDToken))
				assert.NotEmpty(t, responder.GetParameters().Get(consts.AccessResponseAccessToken))
				assert.Empty(t, responder.GetParameters().Get(consts.FormParameterNonce))
			},
		},
		{
			name: "ShouldFailWithoutRedirectURI",
			setup: func(requester *oauth2.AuthorizeRequest, responder *oauth2.AuthorizeResponse) (handler OpenIDConnectImplicitHandler) {
				requester.Form.Del(consts.FormParameterRedirectURI)
				requester.RedirectURI = nil

				return makeOpenIDConnectImplicitHandler(4)
			},
			expected:      "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The 'redirect_uri' parameter is required when using OpenID Connect 1.0.",
			expectedField: "invalid_request",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			responder := oauth2.NewAuthorizeResponse()
			requester := oauth2.NewAuthorizeRequest()

			requester.Session = &DefaultSession{
				Claims: &jwt.IDTokenClaims{
					Subject: testSubjectPeter,
				},
				Headers: &jwt.Headers{},
				Subject: testSubjectPeter,
			}

			requester.Client = &oauth2.DefaultClientWithCustomTokenLifespans{
				DefaultClient: &oauth2.DefaultClient{
					Scopes:        oauth2.Arguments{consts.ScopeOpenID},
					ResponseTypes: oauth2.Arguments{consts.ResponseTypeImplicitFlowToken, consts.ResponseTypeImplicitFlowIDToken, consts.ResponseTypeImplicitFlowBoth},
					GrantTypes:    oauth2.Arguments{consts.GrantTypeImplicit},
				},
			}

			requester.ResponseTypes = oauth2.Arguments{consts.ResponseTypeImplicitFlowIDToken, consts.ResponseTypeImplicitFlowToken}
			requester.RequestedScope = oauth2.Arguments{consts.ScopeOpenID}
			requester.GrantedScope = oauth2.Arguments{consts.ScopeOpenID}

			requester.Form = url.Values{
				consts.FormParameterRedirectURI: {"https://example.com"},
				consts.FormParameterState:       {"test-state-value"},
				consts.FormParameterNonce:       {"test-nonce-value"},
			}

			requester.RedirectURI, _ = url.Parse("https://example.com")

			h := tc.setup(requester, responder)
			err := h.HandleAuthorizeEndpointRequest(t.Context(), requester, responder)

			if len(tc.expected) != 0 || len(tc.expectedField) != 0 {
				e := oauth2.ErrorToDebugRFC6749Error(err).(*oauth2.DebugRFC6749Error)

				assert.EqualError(t, e, tc.expected)
				assert.Equal(t, e.ErrorField, tc.expectedField)
			} else {
				assert.NoError(t, err)
				if tc.check != nil {
					tc.check(t, requester, responder)
				}
			}
		})
	}
}

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
