// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package openid

import (
	"context"
	"net/url"
	"testing"
	"time"

	xjwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/internal"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/gen"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/token/hmac"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestHybrid_HandleAuthorizeEndpointRequest(t *testing.T) {
	testCases := []struct {
		name          string
		setup         func(t *testing.T, request *oauth2.AuthorizeRequest, response *oauth2.AuthorizeResponse) OpenIDConnectHybridHandler
		check         func(t *testing.T, request *oauth2.AuthorizeRequest, response *oauth2.AuthorizeResponse)
		expected      string
		expectedField string
	}{
		{
			name: "should not do anything because not a hybrid request",
			setup: func(t *testing.T, request *oauth2.AuthorizeRequest, response *oauth2.AuthorizeResponse) OpenIDConnectHybridHandler {
				return makeOpenIDConnectHybridHandler(oauth2.MinParameterEntropy)
			},
		},
		{
			name: "should not do anything because not a hybrid request",
			setup: func(t *testing.T, request *oauth2.AuthorizeRequest, response *oauth2.AuthorizeResponse) OpenIDConnectHybridHandler {
				request.ResponseTypes = oauth2.Arguments{consts.ResponseTypeImplicitFlowToken, consts.ResponseTypeImplicitFlowIDToken}
				return makeOpenIDConnectHybridHandler(oauth2.MinParameterEntropy)
			},
		},
		{
			name: "should fail because nonce set but too short",
			setup: func(t *testing.T, request *oauth2.AuthorizeRequest, response *oauth2.AuthorizeResponse) OpenIDConnectHybridHandler {
				request.Form = url.Values{consts.FormParameterNonce: {"short"}}
				request.ResponseTypes = oauth2.Arguments{consts.ResponseTypeImplicitFlowToken, consts.ResponseTypeAuthorizationCodeFlow}
				request.Client = &oauth2.DefaultClient{
					GrantTypes:    oauth2.Arguments{consts.GrantTypeAuthorizationCode, consts.GrantTypeImplicit},
					ResponseTypes: oauth2.Arguments{consts.ResponseTypeImplicitFlowToken, consts.ResponseTypeAuthorizationCodeFlow, consts.ResponseTypeImplicitFlowIDToken},
					Scopes:        []string{consts.ScopeOpenID},
				}
				request.GrantedScope = oauth2.Arguments{consts.ScopeOpenID}
				return makeOpenIDConnectHybridHandler(oauth2.MinParameterEntropy)
			},
			expected:      "The request used a security parameter (e.g., anti-replay, anti-csrf) with insufficient entropy. Parameter 'nonce' is set but does not satisfy the minimum entropy of 8 characters.",
			expectedField: "insufficient_entropy",
		},
		{
			name: "should fail because nonce set but too short for non-default min entropy",
			setup: func(t *testing.T, request *oauth2.AuthorizeRequest, response *oauth2.AuthorizeResponse) OpenIDConnectHybridHandler {
				request.Form = url.Values{consts.FormParameterNonce: {"some-foobar-nonce-win"}}
				request.ResponseTypes = oauth2.Arguments{consts.ResponseTypeImplicitFlowToken, consts.ResponseTypeAuthorizationCodeFlow}
				request.Client = &oauth2.DefaultClient{
					GrantTypes:    oauth2.Arguments{consts.GrantTypeAuthorizationCode, consts.GrantTypeImplicit},
					ResponseTypes: oauth2.Arguments{consts.ResponseTypeImplicitFlowToken, consts.ResponseTypeAuthorizationCodeFlow, consts.ResponseTypeImplicitFlowIDToken},
					Scopes:        []string{consts.ScopeOpenID},
				}
				request.GrantedScope = oauth2.Arguments{consts.ScopeOpenID}
				return makeOpenIDConnectHybridHandler(42)
			},
			expected:      "The request used a security parameter (e.g., anti-replay, anti-csrf) with insufficient entropy. Parameter 'nonce' is set but does not satisfy the minimum entropy of 42 characters.",
			expectedField: "insufficient_entropy",
		},
		{
			name: "should fail because session not given",
			setup: func(t *testing.T, request *oauth2.AuthorizeRequest, response *oauth2.AuthorizeResponse) OpenIDConnectHybridHandler {
				request.Session = nil
				request.Form = url.Values{consts.FormParameterNonce: {"long-enough"}}
				request.ResponseTypes = oauth2.Arguments{consts.ResponseTypeImplicitFlowToken, consts.ResponseTypeAuthorizationCodeFlow}
				request.Client = &oauth2.DefaultClient{
					GrantTypes:    oauth2.Arguments{consts.GrantTypeAuthorizationCode, consts.GrantTypeImplicit},
					ResponseTypes: oauth2.Arguments{consts.ResponseTypeImplicitFlowToken, consts.ResponseTypeAuthorizationCodeFlow, consts.ResponseTypeImplicitFlowIDToken},
					Scopes:        []string{consts.ScopeOpenID},
				}
				request.GrantedScope = oauth2.Arguments{consts.ScopeOpenID}
				return makeOpenIDConnectHybridHandler(oauth2.MinParameterEntropy)
			},
			expected:      "Session type mismatch",
			expectedField: "Session type mismatch",
		},
		{
			name: "should fail because client missing response types",
			setup: func(t *testing.T, request *oauth2.AuthorizeRequest, response *oauth2.AuthorizeResponse) OpenIDConnectHybridHandler {
				request.ResponseTypes = oauth2.Arguments{consts.ResponseTypeImplicitFlowToken, consts.ResponseTypeAuthorizationCodeFlow, consts.ResponseTypeImplicitFlowIDToken}
				request.Client = &oauth2.DefaultClient{
					GrantTypes:    oauth2.Arguments{consts.GrantTypeImplicit},
					ResponseTypes: oauth2.Arguments{consts.ResponseTypeImplicitFlowToken, consts.ResponseTypeAuthorizationCodeFlow, consts.ResponseTypeImplicitFlowIDToken},
					Scopes:        []string{consts.ScopeOpenID},
				}
				request.Session = &DefaultSession{
					Claims: &jwt.IDTokenClaims{
						Subject: "peter",
					},
					Headers: &jwt.Headers{},
					Subject: "peter",
				}
				return makeOpenIDConnectHybridHandler(oauth2.MinParameterEntropy)
			},
			//expectErr: oauth2.ErrInvalidGrant,
			expected:      "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Parameter 'nonce' must be set when requesting an ID Token using the OpenID Connect Hybrid Flow.",
			expectedField: "invalid_request",
		},
		{
			name: "should pass with exact one state parameter in response",
			setup: func(t *testing.T, request *oauth2.AuthorizeRequest, response *oauth2.AuthorizeResponse) OpenIDConnectHybridHandler {
				request.Form.Set(consts.FormParameterNonce, "some-foobar-nonce-win")
				request.Form.Set(consts.FormParameterState, "some-foobar-state-win")
				request.ResponseTypes = oauth2.Arguments{consts.ResponseTypeAuthorizationCodeFlow, consts.ResponseTypeImplicitFlowToken}
				request.State = "some-foobar-state-win"
				request.Session = &DefaultSession{
					Claims: &jwt.IDTokenClaims{
						Subject: "peter",
					},
					Headers: &jwt.Headers{},
					Subject: "peter",
				}
				request.Client = &oauth2.DefaultClient{
					GrantTypes:    oauth2.Arguments{consts.GrantTypeAuthorizationCode, consts.GrantTypeImplicit},
					ResponseTypes: oauth2.Arguments{consts.ResponseTypeImplicitFlowToken, consts.ResponseTypeAuthorizationCodeFlow, consts.ResponseTypeImplicitFlowIDToken},
					Scopes:        []string{consts.ScopeOpenID},
				}

				return makeOpenIDConnectHybridHandler(oauth2.MinParameterEntropy)
			},
			check: func(t *testing.T, request *oauth2.AuthorizeRequest, response *oauth2.AuthorizeResponse) {
				params := response.GetParameters()
				var stateParam []string
				for k, v := range params {
					if k == "state" {
						stateParam = v
						break
					}
				}
				assert.Len(t, stateParam, 1)
			},
		},
		{
			name: "ShouldPassWithStateParameterAndGenerateStateHash",
			setup: func(t *testing.T, request *oauth2.AuthorizeRequest, response *oauth2.AuthorizeResponse) OpenIDConnectHybridHandler {
				request.Form.Set(consts.FormParameterNonce, "some-foobar-nonce-win")
				request.Form.Set(consts.FormParameterState, "some-foobar-state-win")
				request.ResponseTypes = oauth2.Arguments{consts.ResponseTypeAuthorizationCodeFlow, consts.ResponseTypeImplicitFlowIDToken}
				request.State = "some-foobar-state-win"
				request.GrantedScope = oauth2.Arguments{consts.ScopeOpenID}

				request.Session = &DefaultSession{
					Claims: &jwt.IDTokenClaims{
						Subject: "peter",
					},
					Headers: &jwt.Headers{},
					Subject: "peter",
				}
				request.Client = &oauth2.DefaultClient{
					GrantTypes:    oauth2.Arguments{consts.GrantTypeAuthorizationCode, consts.GrantTypeImplicit},
					ResponseTypes: oauth2.Arguments{consts.ResponseTypeImplicitFlowToken, consts.ResponseTypeAuthorizationCodeFlow, consts.ResponseTypeImplicitFlowIDToken, consts.ResponseTypeHybridFlowToken, consts.ResponseTypeHybridFlowBoth, consts.ResponseTypeHybridFlowIDToken},
					Scopes:        []string{consts.ScopeOpenID},
				}

				return makeOpenIDConnectHybridHandler(oauth2.MinParameterEntropy)
			},
			check: func(t *testing.T, request *oauth2.AuthorizeRequest, response *oauth2.AuthorizeResponse) {
				params := response.GetParameters()
				var stateParam []string
				for k, v := range params {
					if k == consts.FormParameterState {
						stateParam = v
						break
					}
				}
				assert.Len(t, stateParam, 1)

				idToken := response.GetParameters().Get(consts.AccessResponseIDToken)
				assert.NotEmpty(t, idToken)
				assert.True(t, request.GetSession().GetExpiresAt(oauth2.IDToken).IsZero())

				parser := xjwt.NewParser()

				claims := &IDTokenClaims{}

				_, _, err := parser.ParseUnverified(idToken, claims)
				require.NoError(t, err)

				assert.Equal(t, "MvmJNOT-fq6rnnnrUTC_2A", claims.StateHash)
			},
		},
		{
			name: "ShouldPassWhenNonceHasMinimumEntropy",
			setup: func(t *testing.T, request *oauth2.AuthorizeRequest, response *oauth2.AuthorizeResponse) OpenIDConnectHybridHandler {
				request.Form.Set(consts.FormParameterNonce, "some-foobar-nonce-win")
				request.Client = &oauth2.DefaultClient{
					GrantTypes:    oauth2.Arguments{consts.GrantTypeAuthorizationCode, consts.GrantTypeImplicit},
					ResponseTypes: oauth2.Arguments{consts.ResponseTypeImplicitFlowToken, consts.ResponseTypeAuthorizationCodeFlow, consts.ResponseTypeImplicitFlowIDToken},
					Scopes:        []string{consts.ScopeOpenID},
				}

				return makeOpenIDConnectHybridHandler(oauth2.MinParameterEntropy)
			},
		},
		{
			name: "ShouldPassIfNonceNotSet",
			setup: func(t *testing.T, request *oauth2.AuthorizeRequest, response *oauth2.AuthorizeResponse) OpenIDConnectHybridHandler {
				request.Client = &oauth2.DefaultClient{
					GrantTypes:    oauth2.Arguments{consts.GrantTypeAuthorizationCode, consts.GrantTypeImplicit},
					ResponseTypes: oauth2.Arguments{consts.ResponseTypeImplicitFlowToken, consts.ResponseTypeAuthorizationCodeFlow, consts.ResponseTypeImplicitFlowIDToken},
					Scopes:        []string{consts.ScopeOpenID},
				}

				return makeOpenIDConnectHybridHandler(oauth2.MinParameterEntropy)
			},
		},
		{
			name: "should pass because nonce was set with low entropy but also with low min entropy",
			setup: func(t *testing.T, request *oauth2.AuthorizeRequest, response *oauth2.AuthorizeResponse) OpenIDConnectHybridHandler {
				request.Form.Set(consts.FormParameterNonce, "short")
				request.Client = &oauth2.DefaultClient{
					GrantTypes:    oauth2.Arguments{consts.GrantTypeAuthorizationCode, consts.GrantTypeImplicit},
					ResponseTypes: oauth2.Arguments{consts.ResponseTypeImplicitFlowToken, consts.ResponseTypeAuthorizationCodeFlow, consts.ResponseTypeImplicitFlowIDToken},
					Scopes:        []string{consts.ScopeOpenID},
				}

				return makeOpenIDConnectHybridHandler(4)
			},
		},
		{
			name: "ShouldPassWhenExpiresAtSetWithCodeLifespanZero",
			setup: func(t *testing.T, request *oauth2.AuthorizeRequest, response *oauth2.AuthorizeResponse) OpenIDConnectHybridHandler {
				request.Form.Set(consts.FormParameterNonce, "some-foobar-nonce-win")
				request.ResponseTypes = oauth2.Arguments{consts.ResponseTypeImplicitFlowToken, consts.ResponseTypeAuthorizationCodeFlow, consts.ResponseTypeImplicitFlowIDToken}
				request.Client = &oauth2.DefaultClient{
					GrantTypes:    oauth2.Arguments{consts.GrantTypeAuthorizationCode, consts.GrantTypeImplicit},
					ResponseTypes: oauth2.Arguments{consts.ResponseTypeImplicitFlowToken, consts.ResponseTypeAuthorizationCodeFlow, consts.ResponseTypeImplicitFlowIDToken},
					Scopes:        []string{consts.ScopeOpenID},
				}
				request.Session = &DefaultSession{
					Claims: &jwt.IDTokenClaims{
						Subject: "peter",
					},
					Headers: &jwt.Headers{},
					Subject: "peter",
				}

				return makeOpenIDConnectHybridHandler(oauth2.MinParameterEntropy)
			},
			check: func(t *testing.T, request *oauth2.AuthorizeRequest, response *oauth2.AuthorizeResponse) {
				assert.True(t, !request.Session.GetExpiresAt(oauth2.AuthorizeCode).IsZero())
			},
		},
		{
			name: "ShouldPass",
			setup: func(t *testing.T, request *oauth2.AuthorizeRequest, response *oauth2.AuthorizeResponse) OpenIDConnectHybridHandler {
				request.Form.Set(consts.FormParameterNonce, "some-foobar-nonce-win")
				request.ResponseTypes = oauth2.Arguments{consts.ResponseTypeImplicitFlowToken, consts.ResponseTypeAuthorizationCodeFlow, consts.ResponseTypeImplicitFlowIDToken}
				request.Client = &oauth2.DefaultClientWithCustomTokenLifespans{
					DefaultClient: &oauth2.DefaultClient{
						GrantTypes:    oauth2.Arguments{consts.GrantTypeAuthorizationCode, consts.GrantTypeImplicit},
						ResponseTypes: oauth2.Arguments{consts.ResponseTypeImplicitFlowToken, consts.ResponseTypeAuthorizationCodeFlow, consts.ResponseTypeImplicitFlowIDToken},
						Scopes:        []string{consts.ScopeOpenID},
					},
				}
				request.GrantedScope = oauth2.Arguments{consts.ScopeOpenID}
				request.Session = &DefaultSession{
					Claims: &jwt.IDTokenClaims{
						Subject: "peter",
					},
					Headers: &jwt.Headers{},
					Subject: "peter",
				}

				return makeOpenIDConnectHybridHandler(oauth2.MinParameterEntropy)
			},
			check: func(t *testing.T, request *oauth2.AuthorizeRequest, response *oauth2.AuthorizeResponse) {
				assert.NotEmpty(t, response.GetParameters().Get(consts.AccessResponseIDToken))
				assert.NotEmpty(t, response.GetParameters().Get(consts.AccessResponseAuthorizationCode))
				assert.NotEmpty(t, response.GetParameters().Get(consts.AccessResponseAccessToken))
				internal.RequireEqualTime(t, time.Now().Add(time.Hour).UTC(), request.GetSession().GetExpiresAt(oauth2.AuthorizeCode), time.Second)
			},
		},
		{
			name: "ShouldPassWithCustomLifespan",
			setup: func(t *testing.T, request *oauth2.AuthorizeRequest, response *oauth2.AuthorizeResponse) OpenIDConnectHybridHandler {
				request.Form.Set(consts.FormParameterNonce, "some-foobar-nonce-win")
				request.ResponseTypes = oauth2.Arguments{consts.ResponseTypeImplicitFlowToken, consts.ResponseTypeAuthorizationCodeFlow, consts.ResponseTypeImplicitFlowIDToken}
				request.Client = &oauth2.DefaultClientWithCustomTokenLifespans{
					DefaultClient: &oauth2.DefaultClient{
						GrantTypes:    oauth2.Arguments{consts.GrantTypeAuthorizationCode, consts.GrantTypeImplicit},
						ResponseTypes: oauth2.Arguments{consts.ResponseTypeImplicitFlowToken, consts.ResponseTypeAuthorizationCodeFlow, consts.ResponseTypeImplicitFlowIDToken},
						Scopes:        []string{consts.ScopeOpenID},
					},
				}
				request.GrantedScope = oauth2.Arguments{consts.ScopeOpenID}
				request.Session = &DefaultSession{
					Claims: &jwt.IDTokenClaims{
						Subject: "peter",
					},
					Headers: &jwt.Headers{},
					Subject: "peter",
				}
				request.GetClient().(*oauth2.DefaultClientWithCustomTokenLifespans).SetTokenLifespans(&internal.TestLifespans)

				return makeOpenIDConnectHybridHandler(oauth2.MinParameterEntropy)
			},
			check: func(t *testing.T, request *oauth2.AuthorizeRequest, response *oauth2.AuthorizeResponse) {
				assert.NotEmpty(t, response.GetParameters().Get(consts.AccessResponseAuthorizationCode))
				internal.RequireEqualTime(t, time.Now().Add(1*time.Hour).UTC(), request.GetSession().GetExpiresAt(oauth2.AuthorizeCode), time.Second)

				idToken := response.GetParameters().Get(consts.AccessResponseIDToken)
				assert.NotEmpty(t, idToken)
				assert.True(t, request.GetSession().GetExpiresAt(oauth2.IDToken).IsZero())

				parser := xjwt.NewParser()

				claims := &IDTokenClaims{}

				_, _, err := parser.ParseUnverified(idToken, claims)

				require.NoError(t, err)
				internal.RequireEqualTime(t, time.Now().Add(*internal.TestLifespans.ImplicitGrantIDTokenLifespan), claims.ExpiresAt.Time, time.Minute)
				assert.NotEmpty(t, claims.CodeHash)
				assert.Empty(t, claims.StateHash)

				assert.NotEmpty(t, claims)
				assert.NotEmpty(t, response.GetParameters().Get(consts.AccessResponseAccessToken))
				internal.RequireEqualTime(t, time.Now().Add(*internal.TestLifespans.ImplicitGrantAccessTokenLifespan).UTC(), request.GetSession().GetExpiresAt(oauth2.AccessToken), time.Second)
			},
		},
		{
			name: "ShouldHandleDefaultResponseMode",
			setup: func(t *testing.T, request *oauth2.AuthorizeRequest, response *oauth2.AuthorizeResponse) OpenIDConnectHybridHandler {
				request.Form.Set(consts.FormParameterNonce, "some-foobar-nonce-win")
				request.ResponseTypes = oauth2.Arguments{consts.ResponseTypeImplicitFlowToken, consts.ResponseTypeAuthorizationCodeFlow, consts.ResponseTypeImplicitFlowIDToken}
				request.Client = &oauth2.DefaultClientWithCustomTokenLifespans{
					DefaultClient: &oauth2.DefaultClient{
						GrantTypes:    oauth2.Arguments{consts.GrantTypeAuthorizationCode, consts.GrantTypeImplicit},
						ResponseTypes: oauth2.Arguments{consts.ResponseTypeImplicitFlowToken, consts.ResponseTypeAuthorizationCodeFlow, consts.ResponseTypeImplicitFlowIDToken},
						Scopes:        []string{consts.ScopeOpenID},
					},
				}
				request.GrantedScope = oauth2.Arguments{consts.ScopeOpenID}
				request.Session = &DefaultSession{
					Claims: &jwt.IDTokenClaims{
						Subject: "peter",
					},
					Headers: &jwt.Headers{},
					Subject: "peter",
				}

				return makeOpenIDConnectHybridHandler(oauth2.MinParameterEntropy)
			},
			check: func(t *testing.T, request *oauth2.AuthorizeRequest, response *oauth2.AuthorizeResponse) {
				assert.NotEmpty(t, response.GetParameters().Get(consts.AccessResponseAuthorizationCode))
				assert.NotEmpty(t, response.GetParameters().Get(consts.AccessResponseAccessToken))
				assert.NotEmpty(t, response.GetParameters().Get(consts.AccessResponseIDToken))

				assert.Equal(t, oauth2.ResponseModeFragment, request.GetResponseMode())
				assert.WithinDuration(t, time.Now().Add(time.Hour).UTC(), request.GetSession().GetExpiresAt(oauth2.AuthorizeCode), 5*time.Second)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			request := oauth2.NewAuthorizeRequest()
			request.Session = NewDefaultSession()

			response := oauth2.NewAuthorizeResponse()

			h := tc.setup(t, request, response)
			err := h.HandleAuthorizeEndpointRequest(context.TODO(), request, response)

			if len(tc.expected) != 0 {
				require.EqualError(t, err, tc.expectedField)
				require.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), tc.expected)
			} else {
				require.NoError(t, err)
			}

			if tc.check != nil {
				tc.check(t, request, response)
			}
		})
	}
}

type IDTokenClaims struct {
	StateHash string `json:"s_hash"`
	CodeHash  string `json:"c_hash"`

	xjwt.RegisteredClaims
}

var hmacStrategy = &hoauth2.HMACSHAStrategy{
	Enigma: &hmac.HMACStrategy{
		Config: &oauth2.Config{
			GlobalSecret: []byte("some-super-cool-secret-that-nobody-knows-nobody-knows"),
		},
	},
}

func makeOpenIDConnectHybridHandler(minParameterEntropy int) OpenIDConnectHybridHandler {
	var idStrategy = &DefaultStrategy{
		Signer: &jwt.DefaultSigner{
			GetPrivateKey: func(_ context.Context) (any, error) {
				return gen.MustRSAKey(), nil
			},
		},
		Config: &oauth2.Config{
			MinParameterEntropy: minParameterEntropy,
		},
	}

	var j = &DefaultStrategy{
		Signer: &jwt.DefaultSigner{
			GetPrivateKey: func(_ context.Context) (any, error) {
				return key, nil
			},
		},
		Config: &oauth2.Config{
			MinParameterEntropy: minParameterEntropy,
		},
	}

	config := &oauth2.Config{
		ScopeStrategy:         oauth2.HierarchicScopeStrategy,
		MinParameterEntropy:   minParameterEntropy,
		AccessTokenLifespan:   time.Hour,
		AuthorizeCodeLifespan: time.Hour,
		RefreshTokenLifespan:  time.Hour,
	}
	return OpenIDConnectHybridHandler{
		AuthorizeExplicitGrantHandler: &hoauth2.AuthorizeExplicitGrantHandler{
			AuthorizeCodeStrategy: hmacStrategy,
			AccessTokenStrategy:   hmacStrategy,
			CoreStorage:           storage.NewMemoryStore(),
			Config:                config,
		},
		AuthorizeImplicitGrantTypeHandler: &hoauth2.AuthorizeImplicitGrantTypeHandler{
			Config: &oauth2.Config{
				AccessTokenLifespan: time.Hour,
			},
			AccessTokenStrategy: hmacStrategy,
			AccessTokenStorage:  storage.NewMemoryStore(),
		},
		IDTokenHandleHelper: &IDTokenHandleHelper{
			IDTokenStrategy: idStrategy,
		},
		Config:                        config,
		OpenIDConnectRequestValidator: NewOpenIDConnectRequestValidator(j.Signer, config),
		OpenIDConnectRequestStorage:   storage.NewMemoryStore(),
	}
}

//nolint:unused
type defaultSession struct {
	Claims  *jwt.IDTokenClaims
	Headers *jwt.Headers
	*oauth2.DefaultSession
}

//nolint:unused
func (s *defaultSession) IDTokenHeaders() *jwt.Headers {
	if s.Headers == nil {
		s.Headers = &jwt.Headers{}
	}
	return s.Headers
}

//nolint:unused
func (s *defaultSession) IDTokenClaims() *jwt.IDTokenClaims {
	if s.Claims == nil {
		s.Claims = &jwt.IDTokenClaims{}
	}
	return s.Claims
}
