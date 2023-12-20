// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package openid

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"testing"
	"time"

	cristaljwt "github.com/cristalhq/jwt/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/internal"
	"authelia.com/provider/oauth2/internal/gen"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/token/hmac"
	"authelia.com/provider/oauth2/token/jwt"
)

var hmacStrategy = &hoauth2.HMACSHAStrategy{
	Enigma: &hmac.HMACStrategy{
		Config: &oauth2.Config{
			GlobalSecret: []byte("some-super-cool-secret-that-nobody-knows-nobody-knows"),
		},
	},
}

type defaultSession struct {
	Claims  *jwt.IDTokenClaims
	Headers *jwt.Headers
	*oauth2.DefaultSession
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

func (s *defaultSession) IDTokenHeaders() *jwt.Headers {
	if s.Headers == nil {
		s.Headers = &jwt.Headers{}
	}
	return s.Headers
}

func (s *defaultSession) IDTokenClaims() *jwt.IDTokenClaims {
	if s.Claims == nil {
		s.Claims = &jwt.IDTokenClaims{}
	}
	return s.Claims
}

func TestHybrid_HandleAuthorizeEndpointRequest(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	aresp := oauth2.NewAuthorizeResponse()
	areq := oauth2.NewAuthorizeRequest()

	for k, c := range []struct {
		description string
		setup       func() OpenIDConnectHybridHandler
		check       func()
		expectErr   error
	}{
		{
			description: "should not do anything because not a hybrid request",
			setup: func() OpenIDConnectHybridHandler {
				return makeOpenIDConnectHybridHandler(oauth2.MinParameterEntropy)
			},
		},
		{
			description: "should not do anything because not a hybrid request",
			setup: func() OpenIDConnectHybridHandler {
				areq.ResponseTypes = oauth2.Arguments{"token", "id_token"}
				return makeOpenIDConnectHybridHandler(oauth2.MinParameterEntropy)
			},
		},
		{
			description: "should fail because nonce set but too short",
			setup: func() OpenIDConnectHybridHandler {
				areq.Form = url.Values{"nonce": {"short"}}
				areq.ResponseTypes = oauth2.Arguments{"token", "code"}
				areq.Client = &oauth2.DefaultClient{
					GrantTypes:    oauth2.Arguments{"authorization_code", "implicit"},
					ResponseTypes: oauth2.Arguments{"token", "code", "id_token"},
					Scopes:        []string{"openid"},
				}
				areq.GrantedScope = oauth2.Arguments{"openid"}
				return makeOpenIDConnectHybridHandler(oauth2.MinParameterEntropy)
			},
			expectErr: oauth2.ErrInsufficientEntropy,
		},
		{
			description: "should fail because nonce set but too short for non-default min entropy",
			setup: func() OpenIDConnectHybridHandler {
				areq.Form = url.Values{"nonce": {"some-foobar-nonce-win"}}
				areq.ResponseTypes = oauth2.Arguments{"token", "code"}
				areq.Client = &oauth2.DefaultClient{
					GrantTypes:    oauth2.Arguments{"authorization_code", "implicit"},
					ResponseTypes: oauth2.Arguments{"token", "code", "id_token"},
					Scopes:        []string{"openid"},
				}
				areq.GrantedScope = oauth2.Arguments{"openid"}
				return makeOpenIDConnectHybridHandler(42)
			},
			expectErr: oauth2.ErrInsufficientEntropy,
		},
		{
			description: "should fail because session not given",
			setup: func() OpenIDConnectHybridHandler {
				areq.Form = url.Values{"nonce": {"long-enough"}}
				areq.ResponseTypes = oauth2.Arguments{"token", "code"}
				areq.Client = &oauth2.DefaultClient{
					GrantTypes:    oauth2.Arguments{"authorization_code", "implicit"},
					ResponseTypes: oauth2.Arguments{"token", "code", "id_token"},
					Scopes:        []string{"openid"},
				}
				areq.GrantedScope = oauth2.Arguments{"openid"}
				return makeOpenIDConnectHybridHandler(oauth2.MinParameterEntropy)
			},
			expectErr: ErrInvalidSession,
		},
		{
			description: "should fail because client missing response types",
			setup: func() OpenIDConnectHybridHandler {
				areq.ResponseTypes = oauth2.Arguments{"token", "code", "id_token"}
				areq.Client = &oauth2.DefaultClient{
					GrantTypes:    oauth2.Arguments{"implicit"},
					ResponseTypes: oauth2.Arguments{"token", "code", "id_token"},
					Scopes:        []string{"openid"},
				}
				areq.Session = &DefaultSession{
					Claims: &jwt.IDTokenClaims{
						Subject: "peter",
					},
					Headers: &jwt.Headers{},
					Subject: "peter",
				}
				return makeOpenIDConnectHybridHandler(oauth2.MinParameterEntropy)
			},
			expectErr: oauth2.ErrInvalidGrant,
		},
		{
			description: "should pass with exact one state parameter in response",
			setup: func() OpenIDConnectHybridHandler {
				areq.Form = url.Values{"nonce": {"long-enough"}, "state": {""}}
				areq.Client = &oauth2.DefaultClient{
					GrantTypes:    oauth2.Arguments{"authorization_code", "implicit"},
					ResponseTypes: oauth2.Arguments{"token", "code", "id_token"},
					Scopes:        []string{"openid"},
				}
				return makeOpenIDConnectHybridHandler(oauth2.MinParameterEntropy)
			},
			check: func() {
				params := aresp.GetParameters()
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
			description: "should pass because nonce was set with sufficient entropy",
			setup: func() OpenIDConnectHybridHandler {
				areq.Form.Set("nonce", "some-foobar-nonce-win")
				areq.Client = &oauth2.DefaultClient{
					GrantTypes:    oauth2.Arguments{"authorization_code", "implicit"},
					ResponseTypes: oauth2.Arguments{"token", "code", "id_token"},
					Scopes:        []string{"openid"},
				}
				return makeOpenIDConnectHybridHandler(oauth2.MinParameterEntropy)
			},
		},
		{
			description: "should pass even if nonce was not set",
			setup: func() OpenIDConnectHybridHandler {
				areq.Client = &oauth2.DefaultClient{
					GrantTypes:    oauth2.Arguments{"authorization_code", "implicit"},
					ResponseTypes: oauth2.Arguments{"token", "code", "id_token"},
					Scopes:        []string{"openid"},
				}
				return makeOpenIDConnectHybridHandler(oauth2.MinParameterEntropy)
			},
		},
		{
			description: "should pass because nonce was set with low entropy but also with low min entropy",
			setup: func() OpenIDConnectHybridHandler {
				areq.Form.Set("nonce", "short")
				areq.Client = &oauth2.DefaultClient{
					GrantTypes:    oauth2.Arguments{"authorization_code", "implicit"},
					ResponseTypes: oauth2.Arguments{"token", "code", "id_token"},
					Scopes:        []string{"openid"},
				}
				return makeOpenIDConnectHybridHandler(4)
			},
		},
		{
			description: "should pass because AuthorizeCode's ExpiresAt is set, even if AuthorizeCodeLifespan is zero",
			setup: func() OpenIDConnectHybridHandler {
				areq.Form.Set("nonce", "some-foobar-nonce-win")
				return makeOpenIDConnectHybridHandler(oauth2.MinParameterEntropy)
			},
			check: func() {
				assert.True(t, !areq.Session.GetExpiresAt(oauth2.AuthorizeCode).IsZero())
			},
		},
		{
			description: "should pass",
			setup: func() OpenIDConnectHybridHandler {
				return makeOpenIDConnectHybridHandler(oauth2.MinParameterEntropy)
			},
			check: func() {
				assert.NotEmpty(t, aresp.GetParameters().Get("id_token"))
				assert.NotEmpty(t, aresp.GetParameters().Get("code"))
				assert.NotEmpty(t, aresp.GetParameters().Get("access_token"))
				internal.RequireEqualTime(t, time.Now().Add(time.Hour).UTC(), areq.GetSession().GetExpiresAt(oauth2.AuthorizeCode), time.Second)
			},
		},
		{
			description: "should pass with custom client lifespans",
			setup: func() OpenIDConnectHybridHandler {
				aresp = oauth2.NewAuthorizeResponse()
				areq = oauth2.NewAuthorizeRequest()
				areq.Form.Set("nonce", "some-foobar-nonce-win")
				areq.ResponseTypes = oauth2.Arguments{"token", "code", "id_token"}
				areq.Client = &oauth2.DefaultClientWithCustomTokenLifespans{
					DefaultClient: &oauth2.DefaultClient{
						GrantTypes:    oauth2.Arguments{"authorization_code", "implicit"},
						ResponseTypes: oauth2.Arguments{"token", "code", "id_token"},
						Scopes:        []string{"openid"},
					},
				}
				areq.GrantedScope = oauth2.Arguments{"openid"}
				areq.Session = &DefaultSession{
					Claims: &jwt.IDTokenClaims{
						Subject: "peter",
					},
					Headers: &jwt.Headers{},
					Subject: "peter",
				}
				areq.GetClient().(*oauth2.DefaultClientWithCustomTokenLifespans).SetTokenLifespans(&internal.TestLifespans)
				return makeOpenIDConnectHybridHandler(oauth2.MinParameterEntropy)
			},
			check: func() {
				assert.NotEmpty(t, aresp.GetParameters().Get("code"))
				internal.RequireEqualTime(t, time.Now().Add(1*time.Hour).UTC(), areq.GetSession().GetExpiresAt(oauth2.AuthorizeCode), time.Second)

				idToken := aresp.GetParameters().Get("id_token")
				assert.NotEmpty(t, idToken)
				assert.True(t, areq.GetSession().GetExpiresAt(oauth2.IDToken).IsZero())
				jwt, err := cristaljwt.ParseNoVerify([]byte(idToken))
				require.NoError(t, err)
				claims := &cristaljwt.RegisteredClaims{}
				require.NoError(t, json.Unmarshal(jwt.Claims(), claims))
				internal.RequireEqualTime(t, time.Now().Add(*internal.TestLifespans.ImplicitGrantIDTokenLifespan), claims.ExpiresAt.Time, time.Minute)

				assert.NotEmpty(t, aresp.GetParameters().Get("access_token"))
				internal.RequireEqualTime(t, time.Now().Add(*internal.TestLifespans.ImplicitGrantAccessTokenLifespan).UTC(), areq.GetSession().GetExpiresAt(oauth2.AccessToken), time.Second)
			},
		},
		{
			description: "Default responseMode check",
			setup: func() OpenIDConnectHybridHandler {
				return makeOpenIDConnectHybridHandler(oauth2.MinParameterEntropy)
			},
			check: func() {
				assert.NotEmpty(t, aresp.GetParameters().Get("id_token"))
				assert.NotEmpty(t, aresp.GetParameters().Get("code"))
				assert.NotEmpty(t, aresp.GetParameters().Get("access_token"))
				assert.Equal(t, oauth2.ResponseModeFragment, areq.GetResponseMode())
				assert.WithinDuration(t, time.Now().Add(time.Hour).UTC(), areq.GetSession().GetExpiresAt(oauth2.AuthorizeCode), 5*time.Second)
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

			if c.check != nil {
				c.check()
			}
		})
	}
}
