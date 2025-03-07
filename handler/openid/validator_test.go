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
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestValidatePrompt(t *testing.T) {
	config := &oauth2.Config{
		MinParameterEntropy: oauth2.MinParameterEntropy,
	}

	var j = &DefaultStrategy{
		Strategy: &jwt.DefaultStrategy{
			Config: config,
			Issuer: jwt.NewDefaultIssuerRS256Unverified(key),
		},
		Config: &oauth2.Config{
			MinParameterEntropy: oauth2.MinParameterEntropy,
		},
	}

	v := NewOpenIDConnectRequestValidator(j, config)

	var genIDToken = func(c jwt.IDTokenClaims) string {
		s, _, err := j.Encode(context.TODO(), c.ToMapClaims())
		require.NoError(t, err)
		return s
	}

	for k, tc := range []struct {
		d           string
		prompt      string
		redirectURL string
		isPublic    bool
		expectErr   bool
		idTokenHint string
		s           *DefaultSession
	}{
		{
			d:           "should fail because prompt=none should not work together with public clients and http non-localhost",
			prompt:      "none",
			isPublic:    true,
			expectErr:   true,
			redirectURL: "http://foo-bar/",
			s: &DefaultSession{
				Subject: "foo",
				Claims: &jwt.IDTokenClaims{
					Subject:     "foo",
					RequestedAt: jwt.Now(),
					AuthTime:    jwt.NewNumericDate(time.Now().Add(-time.Minute)),
				},
			},
		},
		{
			d:           "should pass because prompt=none works for public clients and http localhost",
			prompt:      "none",
			isPublic:    true,
			expectErr:   false,
			redirectURL: "http://localhost/",
			s: &DefaultSession{
				Subject: "foo",
				Claims: &jwt.IDTokenClaims{
					Subject:     "foo",
					RequestedAt: jwt.Now(),
					AuthTime:    jwt.NewNumericDate(time.Now().Add(-time.Minute)),
				},
			},
		},
		{
			d:           "should pass",
			prompt:      "none",
			isPublic:    true,
			expectErr:   false,
			redirectURL: "https://foo-bar/",
			s: &DefaultSession{
				Subject: "foo",
				Claims: &jwt.IDTokenClaims{
					Subject:     "foo",
					RequestedAt: jwt.Now(),
					AuthTime:    jwt.NewNumericDate(time.Now().Add(-time.Minute)),
				},
			},
		},
		{
			d:         "should fail because prompt=none requires an auth time being set",
			prompt:    "none",
			isPublic:  false,
			expectErr: true,
			s: &DefaultSession{
				Subject: "foo",
				Claims: &jwt.IDTokenClaims{
					Subject:     "foo",
					RequestedAt: jwt.Now(),
				},
			},
		},
		{
			d:         "should fail because prompt=none and auth time is recent (after requested at)",
			prompt:    "none",
			isPublic:  false,
			expectErr: true,
			s: &DefaultSession{
				Subject: "foo",
				Claims: &jwt.IDTokenClaims{
					Subject:     "foo",
					RequestedAt: jwt.NewNumericDate(time.Now().Add(-time.Minute)),
					AuthTime:    jwt.Now(),
				},
			},
		},
		{
			d:         "should pass because prompt=none and auth time is in the past (before requested at)",
			prompt:    "none",
			isPublic:  false,
			expectErr: false,
			s: &DefaultSession{
				Subject: "foo",
				Claims: &jwt.IDTokenClaims{
					Subject:     "foo",
					RequestedAt: jwt.Now(),
					AuthTime:    jwt.NewNumericDate(time.Now().Add(-time.Minute)),
				},
			},
		},
		{
			d:         "should fail because prompt=none can not be used together with other prompts",
			prompt:    "none login",
			isPublic:  false,
			expectErr: true,
			s: &DefaultSession{
				Subject: "foo",
				Claims: &jwt.IDTokenClaims{
					Subject:     "foo",
					RequestedAt: jwt.Now(),
					AuthTime:    jwt.Now(),
				},
			},
		},
		{
			d:         "should fail because prompt=foo is an unknown value",
			prompt:    "foo",
			isPublic:  false,
			expectErr: true,
			s: &DefaultSession{
				Subject: "foo",
				Claims: &jwt.IDTokenClaims{
					Subject:     "foo",
					RequestedAt: jwt.Now(),
					AuthTime:    jwt.Now(),
				},
			},
		},
		{
			d:         "should pass because requesting consent and login works with public clients",
			prompt:    "login consent",
			isPublic:  true,
			expectErr: false,
			s: &DefaultSession{
				Subject: "foo",
				Claims: &jwt.IDTokenClaims{
					Subject:     "foo",
					RequestedAt: jwt.NewNumericDate(time.Now().Add(-time.Second * 5)),
					AuthTime:    jwt.NewNumericDate(time.Now().Add(-time.Second)),
				},
			},
		},
		{
			d:         "should pass because requesting consent and login works with confidential clients",
			prompt:    "login consent",
			isPublic:  false,
			expectErr: false,
			s: &DefaultSession{
				Subject: "foo",
				Claims: &jwt.IDTokenClaims{
					Subject:     "foo",
					RequestedAt: jwt.NewNumericDate(time.Now().Add(-time.Second * 5)),
					AuthTime:    jwt.NewNumericDate(time.Now().Add(-time.Second)),
				},
			},
		},
		{
			d:         "should fail subject from ID token does not match subject from session",
			prompt:    "login",
			isPublic:  false,
			expectErr: true,
			s: &DefaultSession{
				Subject: "foo",
				Claims: &jwt.IDTokenClaims{
					Subject:     "foo",
					RequestedAt: jwt.Now(),
					AuthTime:    jwt.NewNumericDate(time.Now().Add(-time.Second)),
				},
			},
			idTokenHint: genIDToken(jwt.IDTokenClaims{
				Subject:        "bar",
				RequestedAt:    jwt.Now(),
				ExpirationTime: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			}),
		},
		{
			d:         "should pass subject from ID token matches subject from session",
			prompt:    "",
			isPublic:  false,
			expectErr: false,
			s: &DefaultSession{
				Subject: "foo",
				Claims: &jwt.IDTokenClaims{
					Subject:     "foo",
					RequestedAt: jwt.Now(),
					AuthTime:    jwt.NewNumericDate(time.Now().Add(-time.Second)),
				},
			},
			idTokenHint: genIDToken(jwt.IDTokenClaims{
				Subject:        "foo",
				RequestedAt:    jwt.Now(),
				ExpirationTime: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			}),
		},
		{
			d:         "should pass subject from ID token matches subject from session even though id token is expired",
			prompt:    "",
			isPublic:  false,
			expectErr: false,
			s: &DefaultSession{
				Subject: "foo",
				Claims: &jwt.IDTokenClaims{
					Subject:        "foo",
					RequestedAt:    jwt.Now(),
					AuthTime:       jwt.NewNumericDate(time.Now().Add(-time.Second)),
					ExpirationTime: jwt.NewNumericDate(time.Now().Add(-time.Second)),
				},
			},
			idTokenHint: genIDToken(jwt.IDTokenClaims{
				Subject:        "foo",
				RequestedAt:    jwt.Now(),
				ExpirationTime: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			}),
		},
	} {
		t.Run(fmt.Sprintf("case=%d/description=%s", k, tc.d), func(t *testing.T) {
			err := v.ValidatePrompt(context.TODO(), &oauth2.AuthorizeRequest{
				Request: oauth2.Request{
					Form:    url.Values{"prompt": {tc.prompt}, "id_token_hint": {tc.idTokenHint}},
					Client:  &oauth2.DefaultClient{Public: tc.isPublic},
					Session: tc.s,
				},
				RedirectURI: parse(tc.redirectURL),
			})
			if tc.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func parse(u string) *url.URL {
	o, _ := url.Parse(u)
	return o
}
