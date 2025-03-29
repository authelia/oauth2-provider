// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package openid

import (
	"context"
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

	now := time.Unix(1000000000, 0)

	testCases := []struct {
		name        string
		prompt      string
		redirectURL string
		isPublic    bool
		err         string
		idTokenHint string
		session     *DefaultSession
	}{
		{
			name:        "ShouldFailPromptNoneWithPublicClientInsecureLocalhost",
			prompt:      "none",
			isPublic:    true,
			err:         "The Authorization Server requires End-User consent. OAuth 2.0 Client is marked public and redirect uri is not considered secure (https missing), but 'prompt' type 'none' was requested.",
			redirectURL: "http://foo-bar/",
			session: &DefaultSession{
				Subject: "foo",
				Claims: &jwt.IDTokenClaims{
					Subject:  "foo",
					AuthTime: jwt.NewNumericDate(time.Now().Add(-time.Minute)),
				},
				RequestedAt: time.Now().UnixMicro(),
			},
		},
		{
			name:        "ShouldPassPromptNonePublicClientAndLocalhost",
			prompt:      "none",
			isPublic:    true,
			err:         "",
			redirectURL: "http://localhost/",
			session: &DefaultSession{
				Subject: "foo",
				Claims: &jwt.IDTokenClaims{
					Subject:  "foo",
					AuthTime: jwt.NewNumericDate(time.Now().Add(-time.Minute)),
				},
				RequestedAt: time.Now().UnixMicro(),
			},
		},
		{
			name:        "should pass",
			prompt:      "none",
			isPublic:    true,
			err:         "",
			redirectURL: "https://foo-bar/",
			session: &DefaultSession{
				Subject: "foo",
				Claims: &jwt.IDTokenClaims{
					Subject:  "foo",
					AuthTime: jwt.NewNumericDate(time.Now().Add(-time.Minute)),
				},
				RequestedAt: time.Now().UnixMicro(),
			},
		},
		{
			name:     "should fail because prompt=none requires an auth time being set",
			prompt:   "none",
			isPublic: false,
			err:      "The authorization server encountered an unexpected condition that prevented it from fulfilling the request. Failed to validate OpenID Connect request because because auth_time is missing from session.",
			session: &DefaultSession{
				Subject: "foo",
				Claims: &jwt.IDTokenClaims{
					Subject: "foo",
				},
				RequestedAt: time.Now().UnixMicro(),
			},
		},
		{
			name:     "ShouldFailPromptNoneAuthTimeMissing",
			prompt:   "none",
			isPublic: false,
			err:      "The authorization server encountered an unexpected condition that prevented it from fulfilling the request. Failed to validate OpenID Connect request because because auth_time is missing from session.",
			session: &DefaultSession{
				Subject: "foo",
				Claims: &jwt.IDTokenClaims{
					Subject: "foo",
				},
				RequestedAt: time.Now().Add(-time.Minute).UnixMicro(),
			},
		},
		{
			name:     "ShouldPassPromptNoneAuthTimeInPast",
			prompt:   "none",
			isPublic: false,
			err:      "",
			session: &DefaultSession{
				Subject: "foo",
				Claims: &jwt.IDTokenClaims{
					Subject:  "foo",
					AuthTime: jwt.NewNumericDate(time.Now().Add(-time.Minute)),
				},
				RequestedAt: time.Now().UnixMicro(),
			},
		},
		{
			name:     "ShouldFailPromptNoneWithLogin",
			prompt:   "none login",
			isPublic: false,
			err:      "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Parameter 'prompt' was set to 'none', but contains other values as well which is not allowed.",
			session: &DefaultSession{
				Subject: "foo",
				Claims: &jwt.IDTokenClaims{
					Subject:  "foo",
					AuthTime: jwt.Now(),
				},
				RequestedAt: time.Now().UnixMicro(),
			},
		},
		{
			name:     "ShouldFailPromptFoo",
			prompt:   "foo",
			isPublic: false,
			err:      "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Used unknown value '[foo]' for prompt parameter",
			session: &DefaultSession{
				Subject: "foo",
				Claims: &jwt.IDTokenClaims{
					Subject:  "foo",
					AuthTime: jwt.Now(),
				},
				RequestedAt: time.Now().UnixMicro(),
			},
		},
		{
			name:     "ShouldPassRequestingConsentAndLoginPublicClients",
			prompt:   "login consent",
			isPublic: true,
			err:      "",
			session: &DefaultSession{
				Subject: "foo",
				Claims: &jwt.IDTokenClaims{
					Subject:  "foo",
					AuthTime: jwt.NewNumericDate(time.Now().Add(-time.Second)),
				},
				RequestedAt: time.Now().Add(-time.Second * 5).UnixMicro(),
			},
		},
		{
			name:     "ShouldPassRequestingConsentAndLoginConfidentialClients",
			prompt:   "login consent",
			isPublic: false,
			err:      "",
			session: &DefaultSession{
				Subject: "foo",
				Claims: &jwt.IDTokenClaims{
					Subject:  "foo",
					AuthTime: jwt.NewNumericDate(time.Now().Add(-time.Second)),
				},
				RequestedAt: time.Now().Add(-time.Second * 5).UnixMicro(),
			},
		},
		{
			name:     "ShouldFailSubjectFromIDTokenAndSessionMismatch",
			prompt:   "login",
			isPublic: false,
			err:      "The Authorization Server requires End-User authentication. Failed to validate OpenID Connect request because prompt was set to 'login' but auth_time ('2001-09-09 01:46:39 +0000 UTC') happened before the authorization request ('2001-09-09 01:46:40 +0000 UTC') was registered, indicating that the user was not re-authenticated which is forbidden.",
			session: &DefaultSession{
				Subject: "foo",
				Claims: &jwt.IDTokenClaims{
					Subject:  "foo",
					AuthTime: jwt.NewNumericDate(now.Add(-time.Second)),
				},
				RequestedAt: now.UnixMicro(),
			},
			idTokenHint: genIDToken(jwt.IDTokenClaims{
				Subject:        "bar",
				ExpirationTime: jwt.NewNumericDate(now.Add(time.Hour)),
			}),
		},
		{
			name:     "ShouldPassSubjectFromIDTokenAndSessionMatch",
			prompt:   "",
			isPublic: false,
			err:      "",
			session: &DefaultSession{
				Subject: "foo",
				Claims: &jwt.IDTokenClaims{
					Subject:  "foo",
					AuthTime: jwt.NewNumericDate(time.Now().Add(-time.Second)),
				},
				RequestedAt: time.Now().UnixMicro(),
			},
			idTokenHint: genIDToken(jwt.IDTokenClaims{
				Subject:        "foo",
				ExpirationTime: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			}),
		},
		{
			name:     "ShouldPassSubjectFromIDTokenAndSessionMatchHintExpired",
			prompt:   "",
			isPublic: false,
			err:      "",
			session: &DefaultSession{
				Subject: "foo",
				Claims: &jwt.IDTokenClaims{
					Subject:        "foo",
					AuthTime:       jwt.NewNumericDate(time.Now().Add(-time.Second)),
					ExpirationTime: jwt.NewNumericDate(time.Now().Add(-time.Second)),
				},
				RequestedAt: time.Now().UnixMicro(),
			},
			idTokenHint: genIDToken(jwt.IDTokenClaims{
				Subject:        "foo",
				ExpirationTime: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			}),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := v.ValidatePrompt(context.TODO(), &oauth2.AuthorizeRequest{
				Request: oauth2.Request{
					Form:    url.Values{"prompt": {tc.prompt}, "id_token_hint": {tc.idTokenHint}},
					Client:  &oauth2.DefaultClient{Public: tc.isPublic},
					Session: tc.session,
				},
				RedirectURI: parse(tc.redirectURL),
			})

			if tc.err != "" {
				assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), tc.err)
			} else {
				assert.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
			}
		})
	}
}

func parse(u string) *url.URL {
	o, _ := url.Parse(u)
	return o
}
