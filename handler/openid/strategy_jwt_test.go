// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package openid

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestDefaultSession_GetRequestedAt(t *testing.T) {
	testCases := []struct {
		name     string
		have     *DefaultSession
		expected time.Time
		zero     bool
	}{
		{
			"ShouldHandleZero",
			&DefaultSession{},
			time.Time{},
			true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			have := tc.have.GetRequestedAt()

			assert.Equal(t, tc.expected, have)
			assert.Equal(t, tc.zero, have.IsZero())
			assert.Equal(t, tc.zero, tc.expected.IsZero())
		})
	}
}

func TestJWTStrategy_GenerateIDToken(t *testing.T) {
	config := &oauth2.Config{
		MinParameterEntropy: oauth2.MinParameterEntropy,
	}

	var j = &DefaultStrategy{
		Strategy: &jwt.DefaultStrategy{
			Config: config,
			Issuer: jwt.NewDefaultIssuerRS256Unverified(key),
		},
		Config: config,
	}

	testCases := []struct {
		name  string
		setup func() (requester *oauth2.AccessRequest)
		err   string
	}{
		{
			name: "ShouldHandleNonce",
			setup: func() (requester *oauth2.AccessRequest) {
				requester = oauth2.NewAccessRequest(&DefaultSession{
					Claims: &jwt.IDTokenClaims{
						Subject: "peter",
					},
					Headers: &jwt.Headers{},
				})

				requester.Form.Set(consts.FormParameterNonce, "some-secure-nonce-state")

				return requester
			},
			err: "",
		},
		{
			name: "ShouldHandleNonceAndMaxAge",
			setup: func() (requester *oauth2.AccessRequest) {
				requester = oauth2.NewAccessRequest(&DefaultSession{
					Claims: &jwt.IDTokenClaims{
						Subject:  "peter",
						AuthTime: jwt.Now(),
					},
					Headers:     &jwt.Headers{},
					RequestedAt: time.Now(),
				})

				requester.Form.Set(consts.FormParameterNonce, "some-secure-nonce-state")
				requester.Form.Set(consts.FormParameterMaximumAge, "1234")

				return requester
			},
			err: "",
		},
		{
			name: "ShouldFailExpiresInPast",
			setup: func() (requester *oauth2.AccessRequest) {
				requester = oauth2.NewAccessRequest(&DefaultSession{
					Claims: &jwt.IDTokenClaims{
						Subject:        "peter",
						ExpirationTime: jwt.NewNumericDate(time.Now().Add(-time.Hour)),
					},
					Headers: &jwt.Headers{},
				})

				requester.Form.Set(consts.FormParameterNonce, "some-secure-nonce-state")

				return requester
			},
			err: "The authorization server encountered an unexpected condition that prevented it from fulfilling the request. Failed to generate id token because expiry claim can not be in the past.",
		},
		{
			name: "ShouldFailAuthMaxAgeNoAuthTime",
			setup: func() (requester *oauth2.AccessRequest) {
				requester = oauth2.NewAccessRequest(&DefaultSession{
					Claims: &jwt.IDTokenClaims{
						Subject: "peter",
					},
					Headers: &jwt.Headers{},
				})

				requester.Form.Set(consts.FormParameterNonce, "some-secure-nonce-state")
				requester.Form.Set(consts.FormParameterMaximumAge, "1234")

				return requester
			},
			err: "The authorization server encountered an unexpected condition that prevented it from fulfilling the request. Failed to generate id token because authentication time claim is required when max_age is set.",
		},
		{
			name: "ShouldFailEmptySubject",
			setup: func() (requester *oauth2.AccessRequest) {
				requester = oauth2.NewAccessRequest(&DefaultSession{
					Claims:  &jwt.IDTokenClaims{},
					Headers: &jwt.Headers{},
				})
				requester.Form.Set(consts.FormParameterNonce, "some-secure-nonce-state")

				return requester
			},
			err: "The authorization server encountered an unexpected condition that prevented it from fulfilling the request. Failed to generate id token because subject is an empty string.",
		},
		{
			name: "ShouldPassWithSubject",
			setup: func() (requester *oauth2.AccessRequest) {
				requester = oauth2.NewAccessRequest(&DefaultSession{
					Claims: &jwt.IDTokenClaims{
						Subject: "peter",
					},
					Headers: &jwt.Headers{},
				})

				return requester
			},
			err: "",
		},
		{
			name: "ShouldPassMaxAgeWhenSameAuthTimeAndRequestTime",
			setup: func() (requester *oauth2.AccessRequest) {
				requester = oauth2.NewAccessRequest(&DefaultSession{
					Claims: &jwt.IDTokenClaims{
						Subject:  "peter",
						AuthTime: jwt.Now(),
					},
					RequestedAt: time.Now(),
					Headers:     &jwt.Headers{},
				})
				requester.Form.Set(consts.FormParameterMaximumAge, "60")

				return requester
			},
			err: "",
		},
		{
			name: "ShouldFailAuthTimeBeforeMaxAge",
			setup: func() (requester *oauth2.AccessRequest) {
				requester = oauth2.NewAccessRequest(&DefaultSession{
					Claims: &jwt.IDTokenClaims{
						Subject:  "peter",
						AuthTime: jwt.NewNumericDate(time.Now().Add(-time.Hour)),
					},
					Headers:     &jwt.Headers{},
					RequestedAt: time.Now(),
				})

				requester.Form.Set(consts.FormParameterMaximumAge, "60")

				return requester
			},
			err: "The authorization server encountered an unexpected condition that prevented it from fulfilling the request. Failed to generate id token because authentication time does not satisfy max_age time.",
		},
		{
			name: "ShouldFailPromptNoneAndAuthTimeIndicatesFreshLogin",
			setup: func() (requester *oauth2.AccessRequest) {
				now := time.Unix(1000000000, 0).UTC()

				requester = oauth2.NewAccessRequest(&DefaultSession{
					Claims: &jwt.IDTokenClaims{
						Subject:  "peter",
						AuthTime: &jwt.NumericDate{Time: now},
					},
					Headers:     &jwt.Headers{},
					RequestedAt: now.Add(-time.Minute),
				})

				requester.Form.Set(consts.FormParameterPrompt, consts.PromptTypeNone)

				return requester
			},
			err: "The authorization server encountered an unexpected condition that prevented it from fulfilling the request. Failed to generate id token because prompt was set to 'none' but auth_time ('2001-09-09 01:46:40 +0000 UTC') happened after the authorization request ('2001-09-09 01:45:40 +0000 UTC') was registered, indicating that the user was logged in during this request which is not allowed.",
		},
		{
			name: "ShouldPassPromptNoneWithAuthTimeFreshLoginFlowRefresh",
			setup: func() (requester *oauth2.AccessRequest) {
				requester = oauth2.NewAccessRequest(&DefaultSession{
					Claims: &jwt.IDTokenClaims{
						Subject:  "peter",
						AuthTime: jwt.Now(),
					},
					Headers:     &jwt.Headers{},
					RequestedAt: time.Now().Add(-time.Minute),
				})
				requester.Form.Set(consts.FormParameterPrompt, consts.PromptTypeNone)
				requester.Form.Set(consts.FormParameterGrantType, consts.GrantTypeRefreshToken)

				return requester
			},
			err: "",
		},
		{
			name: "ShouldPassPromptNoneAndAuthTimeOldLogin",
			setup: func() (requester *oauth2.AccessRequest) {
				requester = oauth2.NewAccessRequest(&DefaultSession{
					Claims: &jwt.IDTokenClaims{
						Subject:  "peter",
						AuthTime: jwt.NewNumericDate(time.Now().Add(-time.Hour)),
					},
					Headers:     &jwt.Headers{},
					RequestedAt: time.Now().Add(-time.Minute),
				})
				requester.Form.Set(consts.FormParameterPrompt, consts.PromptTypeNone)

				return requester
			},
			err: "",
		},
		{
			name: "should pass because prompt=login was requested and auth_time indicates fresh login",
			setup: func() (requester *oauth2.AccessRequest) {
				requester = oauth2.NewAccessRequest(&DefaultSession{
					Claims: &jwt.IDTokenClaims{
						Subject:  "peter",
						AuthTime: jwt.Now(),
					},
					Headers:     &jwt.Headers{},
					RequestedAt: time.Now().Add(-time.Minute),
				})
				requester.Form.Set(consts.FormParameterPrompt, consts.PromptTypeLogin)

				return requester
			},
			err: "",
		},
		{
			name: "ShouldFailPromptLoginAuthTimeIsBeforeRequest",
			setup: func() (requester *oauth2.AccessRequest) {
				now := time.Unix(1000000000, 0).UTC()

				requester = oauth2.NewAccessRequest(&DefaultSession{
					Claims: &jwt.IDTokenClaims{
						Subject:  "peter",
						AuthTime: jwt.NewNumericDate(now.Add(-time.Hour)),
					},
					Headers:     &jwt.Headers{},
					RequestedAt: now.Add(-time.Minute),
				})
				requester.Form.Set(consts.FormParameterPrompt, consts.PromptTypeLogin)

				return requester
			},
			err: "The authorization server encountered an unexpected condition that prevented it from fulfilling the request. Failed to generate id token because prompt was set to 'login' but auth_time ('2001-09-09 00:46:40 +0000 UTC') happened before the authorization request ('2001-09-09 01:45:40 +0000 UTC') was registered, indicating that the user was not re-authenticated which is forbidden.",
		},
		{
			name: "ShouldPassIDTokenHintSubjectMatches",
			setup: func() (requester *oauth2.AccessRequest) {
				requester = oauth2.NewAccessRequest(&DefaultSession{
					Claims: &jwt.IDTokenClaims{
						Subject:  "peter",
						AuthTime: jwt.NewNumericDate(time.Now().Add(-time.Hour)),
					},
					Headers:     &jwt.Headers{},
					RequestedAt: time.Now().Add(-time.Minute),
				})
				token, _ := j.GenerateIDToken(context.TODO(), time.Duration(0), oauth2.NewAccessRequest(&DefaultSession{
					Claims: &jwt.IDTokenClaims{
						Subject: "peter",
					},
					Headers: &jwt.Headers{},
				}))
				requester.Form.Set(consts.FormParameterIDTokenHint, token)

				return requester
			},
			err: "",
		},
		{
			name: "ShouldPassIDTokenHintExpired",
			setup: func() (requester *oauth2.AccessRequest) {
				requester = oauth2.NewAccessRequest(&DefaultSession{
					Claims: &jwt.IDTokenClaims{
						Subject:  "peter",
						AuthTime: jwt.NewNumericDate(time.Now().Add(-time.Hour)),
					},
					Headers:     &jwt.Headers{},
					RequestedAt: time.Now().Add(-time.Minute),
				})
				token, _ := j.GenerateIDToken(context.TODO(), time.Duration(0), oauth2.NewAccessRequest(&DefaultSession{
					Claims: &jwt.IDTokenClaims{
						Subject:        "peter",
						ExpirationTime: jwt.NewNumericDate(time.Now().Add(-time.Hour)),
					},
					Headers: &jwt.Headers{},
				}))
				requester.Form.Set(consts.FormParameterIDTokenHint, token)

				return requester
			},
			err: "",
		},
		{
			name: "ShouldFailIDTokenHintDoesNotMatch",
			setup: func() (requester *oauth2.AccessRequest) {
				requester = oauth2.NewAccessRequest(&DefaultSession{
					Claims: &jwt.IDTokenClaims{
						Subject:  "peter",
						AuthTime: jwt.NewNumericDate(time.Now().Add(-time.Hour)),
					},
					Headers:     &jwt.Headers{},
					RequestedAt: time.Now().Add(-time.Minute),
				})
				token, _ := j.GenerateIDToken(context.TODO(), time.Duration(0), oauth2.NewAccessRequest(&DefaultSession{
					Claims: &jwt.IDTokenClaims{Subject: "alice"}, Headers: &jwt.Headers{},
				}))
				requester.Form.Set(consts.FormParameterIDTokenHint, token)

				return requester
			},
			err: "The authorization server encountered an unexpected condition that prevented it from fulfilling the request. Subject from authorization mismatches id token subject from 'id_token_hint'.",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var requester *oauth2.AccessRequest

			if tc.setup != nil {
				requester = tc.setup()
			} else {
				requester = oauth2.NewAccessRequest(&DefaultSession{})
			}

			token, err := j.GenerateIDToken(context.TODO(), time.Duration(0), requester)

			if tc.err != "" {
				assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), tc.err)
			} else {
				assert.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
				assert.NotEmpty(t, token)
			}
		})
	}
}

func TestDefaultSession_MarshalJSON(t *testing.T) {
	testCases := []struct {
		name     string
		have     *DefaultSession
		expected string
	}{
		{
			"ShouldHandleEmptyTime",
			&DefaultSession{
				Claims:      nil,
				Headers:     nil,
				ExpiresAt:   nil,
				Username:    "",
				Subject:     "",
				RequestedAt: time.Time{},
			},
			`{"requested_at":"0001-01-01T00:00:00Z"}`,
		},
		{
			"ShouldHandleTimeValue",
			&DefaultSession{
				Claims:      nil,
				Headers:     nil,
				ExpiresAt:   nil,
				Username:    "",
				Subject:     "",
				RequestedAt: time.Unix(1743845057, 1000).UTC(),
			},
			`{"requested_at":"2025-04-05T09:24:17.000001Z"}`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			data, err := json.Marshal(tc.have)
			require.NoError(t, err)

			assert.Equal(t, tc.expected, string(data))

			actual := &DefaultSession{}

			require.NoError(t, json.Unmarshal(data, actual))

			assert.Equal(t, tc.have, actual)
		})
	}
}
