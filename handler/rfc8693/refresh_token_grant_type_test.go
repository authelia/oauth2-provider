// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc8693_test

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	. "authelia.com/provider/oauth2/handler/rfc8693"
	"authelia.com/provider/oauth2/internal/consts"
)

func TestRefreshTokenRequiresTheRefreshTokenGrant(t *testing.T) {
	testCases := []struct {
		name       string
		actor      bool
		grantTypes []string
		expected   string
	}{
		{
			name:       "ShouldAcceptASubjectTokenOfAClientWithTheGrant",
			grantTypes: []string{consts.GrantTypeAuthorizationCode, consts.GrantTypeRefreshToken},
		},
		{
			name:       "ShouldRejectASubjectTokenOfAClientWithoutTheGrant",
			grantTypes: []string{consts.GrantTypeAuthorizationCode},
			expected:   "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The OAuth 2.0 Client the refresh token was issued to is not allowed to use authorization grant 'refresh_token'.",
		},
		{
			name:       "ShouldAcceptAnActorTokenOfAClientWithTheGrant",
			actor:      true,
			grantTypes: []string{consts.GrantTypeAuthorizationCode, consts.GrantTypeRefreshToken},
		},
		{
			name:       "ShouldRejectAnActorTokenOfAClientWithoutTheGrant",
			actor:      true,
			grantTypes: []string{consts.GrantTypeAuthorizationCode},
			expected:   "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The OAuth 2.0 Client the refresh token was issued to is not allowed to use authorization grant 'refresh_token'.",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, store, strategy := newExchangeFixture(t)
			cfg.RFC8693TokenTypes[consts.TokenTypeRFC8693RefreshToken] = &DefaultTokenType{Name: consts.TokenTypeRFC8693RefreshToken}

			owner := &oauth2.DefaultClient{ID: "refresh-token-owner", GrantTypes: tc.grantTypes, Scopes: []string{consts.ScopeOpenID}}

			original := newIssuedRequest(owner, "peter", []string{consts.ScopeOpenID}, oauth2.RefreshToken)

			token, signature, err := strategy.GenerateRefreshToken(t.Context(), original)
			require.NoError(t, err)
			require.NoError(t, store.CreateRefreshTokenSession(t.Context(), signature, "", original.Sanitize(nil)))

			form := url.Values{
				consts.FormParameterSubjectTokenType: {consts.TokenTypeRFC8693RefreshToken},
				consts.FormParameterSubjectToken:     {token},
			}

			if tc.actor {
				form = url.Values{
					consts.FormParameterSubjectTokenType: {consts.TokenTypeRFC8693AccessToken},
					consts.FormParameterSubjectToken:     {"opaque-subject-token"},
					consts.FormParameterActorTokenType:   {consts.TokenTypeRFC8693RefreshToken},
					consts.FormParameterActorToken:       {token},
				}
			}

			request := newExchangeRequest(t, store.Clients["my-client"], newSpecSession(""), form)

			err = newRefreshTokenTypeHandler(cfg, store, strategy).HandleTokenEndpointRequest(t.Context(), request)

			if tc.expected == "" {
				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
			} else {
				assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), tc.expected)
			}
		})
	}
}
