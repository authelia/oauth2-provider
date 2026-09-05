// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc8693_test

import (
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/handler/openid"
	. "authelia.com/provider/oauth2/handler/rfc8693"
	"authelia.com/provider/oauth2/internal/consts"
)

// RFC 8693 §2.1: the per-client token type restrictions are gated on the client implementing Client.
func TestDefaultRegisteredClientImplementsClient(t *testing.T) {
	registered := &oauth2.DefaultRegisteredClient{DefaultClient: &oauth2.DefaultClient{ID: "registered"}}

	client, ok := any(registered).(Client)
	require.True(t, ok, "a registered client must be able to express the RFC 8693 restrictions")

	t.Run("ShouldNotRestrictWhenUnset", func(t *testing.T) {
		assert.Empty(t, client.GetSupportedSubjectTokenTypes())
		assert.Empty(t, client.GetSupportedActorTokenTypes())
		assert.Empty(t, client.GetSupportedRequestTokenTypes())

		assert.True(t, client.GetTokenExchangePermitted(&oauth2.DefaultClient{ID: "other"}, nil),
			"an unset exchange policy must permit, matching the behaviour of a client that did not implement this at all")

		assert.False(t, client.GetAllowActorTokenWithoutMayAct(),
			"delegation without may_act stays opt-in")
	})

	t.Run("ShouldRestrictWhenSet", func(t *testing.T) {
		restricted := &oauth2.DefaultRegisteredClient{
			DefaultClient:                   &oauth2.DefaultClient{ID: "registered"},
			TokenExchangeSubjectTokenTypes:  []string{"urn:ietf:params:oauth:token-type:access_token"},
			TokenExchangeActorTokenTypes:    []string{"urn:ietf:params:oauth:token-type:id_token"},
			TokenExchangeRequestTokenTypes:  []string{"urn:ietf:params:oauth:token-type:access_token"},
			TokenExchangePermittedClientIDs: []string{"broker"},
		}

		rc, ok := any(restricted).(Client)
		require.True(t, ok)

		assert.Equal(t, []string{"urn:ietf:params:oauth:token-type:access_token"}, rc.GetSupportedSubjectTokenTypes())
		assert.Equal(t, []string{"urn:ietf:params:oauth:token-type:id_token"}, rc.GetSupportedActorTokenTypes())
		assert.Equal(t, []string{"urn:ietf:params:oauth:token-type:access_token"}, rc.GetSupportedRequestTokenTypes())

		assert.True(t, rc.GetTokenExchangePermitted(&oauth2.DefaultClient{ID: "broker"}, nil))
		assert.False(t, rc.GetTokenExchangePermitted(&oauth2.DefaultClient{ID: "stranger"}, nil),
			"a client outside the permitted list must not exchange this client's tokens")
	})
}

func TestRegisteredClientTokenTypeRestrictionIsEnforced(t *testing.T) {
	handler := newTokenExchangeHandler()

	newRequest := func(client oauth2.Client) *oauth2.AccessRequest {
		return &oauth2.AccessRequest{
			GrantTypes: oauth2.Arguments{consts.GrantTypeOAuthTokenExchange},
			Request: oauth2.Request{
				Client: client,
				Form: url.Values{
					consts.FormParameterGrantType:        {consts.GrantTypeOAuthTokenExchange},
					consts.FormParameterSubjectTokenType: {consts.TokenTypeRFC8693AccessToken},
					consts.FormParameterSubjectToken:     {"a-token"},
				},
				Session:     &DefaultSession{DefaultSession: &openid.DefaultSession{}, Extra: map[string]any{}},
				RequestedAt: time.Now().UTC(),
			},
		}
	}

	permitted := &oauth2.DefaultRegisteredClient{
		DefaultClient:                  &oauth2.DefaultClient{ID: "registered", GrantTypes: oauth2.Arguments{consts.GrantTypeOAuthTokenExchange}},
		TokenExchangeSubjectTokenTypes: []string{consts.TokenTypeRFC8693AccessToken},
	}

	forbidden := &oauth2.DefaultRegisteredClient{
		DefaultClient:                  &oauth2.DefaultClient{ID: "registered", GrantTypes: oauth2.Arguments{consts.GrantTypeOAuthTokenExchange}},
		TokenExchangeSubjectTokenTypes: []string{consts.TokenTypeRFC8693IDToken},
	}

	require.NoError(t, handler.HandleTokenEndpointRequest(t.Context(), newRequest(permitted)))

	err := handler.HandleTokenEndpointRequest(t.Context(), newRequest(forbidden))
	require.Error(t, err)
	assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The OAuth 2.0 client is not allowed to use 'urn:ietf:params:oauth:token-type:access_token' as 'subject_token_type'.")
}
