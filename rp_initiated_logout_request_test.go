// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2/token/jwt"
)

func TestNewRPInitiatedLogoutRequest_ZeroValues(t *testing.T) {
	request := NewRPInitiatedLogoutRequest()

	require.NotNil(t, request)
	assert.Empty(t, request.GetIDTokenHint())
	assert.Nil(t, request.GetIDTokenHintClaims())
	assert.Empty(t, request.GetSubject())
	assert.Empty(t, request.GetSessionID())
	assert.Empty(t, request.GetLogoutHint())
	assert.Nil(t, request.GetClient())
	assert.Nil(t, request.GetPostLogoutRedirectURI())
	assert.Empty(t, request.GetState())
	assert.Empty(t, request.GetUILocales())
	assert.NotNil(t, request.GetRequestForm(), "form must be initialized, not nil")
}

func TestRPInitiatedLogoutRequest_Getters(t *testing.T) {
	uri, err := url.Parse("https://rp.example/logged-out")
	require.NoError(t, err)

	client := &DefaultClient{ID: "test-client"}

	request := &RPInitiatedLogoutRequest{
		IDTokenHint: "abc.def.ghi",
		IDTokenHintClaims: jwt.MapClaims{
			jwt.ClaimSubject:   "alice",
			jwt.ClaimSessionID: "session-1",
		},
		LogoutHint:            "alice@example.com",
		Client:                client,
		PostLogoutRedirectURI: uri,
		State:                 "opaque",
		UILocales:             Arguments{"en-AU", "en"},
		Form:                  url.Values{"state": []string{"opaque"}},
	}

	assert.Equal(t, "abc.def.ghi", request.GetIDTokenHint())
	assert.Equal(t, "alice", request.GetSubject())
	assert.Equal(t, "session-1", request.GetSessionID())
	assert.Equal(t, "alice@example.com", request.GetLogoutHint())
	assert.Same(t, client, request.GetClient())
	assert.Equal(t, uri, request.GetPostLogoutRedirectURI())
	assert.Equal(t, "opaque", request.GetState())
	assert.Equal(t, Arguments{"en-AU", "en"}, request.GetUILocales())
	assert.Equal(t, "opaque", request.GetRequestForm().Get("state"))
}

func TestRPInitiatedLogoutRequest_NonStringClaimsIgnored(t *testing.T) {
	request := &RPInitiatedLogoutRequest{
		IDTokenHintClaims: jwt.MapClaims{
			jwt.ClaimSubject:   12345,
			jwt.ClaimSessionID: []string{"nope"},
		},
	}

	assert.Empty(t, request.GetSubject())
	assert.Empty(t, request.GetSessionID())
}
