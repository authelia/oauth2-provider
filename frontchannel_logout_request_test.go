// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
)

func TestNewFrontChannelLogoutRequest(t *testing.T) {
	client := &oauth2.DefaultFrontChannelLogoutClient{DefaultClient: &oauth2.DefaultClient{ID: "rp-1"}}

	request := oauth2.NewFrontChannelLogoutRequest("session-1", []oauth2.Client{client})

	assert.Equal(t, "session-1", request.GetSessionID())
	assert.Len(t, request.GetClients(), 1)

	var requester oauth2.FrontChannelLogoutRequester = request

	assert.Equal(t, "session-1", requester.GetSessionID())
}

func TestNewFrontChannelLogoutURI(t *testing.T) {
	testCases := []struct {
		name     string
		uri      string
		issuer   string
		sid      string
		expected string
		err      string
	}{
		{
			name:     "ShouldAppendToURIWithoutQuery",
			uri:      "https://rp.example.org/frontchannel_logout",
			issuer:   "https://server.example.com",
			sid:      "08a5019c-17e1-4977-8f42-65a12843ea02",
			expected: "https://rp.example.org/frontchannel_logout?iss=https%3A%2F%2Fserver.example.com&sid=08a5019c-17e1-4977-8f42-65a12843ea02",
		},
		{
			name:     "ShouldRetainExistingQueryAsRegistered",
			uri:      "https://rp.example.org/logout?z=1&a=b%20c&a=d&flag",
			issuer:   "https://server.example.com",
			sid:      "s1",
			expected: "https://rp.example.org/logout?z=1&a=b%20c&a=d&flag&iss=https%3A%2F%2Fserver.example.com&sid=s1",
		},
		{
			name:     "ShouldAppendToEmptyQuery",
			uri:      "https://rp.example.org/logout?",
			issuer:   "https://server.example.com",
			sid:      "s1",
			expected: "https://rp.example.org/logout?iss=https%3A%2F%2Fserver.example.com&sid=s1",
		},
		{
			name:     "ShouldEscapeParameterValues",
			uri:      "https://rp.example.org:8443/logout",
			issuer:   "https://server.example.com/a b?c=d&e",
			sid:      "s 1&x=y#z",
			expected: "https://rp.example.org:8443/logout?iss=https%3A%2F%2Fserver.example.com%2Fa+b%3Fc%3Dd%26e&sid=s+1%26x%3Dy%23z",
		},
		{
			name:     "ShouldDropBareFragmentDelimiter",
			uri:      "https://rp.example.org/logout?a=b#",
			issuer:   "https://server.example.com",
			sid:      "s1",
			expected: "https://rp.example.org/logout?a=b&iss=https%3A%2F%2Fserver.example.com&sid=s1",
		},
		{
			name:     "ShouldAcceptHTTPScheme",
			uri:      "http://rp.example.org/logout",
			issuer:   "https://server.example.com",
			sid:      "s1",
			expected: "http://rp.example.org/logout?iss=https%3A%2F%2Fserver.example.com&sid=s1",
		},
		{
			name:   "ShouldRejectEmptyIssuer",
			uri:    "https://rp.example.org/logout",
			sid:    "s1",
			err:    "The 'iss' and 'sid' parameters must both be included in a front-channel logout URI.",
			issuer: "",
		},
		{
			name:   "ShouldRejectEmptySessionID",
			uri:    "https://rp.example.org/logout",
			issuer: "https://server.example.com",
			err:    "The 'iss' and 'sid' parameters must both be included in a front-channel logout URI.",
		},
		{
			name:   "ShouldRejectFragment",
			uri:    "https://rp.example.org/logout#frag",
			issuer: "https://server.example.com",
			sid:    "s1",
			err:    "The OAuth 2.0 Client has a registered 'frontchannel_logout_uri' which contains a fragment component.",
		},
		{
			name:   "ShouldRejectRelativeURI",
			uri:    "/logout",
			issuer: "https://server.example.com",
			sid:    "s1",
			err:    "The OAuth 2.0 Client has a registered 'frontchannel_logout_uri' which is not an absolute 'https' or 'http' URI.",
		},
		{
			name:   "ShouldRejectHostlessURI",
			uri:    "https:/logout",
			issuer: "https://server.example.com",
			sid:    "s1",
			err:    "The OAuth 2.0 Client has a registered 'frontchannel_logout_uri' which is not an absolute 'https' or 'http' URI.",
		},
		{
			name:   "ShouldRejectJavascriptScheme",
			uri:    "javascript:alert(1)",
			issuer: "https://server.example.com",
			sid:    "s1",
			err:    "The OAuth 2.0 Client has a registered 'frontchannel_logout_uri' which is not an absolute 'https' or 'http' URI.",
		},
		{
			name:   "ShouldRejectUnparsableURI",
			uri:    "https://rp.example.org/%zz",
			issuer: "https://server.example.com",
			sid:    "s1",
			err:    "The OAuth 2.0 Client has a registered 'frontchannel_logout_uri' which is not an absolute 'https' or 'http' URI.",
		},
		{
			name:   "ShouldRejectRegisteredIssuerParameter",
			uri:    "https://rp.example.org/logout?iss=https%3A%2F%2Fattacker.example.com",
			issuer: "https://server.example.com",
			sid:    "s1",
			err:    "The OAuth 2.0 Client has a registered 'frontchannel_logout_uri' which contains the 'iss' or 'sid' query parameter.",
		},
		{
			name:   "ShouldRejectRegisteredSessionIDParameter",
			uri:    "https://rp.example.org/logout?sid=other",
			issuer: "https://server.example.com",
			sid:    "s1",
			err:    "The OAuth 2.0 Client has a registered 'frontchannel_logout_uri' which contains the 'iss' or 'sid' query parameter.",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual, err := oauth2.NewFrontChannelLogoutURI(tc.uri, tc.issuer, tc.sid)

			if tc.err != "" {
				require.Error(t, err)
				assert.ErrorIs(t, err, oauth2.ErrInvalidRequest)
				assert.Equal(t, tc.err, oauth2.ErrorToRFC6749Error(err).HintField)
				assert.Empty(t, actual)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.expected, actual)
		})
	}
}
