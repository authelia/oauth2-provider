// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/storage"
)

func TestBuildFrontChannelLogout(t *testing.T) {
	const (
		issuer = "https://server.example.com"
		params = "iss=https%3A%2F%2Fserver.example.com&sid=session-1"
	)

	testCases := []struct {
		name     string
		issuer   string
		sid      string
		client   oauth2.Client
		expected oauth2.FrontChannelLogoutResult
	}{
		{
			name:     "ShouldReturnRegisteredURIWhenSessionNotRequired",
			issuer:   issuer,
			sid:      "session-1",
			client:   fclClient("rp", "https://rp.example.org/frontchannel_logout", false),
			expected: oauth2.FrontChannelLogoutResult{ClientID: "rp", URI: "https://rp.example.org/frontchannel_logout"},
		},
		{
			name:     "ShouldReturnRegisteredURIWithQueryWhenSessionNotRequired",
			issuer:   issuer,
			sid:      "session-1",
			client:   fclClient("rp", "https://rp.example.org/logout?tenant=a%20b&x", false),
			expected: oauth2.FrontChannelLogoutResult{ClientID: "rp", URI: "https://rp.example.org/logout?tenant=a%20b&x"},
		},
		{
			name:     "ShouldReturnRegisteredURIWithoutSessionIDWhenSessionNotRequired",
			client:   fclClient("rp", "https://rp.example.org/logout", false),
			expected: oauth2.FrontChannelLogoutResult{ClientID: "rp", URI: "https://rp.example.org/logout"},
		},
		{
			name:     "ShouldAddIssuerAndSessionIDWhenSessionRequired",
			issuer:   issuer,
			sid:      "session-1",
			client:   fclClient("rp", "https://rp.example.org/frontchannel_logout", true),
			expected: oauth2.FrontChannelLogoutResult{ClientID: "rp", URI: "https://rp.example.org/frontchannel_logout?" + params},
		},
		{
			name:     "ShouldRetainQueryWhenSessionRequired",
			issuer:   issuer,
			sid:      "session-1",
			client:   fclClient("rp", "https://rp.example.org/logout?z=1&tenant=a%20b&x", true),
			expected: oauth2.FrontChannelLogoutResult{ClientID: "rp", URI: "https://rp.example.org/logout?z=1&tenant=a%20b&x&" + params},
		},
		{
			name:     "ShouldSkipWhenSessionRequiredWithoutSessionID",
			issuer:   issuer,
			client:   fclClient("rp", "https://rp.example.org/logout", true),
			expected: oauth2.FrontChannelLogoutResult{ClientID: "rp", Skipped: true, Reason: "The OAuth 2.0 Client requires the 'sid' parameter but no session identifier was supplied."},
		},
		{
			name:     "ShouldSkipWhenSessionRequiredWithoutIssuer",
			sid:      "session-1",
			client:   fclClient("rp", "https://rp.example.org/logout", true),
			expected: oauth2.FrontChannelLogoutResult{ClientID: "rp", Skipped: true, Reason: "The OAuth 2.0 Client requires the 'iss' parameter but no issuer is configured."},
		},
		{
			name:     "ShouldSkipClientWithoutRegisteredURI",
			issuer:   issuer,
			sid:      "session-1",
			client:   fclClient("rp", "", true),
			expected: oauth2.FrontChannelLogoutResult{ClientID: "rp", Skipped: true, Reason: "The OAuth 2.0 Client does not have a registered 'frontchannel_logout_uri'."},
		},
		{
			name:     "ShouldSkipClientWhichIsNotAFrontChannelLogoutClient",
			issuer:   issuer,
			sid:      "session-1",
			client:   &oauth2.DefaultClient{ID: "rp"},
			expected: oauth2.FrontChannelLogoutResult{ClientID: "rp", Skipped: true, Reason: "The OAuth 2.0 Client does not support OpenID Connect Front-Channel Logout."},
		},
		{
			name:     "ShouldSkipURIWithFragment",
			issuer:   issuer,
			sid:      "session-1",
			client:   fclClient("rp", "https://rp.example.org/logout#frag", false),
			expected: oauth2.FrontChannelLogoutResult{ClientID: "rp", Skipped: true, Reason: "The OAuth 2.0 Client has a registered 'frontchannel_logout_uri' which contains a fragment component."},
		},
		{
			name:     "ShouldSkipRelativeURI",
			issuer:   issuer,
			sid:      "session-1",
			client:   fclClient("rp", "/logout", false),
			expected: oauth2.FrontChannelLogoutResult{ClientID: "rp", Skipped: true, Reason: "The OAuth 2.0 Client has a registered 'frontchannel_logout_uri' which is not an absolute 'https' or 'http' URI."},
		},
		{
			name:     "ShouldSkipJavascriptURI",
			issuer:   issuer,
			sid:      "session-1",
			client:   fclClient("rp", "javascript:alert(1)", false),
			expected: oauth2.FrontChannelLogoutResult{ClientID: "rp", Skipped: true, Reason: "The OAuth 2.0 Client has a registered 'frontchannel_logout_uri' which is not an absolute 'https' or 'http' URI."},
		},
		{
			name:     "ShouldSkipURIWithRegisteredSessionParameters",
			issuer:   issuer,
			sid:      "session-1",
			client:   fclClient("rp", "https://rp.example.org/logout?sid=other", false),
			expected: oauth2.FrontChannelLogoutResult{ClientID: "rp", Skipped: true, Reason: "The OAuth 2.0 Client has a registered 'frontchannel_logout_uri' which contains the 'iss' or 'sid' query parameter."},
		},
		{
			name:     "ShouldAllowHTTPForConfidentialClient",
			issuer:   issuer,
			sid:      "session-1",
			client:   fclClient("rp", "http://rp.example.org/logout", true),
			expected: oauth2.FrontChannelLogoutResult{ClientID: "rp", URI: "http://rp.example.org/logout?" + params},
		},
		{
			name:     "ShouldSkipHTTPForPublicClient",
			issuer:   issuer,
			sid:      "session-1",
			client:   fclPublicClient("rp", "http://rp.example.org/logout"),
			expected: oauth2.FrontChannelLogoutResult{ClientID: "rp", Skipped: true, Reason: "The OAuth 2.0 Client is a public client and has a registered 'frontchannel_logout_uri' which does not use the 'https' scheme."},
		},
		{
			name:     "ShouldAllowHTTPSForPublicClient",
			issuer:   issuer,
			sid:      "session-1",
			client:   fclPublicClient("rp", "https://rp.example.org/logout"),
			expected: oauth2.FrontChannelLogoutResult{ClientID: "rp", URI: "https://rp.example.org/logout"},
		},
		{
			name:     "ShouldTreatClientIDMetadataDocumentClientAsAnyOther",
			issuer:   issuer,
			sid:      "session-1",
			client:   &fclDocumentClient{DefaultFrontChannelLogoutClient: fclClient("https://client.example.com/c", "https://client.example.com/logout", true)},
			expected: oauth2.FrontChannelLogoutResult{ClientID: "https://client.example.com/c", URI: "https://client.example.com/logout?" + params},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFCLProvider(tc.issuer)

			results := f.BuildFrontChannelLogout(t.Context(), oauth2.NewFrontChannelLogoutRequest(tc.sid, []oauth2.Client{tc.client}))

			require.Len(t, results, 1)
			assert.Equal(t, tc.expected, results[0])
		})
	}
}

func TestBuildFrontChannelLogout_EmptyClients(t *testing.T) {
	f := newFCLProvider("https://server.example.com")

	results := f.BuildFrontChannelLogout(t.Context(), oauth2.NewFrontChannelLogoutRequest("session-1", nil))

	assert.NotNil(t, results)
	assert.Empty(t, results)
}

func TestBuildFrontChannelLogout_ResultsMatchInputOrder(t *testing.T) {
	f := newFCLProvider("https://server.example.com")

	clients := []oauth2.Client{
		fclClient("rp-1", "https://one.example.org/logout", false),
		&oauth2.DefaultClient{ID: "rp-2"},
		fclClient("rp-3", "https://three.example.org/logout?a=b", true),
		fclClient("rp-4", "", false),
		fclClient("rp-1", "https://one.example.org/logout", false),
	}

	results := f.BuildFrontChannelLogout(t.Context(), oauth2.NewFrontChannelLogoutRequest("session-1", clients))

	require.Len(t, results, len(clients))

	expected := []oauth2.FrontChannelLogoutResult{
		{ClientID: "rp-1", URI: "https://one.example.org/logout"},
		{ClientID: "rp-2", Skipped: true, Reason: "The OAuth 2.0 Client does not support OpenID Connect Front-Channel Logout."},
		{ClientID: "rp-3", URI: "https://three.example.org/logout?a=b&iss=https%3A%2F%2Fserver.example.com&sid=session-1"},
		{ClientID: "rp-4", Skipped: true, Reason: "The OAuth 2.0 Client does not have a registered 'frontchannel_logout_uri'."},
		{ClientID: "rp-1", URI: "https://one.example.org/logout"},
	}

	assert.Equal(t, expected, results)
}

func TestBuildFrontChannelLogout_RegisteredClient(t *testing.T) {
	f := newFCLProvider("https://server.example.com")

	client := &oauth2.DefaultRegisteredClient{
		DefaultClient:                     &oauth2.DefaultClient{ID: "rp-1"},
		FrontChannelLogoutURI:             "https://rp.example.org/logout",
		FrontChannelLogoutSessionRequired: true,
	}

	results := f.BuildFrontChannelLogout(t.Context(), oauth2.NewFrontChannelLogoutRequest("session-1", []oauth2.Client{client}))

	require.Len(t, results, 1)
	assert.Equal(t, oauth2.FrontChannelLogoutResult{ClientID: "rp-1", URI: "https://rp.example.org/logout?iss=https%3A%2F%2Fserver.example.com&sid=session-1"}, results[0])
}

func newFCLProvider(issuer string) *oauth2.Fosite {
	return &oauth2.Fosite{Store: storage.NewMemoryStore(), Config: &oauth2.Config{Issuer: issuer}}
}

func fclClient(id, uri string, sessionRequired bool) *oauth2.DefaultFrontChannelLogoutClient {
	return &oauth2.DefaultFrontChannelLogoutClient{
		DefaultClient:                     &oauth2.DefaultClient{ID: id},
		FrontChannelLogoutURI:             uri,
		FrontChannelLogoutSessionRequired: sessionRequired,
	}
}

func fclPublicClient(id, uri string) *oauth2.DefaultFrontChannelLogoutClient {
	client := fclClient(id, uri, false)

	client.Public = true

	return client
}

type fclDocumentClient struct {
	*oauth2.DefaultFrontChannelLogoutClient
}

func (c *fclDocumentClient) IsClientIDMetadataDocumentClient() bool { return true }
