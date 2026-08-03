// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"authelia.com/provider/oauth2/internal/consts"
)

func TestDefaultClient(t *testing.T) {
	sc := &DefaultClient{
		ID:            "1",
		RedirectURIs:  []string{"foo", "bar"},
		ResponseTypes: []string{"foo", "bar"},
		GrantTypes:    []string{"foo", "bar"},
		Scopes:        []string{"fooscope"},
	}

	assert.Equal(t, sc.ID, sc.GetID())
	assert.Equal(t, sc.RedirectURIs, sc.GetRedirectURIs())
	assert.Equal(t, sc.ClientSecret, sc.GetClientSecret())
	assert.Equal(t, sc.RotatedClientSecrets, sc.GetRotatedClientSecrets())
	assert.EqualValues(t, sc.ResponseTypes, sc.GetResponseTypes())
	assert.EqualValues(t, sc.GrantTypes, sc.GetGrantTypes())
	assert.EqualValues(t, sc.Scopes, sc.GetScopes())

	sc.GrantTypes = []string{}
	sc.ResponseTypes = []string{}
	assert.Equal(t, consts.ResponseTypeAuthorizationCodeFlow, sc.GetResponseTypes()[0])
	assert.Equal(t, consts.GrantTypeAuthorizationCode, sc.GetGrantTypes()[0])

	var _ RotatedClientSecretsClient = sc
}

func TestDefaultResponseModeClient_GetResponseMode(t *testing.T) {
	rc := &DefaultResponseModeClient{ResponseModes: []ResponseModeType{ResponseModeFragment}}
	assert.Equal(t, []ResponseModeType{ResponseModeFragment}, rc.GetResponseModes())
}

func TestDefaultClientDPoP(t *testing.T) {
	c := &DefaultClient{DPoPBoundAccessTokens: true}

	var dc DPoPClient = c
	assert.True(t, dc.GetEnableDPoPBoundAccessTokens())

	assert.False(t, (&DefaultClient{}).GetEnableDPoPBoundAccessTokens())
}

func TestDefaultRPInitiatedLogoutClient(t *testing.T) {
	client := &DefaultRPInitiatedLogoutClient{
		DefaultClient:          &DefaultClient{ID: "test-client"},
		PostLogoutRedirectURIs: []string{"https://rp.example/logged-out"},
	}

	assert.Equal(t, "test-client", client.GetID(), "must delegate to the embedded DefaultClient")
	assert.Equal(t, []string{"https://rp.example/logged-out"}, client.GetPostLogoutRedirectURIs())

	var rp RPInitiatedLogoutClient = client
	assert.NotNil(t, rp)

	_, ok := any(&DefaultClient{}).(RPInitiatedLogoutClient)
	assert.False(t, ok, "DefaultClient must not satisfy RPInitiatedLogoutClient")
}

func TestDefaultBackChannelLogoutClient(t *testing.T) {
	client := &DefaultBackChannelLogoutClient{
		DefaultClient:                    &DefaultClient{ID: "rp-1"},
		BackChannelLogoutURI:             "https://rp.example/backchannel-logout",
		BackChannelLogoutSessionRequired: true,
	}

	assert.Equal(t, "rp-1", client.GetID())
	assert.Equal(t, "https://rp.example/backchannel-logout", client.GetBackChannelLogoutURI())
	assert.True(t, client.GetBackChannelLogoutSessionRequired())

	var iface BackChannelLogoutClient = client

	assert.Equal(t, "https://rp.example/backchannel-logout", iface.GetBackChannelLogoutURI())
}

func TestDefaultBackChannelLogoutClientDefaults(t *testing.T) {
	client := &DefaultBackChannelLogoutClient{DefaultClient: &DefaultClient{ID: "rp-2"}}

	assert.Equal(t, "", client.GetBackChannelLogoutURI())
	assert.False(t, client.GetBackChannelLogoutSessionRequired())
}

func TestDefaultMTLSClient(t *testing.T) {
	client := &DefaultMTLSClient{
		DefaultJARClient: &DefaultJARClient{
			DefaultClient:           &DefaultClient{ID: "test", TLSClientCertificateBoundAccessTokens: true},
			TokenEndpointAuthMethod: consts.ClientAuthMethodTLSClientAuth,
		},
		TLSClientAuthSubjectDN: "CN=test,O=Example",
		TLSClientAuthSANDNS:    "client.example.com",
		TLSClientAuthSANURI:    "https://client.example.com/",
		TLSClientAuthSANIP:     "203.0.113.1",
		TLSClientAuthSANEmail:  "client@example.com",
	}

	assert.Equal(t, "CN=test,O=Example", client.GetTLSClientAuthSubjectDN())
	assert.Equal(t, "client.example.com", client.GetTLSClientAuthSANDNS())
	assert.Equal(t, "https://client.example.com/", client.GetTLSClientAuthSANURI())
	assert.Equal(t, "203.0.113.1", client.GetTLSClientAuthSANIP())
	assert.Equal(t, "client@example.com", client.GetTLSClientAuthSANEmail())
	assert.True(t, client.GetEnableTLSClientAuthBoundAccessTokens())

	var (
		tlsClient  TLSClientAuthClient
		mtlsClient MTLSClient
		authClient AuthenticationMethodClient
	)

	assert.Implements(t, &tlsClient, client)
	assert.Implements(t, &mtlsClient, client)

	assert.Implements(t, &authClient, client)
	assert.Equal(t, consts.ClientAuthMethodTLSClientAuth, (&TokenEndpointClientAuthStrategy{}).GetAuthMethod(client))
	assert.True(t, isMTLSAuthMethod(client, &TokenEndpointClientAuthStrategy{}))

	assert.False(t, (&DefaultClient{}).GetEnableTLSClientAuthBoundAccessTokens())
}
