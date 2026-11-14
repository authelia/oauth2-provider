// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultOpenIDConnectClientCIBA(t *testing.T) {
	client := &DefaultCIBAClient{
		DefaultClient:                              &DefaultClient{ID: "ciba-1"},
		BackChannelTokenDeliveryMode:               "ping",
		BackChannelClientNotificationEndpoint:      "https://client.example.com/notify",
		BackChannelAuthenticationRequestSigningAlg: "ES256",
		BackChannelUserCodeParameter:               true,
		BackChannelEndpointLoginHintTokenTypes:     []string{"urn:example:token"},
	}

	assert.Equal(t, "ciba-1", client.GetID())
	assert.Equal(t, "ping", client.GetBackChannelTokenDeliveryMode())
	assert.Equal(t, "https://client.example.com/notify", client.GetBackChannelClientNotificationEndpoint())
	assert.Equal(t, "ES256", client.GetBackChannelAuthenticationRequestSigningAlg())
	assert.True(t, client.GetBackChannelUserCodeParameter())
	assert.Equal(t, []string{"urn:example:token"}, client.GetBackChannelEndpointLoginHintTokenTypes())

	assert.Equal(t, "ping", GetCIBADeliveryMode(client))
	assert.Equal(t, "", GetCIBADeliveryMode(&DefaultClient{}))

	registered := &DefaultRegisteredClient{BackChannelTokenDeliveryMode: "push"}

	assert.Equal(t, "push", GetCIBADeliveryMode(registered))

	var _ CIBALoginHintTokenTypesClient = registered

	_, ok := any(&DefaultClient{}).(CIBAClient)
	assert.False(t, ok)
}

func TestClientRegistrationMetadataCIBARoundTrip(t *testing.T) {
	in := `{"backchannel_token_delivery_mode":"push","backchannel_client_notification_endpoint":"https://c.example.com/n","backchannel_authentication_request_signing_alg":"PS256","backchannel_user_code_parameter":true,"backchannel_endpoint_login_hint_token_types":["a","b"]}`

	var metadata ClientRegistrationMetadata

	require.NoError(t, json.Unmarshal([]byte(in), &metadata))

	assert.Equal(t, "push", metadata.BackChannelTokenDeliveryMode)

	out, err := json.Marshal(&metadata)
	require.NoError(t, err)

	assert.JSONEq(t, in, string(out))
}
