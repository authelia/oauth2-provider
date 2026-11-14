// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package cimd

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
)

func TestCIMDDocumentCIBAMetadata(t *testing.T) {
	metadata, err := parseDocument(testClientID, document(`"redirect_uris":["https://client.example.com/cb"],"grant_types":["urn:openid:params:grant-type:ciba"],"backchannel_token_delivery_mode":"ping","backchannel_client_notification_endpoint":"https://client.example.com/notify","backchannel_authentication_request_signing_alg":"ES256","backchannel_user_code_parameter":true,"backchannel_endpoint_login_hint_token_types":["urn:example:t"]`))
	require.NoError(t, err)

	client, err := DefaultClientStrategy{}.NewClient(context.Background(), &oauth2.ClientIDMetadataDocumentRecord{ID: testClientID, Metadata: metadata})
	require.NoError(t, err)

	ciba, ok := client.(oauth2.CIBAClient)
	require.True(t, ok)

	assert.Equal(t, "ping", ciba.GetBackChannelTokenDeliveryMode())
	assert.Equal(t, "https://client.example.com/notify", ciba.GetBackChannelClientNotificationEndpoint())
	assert.Equal(t, "ES256", ciba.GetBackChannelAuthenticationRequestSigningAlg())
	assert.True(t, ciba.GetBackChannelUserCodeParameter())

	hint, ok := client.(oauth2.CIBALoginHintTokenTypesClient)
	require.True(t, ok)
	assert.Equal(t, []string{"urn:example:t"}, hint.GetBackChannelEndpointLoginHintTokenTypes())
}
