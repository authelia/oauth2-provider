// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"authelia.com/provider/oauth2/token/jwt"
)

func TestSignedResponseAlgClientWrappersForwardTheDocumentClientMarker(t *testing.T) {
	assert.True(t, jwt.IsClientIDMetadataDocumentClient(&introspectionSignedResponseAlgClient{IntrospectionClient: &markedIntrospectionClient{}}))
	assert.False(t, jwt.IsClientIDMetadataDocumentClient(&introspectionSignedResponseAlgClient{IntrospectionClient: &unmarkedIntrospectionClient{}}))
	assert.True(t, jwt.IsClientIDMetadataDocumentClient(&userinfoUnsignedClient{UserInfoClient: &markedUserInfoClient{}}))
}

type markedIntrospectionClient struct {
	jwt.IntrospectionClient
}

func (c *markedIntrospectionClient) IsClientIDMetadataDocumentClient() bool { return true }

type unmarkedIntrospectionClient struct {
	jwt.IntrospectionClient
}

type markedUserInfoClient struct {
	jwt.UserInfoClient
}

func (c *markedUserInfoClient) IsClientIDMetadataDocumentClient() bool { return true }
