// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package jarm

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"authelia.com/provider/oauth2/token/jwt"
)

func TestSignedResponseAlgClientForwardsTheDocumentClientMarker(t *testing.T) {
	assert.True(t, jwt.IsClientIDMetadataDocumentClient(&signedResponseAlgClient{JARMClient: &markedJARMClient{}}))
	assert.False(t, jwt.IsClientIDMetadataDocumentClient(&signedResponseAlgClient{JARMClient: &unmarkedJARMClient{}}))
}

type markedJARMClient struct {
	jwt.JARMClient
}

func (c *markedJARMClient) IsClientIDMetadataDocumentClient() bool { return true }

type unmarkedJARMClient struct {
	jwt.JARMClient
}
