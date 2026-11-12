// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestIntrospectionSignedResponseAlgClientClientSecretExpiresAt(t *testing.T) {
	expires := time.Now().Add(-time.Hour)

	assert.Equal(t, expires, (&introspectionSignedResponseAlgClient{IntrospectionClient: &DefaultRegisteredClient{DefaultClient: &DefaultClient{}, ClientSecretExpiresAt: expires}}).GetClientSecretExpiresAt())
	assert.True(t, (&introspectionSignedResponseAlgClient{IntrospectionClient: &DefaultRegisteredClient{DefaultClient: &DefaultClient{}}}).GetClientSecretExpiresAt().IsZero())
}
