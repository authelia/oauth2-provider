// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestConfigRFC7591ClientRegistrationProvider(t *testing.T) {
	ctx := context.Background()

	config := &Config{
		RFC7591ClientRegistrationEndpointURL: "https://auth.example.com/register",
		RFC7591ClientSecretLifespan:          time.Hour,
	}

	assert.Equal(t, "https://auth.example.com/register", config.GetRFC7591ClientRegistrationEndpointURL(ctx))
	assert.Equal(t, time.Hour, config.GetRFC7591ClientSecretLifespan(ctx))
	assert.Nil(t, config.GetRFC7591ClientRegistrationStrategy(ctx))
	assert.Nil(t, config.GetRFC7591ClientRegistrationEndpointAuthStrategy(ctx))
	assert.Empty(t, config.GetRFC7591ClientRegistrationValidators(ctx))

	var _ RFC7591ClientRegistrationConfigProvider = config
}
