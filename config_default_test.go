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

func TestConfigRFC7591ClientRegistrationTokenLifespans(t *testing.T) {
	ctx := context.Background()

	t.Run("Defaults", func(t *testing.T) {
		config := &Config{}

		// A creation token is short-lived; it exists only to onboard one client.
		assert.Equal(t, time.Minute*10, config.GetRFC7591ClientRegistrationCreateTokenLifespan(ctx))

		// A management token defaults to never expiring, the usual case for an RFC 7592 registration_access_token.
		assert.Equal(t, time.Duration(0), config.GetRFC7591ClientRegistrationManageTokenLifespan(ctx))
	})

	t.Run("Configured", func(t *testing.T) {
		config := &Config{
			RFC7591ClientRegistrationCreateTokenLifespan: time.Minute * 3,
			RFC7591ClientRegistrationManageTokenLifespan: time.Hour * 24,
		}

		assert.Equal(t, time.Minute*3, config.GetRFC7591ClientRegistrationCreateTokenLifespan(ctx))
		assert.Equal(t, time.Hour*24, config.GetRFC7591ClientRegistrationManageTokenLifespan(ctx))
	})
}
