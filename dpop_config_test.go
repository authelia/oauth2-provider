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

func TestConfigDPoPDefaults(t *testing.T) {
	c := &Config{}
	ctx := context.Background()

	assert.False(t, c.GetDPoPEnabled(ctx))
	assert.Equal(t, []string{"ES256", "ES384", "ES512", "PS256", "PS384", "PS512", "RS256", "RS384", "RS512", "EdDSA"}, c.GetDPoPAllowedJWSAlgorithms(ctx))
	assert.Equal(t, time.Minute*5, c.GetDPoPClockSkew(ctx))
	assert.Equal(t, time.Hour, c.GetDPoPNonceLifespan(ctx))

	var _ DPoPConfigProvider = c
}
