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
	assert.Equal(t, time.Second*10, c.GetDPoPClockSkew(ctx))
	assert.Equal(t, time.Second*10, c.GetDPoPProofLifespan(ctx))
	assert.Equal(t, time.Hour, c.GetDPoPNonceLifespan(ctx))
	assert.Equal(t, time.Second*20, c.GetDPoPProofLifespan(ctx)+c.GetDPoPClockSkew(ctx))

	var _ DPoPConfigProvider = c
}

func TestConfigDPoPOverrides(t *testing.T) {
	ctx := context.Background()

	c := &Config{DPoPClockSkew: time.Minute * 2, DPoPProofLifespan: time.Second * 5}

	assert.Equal(t, time.Minute*2, c.GetDPoPClockSkew(ctx))
	assert.Equal(t, time.Second*5, c.GetDPoPProofLifespan(ctx))

	zero := &Config{}

	_, _ = zero.GetDPoPClockSkew(ctx), zero.GetDPoPProofLifespan(ctx)

	assert.Zero(t, zero.DPoPClockSkew, "GetDPoPClockSkew wrote its default back onto the Config")
	assert.Zero(t, zero.DPoPProofLifespan, "GetDPoPProofLifespan wrote its default back onto the Config")
}
