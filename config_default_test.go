// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"authelia.com/provider/oauth2/token/jwt"
)

func TestConfig_GetIDTokenValidationStrategy(t *testing.T) {
	c := &Config{}
	assert.Nil(t, c.GetIDTokenValidationStrategy(t.Context()), "must be nil when unconfigured")

	strategy := &testTokenValidationStrategy{}
	c.IDTokenValidationStrategy = strategy

	assert.Same(t, strategy, c.GetIDTokenValidationStrategy(t.Context()))
}

type testTokenValidationStrategy struct{}

func (s *testTokenValidationStrategy) ValidateIDToken(ctx context.Context, request Requester, token string, opts ...IDTokenValidationOpt) (claims jwt.MapClaims, err error) {
	return nil, nil
}

func TestConfigBackChannelLogoutDefaults(t *testing.T) {
	config := &Config{}

	assert.Nil(t, config.GetBackChannelLogoutTokenStrategy(t.Context()))
	assert.Equal(t, time.Minute*5, config.GetBackChannelLogoutLifespan(t.Context()))
	assert.Equal(t, 10, config.GetBackChannelLogoutConcurrency(t.Context()))
}

func TestConfigBackChannelLogoutOverrides(t *testing.T) {
	config := &Config{
		BackChannelLogoutLifespan:    time.Minute * 2,
		BackChannelLogoutConcurrency: 3,
	}

	assert.Equal(t, time.Minute*2, config.GetBackChannelLogoutLifespan(t.Context()))
	assert.Equal(t, 3, config.GetBackChannelLogoutConcurrency(t.Context()))
}

func TestConfigBackChannelLogoutNonPositiveFallsBackToDefaults(t *testing.T) {
	config := &Config{
		BackChannelLogoutLifespan:    -time.Second,
		BackChannelLogoutConcurrency: -1,
	}

	assert.Equal(t, time.Minute*5, config.GetBackChannelLogoutLifespan(t.Context()))
	assert.Equal(t, 10, config.GetBackChannelLogoutConcurrency(t.Context()))
}

func TestConfigMTLS(t *testing.T) {
	config := &Config{}

	assert.False(t, config.GetMTLSEnabled(context.TODO()))
	assert.False(t, config.GetMTLSEnforce(context.TODO()))
	assert.Empty(t, config.GetMTLSClientCertificateHeader(context.TODO()))

	config = &Config{MTLSEnforce: true}

	assert.True(t, config.GetMTLSEnabled(context.TODO()))
	assert.True(t, config.GetMTLSEnforce(context.TODO()))

	config = &Config{MTLSEnabled: true, MTLSEnforce: true, MTLSClientCertificateHeader: "X-Forwarded-Tls-Client-Cert"}

	assert.True(t, config.GetMTLSEnabled(context.TODO()))
	assert.True(t, config.GetMTLSEnforce(context.TODO()))
	assert.Equal(t, "X-Forwarded-Tls-Client-Cert", config.GetMTLSClientCertificateHeader(context.TODO()))

	var provider MTLSConfigProvider

	assert.Implements(t, &provider, config)
}
