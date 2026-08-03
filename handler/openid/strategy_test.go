// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package openid_test

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/handler/openid"
	"authelia.com/provider/oauth2/internal/gen"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestDefaultStrategyImplementsBackChannelLogoutTokenStrategy(t *testing.T) {
	var strategy oauth2.BackChannelLogoutTokenStrategy = &openid.DefaultStrategy{}

	assert.NotNil(t, strategy)
}

func TestGenerateBackChannelLogoutTokenSetsRequiredClaims(t *testing.T) {
	config := &oauth2.Config{IDTokenIssuer: "https://op.example/", MinParameterEntropy: 8}

	jwtStrategy := &jwt.DefaultStrategy{Config: config, Issuer: jwt.NewDefaultIssuerRS256Unverified(gen.MustRSAKey())}

	strategy := &openid.DefaultStrategy{Strategy: jwtStrategy, Config: config}

	token, err := strategy.GenerateBackChannelLogoutToken(
		t.Context(), &oauth2.DefaultClient{ID: "rp-1"}, time.Minute*5, "alice", "session-1", []string{"rp-1"}, nil,
	)

	require.NoError(t, err)

	parts := strings.Split(token, ".")
	require.Len(t, parts, 3)

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)

	claims := map[string]any{}
	require.NoError(t, json.Unmarshal(payload, &claims))

	assert.Equal(t, "https://op.example/", claims["iss"])
	assert.Equal(t, []any{"rp-1"}, claims["aud"])
	assert.NotEmpty(t, claims["iat"])
	assert.NotEmpty(t, claims["exp"])
	assert.NotEmpty(t, claims["jti"])

	assert.Equal(t, "alice", claims["sub"])
	assert.Equal(t, "session-1", claims["sid"])
	assert.NotContains(t, claims, "nonce")
}

func TestGenerateBackChannelLogoutTokenDefaultsToFiveMinuteLifespan(t *testing.T) {
	config := &oauth2.Config{IDTokenIssuer: "https://op.example/", MinParameterEntropy: 8}

	jwtStrategy := &jwt.DefaultStrategy{Config: config, Issuer: jwt.NewDefaultIssuerRS256Unverified(gen.MustRSAKey())}

	strategy := &openid.DefaultStrategy{Strategy: jwtStrategy, Config: config}

	before := time.Now().UTC()

	token, err := strategy.GenerateBackChannelLogoutToken(
		t.Context(), &oauth2.DefaultClient{ID: "rp-1"}, 0, "alice", "session-1", []string{"rp-1"}, nil,
	)

	require.NoError(t, err)

	parts := strings.Split(token, ".")
	require.Len(t, parts, 3)

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)

	claims := map[string]any{}
	require.NoError(t, json.Unmarshal(payload, &claims))

	exp, ok := claims["exp"].(float64)
	require.True(t, ok)

	expiresAt := time.Unix(int64(exp), 0).UTC()

	assert.WithinDuration(t, before.Add(5*time.Minute), expiresAt, 5*time.Second)
	assert.Less(t, expiresAt.Sub(before), time.Hour)
}

func TestGenerateBackChannelLogoutTokenRejectsNegativeLifespan(t *testing.T) {
	config := &oauth2.Config{IDTokenIssuer: "https://op.example/", MinParameterEntropy: 8}

	jwtStrategy := &jwt.DefaultStrategy{Config: config, Issuer: jwt.NewDefaultIssuerRS256Unverified(gen.MustRSAKey())}

	strategy := &openid.DefaultStrategy{Strategy: jwtStrategy, Config: config}

	token, err := strategy.GenerateBackChannelLogoutToken(
		t.Context(), &oauth2.DefaultClient{ID: "rp-1"}, -time.Hour, "alice", "session-1", []string{"rp-1"}, nil,
	)

	require.Error(t, err)
	assert.Empty(t, token)
	assert.ErrorIs(t, err, oauth2.ErrServerError)
}
