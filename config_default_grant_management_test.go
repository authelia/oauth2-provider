// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfigGetGrantManagementConfig(t *testing.T) {
	const (
		issuer   = "https://as.example.com"
		endpoint = "https://as.example.com/grants"
	)

	t.Run("ShouldReturnNilWhenNotConfigured", func(t *testing.T) {
		var provider GrantManagementConfigProvider = &Config{Issuer: issuer}

		assert.Nil(t, provider.GetGrantManagementConfig(t.Context()))
	})

	t.Run("ShouldDefaultTheAudienceToTheIssuer", func(t *testing.T) {
		config := &Config{
			Issuer: issuer,
			GrantManagement: &GrantManagementConfig{
				Actions:        []GrantManagementAction{GrantManagementActionQuery, GrantManagementActionCreate},
				Endpoint:       endpoint,
				ActionRequired: true,
			},
		}

		actual := config.GetGrantManagementConfig(t.Context())

		require.NotNil(t, actual)
		assert.Equal(t, &GrantManagementConfig{
			Actions:        []GrantManagementAction{GrantManagementActionQuery, GrantManagementActionCreate},
			Endpoint:       endpoint,
			ActionRequired: true,
			Audience:       issuer,
		}, actual)
		assert.Empty(t, config.GrantManagement.Audience)
	})

	t.Run("ShouldKeepTheConfiguredAudience", func(t *testing.T) {
		config := &Config{
			Issuer:          issuer,
			GrantManagement: &GrantManagementConfig{Audience: "https://api.example.com"},
		}

		assert.Equal(t, "https://api.example.com", config.GetGrantManagementConfig(t.Context()).Audience)
	})

	t.Run("ShouldReturnACopy", func(t *testing.T) {
		config := &Config{
			Issuer: issuer,
			GrantManagement: &GrantManagementConfig{
				Actions:  []GrantManagementAction{GrantManagementActionQuery},
				Endpoint: endpoint,
			},
		}

		actual := config.GetGrantManagementConfig(t.Context())

		require.NotNil(t, actual)
		assert.NotSame(t, config.GrantManagement, actual)

		actual.Actions[0] = GrantManagementActionRevoke
		actual.Endpoint = "https://other.example.com/grants"

		assert.Equal(t, []GrantManagementAction{GrantManagementActionQuery}, config.GrantManagement.Actions)
		assert.Equal(t, endpoint, config.GrantManagement.Endpoint)
	})
}

func TestGrantManagementConfigSupports(t *testing.T) {
	config := &GrantManagementConfig{Actions: []GrantManagementAction{GrantManagementActionCreate, GrantManagementActionQuery}}

	assert.True(t, config.Supports(GrantManagementActionCreate))
	assert.True(t, config.Supports(GrantManagementActionQuery))
	assert.False(t, config.Supports(GrantManagementActionMerge))
	assert.False(t, config.Supports(""))
	assert.False(t, (&GrantManagementConfig{}).Supports(GrantManagementActionCreate))
	assert.False(t, (*GrantManagementConfig)(nil).Supports(GrantManagementActionCreate))
}
