// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

type onlineRefreshTokenTestClient struct {
	*DefaultClient

	allow bool
}

func (c *onlineRefreshTokenTestClient) GetAllowOnlineRefreshTokens() bool {
	return c.allow
}

func TestGetRefreshTokenModeForScopes(t *testing.T) {
	testCases := []struct {
		name     string
		scopes   []string
		granted  Arguments
		expected RefreshTokenMode
	}{
		{"ShouldBeOfflineWithARefreshTokenScope", []string{"offline", "offline_access"}, Arguments{"foo", "offline_access"}, RefreshTokenModeOffline},
		{"ShouldBeOnlineWithoutARefreshTokenScope", []string{"offline", "offline_access"}, Arguments{"foo"}, RefreshTokenModeOnline},
		{"ShouldBeOnlineWithNothingGranted", []string{"offline_access"}, nil, RefreshTokenModeOnline},
		{"ShouldBeOfflineWithoutRefreshTokenScopes", nil, Arguments{"foo"}, RefreshTokenModeOffline},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, GetRefreshTokenModeForScopes(tc.scopes, tc.granted))
		})
	}
}

func TestIsRefreshTokenModeAllowed(t *testing.T) {
	testCases := []struct {
		name     string
		client   Client
		mode     RefreshTokenMode
		expected bool
	}{
		{"ShouldAllowOfflineForAnyClient", &DefaultClient{}, RefreshTokenModeOffline, true},
		{"ShouldNotAllowOnlineForAPlainClient", &DefaultClient{}, RefreshTokenModeOnline, false},
		{"ShouldNotAllowOnlineWhenTheClientDisallowsIt", &onlineRefreshTokenTestClient{DefaultClient: &DefaultClient{}}, RefreshTokenModeOnline, false},
		{"ShouldAllowOnlineWhenTheClientAllowsIt", &onlineRefreshTokenTestClient{DefaultClient: &DefaultClient{}, allow: true}, RefreshTokenModeOnline, true},
		{"ShouldNotAllowNone", &onlineRefreshTokenTestClient{DefaultClient: &DefaultClient{}, allow: true}, RefreshTokenModeNone, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, IsRefreshTokenModeAllowed(tc.client, tc.mode))
		})
	}
}

func TestRecordRefreshTokenMode(t *testing.T) {
	t.Run("ShouldSetTheModeOnARefreshTokenModeSession", func(t *testing.T) {
		session := &DefaultSession{RefreshTokenMode: RefreshTokenModeOffline}

		RecordRefreshTokenMode(session, RefreshTokenModeOnline)
		assert.Equal(t, RefreshTokenModeOnline, session.GetRefreshTokenMode())

		RecordRefreshTokenMode(session, RefreshTokenModeNone)
		assert.Equal(t, RefreshTokenModeNone, session.GetRefreshTokenMode())
	})

	t.Run("ShouldIgnoreOtherSessions", func(t *testing.T) {
		assert.NotPanics(t, func() { RecordRefreshTokenMode(nil, RefreshTokenModeOnline) })
	})
}
