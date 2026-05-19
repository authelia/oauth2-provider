// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultSessionNil(t *testing.T) {
	testCases := []struct {
		name  string
		check func(t *testing.T, s *DefaultSession)
	}{
		{
			name: "ShouldReturnEmptySubjectForNilReceiver",
			check: func(t *testing.T, s *DefaultSession) {
				assert.Empty(t, s.GetSubject())
			},
		},
		{
			name: "ShouldReturnEmptyUsernameForNilReceiver",
			check: func(t *testing.T, s *DefaultSession) {
				assert.Empty(t, s.GetUsername())
			},
		},
		{
			name: "ShouldReturnNilCloneForNilReceiver",
			check: func(t *testing.T, s *DefaultSession) {
				assert.Nil(t, s.Clone())
			},
		},
		{
			name: "ShouldReturnNilExtraClaimsForNilReceiver",
			check: func(t *testing.T, s *DefaultSession) {
				assert.Nil(t, s.GetExtraClaims())
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var s *DefaultSession
			tc.check(t, s)
		})
	}
}

func TestDefaultSessionZeroValue(t *testing.T) {
	testCases := []struct {
		name  string
		check func(t *testing.T, s *DefaultSession)
	}{
		{
			name: "ShouldReturnEmptySubject",
			check: func(t *testing.T, s *DefaultSession) {
				assert.Empty(t, s.GetSubject())
			},
		},
		{
			name: "ShouldReturnEmptyUsername",
			check: func(t *testing.T, s *DefaultSession) {
				assert.Empty(t, s.GetUsername())
			},
		},
		{
			name: "ShouldReturnEmptyClone",
			check: func(t *testing.T, s *DefaultSession) {
				assert.Empty(t, s.Clone())
			},
		},
		{
			name: "ShouldReturnZeroTimeForUnsetExpiresAt",
			check: func(t *testing.T, s *DefaultSession) {
				assert.True(t, s.GetExpiresAt(AccessToken).IsZero())
			},
		},
		{
			name: "ShouldReturnEmptyExtraClaimsMap",
			check: func(t *testing.T, s *DefaultSession) {
				actual := s.GetExtraClaims()
				require.NotNil(t, actual)
				assert.Empty(t, actual)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			s := new(DefaultSession)
			tc.check(t, s)
		})
	}
}

func TestDefaultSessionSetters(t *testing.T) {
	testCases := []struct {
		name  string
		check func(t *testing.T)
	}{
		{
			name: "ShouldSetAndGetSubject",
			check: func(t *testing.T) {
				s := &DefaultSession{}
				s.SetSubject("alice")
				assert.Equal(t, "alice", s.GetSubject())
			},
		},
		{
			name: "ShouldSetAndGetExpiresAt",
			check: func(t *testing.T) {
				s := &DefaultSession{}
				expiry := time.Now().Add(time.Hour).Truncate(time.Second)
				s.SetExpiresAt(AccessToken, expiry)
				assert.Equal(t, expiry, s.GetExpiresAt(AccessToken))
			},
		},
		{
			name: "ShouldSetExpiresAtIndependentlyPerTokenType",
			check: func(t *testing.T) {
				s := &DefaultSession{}
				accessExpiry := time.Now().Add(time.Hour).Truncate(time.Second)
				refreshExpiry := time.Now().Add(24 * time.Hour).Truncate(time.Second)
				s.SetExpiresAt(AccessToken, accessExpiry)
				s.SetExpiresAt(RefreshToken, refreshExpiry)
				assert.Equal(t, accessExpiry, s.GetExpiresAt(AccessToken))
				assert.Equal(t, refreshExpiry, s.GetExpiresAt(RefreshToken))
			},
		},
		{
			name: "ShouldInitializeExpiresAtMapLazilyOnGet",
			check: func(t *testing.T) {
				s := &DefaultSession{}
				assert.Nil(t, s.ExpiresAt)
				assert.True(t, s.GetExpiresAt(AccessToken).IsZero())
				assert.NotNil(t, s.ExpiresAt)
			},
		},
		{
			name: "ShouldReturnUsername",
			check: func(t *testing.T) {
				s := &DefaultSession{Username: "bob"}
				assert.Equal(t, "bob", s.GetUsername())
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, tc.check)
	}
}

func TestDefaultSessionGetExtraClaims(t *testing.T) {
	testCases := []struct {
		name  string
		check func(t *testing.T)
	}{
		{
			name: "ShouldInitializeExtraClaimsLazily",
			check: func(t *testing.T) {
				s := &DefaultSession{}
				assert.Nil(t, s.Extra)
				actual := s.GetExtraClaims()
				assert.NotNil(t, actual)
				assert.Empty(t, actual)
				assert.NotNil(t, s.Extra)
			},
		},
		{
			name: "ShouldReturnInPlaceMutableMap",
			check: func(t *testing.T) {
				s := &DefaultSession{}
				s.GetExtraClaims()["foo"] = "bar"
				assert.Equal(t, "bar", s.GetExtraClaims()["foo"])
				assert.Equal(t, "bar", s.Extra["foo"])
			},
		},
		{
			name: "ShouldReturnExistingExtra",
			check: func(t *testing.T) {
				s := &DefaultSession{Extra: map[string]any{"hello": "world"}}
				actual := s.GetExtraClaims()
				assert.Equal(t, "world", actual["hello"])
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, tc.check)
	}
}

func TestDefaultSessionClone(t *testing.T) {
	testCases := []struct {
		name  string
		check func(t *testing.T)
	}{
		{
			name: "ShouldDeepCopyExpiresAt",
			check: func(t *testing.T) {
				expiry := time.Now().Add(time.Hour).Truncate(time.Second)
				s := &DefaultSession{Subject: "alice", Username: "alice@example"}
				s.SetExpiresAt(AccessToken, expiry)

				cloned := s.Clone().(*DefaultSession)
				assert.Equal(t, s.Subject, cloned.Subject)
				assert.Equal(t, s.Username, cloned.Username)
				assert.Equal(t, expiry, cloned.GetExpiresAt(AccessToken))

				// Mutate the original; the clone must be unaffected.
				newExpiry := time.Now().Add(48 * time.Hour).Truncate(time.Second)
				s.SetExpiresAt(AccessToken, newExpiry)
				assert.Equal(t, expiry, cloned.GetExpiresAt(AccessToken))
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, tc.check)
	}
}
