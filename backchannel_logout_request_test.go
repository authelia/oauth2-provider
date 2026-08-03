// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"authelia.com/provider/oauth2"
)

func TestNewBackChannelLogoutRequest(t *testing.T) {
	client := &oauth2.DefaultBackChannelLogoutClient{DefaultClient: &oauth2.DefaultClient{ID: "rp-1"}}

	request := oauth2.NewBackChannelLogoutRequest("alice", "session-1", []oauth2.Client{client})

	assert.Equal(t, "alice", request.GetSubject())
	assert.Equal(t, "session-1", request.GetSessionID())
	assert.Len(t, request.GetClients(), 1)
	assert.NotNil(t, request.GetExtra())
	assert.Empty(t, request.GetExtra())

	var requester oauth2.BackChannelLogoutRequester = request

	assert.Equal(t, "alice", requester.GetSubject())
}

func TestBackChannelLogoutResultSuccess(t *testing.T) {
	testCases := []struct {
		name     string
		result   oauth2.BackChannelLogoutResult
		expected bool
	}{
		{"ShouldSucceedWhenDelivered", oauth2.BackChannelLogoutResult{Status: 200}, true},
		{"ShouldFailWhenSkipped", oauth2.BackChannelLogoutResult{Skipped: true, Reason: "x"}, false},
		{"ShouldFailWhenErrored", oauth2.BackChannelLogoutResult{Err: assert.AnError}, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.result.Success())
		})
	}
}
