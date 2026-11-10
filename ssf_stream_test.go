// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
)

func TestSSFStreamAccepts(t *testing.T) {
	const event = "https://schemas.openid.net/secevent/caep/event-type/session-revoked"

	testCases := []struct {
		name     string
		stream   *oauth2.SSFStream
		event    string
		expected bool
	}{
		{name: "ShouldAcceptEnabledListed", stream: &oauth2.SSFStream{Status: oauth2.SSFStreamStatusEnabled, EventsDelivered: []string{event}}, event: event, expected: true},
		{name: "ShouldRejectPaused", stream: &oauth2.SSFStream{Status: oauth2.SSFStreamStatusPaused, EventsDelivered: []string{event}}, event: event},
		{name: "ShouldRejectDisabled", stream: &oauth2.SSFStream{Status: oauth2.SSFStreamStatusDisabled, EventsDelivered: []string{event}}, event: event},
		{name: "ShouldRejectUnlisted", stream: &oauth2.SSFStream{Status: oauth2.SSFStreamStatusEnabled, EventsDelivered: []string{event}}, event: event + "-other"},
		{name: "ShouldRejectEmptyStatus", stream: &oauth2.SSFStream{EventsDelivered: []string{event}}, event: event},
		{name: "ShouldRejectNil", stream: nil, event: event},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.stream.Accepts(tc.event))
		})
	}
}

func TestSSFStreamJSON(t *testing.T) {
	stream := &oauth2.SSFStream{
		StreamID:                "s1",
		ClientID:                "private-client",
		Issuer:                  "https://tx.example.com",
		Audience:                []string{"rx"},
		EventsSupported:         []string{"a", "b"},
		EventsRequested:         []string{"a"},
		EventsDelivered:         []string{"a"},
		Delivery:                oauth2.SSFDelivery{Method: oauth2.SSFDeliveryMethodPush, EndpointURL: "https://rx.example.com/push", AuthorizationHeader: "Bearer secret-value"},
		MinVerificationInterval: 30,
		LastVerificationAt:      time.Unix(1700000000, 0),
	}

	raw, err := json.Marshal(stream)
	require.NoError(t, err)

	var out map[string]any

	require.NoError(t, json.Unmarshal(raw, &out))

	for _, key := range []string{"stream_id", "iss", "aud", "events_delivered", "delivery"} {
		assert.Contains(t, out, key)
	}

	assert.Equal(t, "s1", out["stream_id"])
	assert.Equal(t, "https://tx.example.com", out["iss"])
	assert.Equal(t, []any{"rx"}, out["aud"])
	assert.Equal(t, map[string]any{"method": oauth2.SSFDeliveryMethodPush, "endpoint_url": "https://rx.example.com/push"}, out["delivery"])

	body := string(raw)
	assert.NotContains(t, body, "private-client")
	assert.NotContains(t, body, "secret-value")
	assert.NotContains(t, body, "authorization_header")
	assert.NotContains(t, body, "client_id")
	assert.NotContains(t, body, "last_verification")
	assert.NotContains(t, body, "1700000000")

	raw, err = json.Marshal(oauth2.SSFDelivery{Method: oauth2.SSFDeliveryMethodPush, EndpointURL: "https://rx.example.com/push", AuthorizationHeader: "Bearer secret-value"})
	require.NoError(t, err)
	assert.NotContains(t, string(raw), "secret-value")
}

func TestSSFStreamClone(t *testing.T) {
	stream := &oauth2.SSFStream{StreamID: "s1", Audience: []string{"a"}, EventsSupported: []string{"b"}, EventsRequested: []string{"c"}, EventsDelivered: []string{"d"}}

	clone := stream.Clone()
	require.NotSame(t, stream, clone)
	assert.Equal(t, stream, clone)

	clone.Audience[0], clone.EventsSupported[0], clone.EventsRequested[0], clone.EventsDelivered[0] = "x", "x", "x", "x"

	assert.Equal(t, []string{"a"}, stream.Audience)
	assert.Equal(t, []string{"b"}, stream.EventsSupported)
	assert.Equal(t, []string{"c"}, stream.EventsRequested)
	assert.Equal(t, []string{"d"}, stream.EventsDelivered)

	assert.Nil(t, (*oauth2.SSFStream)(nil).Clone())
}

func TestErrSSFStreamConflict(t *testing.T) {
	assert.Equal(t, 409, oauth2.ErrSSFStreamConflict.CodeField)
}
