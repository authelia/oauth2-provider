// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package ssfreceiver

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
)

func TestStreamRecordClone(t *testing.T) {
	t.Run("ShouldReturnNilForNil", func(t *testing.T) {
		var record *StreamRecord

		assert.Nil(t, record.Clone())
	})

	t.Run("ShouldDeepCopy", func(t *testing.T) {
		at := time.Unix(1700000000, 0).UTC()

		record := &StreamRecord{
			Issuer:                  "https://tx.example.com",
			StreamID:                "s1",
			Audience:                []string{"https://rx.example.com"},
			Delivery:                oauth2.SSFDelivery{Method: oauth2.SSFDeliveryMethodPush, EndpointURL: "https://rx.example.com/push", AuthorizationHeader: "Bearer s"},
			EventsRequested:         []string{"a", "b"},
			EventsDelivered:         []string{"a"},
			Status:                  oauth2.SSFStreamStatusEnabled,
			StatusReason:            "reason",
			State:                   StreamRecordActive,
			VerificationState:       "state",
			VerificationRequestedAt: at,
			VerifiedAt:              at.Add(time.Second),
			MinVerificationInterval: 60,
			InactivityTimeout:       3600,
		}

		clone := record.Clone()

		require.NotSame(t, record, clone)
		assert.Equal(t, record, clone)

		clone.Audience[0] = "changed"
		clone.EventsRequested[0] = "changed"
		clone.EventsDelivered[0] = "changed"
		clone.Delivery.AuthorizationHeader = "changed"

		assert.Equal(t, []string{"https://rx.example.com"}, record.Audience)
		assert.Equal(t, []string{"a", "b"}, record.EventsRequested)
		assert.Equal(t, []string{"a"}, record.EventsDelivered)
		assert.Equal(t, "Bearer s", record.Delivery.AuthorizationHeader)
	})

	t.Run("ShouldKeepNilSlicesNil", func(t *testing.T) {
		clone := (&StreamRecord{Issuer: "https://tx.example.com"}).Clone()

		assert.Nil(t, clone.Audience)
		assert.Nil(t, clone.EventsRequested)
		assert.Nil(t, clone.EventsDelivered)
	})
}

func TestStreamRecordSecret(t *testing.T) {
	record := &StreamRecord{
		Issuer:   "https://tx.example.com",
		StreamID: "s1",
		Delivery: oauth2.SSFDelivery{Method: oauth2.SSFDeliveryMethodPush, EndpointURL: "https://rx.example.com/push", AuthorizationHeader: "Bearer top-secret"},

		PendingAuthorizationHeader: "Bearer next-secret",
	}

	t.Run("ShouldNotFormatTheAuthorizationHeader", func(t *testing.T) {
		for _, format := range []string{"%v", "%+v", "%#v", "%s"} {
			for _, secret := range []string{"top-secret", "next-secret"} {
				assert.NotContains(t, fmt.Sprintf(format, record), secret, format)
				assert.NotContains(t, fmt.Sprintf(format, *record), secret, format)
				assert.NotContains(t, fmt.Sprintf(format, []*StreamRecord{record}), secret, format)
			}

			// The rest of the record is formatted, and the record is not changed.
			assert.Contains(t, fmt.Sprintf(format, record), "https://tx.example.com", format)
			assert.Equal(t, "Bearer next-secret", record.PendingAuthorizationHeader)
		}
	})

	t.Run("ShouldNotMarshalTheAuthorizationHeader", func(t *testing.T) {
		data, err := json.Marshal(record)
		require.NoError(t, err)

		assert.NotContains(t, string(data), "top-secret")
		assert.NotContains(t, string(data), "next-secret")
	})
}
