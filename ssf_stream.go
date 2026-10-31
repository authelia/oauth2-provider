// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"encoding/json"
	"slices"
	"time"
)

const (
	// SSFDeliveryMethodPush is the RFC 8935 push delivery method URI.
	SSFDeliveryMethodPush = "urn:ietf:rfc:8935"

	// SSFDeliveryMethodPoll is the RFC 8936 poll delivery method URI.
	SSFDeliveryMethodPoll = "urn:ietf:rfc:8936"
)

const (
	// SSFStreamStatusEnabled means the Transmitter delivers events on the stream.
	SSFStreamStatusEnabled = "enabled"

	// SSFStreamStatusPaused means the Transmitter does not deliver events on the stream.
	SSFStreamStatusPaused = "paused"

	// SSFStreamStatusDisabled means the Transmitter neither delivers nor holds events on the stream.
	SSFStreamStatusDisabled = "disabled"
)

// SSFStreamStorage persists the streams of a Transmitter. Every method except create takes the owning client ID, and
// an unknown stream and another client's stream must be indistinguishable: both give ErrNotFound.
//
// SSFDelivery.AuthorizationHeader is a secret. Implementations must protect it at rest and must never log it or
// include it in an error. The JSON encoding of SSFStream is the wire view, which omits the owner, the status, the
// verification time and the secret, so it is not a persistence encoding.
type SSFStreamStorage interface {
	// CreateSSFStream stores the stream. It returns ErrSSFStreamConflict when the client already has a stream, and the
	// check must be atomic with the write.
	CreateSSFStream(ctx context.Context, stream *SSFStream) (err error)

	// GetSSFStream returns the stream of the client, or ErrNotFound.
	GetSSFStream(ctx context.Context, clientID, streamID string) (stream *SSFStream, err error)

	// ListSSFStreams returns every stream of the client.
	ListSSFStreams(ctx context.Context, clientID string) (streams []*SSFStream, err error)

	// UpdateSSFStream replaces the configuration of the stream identified by its ClientID and StreamID, or returns
	// ErrNotFound. It must not change Status, StatusReason or LastVerificationAt. Two concurrent configuration updates
	// are last-write-wins.
	UpdateSSFStream(ctx context.Context, stream *SSFStream) (err error)

	// UpdateSSFStreamStatus sets only the Status and StatusReason of the stream of the client, or returns ErrNotFound.
	UpdateSSFStreamStatus(ctx context.Context, clientID, streamID, status, reason string) (err error)

	// UpdateSSFStreamLastVerification sets only the LastVerificationAt of the stream of the client, or returns
	// ErrNotFound.
	UpdateSSFStreamLastVerification(ctx context.Context, clientID, streamID string, at time.Time) (err error)

	// DeleteSSFStream removes the stream of the client, or returns ErrNotFound.
	DeleteSSFStream(ctx context.Context, clientID, streamID string) (err error)
}

// SSFStream is a Shared Signals Framework stream configuration.
//
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.1
type SSFStream struct {
	// StreamID is the Transmitter-assigned stream identifier.
	StreamID string

	// ClientID is the owner of the stream. It is never serialized.
	ClientID string

	// Issuer is the 'iss' of every SET sent on the stream.
	Issuer string

	// Audience is the 'aud' of every SET sent on the stream.
	Audience []string

	EventsSupported []string
	EventsRequested []string
	EventsDelivered []string

	Delivery SSFDelivery

	Description string

	// Status is one of the SSFStreamStatus constants.
	Status       string
	StatusReason string

	MinVerificationInterval int

	// LastVerificationAt is the time of the last verification event. It is never serialized.
	LastVerificationAt time.Time
}

// Accepts returns true when the stream is enabled and eventType is in EventsDelivered. The verification and
// stream-updated events are not filtered by this method.
//
// It is false for a paused stream, where SSF Section 8.1.2.1 says a Transmitter SHOULD hold events, so an application
// holding events checks EventsDelivered instead. EventsDelivered reflects the policy at the last create or update, so
// an application narrowing a policy must re-apply it in its emitter.
//
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.2
func (s *SSFStream) Accepts(eventType string) bool {
	if s == nil || s.Status != SSFStreamStatusEnabled {
		return false
	}

	return slices.Contains(s.EventsDelivered, eventType)
}

// Clone returns a deep copy of the stream.
func (s *SSFStream) Clone() (clone *SSFStream) {
	if s == nil {
		return nil
	}

	c := *s

	c.Audience = slices.Clone(s.Audience)
	c.EventsSupported = slices.Clone(s.EventsSupported)
	c.EventsRequested = slices.Clone(s.EventsRequested)
	c.EventsDelivered = slices.Clone(s.EventsDelivered)

	return &c
}

type ssfStreamJSON struct {
	StreamID                string      `json:"stream_id"`
	Issuer                  string      `json:"iss"`
	Audience                []string    `json:"aud"`
	EventsSupported         []string    `json:"events_supported,omitempty"`
	EventsRequested         []string    `json:"events_requested,omitempty"`
	EventsDelivered         []string    `json:"events_delivered"`
	Delivery                SSFDelivery `json:"delivery"`
	MinVerificationInterval int         `json:"min_verification_interval,omitempty"`
	Description             string      `json:"description,omitempty"`
}

// MarshalJSON returns the SSF stream configuration. It omits the owner, the verification time and the delivery
// authorization header, and the status, which has its own resource.
//
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.1
func (s SSFStream) MarshalJSON() (data []byte, err error) {
	return json.Marshal(ssfStreamJSON{
		StreamID:                s.StreamID,
		Issuer:                  s.Issuer,
		Audience:                s.Audience,
		EventsSupported:         s.EventsSupported,
		EventsRequested:         s.EventsRequested,
		EventsDelivered:         s.EventsDelivered,
		Delivery:                s.Delivery,
		MinVerificationInterval: s.MinVerificationInterval,
		Description:             s.Description,
	})
}
