// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package ssfreceiver

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/ssfjson"
)

const (
	streamMemberStatus = "status"
	streamMemberReason = "reason"
)

// StreamStatus is the status of a stream as a Transmitter returns it. A member which is null is absent, and a member
// that is not understood is ignored. A repeated member or one of the wrong type is an error.
//
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.2.1
type StreamStatus struct {
	StreamID string `json:"stream_id"`

	// Status is one of the oauth2.SSFStreamStatus constants.
	Status string `json:"status"`

	Reason string `json:"reason,omitempty"`
}

// streamStatusRequest is the body of a status update.
//
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.2.2
type streamStatusRequest struct {
	StreamID string `json:"stream_id"`
	Status   string `json:"status"`
	Reason   string `json:"reason,omitempty"`
}

// ReadStreamStatus returns the status of the stream as the Transmitter has it, which must be for the stream ID asked
// for and have a status that is enabled, paused or disabled. When this Receiver has an active record of the stream the
// status and its reason are stored, and nothing else of the record changes. Without a record nothing is stored, nor
// when the stored status changed while the request was made, such as by a stream updated event, or could not be read
// before it.
//
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.2.1
// See: https://openid.net/specs/openid-caep-interoperability-profile-1_0.html#section-2.7.3
func (r *Receiver) ReadStreamStatus(ctx context.Context, issuer, streamID string) (status *StreamStatus, err error) {
	if streamID == "" {
		return nil, streamRequestError("the stream id is required")
	}

	var endpoint string

	if endpoint, err = r.statusEndpoint(ctx, issuer); err != nil {
		return nil, err
	}

	// The status before the request, so one a stream updated event stores while it is made is kept.
	var before *StreamRecord

	if r.Store != nil {
		before, _ = r.Store.GetSSFReceiverStream(ctx, issuer, streamID)
	}

	var response *transmitterResponse

	// SSF Section 8.1.2.1: the 'stream_id' is a query parameter and the response is a 200.
	if response, err = r.transmit(ctx, issuer, transmitterRequest{
		method:   http.MethodGet,
		endpoint: endpoint,
		scope:    oauth2.ScopeSSFRead,
		query:    url.Values{streamMemberStreamID: {streamID}},
		success:  []int{http.StatusOK},
	}); err != nil {
		return nil, err
	}

	if status, err = response.streamStatus(streamID); err != nil {
		return nil, err
	}

	if r.Store == nil {
		return status, nil
	}

	var record *StreamRecord

	switch record, err = r.Store.GetSSFReceiverStream(ctx, issuer, streamID); {
	case errors.Is(err, oauth2.ErrNotFound):
		return status, nil
	case err != nil:
		return nil, fmt.Errorf("ssfreceiver: the stream record could not be read: %w", err)
	case record.State != StreamRecordActive:
		return status, nil
	case before == nil || record.Status != before.Status || record.StatusReason != before.StatusReason:
		// SSF Sections 8.1.2 and 8.1.5: a change of the status is sent as a stream updated event, which is newer. A
		// status which could not be read before the request may have been changed so, and is not replaced either.
		return status, nil
	}

	if err = r.Store.UpdateSSFReceiverStreamStatus(ctx, issuer, streamID, status.Status, status.Reason); err != nil {
		return nil, fmt.Errorf("ssfreceiver: the status of the stream could not be stored: %w", err)
	}

	return status, nil
}

// Touch reads the status of the stream, as ReadStreamStatus does, which is activity that restarts the inactivity
// timeout of the stream. A Transmitter without a Status Endpoint is asked for the configuration of the stream in its
// place, and nothing is stored. A push stream has no other activity of this Receiver, so the caller should touch one
// more often than the InactivityTimeout of its record, when it has one. A poll stream is kept alive by each poll.
//
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.1
func (r *Receiver) Touch(ctx context.Context, issuer, streamID string) (err error) {
	if _, err = r.ReadStreamStatus(ctx, issuer, streamID); !errors.Is(err, ErrEndpointNotSupported) {
		return err
	}

	// SSF Section 8.1.1: any request of the Event Stream Management API which references the stream is activity.
	_, err = r.readStreams(ctx, issuer, url.Values{streamMemberStreamID: {streamID}})

	return err
}

// UpdateStreamStatus asks the Transmitter to enable, pause or disable the stream, which must have an active record,
// with an optional reason. It returns the status of the response, which is the one stored, with its reason, whatever
// was asked for.
//
// A 200 means the Transmitter applied the update. When its response is then refused or could not be read, or the
// status could not be stored, the error matches ErrStreamChangeApplied: the status and the reason that were sent are
// stored, unless they could not be, until ReadStreamStatus reads a valid status. An error matching
// ErrStreamUpdatePending means the Transmitter accepted the update and has not processed it, and one matching
// ErrTransmitterUnconfirmed that it may have processed it: the record is unchanged, and the caller may make the same
// request later. A POST is not sent again after a connection error.
//
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.2.2
func (r *Receiver) UpdateStreamStatus(ctx context.Context, issuer, streamID, status, reason string) (updated *StreamStatus, err error) {
	if _, err = r.activeStream(ctx, issuer, streamID); err != nil {
		return nil, err
	}

	if !isStreamStatus(status) {
		return nil, streamRequestError("the status must be enabled, paused or disabled")
	}

	var endpoint string

	if endpoint, err = r.statusEndpoint(ctx, issuer); err != nil {
		return nil, err
	}

	var response *transmitterResponse

	// SSF Section 8.1.2.2: the response is a 200, and a 202 was accepted but not processed.
	if response, err = r.transmit(ctx, issuer, transmitterRequest{
		method:   http.MethodPost,
		endpoint: endpoint,
		scope:    oauth2.ScopeSSFManage,
		body:     streamStatusRequest{StreamID: streamID, Status: status, Reason: reason},
		success:  []int{http.StatusOK},
		pending:  true,
	}); err != nil && !isUnreadResponse(err) {
		return nil, err
	}

	// A 200 whose body could not be read is a response which is refused.
	refused := err
	if refused == nil {
		if updated, refused = response.streamStatus(streamID); refused == nil {
			status, reason = updated.Status, updated.Reason
		}
	}

	// The Transmitter changed the status, so it is stored though the context may be done.
	if err = r.Store.UpdateSSFReceiverStreamStatus(context.WithoutCancel(ctx), issuer, streamID, status, reason); err != nil {
		return nil, changeAppliedError("the status of the stream could not be stored", err)
	}

	if refused != nil {
		return nil, changeAppliedError("", refused)
	}

	return updated, nil
}

// statusEndpoint returns the Status Endpoint of the validated Transmitter Configuration Metadata, or
// ErrEndpointNotSupported when the Transmitter has none.
//
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-7.1
func (r *Receiver) statusEndpoint(ctx context.Context, issuer string) (endpoint string, err error) {
	var configuration *oauth2.SSFConfiguration

	if configuration, err = r.Discover(ctx, issuer); err != nil {
		return "", err
	}

	if configuration.StatusEndpoint == "" {
		return "", ErrEndpointNotSupported
	}

	return configuration.StatusEndpoint, nil
}

// streamStatus returns the stream status in the body, checked as the one of the stream.
//
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.2.1
func (r *transmitterResponse) streamStatus(streamID string) (status *StreamStatus, err error) {
	if !isJSONContentType(r.header) {
		return nil, streamStatusError("the content type is not '" + consts.MediaTypeApplicationJSON + "'")
	}

	members, err := ssfjson.ParseObject(r.body)
	if err != nil {
		return nil, fmt.Errorf("%w: the body is not a JSON object: %w", ErrStreamStatus, err)
	}

	status = &StreamStatus{}

	targets := []struct {
		name   string
		target *string
	}{
		{streamMemberStreamID, &status.StreamID},
		{streamMemberStatus, &status.Status},
		{streamMemberReason, &status.Reason},
	}

	for _, member := range targets {
		value, present := ssfjson.Member(members, member.name)
		if !present {
			continue
		}

		var ok bool

		if *member.target, ok = ssfjson.ParseString(value); !ok {
			return nil, streamStatusError("the '" + member.name + "' is not a string")
		}
	}

	switch {
	case status.StreamID != streamID:
		return nil, streamStatusError("the 'stream_id' is not the one of the stream")
	case !isStreamStatus(status.Status):
		return nil, streamStatusError("the 'status' is not enabled, paused or disabled")
	}

	return status, nil
}

// isStreamStatus reports whether the status is one a stream may have.
//
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.2.1
func isStreamStatus(status string) (ok bool) {
	switch status {
	case oauth2.SSFStreamStatusEnabled, oauth2.SSFStreamStatusPaused, oauth2.SSFStreamStatusDisabled:
		return true
	default:
		return false
	}
}

func streamStatusError(description string) (err error) {
	return fmt.Errorf("%w: %s", ErrStreamStatus, description)
}
