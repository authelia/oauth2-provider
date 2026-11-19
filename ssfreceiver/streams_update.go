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
	"slices"

	"authelia.com/provider/oauth2"
)

// StreamUpdate is the Receiver-Supplied members of a stream to change. A member which is nil is not sent, so the
// Transmitter does not change it.
//
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.1.3
type StreamUpdate struct {
	// Delivery replaces the whole delivery, the secret AuthorizationHeader of a push delivery included, as
	// CreateStreamRequest.Delivery describes.
	Delivery *oauth2.SSFDelivery

	// EventsRequested should not be empty.
	EventsRequested []string

	Description *string
}

// StreamReplacement is every Receiver-Supplied member of a stream. An empty EventsRequested or Description is not
// sent, which asks the Transmitter to delete it.
//
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.1.4
type StreamReplacement struct {
	// Delivery is required, as CreateStreamRequest.Delivery describes. The secret AuthorizationHeader of a push
	// delivery is sent again, and one that is empty asks the Transmitter to delete it.
	Delivery oauth2.SSFDelivery

	EventsRequested []string
	Description     string
}

// UpdateStream changes the members of the update at the Transmitter and returns the stored record of the stream,
// which must be active. The request has the stream ID and the members of the update, and never a
// Transmitter-Supplied member. The response is checked as ReadStream checks it, against the delivery asked for. The
// Receiver-Supplied members are stored as supplied and the Transmitter-Supplied members from the response; the
// audience, the status and the verification are kept. The record returned is read from the store after the change,
// so it has a status or verification a stream event stored meanwhile, unless that read fails, when it is the record
// as stored by the change, whose status and verification may be older.
//
// A new secret of a push delivery is stored as the PendingAuthorizationHeader of the record before the request is
// made, so a push with the old secret or the new one is authorized for as long as the Transmitter may send either.
//
// A 200 means the Transmitter applied the update: the new secret becomes the Delivery.AuthorizationHeader and the
// pending one is cleared. When its response is then refused or could not be read, or the record could not be stored,
// the error matches ErrStreamChangeApplied: the record has the Receiver-Supplied members that were sent, unless it
// could not be stored, in which case the pending secret stays, and its Transmitter-Supplied members are unchanged
// until ReadStream reads a valid configuration.
//
// An error matching ErrStreamUpdatePending means the Transmitter accepted the update and has not processed it, and
// one matching ErrTransmitterUnconfirmed that it may have processed it: the record is unchanged but for the pending
// secret, and the caller repeats the same request until it is answered with a 200. A *TransmitterError of a 5xx or of
// a 2xx other than a 200 or a 202 keeps the pending secret as well, as the Transmitter may have applied the update.
// Any other error means the Transmitter did not apply the update, and the pending secret is the one from before the
// request again, which is none unless an earlier update is still pending. A record has one pending secret, so a request with another secret
// replaces that of an update the Transmitter has not processed.
//
// When the update moves a push stream to an endpoint URL another record has, it returns ErrStreamRecordConflict
// before any request. A PATCH is not sent again after a connection error.
//
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.1.3
func (r *Receiver) UpdateStream(ctx context.Context, issuer, streamID string, update StreamUpdate) (record *StreamRecord, err error) {
	if record, err = r.activeStream(ctx, issuer, streamID); err != nil {
		return nil, err
	}

	// SSF Section 8.1.1.3: the 'stream_id' is required, and a member which is missing is not changed.
	body := streamRequest{StreamID: streamID, Description: update.Description}
	previous := record.Delivery

	if update.Delivery != nil {
		if record.Delivery, body.Delivery, err = streamDelivery(*update.Delivery); err != nil {
			return nil, err
		}
	}

	if update.EventsRequested != nil {
		if err = validateEventsRequested(update.EventsRequested); err != nil {
			return nil, err
		}

		record.EventsRequested = slices.Clone(update.EventsRequested)
		body.EventsRequested = &record.EventsRequested
	}

	if update.Description != nil {
		record.Description = *update.Description
	}

	return r.changeStream(ctx, http.MethodPatch, record, previous, body)
}

// ReplaceStream replaces every Receiver-Supplied member of the stream at the Transmitter and returns the stored
// record of the stream, which must be active. The request has the stream ID and the members of the replacement, and
// never a Transmitter-Supplied member: a push delivery is sent whole, with its secret, and a poll delivery as its
// method alone, as its endpoint URL is supplied by the Transmitter. The response, the record and a new secret are
// handled as UpdateStream handles them, the errors matching ErrStreamChangeApplied, ErrStreamUpdatePending and
// ErrTransmitterUnconfirmed included. The PUT is not sent again after a connection error either, as the response to
// another attempt would hide whether the first was applied.
//
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.1.4
func (r *Receiver) ReplaceStream(ctx context.Context, issuer, streamID string, replacement StreamReplacement) (record *StreamRecord, err error) {
	if record, err = r.activeStream(ctx, issuer, streamID); err != nil {
		return nil, err
	}

	// SSF Section 8.1.1.4: the 'stream_id' is required, and a member which is missing is deleted.
	body := streamRequest{StreamID: streamID}
	previous := record.Delivery

	if record.Delivery, body.Delivery, err = streamDelivery(replacement.Delivery); err != nil {
		return nil, err
	}

	if err = validateEventsRequested(replacement.EventsRequested); err != nil {
		return nil, err
	}

	record.EventsRequested, record.Description = nil, replacement.Description

	if len(replacement.EventsRequested) != 0 {
		record.EventsRequested = slices.Clone(replacement.EventsRequested)
		body.EventsRequested = &record.EventsRequested
	}

	if replacement.Description != "" {
		body.Description = &replacement.Description
	}

	return r.changeStream(ctx, http.MethodPut, record, previous, body)
}

// DeleteStream deletes the stream at the Transmitter, and then the record of it when there is one. A stream this
// Receiver has no record of is deleted too. A 404 means the Transmitter has no such stream for this Receiver, as
// after a request whose 204 was lost, so the record is deleted and no error returned. Any other response but a 204 is
// an error and keeps the record.
//
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.1.5
func (r *Receiver) DeleteStream(ctx context.Context, issuer, streamID string) (err error) {
	if streamID == "" {
		return streamRequestError("the stream id is required")
	}

	var endpoint string

	if endpoint, err = r.configurationEndpoint(ctx, issuer); err != nil {
		return err
	}

	// SSF Section 8.1.1.5: the 'stream_id' is a query parameter, the response is an empty 204, and a 404 is no such
	// stream for this Receiver.
	if _, err = r.transmit(ctx, issuer, transmitterRequest{
		method:   http.MethodDelete,
		endpoint: endpoint,
		scope:    oauth2.ScopeSSFManage,
		query:    url.Values{streamMemberStreamID: {streamID}},
		success:  []int{http.StatusNoContent},
	}); err != nil && !errors.Is(err, ErrStreamNotFound) {
		return err
	}

	if r.Store == nil {
		return nil
	}

	// The Transmitter no longer has the stream, so the record is deleted though the context may be done.
	if err = r.Store.DeleteSSFReceiverStream(context.WithoutCancel(ctx), issuer, streamID); err != nil && !errors.Is(err, oauth2.ErrNotFound) {
		return fmt.Errorf("ssfreceiver: the stream record could not be deleted: %w", err)
	}

	return nil
}

// activeStream returns the record of a stream the Transmitter created.
func (r *Receiver) activeStream(ctx context.Context, issuer, streamID string) (record *StreamRecord, err error) {
	switch {
	case r.Store == nil:
		return nil, errNoStore
	case streamID == "":
		return nil, streamRequestError("the stream id is required")
	}

	if record, err = r.Store.GetSSFReceiverStream(ctx, issuer, streamID); err != nil {
		if errors.Is(err, oauth2.ErrNotFound) {
			return nil, wrapError("ssfreceiver: the stream record could not be read", err, errStreamRecordGone)
		}

		return nil, fmt.Errorf("ssfreceiver: the stream record could not be read: %w", err)
	}

	if record.State != StreamRecordActive {
		return nil, streamRequestError("the stream record is not active")
	}

	// A record without a delivery method is one of a push stream.
	record.Delivery.Method = streamDeliveryMethod(record.Delivery.Method)

	return record, nil
}

// changeStream sends the update or the replacement the record was changed by, and stores the record. A 200 means the
// Transmitter applied the change, so the record is then stored with the Receiver-Supplied members that were sent
// whatever the response, and with the Transmitter-Supplied members of a response which is valid. The previous
// delivery is the one of the stored record.
//
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.1.3
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.1.4
func (r *Receiver) changeStream(ctx context.Context, method string, record *StreamRecord, previous oauth2.SSFDelivery, body streamRequest) (changed *StreamRecord, err error) {
	if err = r.checkPushEndpoint(ctx, record.Delivery, previous); err != nil {
		return nil, err
	}

	// The poll endpoint URL is supplied by the Transmitter, so it is kept until a valid response has another.
	if record.Delivery.Method == oauth2.SSFDeliveryMethodPoll && previous.Method == oauth2.SSFDeliveryMethodPoll {
		record.Delivery.EndpointURL = previous.EndpointURL
	}

	var endpoint string

	if endpoint, err = r.configurationEndpoint(ctx, record.Issuer); err != nil {
		return nil, err
	}

	streamID := record.StreamID

	var change secretChange

	if change, err = r.offerSecret(ctx, record, previous, body.Delivery); err != nil {
		return nil, err
	}

	var response *transmitterResponse

	// SSF Sections 8.1.1.3 and 8.1.1.4: the response is a 200, and a 202 was accepted but not processed.
	if response, err = r.transmit(ctx, record.Issuer, transmitterRequest{
		method:   method,
		endpoint: endpoint,
		scope:    oauth2.ScopeSSFManage,
		body:     body,
		success:  []int{http.StatusOK},
		pending:  true,
		once:     true,
	}); err != nil && !isUnreadResponse(err) {
		r.withdrawSecret(ctx, record, change, err)

		return nil, err
	}

	// A 200 whose body could not be read is a response which is refused.
	refused := err
	if refused == nil {
		var configuration *StreamConfiguration

		if configuration, refused = response.streamConfiguration(record.Issuer); refused == nil {
			refused = configuration.agrees(streamExpectation{streamID: streamID, audience: record.Audience, exactAudience: true, delivery: record.Delivery})
		}

		if refused == nil {
			configuration.apply(record)
		}
	}

	// The Transmitter changed the stream, so the record is stored though the context may be done.
	if err = r.Store.UpdateSSFReceiverStream(context.WithoutCancel(ctx), record.Issuer, streamID, record); err != nil {
		return nil, changeAppliedError("the stream record could not be stored", err)
	}

	if body.Delivery != nil {
		if err = r.confirmSecret(ctx, record, change); err != nil {
			return nil, err
		}
	}

	if refused != nil {
		return nil, changeAppliedError("", refused)
	}

	return r.storedStream(ctx, record), nil
}

// storedStream returns the stored record of the stream, or the record when it can not be read. The store keeps the
// members a stream event may have changed during a request, such as the verification. Reading it is best effort, as
// the change is applied and stored either way.
func (r *Receiver) storedStream(ctx context.Context, record *StreamRecord) (stored *StreamRecord) {
	var err error

	if stored, err = r.Store.GetSSFReceiverStream(context.WithoutCancel(ctx), record.Issuer, record.StreamID); err != nil {
		return record
	}

	stored.Delivery.Method = streamDeliveryMethod(stored.Delivery.Method)

	return stored
}

// secretChange is the secret of a push stream a change asks the Transmitter for, which is empty when the change has
// none or the one the record has, and the pending secret of the record before the change.
type secretChange struct {
	secret, pending string
}

// offerSecret stores the new secret of the delivery to send as the pending secret of the stored record, before the
// request: the Transmitter may send it before its response is read, and at any time after a 202.
//
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.1.3
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.1.4
func (r *Receiver) offerSecret(ctx context.Context, record *StreamRecord, previous oauth2.SSFDelivery, delivery *streamDeliveryRequest) (change secretChange, err error) {
	change.pending = record.PendingAuthorizationHeader

	if delivery == nil || delivery.AuthorizationHeader == "" || delivery.AuthorizationHeader == previous.AuthorizationHeader {
		return change, nil
	}

	change.secret = delivery.AuthorizationHeader

	if err = r.Store.SetSSFReceiverStreamPendingAuthorizationHeader(ctx, record.Issuer, record.StreamID, change.secret); err != nil {
		return change, fmt.Errorf("ssfreceiver: the pending secret of the stream could not be stored: %w", err)
	}

	return change, nil
}

// withdrawSecret stores the pending secret from before the change again when the error of the request means the
// Transmitter did not apply the change. It keeps the new one when the Transmitter accepted the request or may have
// processed it, which a 2xx other than the expected one and a 5xx do not rule out (RFC 9110 Sections 15.3 and 15.6).
// A pending secret which could not be withdrawn is replaced by the next change.
func (r *Receiver) withdrawSecret(ctx context.Context, record *StreamRecord, change secretChange, cause error) {
	if change.secret == "" || errors.Is(cause, ErrStreamUpdatePending) || errors.Is(cause, ErrTransmitterUnconfirmed) {
		return
	}

	var terr *TransmitterError

	if errors.As(cause, &terr) && (terr.Status < http.StatusMultipleChoices || terr.Status >= http.StatusInternalServerError) {
		return
	}

	_ = r.Store.SetSSFReceiverStreamPendingAuthorizationHeader(context.WithoutCancel(ctx), record.Issuer, record.StreamID, change.pending)
}

// confirmSecret clears the pending secret of the stored record, which has the delivery the Transmitter applied, so
// the Transmitter sends the secret the record has. The record is stored before, so a push with that secret is
// authorized throughout.
func (r *Receiver) confirmSecret(ctx context.Context, record *StreamRecord, change secretChange) (err error) {
	if change.secret == "" && change.pending == "" {
		return nil
	}

	if err = r.Store.SetSSFReceiverStreamPendingAuthorizationHeader(context.WithoutCancel(ctx), record.Issuer, record.StreamID, ""); err != nil {
		return changeAppliedError("the pending secret of the stream could not be cleared", err)
	}

	record.PendingAuthorizationHeader = ""

	return nil
}

// changeAppliedError returns the error matching ErrStreamChangeApplied and the cause.
func changeAppliedError(description string, cause error) (err error) {
	text := ErrStreamChangeApplied.Error()

	if description != "" {
		text += ": " + description
	}

	return wrapError(text, cause, ErrStreamChangeApplied)
}

// checkPushEndpoint returns ErrStreamRecordConflict when the delivery moves the stream to a push endpoint URL of
// another record, which the store would refuse once the Transmitter had changed the stream.
func (r *Receiver) checkPushEndpoint(ctx context.Context, delivery, previous oauth2.SSFDelivery) (err error) {
	if delivery.Method != oauth2.SSFDeliveryMethodPush || (previous.Method == delivery.Method && previous.EndpointURL == delivery.EndpointURL) {
		return nil
	}

	switch _, err = r.Store.GetSSFReceiverStreamByPushEndpoint(ctx, delivery.EndpointURL); {
	case err == nil:
		return fmt.Errorf("ssfreceiver: the push endpoint url is the one of another stream: %w", ErrStreamRecordConflict)
	case errors.Is(err, oauth2.ErrNotFound):
		return nil
	default:
		return fmt.Errorf("ssfreceiver: the stream records could not be read: %w", err)
	}
}
