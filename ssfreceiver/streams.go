// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package ssfreceiver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/ssfjson"
)

const (
	streamMemberStreamID                = "stream_id"
	streamMemberIssuer                  = "iss"
	streamMemberAudience                = "aud"
	streamMemberEventsSupported         = "events_supported"
	streamMemberEventsRequested         = "events_requested"
	streamMemberEventsDelivered         = "events_delivered"
	streamMemberDelivery                = "delivery"
	streamMemberMinVerificationInterval = "min_verification_interval"
	streamMemberDescription             = "description"
	streamMemberInactivityTimeout       = "inactivity_timeout"
	streamMemberMethod                  = "method"
	streamMemberEndpointURL             = "endpoint_url"
)

// StreamConfiguration is the stream configuration a Transmitter returns. The 'aud' is read from a string or an array
// of strings, a member which is null is absent, and a member that is not understood is ignored. A repeated member or
// one of the wrong type is an error. The 'authorization_header' of the 'delivery' is never read.
//
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.1
type StreamConfiguration struct {
	StreamID string   `json:"stream_id"`
	Issuer   string   `json:"iss"`
	Audience []string `json:"aud"`

	EventsSupported []string `json:"events_supported,omitempty"`
	EventsRequested []string `json:"events_requested,omitempty"`

	// EventsDelivered is nil when the member is absent.
	EventsDelivered []string `json:"events_delivered"`

	// Delivery has no Method when the member is absent.
	Delivery oauth2.SSFDelivery `json:"delivery"`

	MinVerificationInterval int    `json:"min_verification_interval,omitempty"`
	Description             string `json:"description,omitempty"`
	InactivityTimeout       int    `json:"inactivity_timeout,omitempty"`
}

// UnmarshalJSON implements [json.Unmarshaler].
func (c *StreamConfiguration) UnmarshalJSON(data []byte) (err error) {
	var members map[string]json.RawMessage

	if members, err = ssfjson.ParseObject(data); err != nil {
		return fmt.Errorf("the stream configuration is not a JSON object: %w", err)
	}

	configuration := StreamConfiguration{}

	decoders := []struct {
		name   string
		decode func(value json.RawMessage) (ok bool)
	}{
		{streamMemberStreamID, decodeStreamString(&configuration.StreamID)},
		{streamMemberIssuer, decodeStreamString(&configuration.Issuer)},
		{streamMemberAudience, decodeStreamStrings(&configuration.Audience, true)},
		{streamMemberEventsSupported, decodeStreamStrings(&configuration.EventsSupported, false)},
		{streamMemberEventsRequested, decodeStreamStrings(&configuration.EventsRequested, false)},
		{streamMemberEventsDelivered, decodeStreamStrings(&configuration.EventsDelivered, false)},
		{streamMemberDelivery, decodeStreamDelivery(&configuration.Delivery)},
		{streamMemberMinVerificationInterval, decodeStreamSeconds(&configuration.MinVerificationInterval)},
		{streamMemberDescription, decodeStreamString(&configuration.Description)},
		{streamMemberInactivityTimeout, decodeStreamSeconds(&configuration.InactivityTimeout)},
	}

	for _, decoder := range decoders {
		value, ok := ssfjson.Member(members, decoder.name)
		if !ok {
			continue
		}

		if !decoder.decode(value) {
			return fmt.Errorf("the stream configuration member '%s' is not valid", decoder.name)
		}
	}

	*c = configuration

	return nil
}

func decodeStreamString(target *string) func(value json.RawMessage) (ok bool) {
	return func(value json.RawMessage) (ok bool) {
		*target, ok = ssfjson.ParseString(value)

		return ok
	}
}

// decodeStreamStrings decodes an array of strings, and a string as an array of one when single is true.
func decodeStreamStrings(target *[]string, single bool) func(value json.RawMessage) (ok bool) {
	return func(value json.RawMessage) (ok bool) {
		if s, isString := ssfjson.ParseString(value); isString {
			if single {
				*target = []string{s}
			}

			return single
		}

		var elements []json.RawMessage

		if len(value) == 0 || value[0] != '[' || json.Unmarshal(value, &elements) != nil {
			return false
		}

		values := make([]string, len(elements))

		for i, element := range elements {
			if values[i], ok = ssfjson.ParseString(element); !ok {
				return false
			}
		}

		*target = values

		return true
	}
}

// decodeStreamSeconds decodes an integer number of seconds which is not negative.
func decodeStreamSeconds(target *int) func(value json.RawMessage) (ok bool) {
	return func(value json.RawMessage) (ok bool) {
		return ssfjson.IsNumber(value) && json.Unmarshal(value, target) == nil && *target >= 0
	}
}

// decodeStreamDelivery decodes the 'method' and the 'endpoint_url' of a 'delivery'.
func decodeStreamDelivery(target *oauth2.SSFDelivery) func(value json.RawMessage) (ok bool) {
	return func(value json.RawMessage) (ok bool) {
		members, err := ssfjson.ParseObject(value)
		if err != nil {
			return false
		}

		for name, member := range map[string]*string{streamMemberMethod: &target.Method, streamMemberEndpointURL: &target.EndpointURL} {
			if raw, present := ssfjson.Member(members, name); present {
				if *member, ok = ssfjson.ParseString(raw); !ok {
					return false
				}
			}
		}

		return true
	}
}

// validate checks the members every stream configuration of the Transmitter identified by issuer must have.
//
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.1
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.1.1
func (c *StreamConfiguration) validate(issuer string) (err error) {
	switch {
	case c.Issuer != issuer:
		// SSF Sections 8.1.1.1 to 8.1.1.4: the 'iss' must match the issuer the metadata was received from.
		return wrapError(ErrStreamConfiguration.Error()+": the 'iss'", ErrIssuerMismatch, ErrStreamConfiguration)
	case c.StreamID == "":
		return streamConfigurationError("the 'stream_id' is required")
	case len(c.Audience) == 0, slices.Contains(c.Audience, ""):
		return streamConfigurationError("the 'aud' is required and has no empty value")
	case c.Delivery.Method == "":
		return streamConfigurationError("the 'delivery' and its 'method' are required")
	case c.EventsDelivered == nil:
		return streamConfigurationError("the 'events_delivered' is required")
	}

	if c.Delivery.Method != oauth2.SSFDeliveryMethodPoll {
		return nil
	}

	// SSF Sections 6.1.2 and 8.1.1.1: the Transmitter supplies the 'endpoint_url' of a poll stream.
	if c.Delivery.EndpointURL == "" {
		return streamConfigurationError("the poll 'endpoint_url' is required")
	}

	if _, err = transmitterLocation(c.Delivery.EndpointURL, nil); err != nil {
		return streamConfigurationError("the poll 'endpoint_url' is not an https url")
	}

	return nil
}

// streamExpectation is what the configuration of a stream must agree with.
type streamExpectation struct {
	// streamID is the stream ID, or empty for a stream being created.
	streamID string

	// audience is the acceptable 'aud' values, or empty when any is.
	audience []string

	// exactAudience requires the 'aud' to have every value of the audience too, as the 'aud' of a stream cannot be
	// updated.
	exactAudience bool

	// delivery is the delivery of the request or the record.
	delivery oauth2.SSFDelivery
}

// agrees checks the configuration is the one of the expected stream.
//
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.1.1.1
func (c *StreamConfiguration) agrees(expected streamExpectation) (err error) {
	switch {
	case expected.streamID != "" && c.StreamID != expected.streamID:
		return streamConfigurationError("the 'stream_id' is not the one of the stream")
	case c.Delivery.Method != streamDeliveryMethod(expected.delivery.Method):
		return streamConfigurationError("the delivery 'method' is not the one of the stream")
	case c.Delivery.Method == oauth2.SSFDeliveryMethodPush && c.Delivery.EndpointURL != expected.delivery.EndpointURL:
		return streamConfigurationError("the push 'endpoint_url' is not the one of the stream")
	}

	if len(expected.audience) == 0 {
		return nil
	}

	// SSF Section 8.1.1.1.1: the 'aud' matches what the Receiver expects.
	if !containsEach(expected.audience, c.Audience) {
		return streamConfigurationError("the 'aud' has a value which is not expected")
	}

	// SSF Section 8.1.1: the 'aud' cannot be updated.
	if expected.exactAudience && !containsEach(c.Audience, expected.audience) {
		return streamConfigurationError("the 'aud' lacks a value of the stream")
	}

	return nil
}

// containsEach reports whether the set has every one of the values.
func containsEach(set, values []string) (ok bool) {
	for _, value := range values {
		if !slices.Contains(set, value) {
			return false
		}
	}

	return true
}

// streamDeliveryMethod returns the delivery method of a record, which is push when empty.
func streamDeliveryMethod(method string) string {
	if method == "" {
		return oauth2.SSFDeliveryMethodPush
	}

	return method
}

// apply sets the Transmitter-Supplied members of the record from the configuration. The audience of a record which
// has one is kept, as the 'aud' cannot be updated.
//
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.1
func (c *StreamConfiguration) apply(record *StreamRecord) {
	record.StreamID = c.StreamID

	if len(record.Audience) == 0 {
		record.Audience = slices.Clone(c.Audience)
	}

	record.EventsSupported = slices.Clone(c.EventsSupported)
	record.EventsDelivered = slices.Clone(c.EventsDelivered)
	record.MinVerificationInterval = c.MinVerificationInterval
	record.InactivityTimeout = c.InactivityTimeout

	if c.Delivery.Method == oauth2.SSFDeliveryMethodPoll {
		record.Delivery = oauth2.SSFDelivery{Method: oauth2.SSFDeliveryMethodPoll, EndpointURL: c.Delivery.EndpointURL}
	}
}

var errNoStore = errors.New("ssfreceiver: the receiver has no store")

// errStreamRecordGone is the error of a stream record which is not found.
var errStreamRecordGone = errors.New("ssfreceiver: the stream record is not found")

func streamConfigurationError(description string) (err error) {
	return fmt.Errorf("%w: %s", ErrStreamConfiguration, description)
}

func streamRequestError(description string) (err error) {
	return fmt.Errorf("%w: %s", ErrStreamRequest, description)
}

// streamConfiguration returns the stream configuration in the body, checked as one of the Transmitter identified by
// issuer.
func (r *transmitterResponse) streamConfiguration(issuer string) (configuration *StreamConfiguration, err error) {
	if err = r.requireJSON(); err != nil {
		return nil, err
	}

	configuration = &StreamConfiguration{}

	if err = configuration.UnmarshalJSON(r.body); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrStreamConfiguration, err)
	}

	if err = configuration.validate(issuer); err != nil {
		return nil, err
	}

	return configuration, nil
}

// requireJSON returns an error matching ErrStreamConfiguration unless the content type is 'application/json'.
func (r *transmitterResponse) requireJSON() (err error) {
	if !isJSONContentType(r.header) {
		return streamConfigurationError("the content type is not '" + consts.MediaTypeApplicationJSON + "'")
	}

	return nil
}

// streamDeliveryRequest is the 'delivery' of a request, which has the Receiver-Supplied members only.
//
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-6.1.1
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-6.1.2
type streamDeliveryRequest struct {
	Method              string `json:"method"`
	EndpointURL         string `json:"endpoint_url,omitempty"`
	AuthorizationHeader string `json:"authorization_header,omitempty"`
}

// streamRequest is the body of a create, update or replace request, which has the 'stream_id' and the
// Receiver-Supplied members only.
//
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.1.1
type streamRequest struct {
	StreamID        string                 `json:"stream_id,omitempty"`
	Delivery        *streamDeliveryRequest `json:"delivery,omitempty"`
	EventsRequested *[]string              `json:"events_requested,omitempty"`
	Description     *string                `json:"description,omitempty"`
}

// streamDelivery returns the delivery to store and the one to send for the delivery the application asked for. The
// endpoint URL and the secret of a poll delivery are dropped, as the Transmitter supplies the first and the second
// is of a push stream.
func streamDelivery(delivery oauth2.SSFDelivery) (stored oauth2.SSFDelivery, sent *streamDeliveryRequest, err error) {
	switch delivery.Method {
	case oauth2.SSFDeliveryMethodPush:
		// RFC 8935 Section 2: the SET is delivered over TLS.
		if _, err = transmitterLocation(delivery.EndpointURL, nil); err != nil {
			return stored, nil, streamRequestError("the push endpoint url is required and must be an https url")
		}

		return delivery, &streamDeliveryRequest{Method: delivery.Method, EndpointURL: delivery.EndpointURL, AuthorizationHeader: delivery.AuthorizationHeader}, nil
	case oauth2.SSFDeliveryMethodPoll:
		return oauth2.SSFDelivery{Method: delivery.Method}, &streamDeliveryRequest{Method: delivery.Method}, nil
	default:
		return stored, nil, streamRequestError("the delivery method must be push or poll")
	}
}

func validateEventsRequested(events []string) (err error) {
	if slices.Contains(events, "") {
		return streamRequestError("an event type requested is empty")
	}

	return nil
}

// CreateStreamRequest is the Receiver-Supplied stream configuration of a stream to create.
//
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.1.1
type CreateStreamRequest struct {
	// Issuer is the issuer of the Transmitter, from a trusted source.
	Issuer string

	// Audience is the 'aud' values this Receiver expects of the stream, as agreed with the Transmitter. When not
	// empty a stream with any other value is refused. When empty any 'aud' is accepted and stored, and every SET of
	// the stream must then have one of its values.
	//
	// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.1.1.1
	Audience []string

	// Delivery is the delivery of the stream, whose Method is oauth2.SSFDeliveryMethodPush or
	// oauth2.SSFDeliveryMethodPoll. A push delivery has the https EndpointURL of this Receiver, which no other
	// record has, and the secret AuthorizationHeader the Transmitter sends with each SET. The EndpointURL and
	// AuthorizationHeader of a poll delivery are not used.
	Delivery oauth2.SSFDelivery

	// EventsRequested is the event types asked for, which should not be empty.
	EventsRequested []string

	// Description is optional.
	Description string
}

// CreateStream creates a stream at the Transmitter and returns its record. A pending record is stored first, so a SET
// the Transmitter delivers before the response is answered rather than refused, then the stream is requested, and the
// record becomes active with the stream ID and the Transmitter-Supplied members of the response. The 'events_requested'
// and the 'description' are stored as this Receiver supplied them.
//
// The response must be a stream configuration whose 'iss' is the issuer, with a 'stream_id', an 'aud' of expected
// values, the 'events_delivered', and the delivery method asked for, with the push endpoint URL of the request or an
// https poll endpoint URL. Any failure once the pending record is stored deletes it. The Transmitter may then have a
// stream this Receiver has no record of, which is so too when the response was lost: ListStreams finds it and
// DeleteStream removes it. A Transmitter which permits one stream answers another request with an error matching
// ErrStreamConflict.
//
// It returns ErrStreamRecordConflict while another stream of the Transmitter is being created, and when a record has
// the push endpoint URL or the stream ID the Transmitter assigned. A process which ends between storing the pending
// record and deleting it leaves the record of the issuer and the empty stream ID, which gives every later request
// that error until the application deletes it from the store.
//
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.1.1
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.1.1.1
func (r *Receiver) CreateStream(ctx context.Context, request CreateStreamRequest) (record *StreamRecord, err error) {
	if r.Store == nil {
		return nil, errNoStore
	}

	body := streamRequest{}
	record = &StreamRecord{Issuer: request.Issuer, State: StreamRecordPending, Description: request.Description}

	if record.Delivery, body.Delivery, err = streamDelivery(request.Delivery); err != nil {
		return nil, err
	}

	if err = validateEventsRequested(request.EventsRequested); err != nil {
		return nil, err
	}

	if slices.Contains(request.Audience, "") {
		return nil, streamRequestError("an expected audience is empty")
	}

	if len(request.EventsRequested) != 0 {
		record.EventsRequested = slices.Clone(request.EventsRequested)
		body.EventsRequested = &record.EventsRequested
	}

	if request.Description != "" {
		body.Description = &request.Description
	}

	var endpoint string

	if endpoint, err = r.configurationEndpoint(ctx, request.Issuer); err != nil {
		return nil, err
	}

	// The transport refuses an empty endpoint too, which here would be after the pending record is stored.
	if endpoint == "" {
		return nil, ErrEndpointNotSupported
	}

	if err = r.Store.CreateSSFReceiverStream(ctx, record); err != nil {
		return nil, fmt.Errorf("ssfreceiver: the pending stream record could not be stored: %w", err)
	}

	if err = r.createStream(ctx, endpoint, record, body, request.Audience); err != nil {
		// The context of a failed request may be done.
		if derr := r.Store.DeleteSSFReceiverStream(context.WithoutCancel(ctx), request.Issuer, ""); derr != nil {
			err = errors.Join(err, fmt.Errorf("ssfreceiver: the pending stream record could not be deleted: %w", derr))
		}

		return nil, err
	}

	return record, nil
}

// createStream requests the stream of the stored pending record and stores the record as active.
func (r *Receiver) createStream(ctx context.Context, endpoint string, record *StreamRecord, body streamRequest, audience []string) (err error) {
	var response *transmitterResponse

	// SSF Section 8.1.1.1: the response is a 201.
	if response, err = r.transmit(ctx, record.Issuer, transmitterRequest{
		method:   http.MethodPost,
		endpoint: endpoint,
		scope:    oauth2.ScopeSSFManage,
		body:     body,
		success:  []int{http.StatusCreated, http.StatusOK},
	}); err != nil {
		return err
	}

	var configuration *StreamConfiguration

	if configuration, err = response.streamConfiguration(record.Issuer); err != nil {
		return err
	}

	if err = configuration.agrees(streamExpectation{audience: audience, delivery: record.Delivery}); err != nil {
		return err
	}

	configuration.apply(record)

	record.State = StreamRecordActive

	// The Transmitter has the stream, so the record is stored though the context may be done.
	if err = r.Store.UpdateSSFReceiverStream(context.WithoutCancel(ctx), record.Issuer, "", record); err != nil {
		return fmt.Errorf("ssfreceiver: the stream record could not be stored: %w", err)
	}

	return nil
}

// ReadStream returns the configuration of the stream as the Transmitter has it, which must have the 'iss' of the
// issuer and the stream ID asked for. When this Receiver has an active record of the stream the configuration must
// agree with its delivery and have the 'aud' values of the record and no other, and the other Transmitter-Supplied
// members of the record are stored from it; the audience, the Receiver-Supplied members, the secret, the status and
// the verification are kept. A record without an audience takes the 'aud'. Without a record nothing is stored.
//
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.1.2
func (r *Receiver) ReadStream(ctx context.Context, issuer, streamID string) (configuration *StreamConfiguration, err error) {
	if streamID == "" {
		return nil, streamRequestError("the stream id is required")
	}

	var response *transmitterResponse

	if response, err = r.readStreams(ctx, issuer, url.Values{streamMemberStreamID: {streamID}}); err != nil {
		return nil, err
	}

	if configuration, err = response.streamConfiguration(issuer); err != nil {
		return nil, err
	}

	if configuration.StreamID != streamID {
		return nil, streamConfigurationError("the 'stream_id' is not the one of the stream")
	}

	if r.Store == nil {
		return configuration, nil
	}

	var record *StreamRecord

	switch record, err = r.Store.GetSSFReceiverStream(ctx, issuer, streamID); {
	case errors.Is(err, oauth2.ErrNotFound):
		return configuration, nil
	case err != nil:
		return nil, fmt.Errorf("ssfreceiver: the stream record could not be read: %w", err)
	case record.State != StreamRecordActive:
		return configuration, nil
	}

	// A record without a delivery method is one of a push stream.
	record.Delivery.Method = streamDeliveryMethod(record.Delivery.Method)

	if err = configuration.agrees(streamExpectation{streamID: streamID, audience: record.Audience, exactAudience: true, delivery: record.Delivery}); err != nil {
		return nil, err
	}

	configuration.apply(record)

	if err = r.Store.UpdateSSFReceiverStream(ctx, issuer, streamID, record); err != nil {
		return nil, fmt.Errorf("ssfreceiver: the stream record could not be stored: %w", err)
	}

	return configuration, nil
}

// ListStreams returns the configuration of every stream the Transmitter has for this Receiver, each of which must
// have the 'iss' of the issuer and a stream ID of its own. Nothing is stored. It finds a stream this Receiver has no
// record of, such as the one a Transmitter which answered CreateStream with an error matching ErrStreamConflict has.
//
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.1.2
func (r *Receiver) ListStreams(ctx context.Context, issuer string) (configurations []*StreamConfiguration, err error) {
	var response *transmitterResponse

	// SSF Section 8.1.1.2: without the 'stream_id' the response is a list.
	if response, err = r.readStreams(ctx, issuer, nil); err != nil {
		return nil, err
	}

	if err = response.requireJSON(); err != nil {
		return nil, err
	}

	var elements []json.RawMessage

	if len(response.body) == 0 || json.Unmarshal(response.body, &elements) != nil || elements == nil {
		return nil, streamConfigurationError("the body is not a JSON array")
	}

	configurations = make([]*StreamConfiguration, len(elements))

	known := make(map[string]struct{}, len(elements))

	for i, element := range elements {
		configuration := &StreamConfiguration{}

		if err = configuration.UnmarshalJSON(element); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrStreamConfiguration, err)
		}

		if err = configuration.validate(issuer); err != nil {
			return nil, err
		}

		if _, ok := known[configuration.StreamID]; ok {
			return nil, streamConfigurationError("the 'stream_id' is repeated")
		}

		known[configuration.StreamID] = struct{}{}
		configurations[i] = configuration
	}

	return configurations, nil
}

func (r *Receiver) readStreams(ctx context.Context, issuer string, query url.Values) (response *transmitterResponse, err error) {
	var endpoint string

	if endpoint, err = r.configurationEndpoint(ctx, issuer); err != nil {
		return nil, err
	}

	return r.transmit(ctx, issuer, transmitterRequest{
		method:   http.MethodGet,
		endpoint: endpoint,
		scope:    oauth2.ScopeSSFRead,
		query:    query,
		success:  []int{http.StatusOK},
	})
}

// configurationEndpoint returns the Configuration Endpoint of the validated Transmitter Configuration Metadata, which
// is empty when the Transmitter has none.
//
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-7.1
func (r *Receiver) configurationEndpoint(ctx context.Context, issuer string) (endpoint string, err error) {
	var configuration *oauth2.SSFConfiguration

	if configuration, err = r.Discover(ctx, issuer); err != nil {
		return "", err
	}

	return configuration.ConfigurationEndpoint, nil
}
