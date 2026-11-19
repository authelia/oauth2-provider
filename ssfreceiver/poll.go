// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package ssfreceiver

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/ssfjson"
)

// DefaultLongPollTimeout bounds a poll request which waits for a SET when Config.LongPollTimeout is not positive.
//
// See: https://www.rfc-editor.org/rfc/rfc8936#section-2.2
const DefaultLongPollTimeout = 5 * time.Minute

// DefaultMaxPollSets is the most SETs of one poll response which are processed when Config.MaxPollSets is not positive.
const DefaultMaxPollSets = 100

// errPollSetName is fixed, and never holds a value of the SET.
//
// See: https://www.rfc-editor.org/rfc/rfc8936#section-2.3
var errPollSetName = &SetError{Code: SetErrorInvalidRequest, Description: "The 'jti' of the SET is not the name of its member in the 'sets'."}

var errPollSetUnnamed = errors.New("ssfreceiver: the name of the SET in the 'sets' of the poll response is empty")

const (
	pollMemberSets          = "sets"
	pollMemberMoreAvailable = "moreAvailable"

	// pollContentLanguage is the language of the description of every SetError.
	pollContentLanguage = "en"
)

// PollRequest is the parameters of a poll request, and encodes as its body: a member without a value is omitted.
//
// See: https://www.rfc-editor.org/rfc/rfc8936#section-2.2
type PollRequest struct {
	// MaxEvents is the 'maxEvents' member, which is omitted when nil. Zero is an acknowledge-only request.
	//
	// See: https://www.rfc-editor.org/rfc/rfc8936#section-2.4.2
	MaxEvents *int `json:"maxEvents,omitempty"`

	// ReturnImmediately is the 'returnImmediately' member. When false the Transmitter waits for a SET, and the request
	// is bounded by Config.LongPollTimeout.
	ReturnImmediately bool `json:"returnImmediately,omitempty"`

	// Ack is the 'jti' of each SET to acknowledge.
	Ack []string `json:"ack,omitempty"`

	// SetErrs is the error of each SET that is refused, by the name of its member in the 'sets' it was received in.
	//
	// See: https://www.rfc-editor.org/rfc/rfc8936#section-2.6
	SetErrs map[string]oauth2.SSFPollSetError `json:"setErrs,omitempty"`
}

// PollResult is the outcome of a poll request and of the SETs of its response.
type PollResult struct {
	// Ack is the 'jti' of each SET of the response which is acknowledged: one that was validated and handled, and one
	// that was received before. It is the Ack of the next PollRequest.
	//
	// See: https://www.rfc-editor.org/rfc/rfc8936#section-2.4
	Ack []string

	// SetErrs is the error of each SET of the response which is refused, by the name of its member in the 'sets'. It
	// is the SetErrs of the next PollRequest.
	//
	// See: https://www.rfc-editor.org/rfc/rfc8936#section-2.4.4
	SetErrs map[string]oauth2.SSFPollSetError

	// MoreAvailable is true when the Transmitter has more SETs, or the response had more than Config.MaxPollSets, or
	// the context was done before every SET was processed.
	MoreAvailable bool

	// Received is the event of each SET the EventHandler accepted, in the order of the response: the copy it was
	// handed, with the Principal. It has no event the handler was not handed, such as one of a SET received before,
	// one outside the EventsDelivered, one that was discarded, one of an unknown subject, or a stream event. An event
	// whose SET could not then be remembered is in it and in Unacknowledged, and is handed again on its redelivery.
	Received []*ReceivedEvent

	// Unacknowledged is the failure, by the name of the member in the 'sets', of each SET that is neither acknowledged
	// nor reported as it is not a fault of the SET, such as an error of the EventHandler or of the storage. It is for
	// the caller to log, and the Transmitter delivers these SETs again.
	//
	// See: https://www.rfc-editor.org/rfc/rfc8936#section-2
	Unacknowledged map[string]error
}

// Poll makes one poll request for the poll stream which has an active record, read from the store before the request
// and again after the response, and validates and handles each SET of the response as HandlePush does one SET. The Ack and SetErrs of the result are
// those of the next request, and the caller sends the same ones again after an error.
//
// A SET that is handled or was received before is acknowledged. One that is not valid, whose 'jti' is not the name of
// its member in the 'sets', or which the handler returned a *SetError for, is reported. Any other failure is in the
// Unacknowledged of the result, and the caller backs off after a result with those and no Ack, as the Transmitter
// may deliver the same SETs again. At most Config.MaxPollSets of the SETs are processed, in the order of the
// response. Only the MaxEvents of the request limits what the Transmitter sends, and a response larger than
// Config.MaxResponseBytes fails every poll until it is set.
//
// See: https://www.rfc-editor.org/rfc/rfc8936#section-2
// See: https://www.rfc-editor.org/rfc/rfc8936#section-2.4
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-6.1.2
func (r *Receiver) Poll(ctx context.Context, issuer, streamID string, request PollRequest) (result *PollResult, err error) {
	var record *StreamRecord

	if record, err = r.activeStream(ctx, issuer, streamID); err != nil {
		return nil, err
	}

	var response *pollResponse

	if response, err = r.requestPoll(ctx, record, request); err != nil {
		return nil, err
	}

	result = &PollResult{MoreAvailable: response.moreAvailable}

	sets := response.sets

	if limit := r.maxPollSets(); len(sets) > limit {
		sets, result.MoreAvailable = sets[:limit], true
	}

	// The record may have changed while the request was held, such as its EventsDelivered. The SETs are delivered
	// again when it can not be read, and the Ack and SetErrs that were sent are confirmed.
	if len(sets) != 0 {
		if record, err = r.activeStream(ctx, issuer, streamID); err != nil {
			for _, set := range sets {
				result.unacknowledged(set.name, err)
			}

			return result, nil
		}
	}

	for _, set := range sets {
		// The SETs which are left are delivered again.
		if ctx.Err() != nil {
			result.MoreAvailable = true

			break
		}

		r.receivePolled(ctx, record, set, result)
	}

	return result, nil
}

// receivePolled validates and handles one SET of a poll response, and adds the outcome to the result.
//
// See: https://www.rfc-editor.org/rfc/rfc8936#section-2
// See: https://www.rfc-editor.org/rfc/rfc8936#section-2.4
func (r *Receiver) receivePolled(ctx context.Context, record *StreamRecord, set polledSet, result *PollResult) {
	// A SET without a name can be neither acknowledged nor reported.
	if set.name == "" {
		result.unacknowledged(set.name, errPollSetUnnamed)

		return
	}

	var (
		event, handed *ReceivedEvent
		serr          *SetError
		err           error
	)

	if event, serr, err = r.validate(ctx, record, set.token); err == nil && serr == nil {
		// RFC 8936 Section 2.3: the name of the member is the 'jti' of the SET.
		if event.Claims.JTI != set.name {
			serr = errPollSetName
		} else {
			handed, serr, err = r.accept(ctx, event)
		}
	}

	switch {
	case err != nil:
		// RFC 8936 Section 2: only an error of the parsing or the validation of a SET is reported.
		result.unacknowledged(set.name, err)

		if handed != nil {
			result.Received = append(result.Received, handed)
		}
	case serr != nil:
		if result.SetErrs == nil {
			result.SetErrs = map[string]oauth2.SSFPollSetError{}
		}

		result.SetErrs[set.name] = oauth2.SSFPollSetError{Err: serr.Code, Description: serr.Description}
	default:
		// RFC 8936 Section 2.4: a repeat SET is acknowledged.
		result.Ack = append(result.Ack, set.name)

		if handed != nil {
			result.Received = append(result.Received, handed)
		}
	}
}

func (p *PollResult) unacknowledged(name string, err error) {
	if p.Unacknowledged == nil {
		p.Unacknowledged = map[string]error{}
	}

	p.Unacknowledged[name] = err
}

// polledSet is a member of the 'sets' of a poll response.
type polledSet struct {
	// name is the member name, which is the 'jti' of the SET as the Transmitter has it.
	name string

	token string
}

// pollResponse is a poll response, with its SETs in the order of the response.
//
// See: https://www.rfc-editor.org/rfc/rfc8936#section-2.3
type pollResponse struct {
	sets          []polledSet
	moreAvailable bool
}

// requestPoll makes one poll request to the poll endpoint of the record, which is an active one and has the endpoint
// the Transmitter supplied in the stream configuration, and returns the response without validating a SET. The
// request is authorized for the 'ssf.manage' scope, as it acknowledges SETs and so is not a read. It is never sent
// again: the Transmitter delivers a SET again when the response which had it was lost.
//
// See: https://www.rfc-editor.org/rfc/rfc8936#section-2.2
// See: https://www.rfc-editor.org/rfc/rfc8936#section-2.3
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-6.1.2
// See: https://openid.net/specs/openid-caep-interoperability-profile-1_0.html#section-2.7.3
func (r *Receiver) requestPoll(ctx context.Context, record *StreamRecord, request PollRequest) (response *pollResponse, err error) {
	switch {
	case record == nil:
		return nil, streamRequestError("the stream record is required")
	case record.Delivery.Method != oauth2.SSFDeliveryMethodPoll:
		return nil, streamRequestError("the stream is not delivered with the poll method")
	}

	if err = request.validate(); err != nil {
		return nil, err
	}

	outbound := transmitterRequest{
		method:   http.MethodPost,
		endpoint: record.Delivery.EndpointURL,
		scope:    oauth2.ScopeSSFManage,
		body:     request,
		success:  []int{http.StatusOK},
	}

	// RFC 8936 Section 2.6: the language of the descriptions is sent with them.
	if len(request.SetErrs) != 0 {
		outbound.header = http.Header{"Content-Language": {pollContentLanguage}}
	}

	// RFC 8936 Section 2.2: the request is a long poll unless 'returnImmediately' is true.
	if !request.ReturnImmediately {
		outbound.timeout = r.longPollTimeout()
	}

	var answer *transmitterResponse

	if answer, err = r.transmit(ctx, record.Issuer, outbound); err != nil {
		return nil, err
	}

	return answer.poll()
}

// validate returns an error for parameters which are not those of a poll request.
//
// See: https://www.rfc-editor.org/rfc/rfc8936#section-2.2
func (p PollRequest) validate() (err error) {
	if p.MaxEvents != nil && *p.MaxEvents < 0 {
		return streamRequestError("the 'maxEvents' is negative")
	}

	for _, jti := range p.Ack {
		if jti == "" {
			return streamRequestError("the 'ack' has an empty value")
		}
	}

	for jti, serr := range p.SetErrs {
		if jti == "" || serr.Err == "" {
			return streamRequestError("the 'setErrs' has a member without a name or an 'err'")
		}
	}

	return nil
}

// poll returns the poll response in the body. The 'sets' is an object of strings, the 'moreAvailable' is a boolean
// which is false when absent, and a member that is not understood is ignored.
//
// See: https://www.rfc-editor.org/rfc/rfc8936#section-2.3
func (r *transmitterResponse) poll() (response *pollResponse, err error) {
	if !isJSONContentType(r.header) {
		return nil, pollResponseError("the content type is not '" + consts.MediaTypeApplicationJSON + "'")
	}

	members, err := ssfjson.ParseObject(r.body)
	if err != nil {
		return nil, fmt.Errorf("%w: the body is not a JSON object: %w", ErrPollResponse, err)
	}

	response = &pollResponse{}

	// RFC 8936 Section 2.3: the 'sets' is an empty object when there is no SET.
	value, present := ssfjson.Member(members, pollMemberSets)
	if !present {
		return nil, pollResponseError("the 'sets' is absent")
	}

	names, sets, err := ssfjson.ParseOrderedObject(value)
	if err != nil {
		return nil, fmt.Errorf("%w: the 'sets' is not a JSON object: %w", ErrPollResponse, err)
	}

	response.sets = make([]polledSet, len(names))

	for i, name := range names {
		token, ok := ssfjson.ParseString(sets[name])
		if !ok {
			return nil, pollResponseError("the 'sets' has a member which is not a string")
		}

		response.sets[i] = polledSet{name: name, token: token}
	}

	if value, present = ssfjson.Member(members, pollMemberMoreAvailable); present {
		switch string(value) {
		case "true":
			response.moreAvailable = true
		case "false":
		default:
			return nil, pollResponseError("the 'moreAvailable' is not a boolean")
		}
	}

	return response, nil
}

func (r *Receiver) longPollTimeout() (timeout time.Duration) {
	if r.Config.LongPollTimeout > 0 {
		return r.Config.LongPollTimeout
	}

	return DefaultLongPollTimeout
}

func (r *Receiver) maxPollSets() (limit int) {
	if r.Config.MaxPollSets > 0 {
		return r.Config.MaxPollSets
	}

	return DefaultMaxPollSets
}

func pollResponseError(description string) (err error) {
	return fmt.Errorf("%w: %s", ErrPollResponse, description)
}
