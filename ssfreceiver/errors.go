// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package ssfreceiver

import (
	"errors"
	"strconv"
	"strings"
	"time"
)

var (
	// ErrPushAuthorizerUnavailable is returned by a PushAuthorizer which could not decide whether a push delivery
	// request is authorized, such as one whose token introspection is not available. The request is answered with a
	// 503, so the Transmitter delivers the SET again, where any other error refuses the SET.
	//
	// See: https://www.rfc-editor.org/rfc/rfc8935#section-2
	ErrPushAuthorizerUnavailable = errors.New("ssfreceiver: the push authorizer is not available")

	// ErrStreamRecordConflict is returned by StreamStorage when another record has the issuer and stream ID, or the
	// push endpoint URL, of the record being stored.
	ErrStreamRecordConflict = errors.New("ssfreceiver: a stream record with the issuer and stream id or the push endpoint url already exists")

	// ErrVerificationStateMismatch is returned by StreamStorage when no verification was requested or the 'state' is
	// not the requested one.
	//
	// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.4.1
	ErrVerificationStateMismatch = errors.New("ssfreceiver: the verification state is not the requested one")

	// ErrVerificationInterval is returned by Receiver.RequestStreamVerification, before any request is made, when the
	// 'min_verification_interval' of the stream has not passed since the last request or verification.
	//
	// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.1
	ErrVerificationInterval = errors.New("ssfreceiver: the minimum verification interval of the stream has not passed")

	// ErrIssuerMismatch is returned by Receiver.Discover when the 'issuer' of the Transmitter Configuration Metadata
	// is not the issuer it was requested for, and matches the ErrStreamConfiguration of a stream configuration whose
	// 'iss' is not the issuer of the Transmitter it was requested from.
	//
	// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-7.2.4
	// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.1.1
	ErrIssuerMismatch = errors.New("ssfreceiver: the 'issuer' is not the requested issuer")

	// ErrStreamConfiguration is returned for a stream configuration of a Transmitter which is not valid, or is not
	// the one of the stream it was requested for.
	//
	// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.1
	// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.1.1.1
	ErrStreamConfiguration = errors.New("ssfreceiver: the stream configuration of the transmitter is not valid")

	// ErrStreamStatus is returned for a stream status of a Transmitter which is not valid, or is not the one of the
	// stream it was requested for.
	//
	// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.2.1
	ErrStreamStatus = errors.New("ssfreceiver: the stream status of the transmitter is not valid")

	// ErrPollResponse is returned for a poll response of a Transmitter which is not valid. No SET of it is processed.
	//
	// See: https://www.rfc-editor.org/rfc/rfc8936#section-2.3
	ErrPollResponse = errors.New("ssfreceiver: the poll response of the transmitter is not valid")

	// ErrStreamRequest is returned for a stream management request which is not valid, before any request is made.
	ErrStreamRequest = errors.New("ssfreceiver: the stream request is not valid")

	// ErrSubjectsImplicit is returned by Receiver.AddSubject and Receiver.RemoveSubject, before any request is made,
	// when Config.EnforceCAEPInteroperabilityProfile is set, as every subject is then implicitly in a stream.
	//
	// See: https://openid.net/specs/openid-caep-interoperability-profile-1_0.html#section-2.4.4
	ErrSubjectsImplicit = errors.New("ssfreceiver: the subjects of a stream are implicit under the caep interoperability profile")

	// ErrEndpointNotSupported is returned for a request to an endpoint the Transmitter Configuration Metadata does
	// not have.
	//
	// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-7.1
	ErrEndpointNotSupported = errors.New("ssfreceiver: the transmitter does not have the endpoint")

	// ErrEndpointNotHTTPS is returned for a request to an endpoint which is not an https URL, before any request is
	// made.
	//
	// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-7.1
	ErrEndpointNotHTTPS = errors.New("ssfreceiver: the transmitter endpoint is not an https url")

	// ErrTransmitterUnauthorized matches the *TransmitterError of a 401, which is returned once the Authorizer had
	// the chance to discard the authorization it cached.
	ErrTransmitterUnauthorized = errors.New("ssfreceiver: the transmitter did not accept the authorization")

	// ErrTransmitterForbidden matches the *TransmitterError of a 403.
	ErrTransmitterForbidden = errors.New("ssfreceiver: the transmitter refused the request")

	// ErrStreamNotFound matches the *TransmitterError of a 404.
	ErrStreamNotFound = errors.New("ssfreceiver: the transmitter has no such stream")

	// ErrStreamConflict matches the *TransmitterError of a 409.
	//
	// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.1.1
	ErrStreamConflict = errors.New("ssfreceiver: the transmitter reported a stream conflict")

	// ErrTransmitterThrottled matches the *TransmitterError of a 429, whose RetryAfter is the delay asked for.
	ErrTransmitterThrottled = errors.New("ssfreceiver: the transmitter is throttling requests")

	// ErrStreamUpdatePending matches the *TransmitterError of a 202 to a stream update, replace or status update: the
	// request was accepted, but not processed, so the stream is unchanged for now.
	//
	// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.1.3
	// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.1.4
	// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.2.2
	ErrStreamUpdatePending = errors.New("ssfreceiver: the transmitter accepted the request but has not processed it")

	// ErrTransmitterUnconfirmed matches the error of a request the Transmitter may have processed: one which may
	// have been sent and has no response, or one answered with an expected status code and a body which could not be
	// read. A request whose error neither matches it nor is a *TransmitterError has no response the Transmitter
	// applied it with, and one that failed before it was sent, as for its authorization, does not match it.
	ErrTransmitterUnconfirmed = errors.New("ssfreceiver: the transmitter may have processed the request")

	// ErrStreamChangeApplied is returned by Receiver.UpdateStream, Receiver.ReplaceStream and
	// Receiver.UpdateStreamStatus when the Transmitter answered with a 200, so it applied the change, and the response
	// was then refused or the record could not be stored. It wraps the cause, such as ErrStreamConfiguration or
	// ErrStreamStatus.
	//
	// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.1.3
	// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.1.4
	// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.2.2
	ErrStreamChangeApplied = errors.New("ssfreceiver: the transmitter applied the stream change")

	// ErrSigningKey is returned when the JSON Web Key Set of the Transmitter has no single key acceptable for the
	// 'kid' and 'alg' of a SET, which must be an asymmetric signature key. It is not returned when the metadata or
	// the keys could not be retrieved.
	//
	// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-4.1.4
	ErrSigningKey = errors.New("ssfreceiver: the transmitter has no acceptable signing key")

	// ErrSigningKeyNotRefreshed is returned when the JSON Web Key Set of the Transmitter has no key with the 'kid' of a
	// SET and could not be fetched again, as the jwt.JWKSRefreshStrategy fetched it within its refresh interval. It is
	// not a fault of the SET: a push is answered with a 503 and a polled SET is not acknowledged, so the Transmitter
	// delivers it again, and the set is fetched again once the interval has passed.
	//
	// See: https://openid.net/specs/openid-connect-core-1_0.html#RotateSigKeys
	// See: https://www.rfc-editor.org/rfc/rfc8935#section-2
	ErrSigningKeyNotRefreshed = errors.New("ssfreceiver: the signing keys of the transmitter could not be fetched again yet")

	// ErrIssuedAtAhead is returned when the 'iat' of a SET is ahead of the clock of the Receiver by more than
	// Config.ClockSkew and by no more than IssuedAtRedeliveryWindow more, and the SET has no other fault. No
	// specification makes such a SET invalid, and the difference of the clocks is recoverable, so it is not a fault of
	// the SET: a push is answered with a 503 and a polled SET is not acknowledged, so the Transmitter delivers it
	// again.
	//
	// See: https://www.rfc-editor.org/rfc/rfc8935#section-2
	// See: https://www.rfc-editor.org/rfc/rfc8936#section-2.3
	// See: https://www.rfc-editor.org/rfc/rfc8417#section-5.3
	ErrIssuedAtAhead = errors.New("ssfreceiver: the security event token was issued ahead of the clock of the receiver")

	// ErrSubjectUnknown is returned by a SubjectResolver for a subject which identifies no principal of the
	// application. The SET is acknowledged, and the Transmitter is never told.
	//
	// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-9.3
	ErrSubjectUnknown = errors.New("ssfreceiver: the subject identifies no principal")

	// ErrRelayEventNotSanitizable is returned by SanitizeRelayEvent for an event of a type it has no rule for, which
	// includes a jwt.RawSecurityEvent and the CAEP token claims change event.
	ErrRelayEventNotSanitizable = errors.New("ssfreceiver: the event type has no relay sanitizing rule")

	// ErrRelayPolicyEvent is returned when a RelayPolicy relays an event and returns no event, or returns a
	// verification or stream updated event.
	//
	// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.4
	ErrRelayPolicyEvent = errors.New("ssfreceiver: the relay policy returned no event or a stream event")

	// ErrRelayStreamEvent is returned for a verification or stream updated event, which is never relayed.
	//
	// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.4
	ErrRelayStreamEvent = errors.New("ssfreceiver: a verification or stream updated event is not relayed")

	// ErrRelayConfiguration is returned by Relay.Prepare for a Relay which can not relay, such as one in the
	// RelayTransactionPerStream mode without a TransactionKey of at least 32 bytes. It is also the RelaySkip reason
	// of a stream the Relay.TransactionModeFor returns an unknown mode for.
	//
	// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-10.1
	ErrRelayConfiguration = errors.New("ssfreceiver: the relay is not configured")

	// ErrRelayEventOrigin is returned for an event to relay without the 'iss' or the 'jti' of the SET it is from,
	// which the 'jti' of each relayed SET is derived from.
	//
	// See: https://www.rfc-editor.org/rfc/rfc8417#section-2.2
	ErrRelayEventOrigin = errors.New("ssfreceiver: the event to relay has no origin issuer or origin jti")

	// ErrRelaySubjectNotCovered is returned by a RelaySubjectMapper for a stream which does not cover the principal
	// of the event, and is the RelaySkip reason of that stream.
	//
	// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.3.1
	ErrRelaySubjectNotCovered = errors.New("ssfreceiver: the stream does not cover the subject")

	// ErrRelayStream is the RelaySkip reason of a candidate stream which is nil, has no stream ID or is listed more
	// than once, and of a RelayIssuer which did not issue the token asked of it.
	ErrRelayStream = errors.New("ssfreceiver: the relay stream is not valid")

	// ErrRelayStreamEventType is the RelaySkip reason of a stream whose EventsDelivered lacks the event type.
	//
	// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.1
	ErrRelayStreamEventType = errors.New("ssfreceiver: the stream is not delivered the event type")

	// ErrRelayStreamDisabled is the RelaySkip reason of a stream whose Status is neither enabled nor paused.
	//
	// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.2.1
	ErrRelayStreamDisabled = errors.New("ssfreceiver: the stream is disabled")

	// ErrRelayStreamExcluded is the RelaySkip reason of a stream of a client in the ExcludeClientIDs of the event.
	ErrRelayStreamExcluded = errors.New("ssfreceiver: the client of the stream is excluded")

	// ErrRelayKnown is returned by RelayStorage when the underlying event was already relayed from another SET.
	//
	// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-4.1.9
	ErrRelayKnown = errors.New("ssfreceiver: the event was already relayed")

	// ErrRelayPrincipal is returned by Relay.Prepare for a relayed event whose Principal has no key, which is one
	// that is not a string that is not empty when the Relay has no PrincipalKey, or one its PrincipalKey returns no
	// key for.
	ErrRelayPrincipal = errors.New("ssfreceiver: the principal of the event to relay has no key")
)

// The 'err' values of a SetError.
//
// See: https://www.rfc-editor.org/rfc/rfc8935#section-2.4
const (
	SetErrorInvalidRequest       = "invalid_request"
	SetErrorInvalidKey           = "invalid_key"
	SetErrorInvalidIssuer        = "invalid_issuer"
	SetErrorInvalidAudience      = "invalid_audience"
	SetErrorAuthenticationFailed = "authentication_failed"
	SetErrorAccessDenied         = "access_denied"
)

// SetErrorInvalidState is the 'err' value of a SetError for a verification event whose 'state' is not the requested
// one.
//
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.4.1
const SetErrorInvalidState = "invalid_state"

// SetError is a SET delivery error reported to the Transmitter.
//
// See: https://www.rfc-editor.org/rfc/rfc8935#section-2.4
type SetError struct {
	// Code is the 'err' value.
	Code string

	// Description is the 'description' value. It must not contain token content.
	Description string
}

// Error implements error.
func (e *SetError) Error() string {
	switch {
	case e == nil:
		return ""
	case e.Description == "":
		return e.Code
	default:
		return e.Code + ": " + e.Description
	}
}

// TransmitterError is a response of a Transmitter to a stream management or poll request with a status code that is
// not the expected one. It matches the error of its status code with [errors.Is], such as ErrStreamNotFound, and never
// has the response body or the authorization of the request.
type TransmitterError struct {
	// Status is the status code of the response.
	Status int

	// RetryAfter is the delay the 'Retry-After' header asks for, at most 5 minutes, and zero without one.
	//
	// See: https://www.rfc-editor.org/rfc/rfc9110.html#section-10.2.3
	RetryAfter time.Duration

	// held is the time from the sending of the request to the response.
	held time.Duration

	sentinel error
}

// Error implements error.
func (e *TransmitterError) Error() string {
	return "ssfreceiver: the transmitter responded with the status code " + strconv.Itoa(e.Status)
}

// Unwrap returns the error of the status code, or nil when it has none.
func (e *TransmitterError) Unwrap() error {
	return e.sentinel
}

// wrapError returns an error with the text followed by the text of the cause without its package prefix, so the
// whole has the prefix once. It matches the cause and each of the sentinels.
func wrapError(text string, cause error, sentinels ...error) error {
	return &wrappedError{text: text + ": " + strings.TrimPrefix(cause.Error(), "ssfreceiver: "), errs: append(sentinels, cause)}
}

type wrappedError struct {
	text string
	errs []error
}

// Error implements error.
func (e *wrappedError) Error() string {
	return e.text
}

// Unwrap returns the sentinels and the cause.
func (e *wrappedError) Unwrap() []error {
	return e.errs
}
