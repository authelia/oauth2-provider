// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package ssfreceiver

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/hashicorp/go-retryablehttp"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/token/jwt"
)

const (
	// StreamRecordPending is the StreamRecord State of a record stored before the Transmitter created the stream, so
	// its StreamID may not be known yet.
	StreamRecordPending = "pending"

	// StreamRecordActive is the StreamRecord State of a record of a stream the Transmitter created.
	StreamRecordActive = "active"
)

// Receiver is a Shared Signals Framework Receiver.
type Receiver struct {
	Config Config
	Store  Storage

	metadata metadataCache

	clientOnce sync.Once
	client     *retryablehttp.Client

	fetcherOnce sync.Once
	fetcher     jwt.JWKSFetcherStrategy
}

// Config is the configuration of a Receiver.
type Config struct {
	// Strategy decrypts an encrypted SET with the keys of the authorization server and verifies the signature with
	// the key of the Transmitter.
	Strategy jwt.Strategy

	// JWKSFetcher fetches the JSON Web Key Set of a Transmitter. The default is used when nil, which fetches with
	// HTTPClient. One that is not an *oauth2.DefaultJWKSFetcherStrategy must apply the special-use address guard
	// itself, and must limit the forced refreshes itself: a SET with an unknown 'kid' forces one, so whoever is
	// authorized to push could otherwise cause a fetch of the key set with each request.
	JWKSFetcher jwt.JWKSFetcherStrategy

	// HTTPClient makes the requests to a Transmitter. The default is used when nil.
	HTTPClient *retryablehttp.Client

	// SpecialUseAddressGuard is optional and configures the special-use address guard of every request to a
	// Transmitter, the fetch of its JSON Web Key Set included. When nil the guard applies and permits no network.
	//
	// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-rfc8725bis-10#section-3.10
	SpecialUseAddressGuard oauth2.SpecialUseAddressGuardProvider

	// Authorizer authorizes the stream management and poll requests, and is required for them: a Transmitter which
	// needs no authorization takes an Authorizer which adds none. The timeout of a request covers the authorization
	// and, after a 401, the second authorization and attempt.
	Authorizer Authorizer

	// PushAuthorizer authorizes a push delivery request. When nil the Authorization header is compared with the
	// secret of the record and with its pending secret.
	PushAuthorizer PushAuthorizer

	// Handler receives every validated event of a type in the EventsDelivered of the record, other than the
	// verification and stream updated events.
	Handler EventHandler

	// StreamHandler is optional and receives the verification and stream updated events, which the Receiver handles
	// itself and accepts whatever the EventsDelivered of the record.
	StreamHandler StreamEventHandler

	// Subjects is optional and resolves the subject of an event to a principal of the application. An event whose
	// subject it does not know is not handed to Handler.
	Subjects SubjectResolver

	// SigningAlgs is the allowed SET signing algorithms. The default is RS256, PS256, ES256, their 384 and 512 forms,
	// and EdDSA. The 'none' and HMAC algorithms are never allowed.
	SigningAlgs []string

	// ClockSkew is how far in the future the 'iat' claim may be. DefaultClockSkew is used when zero, and a negative
	// value permits none. It is not capped, unlike the 60 seconds of the clock skew of the authorization server, and
	// a larger value only widens how far ahead of the clock of the Receiver a Transmitter may date a SET.
	ClockSkew time.Duration

	// MetadataTTL is how long Transmitter Configuration Metadata is cached.
	MetadataTTL time.Duration

	// TokenRetention is how long the 'jti' of a received SET is remembered. DefaultTokenRetention is used when it is
	// not positive.
	TokenRetention time.Duration

	// MaxTokenAge is the oldest 'iat' accepted, so a SET is refused once its 'jti' may be forgotten. TokenRetention is
	// used when zero. A negative value disables the check, which permits the replay of a SET that was forgotten.
	MaxTokenAge time.Duration

	// MaxRequestBytes limits the body of a push delivery request.
	MaxRequestBytes int64

	// MaxResponseBytes limits the body of a Transmitter response.
	MaxResponseBytes int64

	// LongPollTimeout bounds a poll request which waits for a SET, and must be longer than the Transmitter holds one.
	// DefaultLongPollTimeout is used when it is not positive. A poll request which returns immediately is bounded as
	// any other request is. A Config.HTTPClient whose http.Client has a shorter Timeout ends the long poll at that,
	// which is an error and not the end of a long poll, so a Poller backs off after each one of a quiet stream: its
	// Timeout is zero or longer than this.
	//
	// See: https://www.rfc-editor.org/rfc/rfc8936#section-2.2
	LongPollTimeout time.Duration

	// MaxPollSets is the most SETs of one poll response which are processed. DefaultMaxPollSets is used when it is
	// not positive. The SETs after them are neither acknowledged nor reported, so the Transmitter delivers them again.
	// When each of the first ones keeps failing in the EventHandler the same ones may be delivered first again, so the
	// caller backs off after a PollResult with Unacknowledged entries and no Ack.
	//
	// See: https://www.rfc-editor.org/rfc/rfc8936#section-2.3
	MaxPollSets int

	// ProcessedSubjectMembers is the Complex Subject member names the application handles. The default is user,
	// device, session, application, tenant, org_unit and group. An event is discarded when its subject has a member
	// the 'critical_subject_members' of the Transmitter names and this does not.
	//
	// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-3.3
	// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-3.6
	ProcessedSubjectMembers []string

	// EnforceCAEPInteroperabilityProfile applies the CAEP Interoperability Profile 1.0 requirements: the Transmitter
	// Configuration Metadata has the members of Section 2.3.1 to 2.3.7, and a SET is signed using RS256 with an RSA
	// key of at least 2048 bits, Config.SigningAlgs being ignored. An encrypted SET is accepted when the JWS it
	// nests is signed so. Every subject is implicitly in a stream, so Receiver.AddSubject and Receiver.RemoveSubject
	// return ErrSubjectsImplicit without making a request.
	//
	// See: https://openid.net/specs/openid-caep-interoperability-profile-1_0.html#section-2.3
	// See: https://openid.net/specs/openid-caep-interoperability-profile-1_0.html#section-2.4.4
	// See: https://openid.net/specs/openid-caep-interoperability-profile-1_0.html#section-2.6
	EnforceCAEPInteroperabilityProfile bool
}

// Authorizer authorizes a request to a Transmitter.
type Authorizer interface {
	// AuthorizeRequest adds the authorization for the scope to the request to the Transmitter identified by issuer.
	AuthorizeRequest(ctx context.Context, issuer, scope string, r *http.Request) (err error)
}

// PushAuthorizer authorizes a push delivery request.
//
// See: https://www.rfc-editor.org/rfc/rfc8935#section-3
type PushAuthorizer interface {
	// AuthorizePush returns an error when the request is not authorized to deliver on the stream of the record,
	// which is answered with an 'authentication_failed' error. An error matching ErrPushAuthorizerUnavailable means
	// it could not decide, and is answered with a 503 so the Transmitter delivers the SET again. It must not read
	// the request body. One which compares the secret of the record accepts its PendingAuthorizationHeader too.
	//
	// See: https://www.rfc-editor.org/rfc/rfc8935#section-2.4
	AuthorizePush(ctx context.Context, record *StreamRecord, r *http.Request) (err error)
}

// EventHandler receives the validated events of a stream.
type EventHandler interface {
	// HandleSecurityEvent persists or enqueues the event. A nil error acknowledges the SET, a *SetError with a Code
	// is reported to the Transmitter, and any other error means the event was not persisted, so the Transmitter
	// delivers the SET again.
	//
	// It must be idempotent on the issuer and the 'jti'. The SET is remembered only after it returns, so a failure
	// between the two, or a concurrent delivery of the same SET, calls it again for the same SET.
	//
	// See: https://www.rfc-editor.org/rfc/rfc8935#section-2
	HandleSecurityEvent(ctx context.Context, event *ReceivedEvent) (err error)
}

// StreamEventHandler receives the verification and stream updated events of a stream.
type StreamEventHandler interface {
	// HandleStreamEvent is called with the Stream of the event a copy of the record as updated from the event. The
	// errors are those of EventHandler, and it must be idempotent in the same way. The record is stored before it
	// is called, except that the requested verification is consumed only after it returns no error for a
	// verification event with the requested 'state', so the stream still verifies when the SET is delivered again
	// after an error. It is not called for a verification event with a 'state' when no verification is requested,
	// which is acknowledged without changing the record.
	//
	// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.4
	// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.5
	HandleStreamEvent(ctx context.Context, event *ReceivedEvent) (err error)
}

// SubjectResolver resolves the subject of an event.
type SubjectResolver interface {
	// ResolveSubject returns the principal the subject identifies to the application, or ErrSubjectUnknown when it
	// identifies none, which acknowledges the SET without handing the event to the EventHandler. Any other error
	// means the subject could not be resolved, so the Transmitter delivers the SET again, and is never reported to
	// the Transmitter. The record is a copy without the secrets.
	//
	// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-9.3
	ResolveSubject(ctx context.Context, record *StreamRecord, subject *jwt.SubjectIdentifier) (principal any, err error)
}

// StreamRecord is what a Receiver knows about a stream of a Transmitter. It is identified by Issuer and StreamID.
//
// Delivery.AuthorizationHeader and PendingAuthorizationHeader are secrets. Implementations of StreamStorage must
// protect them at rest and must never log them or include them in an error. The JSON encoding of a StreamRecord omits
// the secrets, so it is not a persistence encoding.
type StreamRecord struct {
	// Issuer is the issuer of the Transmitter, and the 'iss' of every SET received on the stream.
	Issuer string

	// StreamID is the Transmitter-assigned stream identifier. It may be empty while State is StreamRecordPending.
	StreamID string

	// Audience is the 'aud' of the stream configuration.
	Audience []string

	// Delivery is the endpoint of this Receiver and the secret it issued for a push stream, and the endpoint of the
	// Transmitter for a poll stream.
	Delivery oauth2.SSFDelivery

	// PendingAuthorizationHeader is the secret of a push stream this Receiver asked the Transmitter to change to,
	// while the Transmitter may send it or the Delivery.AuthorizationHeader. It is empty when no change is pending.
	// It is a secret as Delivery.AuthorizationHeader is.
	PendingAuthorizationHeader string `json:"-"`

	// EventsRequested and Description are the Receiver-Supplied 'events_requested' and 'description' as this
	// Receiver last supplied them.
	//
	// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.1
	EventsRequested []string
	Description     string

	// EventsSupported is the 'events_supported' of the stream configuration, which a Transmitter may omit.
	EventsSupported []string

	// EventsDelivered is the event types of the stream. An event of any other type is acknowledged and not handed to
	// the EventHandler, so a record without any hands it no event. The verification and stream updated events are
	// handled whatever it is.
	//
	// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.1
	EventsDelivered []string

	// Status is one of the oauth2.SSFStreamStatus constants.
	Status       string
	StatusReason string

	// State is StreamRecordPending or StreamRecordActive.
	State string

	// VerificationState is the 'state' of the requested verification. A verification is requested, and an empty
	// VerificationState expected, when VerificationRequestedAt is not zero.
	VerificationState       string
	VerificationRequestedAt time.Time

	// VerifiedAt is the time of the last verification event.
	VerifiedAt time.Time

	MinVerificationInterval int
	InactivityTimeout       int
}

// Format implements [fmt.Formatter], redacting the secrets for every verb.
func (r StreamRecord) Format(f fmt.State, verb rune) {
	type streamRecord StreamRecord

	record := streamRecord(r)

	if record.PendingAuthorizationHeader != "" {
		record.PendingAuthorizationHeader = "[redacted]"
	}

	_, _ = fmt.Fprintf(f, fmt.FormatString(f, verb), record)
}

// Clone returns a deep copy of the record.
func (r *StreamRecord) Clone() (clone *StreamRecord) {
	if r == nil {
		return nil
	}

	c := *r

	c.Audience = slices.Clone(r.Audience)
	c.EventsRequested = slices.Clone(r.EventsRequested)
	c.EventsSupported = slices.Clone(r.EventsSupported)
	c.EventsDelivered = slices.Clone(r.EventsDelivered)

	return &c
}

// ReceivedEvent is a validated event of a SET received on a stream.
type ReceivedEvent struct {
	// Stream is a copy of the record of the stream, without the Delivery.AuthorizationHeader and the
	// PendingAuthorizationHeader.
	Stream *StreamRecord

	Claims *jwt.SecurityEventTokenClaims

	// Type is the event type URI.
	Type string

	// Event is the typed event when the type is registered, else a jwt.RawSecurityEvent.
	Event jwt.SecurityEvent

	// Payload is the event object as received, unknown members included.
	Payload map[string]any

	// Principal is the SubjectResolver result, nil without a resolver.
	Principal any

	// Token is the signed SET, after decryption.
	Token string

	// Encrypted is true when the SET was received encrypted.
	Encrypted bool
}
