// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package ssfreceiver

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"slices"
	"time"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/token/jwt"
)

// RelayTransactionMode is how the 'txn' of a relayed SET is derived.
type RelayTransactionMode int

const (
	// RelayTransactionPerStream gives each stream its own 'txn', a keyed digest of the 'txn' of the event and the
	// stream ID, and a keyed 'jti', so two Receivers can not correlate their subjects. It is the default and requires
	// the Relay.TransactionKey.
	//
	// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-10.1
	RelayTransactionPerStream RelayTransactionMode = iota

	// RelayTransactionPropagate carries the 'txn' of the event unchanged to the stream, which lets the Receivers
	// correlate the SETs of the event, and their subjects. The 'jti' is a digest without a key.
	//
	// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-4.1.9
	RelayTransactionPropagate
)

// DefaultRelayMarkerRetention is how long a relayed event is remembered when Relay.MarkerRetention is not positive.
const DefaultRelayMarkerRetention = 30 * 24 * time.Hour

// relayTransactionKeyBytes is the minimum length of the Relay.TransactionKey, the output length of HMAC-SHA-256.
//
// See: https://www.rfc-editor.org/rfc/rfc2104#section-3
const relayTransactionKeyBytes = sha256.Size

// relayIdentifierJTI is the first part of the keyed digest of a 'jti', which no keyed digest of a 'txn' has.
const relayIdentifierJTI = "jti"

// RelayIssuer issues the relayed SET of a stream. An oauth2.Provider is one.
type RelayIssuer interface {
	// GenerateSecurityEventToken returns a SET with the 'iss' and the 'aud' of the stream, signed with the key of
	// the issuer and encrypted for a client configured for it.
	GenerateSecurityEventToken(ctx context.Context, stream *oauth2.SSFStream, subject *jwt.SubjectIdentifier, event jwt.SecurityEvent, jti, txn string) (token, usedJTI string, err error)
}

// RelayStreamSource returns the streams an event may be relayed to.
type RelayStreamSource interface {
	// RelayStreams returns the candidate streams for the event type, of every client. The Relay selects those
	// whose EventsDelivered has the type and whose Status is enabled or paused.
	//
	// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.1
	RelayStreams(ctx context.Context, eventType string) (streams []*oauth2.SSFStream, err error)
}

// RelaySubjectMapper returns the subject of an event for a stream.
type RelaySubjectMapper interface {
	// MapRelaySubject returns the subject which identifies the Principal of the event to the Receiver of the
	// stream, or ErrRelaySubjectNotCovered when the stream does not cover the principal, which skips the stream. The
	// stream is a copy. The event is a copy which shares its Event and its Principal with the one being prepared, so
	// neither is to be changed.
	//
	// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.3.1
	// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-10.1
	MapRelaySubject(ctx context.Context, stream *oauth2.SSFStream, event *RelayEvent) (subject *jwt.SubjectIdentifier, err error)
}

// RelayToken is a SET issued for a stream. It is not delivered by the Relay.
type RelayToken struct {
	// Stream is a copy of the stream the token is for.
	Stream *oauth2.SSFStream

	// Token is the SET, and JTI its 'jti'.
	Token, JTI string

	// EventType is the event type URI of the SET.
	EventType string

	// Held is true when the stream is paused, so the token is held and not delivered until it is enabled.
	//
	// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.2.1
	Held bool
}

// RelaySkip is a candidate stream no SET was issued for.
type RelaySkip struct {
	// Stream is a copy of the stream, nil when the RelayStreamSource returned a nil stream.
	Stream *oauth2.SSFStream

	// Reason is ErrRelayStream, ErrRelayStreamExcluded, ErrRelayStreamEventType, ErrRelayStreamDisabled,
	// ErrRelaySubjectNotCovered, or the error of the RelaySubjectMapper, the RelayStorage or the RelayIssuer.
	Reason error
}

// Relay issues the SETs which relay an event to the streams of the authorization server. A received SET is never
// forwarded: each stream gets a new SET of the issuer with its own 'jti', subject and 'txn'.
//
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-10.1
type Relay struct {
	// Provider issues the SETs.
	Provider RelayIssuer

	// Streams returns the candidate streams.
	Streams RelayStreamSource

	// Subjects maps the principal of an event to the subject of a stream.
	Subjects RelaySubjectMapper

	// Policy decides what is relayed. Nothing is relayed when nil.
	Policy RelayPolicy

	// Store remembers what was relayed.
	Store RelayStorage

	// ReasonAdmin is optional and is the 'reason_admin' the Policy is given to replace the one of the event.
	//
	// See: https://openid.net/specs/openid-caep-interoperability-profile-1_0.html#section-3.1
	ReasonAdmin map[string]string

	// TransactionMode is how the 'txn' of a relayed SET is derived. The zero value is RelayTransactionPerStream.
	TransactionMode RelayTransactionMode

	// TransactionModeFor is optional and returns the mode of a stream in place of the TransactionMode, such as
	// RelayTransactionPerStream for a client with pairwise subjects. The stream is a copy. A stream it returns an
	// unknown mode for is skipped. It requires the TransactionKey.
	//
	// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-10.1
	TransactionModeFor func(stream *oauth2.SSFStream) (mode RelayTransactionMode)

	// TransactionKey is the secret key of the RelayTransactionPerStream mode, of at least 32 bytes. A change of key
	// changes the 'txn' and the 'jti' of every stream in that mode.
	TransactionKey []byte

	// MarkerRetention is how long a relayed event is remembered. DefaultRelayMarkerRetention is used when it is not
	// positive. An event that returns after it is relayed again.
	MarkerRetention time.Duration

	// PrincipalKey is optional and returns the key which identifies the Principal of an event in the Store. Without
	// it the Principal must be a string, which is the key.
	PrincipalKey func(principal any) (key string)

	// Clock is optional and returns the time. It must be the clock of the Store.
	Clock func() time.Time
}

// NewRelayEvent returns the RelayEvent of a received event, without any ExcludeClientIDs. It returns an
// ErrRelayStreamEvent error for a verification or stream updated event, and an ErrRelayEventOrigin error for an event
// without the claims, the 'iss' or the 'jti' of its SET.
//
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.4
func NewRelayEvent(received *ReceivedEvent) (event *RelayEvent, err error) {
	if received == nil || received.Claims == nil || relayEventValue(received.Event) == nil {
		return nil, fmt.Errorf("%w: the received event has no claims or no event", ErrRelayEventOrigin)
	}

	if isStreamEvent(received.Type) || isStreamEvent(received.Event.SecurityEventType()) {
		return nil, ErrRelayStreamEvent
	}

	if received.Claims.Issuer == "" || received.Claims.JTI == "" {
		return nil, ErrRelayEventOrigin
	}

	return &RelayEvent{
		Event:        received.Event,
		Transaction:  received.Claims.Transaction,
		Principal:    received.Principal,
		OriginIssuer: received.Claims.Issuer,
		OriginJTI:    received.Claims.JTI,
	}, nil
}

// Prepare returns a SET for each stream the event is relayed to, and the candidate streams it was not issued for with
// the reason. It delivers nothing: the application queues the tokens as it does those of its own events. Nothing is
// returned for an event the Policy does not relay.
//
// The 'jti' of a stream is derived from the OriginIssuer and OriginJTI of the event and the stream ID, so it is the
// same whenever the event is prepared. The 'txn' is the Transaction of the event, or is derived from the OriginIssuer
// and OriginJTI when it has none. With RelayTransactionPerStream the 'txn' is the keyed digest of that value and the
// stream ID and the 'jti' is a keyed digest too, so neither can be computed for another stream.
//
// An underlying event is relayed from one SET: the 'txn', the event type and the principal are marked in the Store
// with the OriginIssuer and OriginJTI before any SET is issued, and nothing is returned for an event which is marked
// with another origin, which is one that returns from another party or arrives on a second stream. With
// RelayTransactionPerStream the 'txn' of each stream is marked too, as that is the value which returns from its
// Receiver. The guard relies on every party preserving the 'txn', and the ExcludeClientIDs of the event name the
// clients it is never relayed to. An application prepares the events it originates as well, so one that returns is
// recognized. An event with the same origin is issued again with the same 'jti' and 'txn' for every stream, so an
// application which could not queue the tokens prepares the event again.
//
// It returns an ErrRelayStreamEvent error for a verification or stream updated event, an ErrRelayConfiguration error
// for a Relay which can not relay, and for a relayed event an ErrRelayEventOrigin error without an OriginIssuer or
// OriginJTI and an ErrRelayPrincipal error without a key for its Principal.
//
// See: https://www.rfc-editor.org/rfc/rfc8417#section-2.2
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-4.1.9
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.4
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-10.1
func (r *Relay) Prepare(ctx context.Context, event *RelayEvent) (tokens []RelayToken, skipped []RelaySkip, err error) {
	// SSF Section 8.1.4: a verification or stream updated event is of the stream it was received on.
	if event != nil {
		if e := relayEventValue(event.Event); e != nil && isStreamEvent(e.SecurityEventType()) {
			return nil, nil, ErrRelayStreamEvent
		}
	}

	if err = r.validate(); err != nil {
		return nil, nil, err
	}

	var (
		out   jwt.SecurityEvent
		relay bool
	)

	if out, relay, err = r.Policy.decide(ctx, event, r.ReasonAdmin); err != nil || !relay {
		return nil, nil, err
	}

	if event.OriginIssuer == "" || event.OriginJTI == "" {
		return nil, nil, ErrRelayEventOrigin
	}

	p := &relayPrepared{
		event:     event,
		out:       out,
		eventType: out.SecurityEventType(),
		txn:       relayTransaction(event),
		origin:    relayDigest(sha256.New(), event.OriginIssuer, event.OriginJTI),
	}

	if p.principalKey, err = r.principalKey(event.Principal); err != nil {
		return nil, nil, err
	}

	var streams []*oauth2.SSFStream

	// The streams are listed before the event is marked, so an event is not marked when they can not be.
	if streams, err = r.Streams.RelayStreams(ctx, p.eventType); err != nil {
		return nil, nil, fmt.Errorf("ssfreceiver: the relay streams could not be listed: %w", err)
	}

	p.expiry = r.markerExpiry()

	var known bool

	if known, err = r.markEvent(ctx, p); err != nil || known {
		return nil, nil, err
	}

	p.seen = make(map[string]struct{}, len(streams))

	for _, stream := range streams {
		var token *RelayToken

		if token, err = r.prepare(ctx, p, stream); err != nil {
			skipped = append(skipped, RelaySkip{Stream: stream.Clone(), Reason: err})

			continue
		}

		tokens = append(tokens, *token)
	}

	return tokens, skipped, nil
}

// validate returns an ErrRelayConfiguration error for a Relay which can not relay.
func (r *Relay) validate() (err error) {
	switch {
	case r == nil:
		return fmt.Errorf("%w: the relay is nil", ErrRelayConfiguration)
	case r.Provider == nil, r.Streams == nil, r.Subjects == nil, r.Store == nil:
		return fmt.Errorf("%w: the provider, the streams, the subjects and the store are required", ErrRelayConfiguration)
	case r.TransactionModeFor == nil && r.TransactionMode == RelayTransactionPropagate:
		return nil
	case r.TransactionModeFor == nil && r.TransactionMode != RelayTransactionPerStream:
		return fmt.Errorf("%w: the transaction mode is not known", ErrRelayConfiguration)
	case len(r.TransactionKey) < relayTransactionKeyBytes:
		// SSF Section 10.1: without the key the 'txn' of a stream could be computed by any other Receiver.
		return fmt.Errorf("%w: the per-stream transaction mode requires a transaction key of at least %d bytes", ErrRelayConfiguration, relayTransactionKeyBytes)
	default:
		return nil
	}
}

// relayPrepared is an event the Policy relays.
type relayPrepared struct {
	event *RelayEvent
	out   jwt.SecurityEvent

	// eventType is of the event the Policy returned, and txn the propagated 'txn'.
	eventType, txn, principalKey string

	// origin identifies the SET of the event in the Store.
	origin string

	expiry time.Time
	seen   map[string]struct{}
}

// principalKey returns the key of the principal in the Store, or an ErrRelayPrincipal error when it has none.
func (r *Relay) principalKey(principal any) (key string, err error) {
	if r.PrincipalKey != nil {
		key = r.PrincipalKey(principal)
	} else {
		key, _ = principal.(string)
	}

	if key == "" {
		return "", ErrRelayPrincipal
	}

	return key, nil
}

// markerExpiry returns the time a mark made now expires.
func (r *Relay) markerExpiry() (expiry time.Time) {
	retention := r.MarkerRetention

	if retention <= 0 {
		retention = DefaultRelayMarkerRetention
	}

	if r.Clock != nil {
		return r.Clock().Add(retention)
	}

	return time.Now().Add(retention)
}

// markEvent marks the propagated 'txn' as relayed and returns true when it already was from another SET. The 'iss'
// and the 'jti' of a SET that returns are of the party which issued it again, so the 'txn' is the only value which
// survives, and they are never those of the SET the mark was made for. It is marked for the type of the event and for
// the type the Policy relays it as, which is the type it returns as.
//
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-4.1.9
func (r *Relay) markEvent(ctx context.Context, p *relayPrepared) (known bool, err error) {
	types := []string{relayEventValue(p.event.Event).SecurityEventType()}

	if p.eventType != types[0] {
		types = append(types, p.eventType)
	}

	// Both types are marked at once, so a SET which conflicts on one holds no mark of the other.
	if err = r.Store.MarkSSFRelayedEvent(ctx, p.txn, types, p.principalKey, p.origin, p.expiry); err != nil {
		if errors.Is(err, ErrRelayKnown) {
			return true, nil
		}

		return false, fmt.Errorf("ssfreceiver: the relayed event could not be marked: %w", err)
	}

	return false, nil
}

// prepare returns the SET of the event for one stream, or the reason the stream is skipped.
func (r *Relay) prepare(ctx context.Context, p *relayPrepared, stream *oauth2.SSFStream) (token *RelayToken, err error) {
	if err = relayStreamFault(stream, p); err != nil {
		return nil, err
	}

	p.seen[stream.StreamID] = struct{}{}

	handed := *p.event

	handed.ExcludeClientIDs = slices.Clone(p.event.ExcludeClientIDs)

	var subject *jwt.SubjectIdentifier

	if subject, err = r.Subjects.MapRelaySubject(ctx, stream.Clone(), &handed); err != nil {
		return nil, err
	}

	if subject == nil {
		return nil, ErrRelaySubjectNotCovered
	}

	var jti, txn string

	if jti, txn, err = r.identifiers(p.event, p.txn, p.principalKey, stream); err != nil {
		return nil, err
	}

	// SSF Section 4.1.9: the event returns from the Receiver of the stream with the 'txn' of the stream, so it is
	// marked too.
	if txn != p.txn {
		if err = r.Store.MarkSSFRelayedEvent(ctx, txn, []string{p.eventType}, p.principalKey, p.origin, p.expiry); err != nil && !errors.Is(err, ErrRelayKnown) {
			return nil, fmt.Errorf("ssfreceiver: the relayed event could not be marked: %w", err)
		}
	}

	token = &RelayToken{Stream: stream.Clone(), EventType: p.eventType, Held: stream.Status == oauth2.SSFStreamStatusPaused}

	if token.Token, token.JTI, err = r.Provider.GenerateSecurityEventToken(ctx, stream.Clone(), subject, p.out, jti, txn); err != nil {
		return nil, err
	}

	if token.Token == "" || token.JTI != jti {
		return nil, fmt.Errorf("%w: the issuer returned no token or another 'jti'", ErrRelayStream)
	}

	return token, nil
}

// identifiers returns the 'jti' and the 'txn' of the SET of the event for the stream, from the propagated 'txn'. Both
// are the same whenever the event is prepared. The 'jti' is of the principal too, as the SETs of two principals of one
// event are distinct, and the 'txn' is not, as it is of the underlying event.
//
// See: https://www.rfc-editor.org/rfc/rfc8417#section-2.2
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-10.1
func (r *Relay) identifiers(event *RelayEvent, propagated, principalKey string, stream *oauth2.SSFStream) (jti, txn string, err error) {
	mode := r.TransactionMode

	if r.TransactionModeFor != nil {
		mode = r.TransactionModeFor(stream.Clone())
	}

	switch mode {
	case RelayTransactionPropagate:
		return relayDigest(sha256.New(), event.OriginIssuer, event.OriginJTI, stream.StreamID, principalKey), propagated, nil
	case RelayTransactionPerStream:
		// SSF Section 10.1: a value two streams share, or one Receiver can compute for another, correlates their
		// subjects.
		jti = relayDigest(hmac.New(sha256.New, r.TransactionKey), relayIdentifierJTI, event.OriginIssuer, event.OriginJTI, stream.StreamID, principalKey)
		txn = relayDigest(hmac.New(sha256.New, r.TransactionKey), propagated, stream.StreamID)

		return jti, txn, nil
	default:
		return "", "", fmt.Errorf("%w: the transaction mode of the stream is not known", ErrRelayConfiguration)
	}
}

// relayStreamFault returns the reason a candidate stream is not selected for the event type.
//
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.1
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.2.1
func relayStreamFault(stream *oauth2.SSFStream, p *relayPrepared) (err error) {
	if stream == nil || stream.StreamID == "" {
		return fmt.Errorf("%w: the stream is nil or has no stream id", ErrRelayStream)
	}

	if _, ok := p.seen[stream.StreamID]; ok {
		return fmt.Errorf("%w: the stream is listed more than once", ErrRelayStream)
	}

	// The origin of an event is not sent its own event.
	if slices.Contains(p.event.ExcludeClientIDs, stream.ClientID) {
		return ErrRelayStreamExcluded
	}

	if !slices.Contains(stream.EventsDelivered, p.eventType) {
		return ErrRelayStreamEventType
	}

	// SSF Section 8.1.2.1: a disabled stream is neither sent nor held events, and a paused one is held them.
	if stream.Status != oauth2.SSFStreamStatusEnabled && stream.Status != oauth2.SSFStreamStatusPaused {
		return ErrRelayStreamDisabled
	}

	return nil
}

// relayTransaction returns the 'txn' of the event, derived from the 'iss' and the 'jti' of its SET when it has none,
// which are as unique to the underlying event as the SET is.
//
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-4.1.9
func relayTransaction(event *RelayEvent) (txn string) {
	if event.Transaction != "" {
		return event.Transaction
	}

	return relayDigest(sha256.New(), event.OriginIssuer, event.OriginJTI)
}

// relayDigest returns the base64url encoding without padding of the sum of the hash over the parts. Each part is
// written as its length in 8 bytes, big endian, and then its bytes, so no two lists of parts have the same input.
func relayDigest(h hash.Hash, parts ...string) (digest string) {
	var size [8]byte

	for _, part := range parts {
		binary.BigEndian.PutUint64(size[:], uint64(len(part)))

		h.Write(size[:])
		h.Write([]byte(part))
	}

	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}
