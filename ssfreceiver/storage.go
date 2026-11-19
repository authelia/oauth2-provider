// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package ssfreceiver

import (
	"context"
	"time"
)

// Storage is the storage a Receiver requires.
type Storage interface {
	StreamStorage
	TokenStorage
}

// StreamStorage persists the stream records of a Receiver, identified by the issuer of the Transmitter and the
// stream ID. An unknown record gives oauth2.ErrNotFound. Every record given to or returned by a method must be a
// copy which shares no memory with the stored one.
//
// A pending record with an empty StreamID is stored under the issuer and the empty stream ID, so a Transmitter has at
// most one at a time, and the caller must delete one whose stream was never created.
//
// A push endpoint URL is compared as an exact string, both for the lookup and for the conflict check, so the caller
// normalizes it.
//
// StreamRecord.Delivery.AuthorizationHeader and StreamRecord.PendingAuthorizationHeader are secrets. Implementations
// must protect them at rest and must never log them or include them in an error. The JSON encoding of StreamRecord
// omits the secrets, so it is not a persistence encoding.
type StreamStorage interface {
	// CreateSSFReceiverStream stores the record. The Issuer is required, and the StreamID is required unless State
	// is StreamRecordPending. It returns ErrStreamRecordConflict when a record has the same Issuer and StreamID, or
	// the record is of a push stream and a record of a push stream has the same Delivery.EndpointURL, and the check
	// must be atomic with the write.
	CreateSSFReceiverStream(ctx context.Context, record *StreamRecord) (err error)

	// GetSSFReceiverStream returns the record, or oauth2.ErrNotFound.
	GetSSFReceiverStream(ctx context.Context, issuer, streamID string) (record *StreamRecord, err error)

	// GetSSFReceiverStreamByPushEndpoint returns the record of the push stream delivered to the endpoint URL of this
	// Receiver, pending or active, or oauth2.ErrNotFound.
	GetSSFReceiverStreamByPushEndpoint(ctx context.Context, endpointURL string) (record *StreamRecord, err error)

	// ListSSFReceiverStreams returns every record of the Transmitter.
	ListSSFReceiverStreams(ctx context.Context, issuer string) (records []*StreamRecord, err error)

	// UpdateSSFReceiverStream replaces the record identified by issuer and streamID, or returns oauth2.ErrNotFound.
	// The StreamID of the record may differ from streamID, which is how a pending record takes the stream ID the
	// Transmitter assigned; the Issuer may not. It returns ErrStreamRecordConflict as CreateSSFReceiverStream does. It
	// must not change Status, StatusReason, VerificationState, VerificationRequestedAt, VerifiedAt or
	// PendingAuthorizationHeader. Two concurrent updates are last-write-wins.
	UpdateSSFReceiverStream(ctx context.Context, issuer, streamID string, record *StreamRecord) (err error)

	// SetSSFReceiverStreamPendingAuthorizationHeader sets only the PendingAuthorizationHeader of the record, or
	// returns oauth2.ErrNotFound. An empty header clears it. The write is of one record and needs no transaction
	// with UpdateSSFReceiverStream: the Receiver sets the pending secret before it asks the Transmitter for the
	// change and clears it only once the record has the secret the Transmitter sends, so the record accepts that
	// secret in every order of the writes. A read returns the Delivery.AuthorizationHeader and the
	// PendingAuthorizationHeader of one moment.
	SetSSFReceiverStreamPendingAuthorizationHeader(ctx context.Context, issuer, streamID, header string) (err error)

	// UpdateSSFReceiverStreamStatus sets only the Status and StatusReason of the record, or returns
	// oauth2.ErrNotFound.
	UpdateSSFReceiverStreamStatus(ctx context.Context, issuer, streamID, status, reason string) (err error)

	// SetSSFReceiverStreamVerificationState sets only the VerificationState and VerificationRequestedAt of the
	// record, or returns oauth2.ErrNotFound. A zero requestedAt withdraws the request.
	SetSSFReceiverStreamVerificationState(ctx context.Context, issuer, streamID, state string, requestedAt time.Time) (err error)

	// ConsumeSSFReceiverStreamVerificationState clears the VerificationState and VerificationRequestedAt of the
	// record and sets its VerifiedAt when a verification was requested and state is the requested one. Otherwise it
	// changes nothing and returns ErrVerificationStateMismatch, or oauth2.ErrNotFound for an unknown record. The
	// comparison and the write must be atomic, so one request is consumed at most once.
	ConsumeSSFReceiverStreamVerificationState(ctx context.Context, issuer, streamID, state string, verifiedAt time.Time) (err error)

	// SetSSFReceiverStreamVerifiedAt sets only the VerifiedAt of the record, or returns oauth2.ErrNotFound. It is for
	// a verification event the Receiver did not request, which has no 'state' to consume.
	//
	// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.4
	SetSSFReceiverStreamVerifiedAt(ctx context.Context, issuer, streamID string, verifiedAt time.Time) (err error)

	// DeleteSSFReceiverStream removes the record, or returns oauth2.ErrNotFound.
	DeleteSSFReceiverStream(ctx context.Context, issuer, streamID string) (err error)
}

// TokenStorage remembers the received Security Event Tokens of a stream. A 'jti' is known only in the context of the
// issuer and the stream it was received on.
//
// See: https://www.rfc-editor.org/rfc/rfc8417#section-2.2
type TokenStorage interface {
	// IsSSFReceiverTokenKnown returns true when the 'jti' is marked as received and the mark has not expired.
	IsSSFReceiverTokenKnown(ctx context.Context, issuer, streamID, jti string) (known bool, err error)

	// MarkSSFReceiverTokenReceived marks the 'jti' as received until expiresAt, returning oauth2.ErrJTIKnown when
	// it is already marked.
	MarkSSFReceiverTokenReceived(ctx context.Context, issuer, streamID, jti string, expiresAt time.Time) (err error)
}

// RelayStorage remembers the underlying events a Relay relayed, so one that returns from another party, or arrives
// on more than one stream, is relayed once.
//
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-4.1.9
type RelayStorage interface {
	// MarkSSFRelayedEvent marks each of the event types of the 'txn' as relayed for the principal by the origin until
	// expiry. The origin identifies the SET the event was received in. A mark of the same origin which has not expired
	// is kept, with the later of the two expiries, and gives no error, so the same SET may be relayed again. A mark of
	// another origin which has not expired, for any of the event types, gives ErrRelayKnown, and then no mark is
	// written or changed. The check of every event type must be atomic with the writes, and the values are compared
	// exactly and never joined.
	MarkSSFRelayedEvent(ctx context.Context, txn string, eventTypes []string, principalKey, origin string, expiry time.Time) (err error)
}
