// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

// Package ssfreceiver implements the Receiver role of the OpenID Shared Signals Framework 1.0 for an authorization
// server: it keeps a record of each stream a Transmitter delivers on, validates the Security Event Tokens received on
// it and hands them to the application.
//
// A Receiver discovers the Transmitter Configuration Metadata, manages streams (create, read, update, replace, delete,
// status, verification, add and remove subject), answers a push delivery request with Receiver.HandlePush, and polls
// with Receiver.Poll or a Poller. A Relay prepares the SETs which carry a received event on to the streams the
// authorization server transmits on. The package has no routes, no queue, no OAuth client and no knowledge of the
// users of the application, so the duties below are those of the application.
//
// # Transport
//
// Serve the push endpoint, and connect to a Transmitter, over TLS 1.2 or later with certificate validation, following
// RFC 9325 (CAEP Interoperability Profile Section 2.1, RFC 8935 Section 5.3). Go does not check certificate
// revocation: an application which requires that check adds it to the transport of Config.HTTPClient and to its
// server. A Config.HTTPClient with its own transport must keep the TLS version and the certificate validation.
//
// Every request to a Transmitter passes the special-use address guard, which permits no network unless
// Config.SpecialUseAddressGuard does. A Config.JWKSFetcher that is not an *oauth2.DefaultJWKSFetcherStrategy applies
// the guard itself, and limits the forced refreshes itself: a SET with an unknown 'kid' forces one, so whoever is
// authorized to push could otherwise cause a fetch of the key set with each request.
//
// A Config.HTTPClient with a request timeout must have one longer than Config.LongPollTimeout, or each long poll of a
// quiet stream ends as an error and the Poller backs off.
//
// # Authorization
//
// Config.Authorizer is required for the stream management and the poll requests. The read requests ask for the
// ssf.read scope, and every other request, a poll included, for ssf.manage. Obtaining, caching and renewing the access
// token is left to the application: there is no OAuth client for the authorization server of the Transmitter.
//
// The poll endpoint URL is the one of the stored stream configuration, as the Transmitter supplied it. It must be an
// https URL and the request passes the special-use address guard, but its origin is not tied to the issuer: it may be
// of any host. It receives the access token of the Transmitter, so a record is created only for an issuer from a
// trusted source.
//
// # Routing a push
//
// Route one URL per stream to Receiver.HandlePush, and look the record up from the request URL with
// StreamStorage.GetSSFReceiverStreamByPushEndpoint, never from the SET. The URL is compared as an exact string, in
// the lookup and in the conflict check of the store, so the application normalizes it the same way when it creates
// the stream and when it routes a request. A StreamRecord whose Delivery has no Method is a push stream.
//
// Receiver.HandlePush always writes the response, and returns an error for the application to log: the cause of a
// 503, and the error of the PushAuthorizer for a request which is not authorized, so failed attempts can be counted.
// A Config.PushAuthorizer which could not decide, such as one whose token introspection is not available, returns an
// error matching ErrPushAuthorizerUnavailable: the request is then answered with a 503 and the Transmitter delivers
// the SET again, where any other error refuses the SET with 'authentication_failed'.
//
// # The push secret
//
// Delivery.AuthorizationHeader of a push stream is a secret the Receiver issues and the Transmitter sends with each
// SET. It is stored with the record, as is the PendingAuthorizationHeader, so StreamStorage protects both at rest,
// and the JSON encoding and the formatting of a StreamRecord omit them. Neither is in the record an EventHandler, a
// StreamEventHandler or a SubjectResolver is handed.
//
// The secret is rotated with Receiver.ReplaceStream or Receiver.UpdateStream, without the loss of a push. The new
// secret is stored as the PendingAuthorizationHeader before the request is made, and a push is authorized with
// either secret while one is pending, as the Transmitter may send the new one before its response is read:
//
//   - A 200 makes the new secret the Delivery.AuthorizationHeader and clears the pending one.
//   - An error matching ErrStreamChangeApplied means the Transmitter applied the change, and is handled as a 200.
//     When the record could not be stored the pending secret stays, so both are still accepted. The rest of the
//     record is as sent until Receiver.ReadStream succeeds.
//   - An error matching ErrStreamUpdatePending is a 202, and one matching ErrTransmitterUnconfirmed is a request
//     which may have been sent and has no response: both secrets stay accepted, and the application repeats the
//     same request until it is answered with a 200. A *TransmitterError of a 5xx, or of a 2xx other than a 200 or a
//     202, keeps both as well, as the Transmitter may have applied the change.
//   - Any other error means the Transmitter did not apply the change. The pending secret is the one from before the
//     request again, which is none unless an earlier change is still pending.
//
// A record has one pending secret, so the application finishes one rotation before it starts another: a request with
// a third secret replaces the pending one. A Config.PushAuthorizer which compares the secret itself accepts both.
//
// # Handling an event
//
// EventHandler.HandleSecurityEvent persists or enqueues the event and returns. The SET is acknowledged only when it
// returns nil, and the Transmitter waits for the answer, so the application acts on the event, such as ending the
// sessions of the subject, after the handler returned (RFC 8935 Section 2, RFC 8936 Section 2.4).
//
// The handler is idempotent on the issuer and the 'jti'. The 'jti' is marked as received after the handler returns, so
// a failure between the two, or a concurrent delivery of the same SET, calls it again for the same SET.
//
// Other behavior the application relies on:
//
//   - StreamRecord.EventsDelivered must have the event types of the stream. An event of any other type is acknowledged
//     and dropped, so a record with an empty list hands the handler nothing. The verification and stream updated
//     events are handled whatever it is, and go to Config.StreamHandler only.
//   - The Status of a record is stored from the status endpoint and from a stream updated event, and is not enforced
//     on receipt: a SET received on a paused or disabled stream is handled as any other, as SSF Section 8.1.5 puts the
//     status on the Transmitter.
//   - A SubjectResolver which returns ErrSubjectUnknown acknowledges the SET without the handler. Any other error it
//     returns, a *SetError included, is never reported to the Transmitter and leaves the SET to be delivered again
//     (SSF Section 9.3).
//   - An empty Config.ProcessedSubjectMembers means the seven Complex Subject members of SSF Section 3.3: user,
//     device, session, application, tenant, org_unit and group.
//   - A SET older than Config.MaxTokenAge is refused, so replay protection has no gap once its 'jti' is forgotten.
//
// # Streams
//
// The application holds the list of the Transmitters it trusts. CreateStreamRequest.Issuer comes from that list and
// CreateStreamRequest.Audience is the audience agreed with the Transmitter: with none, any 'aud' the Transmitter
// answers with is stored and accepted.
//
// Receiver.CreateStream stores a pending record under the issuer and the empty stream ID before the request, and
// deletes it when the request fails. A process which ends in between leaves that record, which makes every later
// create for the issuer fail with ErrStreamRecordConflict until the application deletes it through the store.
//
// A push to a pending record is answered with a 503, a verification event included, as the stream ID the SET is
// checked against is not known yet. A Transmitter which delivers again verifies the stream once the record is
// active. One which verifies the stream inside the create request and requires the push to succeed fails the create:
// such a Transmitter can not be used with a push stream.
//
// Receiver.UpdateStream, Receiver.ReplaceStream and Receiver.ReadStream each read the record, make the request and
// store the whole record, and the last one to store wins. The application serializes them for one stream, or a
// change of one, a new secret included, is lost to the other. The status, the verification and the pending secret
// are stored on their own and are not affected. Receiver.RequestStreamVerification is serialized for one stream too,
// as a request replaces the 'state' of an earlier one.
//
// Receiver.DeleteStream removes the record when the Transmitter answers with a 204, and also with a 404, which is a
// stream the Transmitter no longer has.
//
// A push stream has no activity of the Receiver. Call Receiver.Touch more often than the InactivityTimeout of the
// record, when it has one, or the Transmitter may pause, disable or delete the stream (SSF Section 8.1.1). Each poll
// is activity of a poll stream.
//
// Receiver.RequestStreamVerification does not wait for the event. The stream is verified when the VerifiedAt of its
// record changes, so the application requests verification on a schedule and alerts when a stream stays unverified,
// paused or disabled.
//
// Receiver.AddSubject and Receiver.RemoveSubject send a subject of a format with defined members only, and refuse a
// proprietary format. With Config.EnforceCAEPInteroperabilityProfile they return ErrSubjectsImplicit.
//
// # Polling
//
// A Poller retries for as long as an error lasts, and backs off up to Poller.Backoff.Max. Poller.Failure is the only
// sight of an error which is retried, such as a 401, a 403, or a 400 or a 413 the request itself causes, so the
// application logs or alerts from it. Poller.Result reports the SETs which were not acknowledged.
//
// Each request of a Poller has a 'maxEvents', which is Config.MaxPollSets unless Poller.MaxEvents is set, so a backlog
// is read in parts: a response with the whole of it could be larger than Config.MaxResponseBytes, which fails the
// poll. A Transmitter which keeps delivering SETs received before is polled once per Poller.Interval, whatever its
// 'moreAvailable'. A 504 ends a long poll and is not a failure, unless more than three in a row are answered without
// the request having been held, which Poller.Failure then reports.
//
// # Relaying
//
// A received SET is never forwarded. Relay.Prepare returns a new SET of the authorization server for each stream, and
// pushes nothing: the application queues the tokens in the outbox it runs for its own events, and delivers a token
// which is Held once its stream is enabled. Prepare is repeatable, as the 'jti' and the 'txn' of a stream are derived
// from the origin of the event, so an application which could not queue the tokens prepares the event again.
//
// The application supplies the candidate streams through a RelayStreamSource and the subject of each through a
// RelaySubjectMapper. Nothing is relayed without a RelayPolicy. Before an event is relayed the application has the
// consent, or another basis, to release it to the Receiver of each stream (SSF Section 10.3), which the RelayPolicy
// and the RelaySubjectMapper decide: the mapper returns ErrRelaySubjectNotCovered for a stream which is not to learn
// of the event.
//
// Choose how the 'txn' is derived:
//
//   - RelayTransactionPerStream, the default, gives each stream its own 'txn' and 'jti', so two Receivers can not
//     correlate their subjects (SSF Section 10.1). It requires a Relay.TransactionKey of at least 32 bytes.
//   - RelayTransactionPropagate carries the 'txn' of the event unchanged (SSF Section 4.1.9).
//   - Relay.TransactionModeFor chooses per stream, such as by the subject type of its client.
//
// A change of the Relay.TransactionKey changes the 'jti' and the 'txn' of every later relay to a stream in the
// RelayTransactionPerStream mode, so an event prepared again after it is a new SET to its Receiver. A stream in the
// RelayTransactionPropagate mode is not affected: its 'jti' has no key and its 'txn' is the one of the event.
//
// SanitizeRelayEvent, which the RelayEventTypes policy applies, drops the 'reason_admin' and 'reason_user' of the
// Transmitter and the members listed in its rules. The free-form members it keeps are relayed as received:
// 'credential_type', the 'namespace' and the levels of an assurance level change, and the 'principal' of a risk level
// change. A policy which returns its own event answers for every member of it.
//
// The marker in RelayStorage is keyed by the 'txn', the event type and the principal. A second upstream Transmitter
// which sends its own SET of the same underlying event with the same 'txn' is therefore not relayed again within
// Relay.MarkerRetention. The upstream Transmitters share one 'txn' space: SSF Section 4.1.9 ties a 'txn' to the
// underlying event and not to the Transmitter, and a 'txn' which returns carries the 'iss' of another party. For a
// Transmitter whose 'txn' values may collide with those of another, the application clears RelayEvent.Transaction,
// which derives a 'txn' from its 'iss' and 'jti', and gives up the recognition of its events on another stream.
//
// A returning event is recognized by a 'txn' this relay marked. A relay which derives a new 'txn' does not preserve
// it, and SSF has no claim for the path of an event, so a cycle through another relay in the RelayTransactionPerStream
// mode is not recognized. The topology of the relays is acyclic, or every relay of a cycle relays in the
// RelayTransactionPropagate mode, and the ExcludeClientIDs of an event name the client of its upstream Transmitter.
//
// # Not implemented
//
//   - A JWE without a 'kid' header is refused.
//   - A SET without a 'sub_id', with the subject inside the event as RISC transmitters before SSF 1.0 send it, is
//     refused (SSF Section 4.1.2).
//   - A SET with more than one event type URI is refused (CAEP Interoperability Profile Section 2.8.1).
//   - Error descriptions are in English only (RFC 8935 Section 2.3).
//   - Encryption can not be required per stream: a signed SET is accepted on any stream.
//   - Certificate revocation is not checked.
//   - The 'toe' claim is neither read nor relayed (RFC 8417 Section 2.2).
//   - The Transmitter of this library has no subject endpoints and no subject list per stream, so which stream covers
//     a relayed subject is the answer of the RelaySubjectMapper.
//
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-2
// See: https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-10.3
// See: https://openid.net/specs/openid-caep-interoperability-profile-1_0.html#section-2.1
// See: https://www.rfc-editor.org/rfc/rfc8935
// See: https://www.rfc-editor.org/rfc/rfc8936
package ssfreceiver
