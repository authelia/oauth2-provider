// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package ciba

import (
	"context"

	"authelia.com/provider/oauth2"
)

// Storage persists OpenID Connect CIBA authentication requests. A request expires at the time recorded with
// session.SetExpiresAt(oauth2.CIBAAuthRequestID, t).
//
// Approving a push mode request records the approval, issues the tokens and invalidates the request atomically only
// when the store implements storage.Transactional. Without it, a push approval whose issuance fails leaves the request
// approved with no tokens delivered: access and refresh token sessions written before the failure remain persisted but
// are never sent, and the client is sent 'transaction_failed'.
//
// CreateCIBASession, GetCIBASession and GetCIBASessionByRequestID must round-trip the concrete
// *oauth2.BackChannelAuthenticationRequest, including its ClientNotificationToken and AuthRequestID fields, and must not
// apply Sanitize to the persisted request, which clears both. The ping and push notifications depend on both: they are
// sent to the client with the ClientNotificationToken as the bearer token and carry the AuthRequestID. Both are
// secrets and should be encrypted at rest.
//
// See: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.10.2
// See: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.10.3.1
type Storage interface {
	// CreateCIBASession stores the authentication request for a given 'auth_req_id' signature.
	CreateCIBASession(ctx context.Context, signature string, request oauth2.BackChannelAuthenticationRequester) (err error)

	// GetCIBASession hydrates the session based on the given 'auth_req_id' signature and returns the authentication
	// request. If the request has been invalidated with InvalidateCIBASession, this method must return the
	// oauth2.ErrInvalidatedCIBASession error together with the request. If no request is stored, it must return
	// oauth2.ErrNotFound.
	GetCIBASession(ctx context.Context, signature string, session oauth2.Session) (request oauth2.BackChannelAuthenticationRequester, err error)

	// GetCIBASessionByRequestID hydrates the session based on the given request ID, as returned by the GetID method of
	// the request, and returns the authentication request. It returns the same errors as GetCIBASession.
	GetCIBASessionByRequestID(ctx context.Context, requestID string, session oauth2.Session) (request oauth2.BackChannelAuthenticationRequester, err error)

	// UpdateCIBASession writes the polling state of the request, the values of GetLastPolled, GetPollingInterval and
	// GetSlowDownCount, onto the stored authentication request for the given 'auth_req_id' signature. It must never
	// overwrite the stored status, failure cause or session, which only DecideCIBASession writes. It does nothing when
	// no request is stored.
	UpdateCIBASession(ctx context.Context, signature string, request oauth2.BackChannelAuthenticationRequester) (err error)

	// DecideCIBASession stores the authentication request for the given 'auth_req_id' signature only while the stored
	// request has the oauth2.CIBAStatusPending status and has not been invalidated with InvalidateCIBASession,
	// checking and writing it in one atomic operation. It returns oauth2.ErrCIBADecided when the stored request was
	// already decided or invalidated, and oauth2.ErrNotFound when no request is stored.
	DecideCIBASession(ctx context.Context, signature string, request oauth2.BackChannelAuthenticationRequester) (err error)

	// InvalidateCIBASession is called when an 'auth_req_id' is being redeemed. Consecutive calls to GetCIBASession
	// must return the oauth2.ErrInvalidatedCIBASession error together with the request. See storage.Transactional,
	// which a store must implement for the revocation of a replayed 'auth_req_id' to be complete.
	//
	// It may return oauth2.ErrSerializationFailure when a concurrent transaction prevents it. GetCIBASession must then
	// return oauth2.ErrInvalidatedCIBASession, with the request, if that transaction committed the invalidation, when
	// called with a context outside the transaction this call rolled back, so that the grant can be revoked. It
	// returns oauth2.ErrNotFound when no request is stored.
	InvalidateCIBASession(ctx context.Context, signature string) (err error)
}
