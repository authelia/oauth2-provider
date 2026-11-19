// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc8628

import (
	"context"

	"authelia.com/provider/oauth2"
)

// Storage persists the sessions of the RFC 8628 device authorization grant.
//
// A user code is unique among the sessions the store holds, so the store is the deny list of user codes: a session
// which has expired, been decided or been invalidated should be retained for at least one code lifespan, the
// oauth2.DeviceCode expiry of its session, so that its user code is not issued again within that window.
//
// See: https://www.rfc-editor.org/rfc/rfc10027#section-6.1.4
type Storage interface {
	// CreateDeviceCodeSession stores the device request for a given device code. It must atomically reject a user code
	// signature already held by another session with oauth2.ErrDuplicateUserCode.
	CreateDeviceCodeSession(ctx context.Context, signature string, request oauth2.DeviceAuthorizeRequester) (err error)

	// UpdateDeviceCodeSession update in store the device code session for a given device code. The token endpoint
	// calls it with a request loaded before the poll was handled when the store does not implement PollStorage, so it
	// should not replace a status of oauth2.DeviceAuthorizeStatusApproved or oauth2.DeviceAuthorizeStatusDenied recorded
	// since.
	UpdateDeviceCodeSession(ctx context.Context, signature string, request oauth2.DeviceAuthorizeRequester) (err error)

	// GetDeviceCodeSession hydrates the session based on the given device code and returns the device request.
	// If the device code has been invalidated with `InvalidateDeviceCodeSession`, this method should return
	// the oauth2.ErrInvalidatedDeviceCode error.
	//
	// Make sure to also return the oauth2.Requester value when returning the oauth2.ErrInvalidatedDeviceCode error.
	GetDeviceCodeSession(ctx context.Context, signature string, session oauth2.Session) (request oauth2.DeviceAuthorizeRequester, err error)

	// GetDeviceCodeSessionByUserCode hydrates the session based on the given device code and returns the device request.
	// If the device code has been invalidated with `InvalidateDeviceCodeSession`, this method should return the
	// oauth2.ErrInvalidatedDeviceCode error.
	//
	// Make sure to also return the oauth2.Requester value when returning the oauth2.ErrInvalidatedDeviceCode error.
	//
	// If no request holds the user code, this method must return the oauth2.ErrNotFound error. The device authorization
	// endpoint relies on this to issue a user code that no other request holds.
	GetDeviceCodeSessionByUserCode(ctx context.Context, signature string, session oauth2.Session) (request oauth2.DeviceAuthorizeRequester, err error)

	// InvalidateDeviceCodeSession is called when a device code is being used. The state of the user
	// code should be set to invalid and consecutive requests to GetDeviceCodeSession should return the
	// oauth2.ErrInvalidatedDeviceCode error. See storage.Transactional, which a store must implement for the revocation of
	// a replayed device code to be complete.
	//
	// It may return oauth2.ErrSerializationFailure when a concurrent transaction prevents it. GetDeviceCodeSession MUST
	// then return oauth2.ErrInvalidatedDeviceCode, with the oauth2.Requester, if that transaction committed the
	// invalidation, when called with a context outside the transaction this request rolled back, so that the grant can be
	// revoked.
	InvalidateDeviceCodeSession(ctx context.Context, signature string) (err error)
}

// DecisionStorage is an optional Storage extension which records the user's decision on a device code session
// atomically. The UserAuthorizeHandler uses it when the Storage implements it, so of two decisions submitted
// concurrently for one user code only the first is recorded.
type DecisionStorage interface {
	// DecideDeviceCodeSession stores the device code session for the given device code only while the stored session
	// has the oauth2.DeviceAuthorizeStatusNew or oauth2.DeviceAuthorizeStatusClaimed status, checking and writing it in
	// one atomic operation. It must not overwrite the stored polling state, which PollStorage writes. It returns the
	// oauth2.ErrDeviceAuthorizeDecided error when the stored session was already decided, and the oauth2.ErrNotFound
	// error when no session is stored for the device code.
	DecideDeviceCodeSession(ctx context.Context, signature string, request oauth2.DeviceAuthorizeRequester) (err error)
}

// PollStorage is an optional Storage extension which records a poll of the token endpoint without writing the rest of
// the device code session. The DeviceCodeTokenHandler uses it when the Storage implements it, so a poll never
// overwrites a decision recorded after the session was loaded.
//
// See: https://www.rfc-editor.org/rfc/rfc8628#section-3.5
type PollStorage interface {
	// UpdateDeviceCodeSessionPolling writes the polling state of the request, the value of GetLastChecked and for an
	// oauth2.DeviceAuthorizePollingRequester the values of GetPollingInterval and GetSlowDownCount, onto the stored
	// device code session for the given device code. It must never overwrite the stored status, claim subject or
	// session. It does nothing when no session is stored.
	UpdateDeviceCodeSessionPolling(ctx context.Context, signature string, request oauth2.DeviceAuthorizeRequester) (err error)
}

// ClaimStorage is a Storage extension which binds the user code of a device code session to the subject who first
// presents it atomically, so of two subjects presenting one user code concurrently only the first is bound. The
// UserAuthorizeHandler requires it unless user code subject binding is disabled.
//
// See: https://www.rfc-editor.org/rfc/rfc10027#section-6.1.3
type ClaimStorage interface {
	// ClaimDeviceCodeSession records the subject and the oauth2.DeviceAuthorizeStatusClaimed status on the stored
	// session for the given device code only while the stored session is undecided and no other subject is recorded,
	// checking and writing it in one atomic operation. It must never overwrite any other part of the stored session.
	// It returns the oauth2.ErrUserCodeClaimed error when another subject is recorded, the
	// oauth2.ErrDeviceAuthorizeDecided error when the stored session was already decided, and the oauth2.ErrNotFound
	// error when no session is stored for the device code.
	ClaimDeviceCodeSession(ctx context.Context, signature string, subject string) (err error)
}
