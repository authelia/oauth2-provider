// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc8628

import (
	"context"

	"authelia.com/provider/oauth2"
)

type Storage interface {
	// CreateDeviceCodeSession stores the device request for a given device code. It must atomically reject a user code
	// signature already held by another session with oauth2.ErrDuplicateUserCode.
	CreateDeviceCodeSession(ctx context.Context, signature string, request oauth2.DeviceAuthorizeRequester) (err error)

	// UpdateDeviceCodeSession update in store the device code session for a given device code.
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
	// oauth2.ErrInvalidatedDeviceCode error.
	InvalidateDeviceCodeSession(ctx context.Context, signature string) (err error)
}

// DecisionStorage is an optional Storage extension which records the user's decision on a device code session
// atomically. The UserAuthorizeHandler uses it when the Storage implements it, so of two decisions submitted
// concurrently for one user code only the first is recorded.
type DecisionStorage interface {
	// DecideDeviceCodeSession stores the device code session for the given device code only while the stored session
	// has the oauth2.DeviceAuthorizeStatusNew status, checking and writing it in one atomic operation. It returns the
	// oauth2.ErrDeviceAuthorizeDecided error when the stored session was already decided, and the oauth2.ErrNotFound
	// error when no session is stored for the device code.
	DecideDeviceCodeSession(ctx context.Context, signature string, request oauth2.DeviceAuthorizeRequester) (err error)
}
