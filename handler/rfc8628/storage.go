package rfc8628

import (
	"context"

	"authelia.com/provider/oauth2"
)

type Storage interface {
	DeviceCodeStorage
	UserCodeStorage
}

type DeviceCodeStorage interface {
	// CreateDeviceCodeSession stores the device request for a given device code.
	CreateDeviceCodeSession(ctx context.Context, signature string, request oauth2.DeviceAuthorizeRequester) (err error)

	// UpdateDeviceCodeSession update in store the device code session for a given device code.
	UpdateDeviceCodeSession(ctx context.Context, signature string, request oauth2.DeviceAuthorizeRequester) (err error)

	// GetDeviceCodeSession hydrates the session based on the given device code and returns the device request.
	// If the device code has been invalidated with `InvalidateDeviceCodeSession`, this
	// method should return the ErrInvalidatedDeviceCode error.
	//
	// Make sure to also return the fosite.Requester value when returning the fosite.ErrInvalidatedDeviceCode error!
	GetDeviceCodeSession(ctx context.Context, signature string, session oauth2.Session) (request oauth2.DeviceAuthorizeRequester, err error)

	// InvalidateDeviceCodeSession is called when an device code is being used. The state of the user
	// code should be set to invalid and consecutive requests to GetDeviceCodeSession should return the
	// ErrInvalidatedDeviceCode error.
	InvalidateDeviceCodeSession(ctx context.Context, signature string) (err error)
}

type UserCodeStorage interface {
	// CreateUserCodeSession stores the device request for a given user code.
	CreateUserCodeSession(ctx context.Context, signature string, request oauth2.DeviceAuthorizeRequester) (err error)

	// GetUserCodeSession hydrates the session based on the given user code and returns the device request.
	// If the user code has been invalidated with `InvalidateUserCodeSession`, this
	// method should return the ErrInvalidatedUserCode error.
	//
	// Make sure to also return the fosite.Requester value when returning the fosite.ErrInvalidatedUserCode error!
	GetUserCodeSession(ctx context.Context, signature string, session oauth2.Session) (request oauth2.DeviceAuthorizeRequester, err error)

	// InvalidateUserCodeSession is called when an user code is being used. The state of the user
	// code should be set to invalid and consecutive requests to GetUserCodeSession should return the
	// ErrInvalidatedUserCode error.
	InvalidateUserCodeSession(ctx context.Context, signature string) (err error)

	// UpdateUserCodeSession updates in store the user code session for a given user code.
	UpdateUserCodeSession(ctx context.Context, signature string, req oauth2.DeviceAuthorizeRequester) error
}
