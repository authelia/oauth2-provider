package rfc8628

import (
	"context"

	"authelia.com/provider/oauth2"
)

type Storage interface {
	// CreateDeviceCodeSession stores the device request for a given device code.
	CreateDeviceCodeSession(ctx context.Context, signature string, request oauth2.DeviceAuthorizeRequester) (err error)

	// UpdateDeviceCodeSession update in store the device code session for a given device code.
	UpdateDeviceCodeSession(ctx context.Context, signature string, request oauth2.DeviceAuthorizeRequester) (err error)

	// GetDeviceCodeSession hydrates the session based on the given device code and returns the device request.
	// If the device code has been invalidated with `InvalidateDeviceCodeSession`, this
	// method should return the ErrInvalidatedDeviceCode error.
	//
	// Make sure to also return the oauth2.Requester value when returning the oauth2.ErrInvalidatedDeviceCode error.
	GetDeviceCodeSession(ctx context.Context, signature string, session oauth2.Session) (request oauth2.DeviceAuthorizeRequester, err error)

	// GetDeviceCodeSessionByUserCode hydrates the session based on the given device code and returns the device request.
	// If the device code has been invalidated with `InvalidateDeviceCodeSession`, this method should return the
	// oauth2.ErrInvalidatedDeviceCode error.
	//
	// Make sure to also return the oauth2.Requester value when returning the oauth2.ErrInvalidatedDeviceCode error.
	GetDeviceCodeSessionByUserCode(ctx context.Context, signature string, session oauth2.Session) (request oauth2.DeviceAuthorizeRequester, err error)

	// InvalidateDeviceCodeSession is called when a device code is being used. The state of the user
	// code should be set to invalid and consecutive requests to GetDeviceCodeSession should return the
	// oauth2.ErrInvalidatedDeviceCode error.
	InvalidateDeviceCodeSession(ctx context.Context, signature string) (err error)
}
