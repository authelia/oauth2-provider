package rfc8628

import (
	"context"

	"authelia.com/provider/oauth2"
)

type RFC8628CodeStrategy interface {
	DeviceCodeStrategy
	UserCodeStrategy
}

type DeviceCodeStrategy interface {
	DeviceCodeSignature(ctx context.Context, code string) (signature string, err error)
	GenerateDeviceCode(ctx context.Context) (code string, signature string, err error)
	ValidateDeviceCode(ctx context.Context, r oauth2.Requester, code string) (err error)
}

type UserCodeStrategy interface {
	UserCodeSignature(ctx context.Context, code string) (signature string, err error)
	GenerateUserCode(ctx context.Context) (code string, signature string, err error)
	ValidateUserCode(ctx context.Context, r oauth2.Requester, code string) (err error)
}
