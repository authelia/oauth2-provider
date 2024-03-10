package rfc8628

import (
	"context"

	"authelia.com/provider/oauth2"
)

type CodeStrategy interface {
	DeviceCodeStrategy
	UserCodeStrategy
}

type DeviceCodeStrategy interface {
	RFC8628DeviceCodeSignature(ctx context.Context, code string) (signature string, err error)
	GenerateRFC8628DeviceCode(ctx context.Context) (code string, signature string, err error)
	ValidateRFC8628DeviceCode(ctx context.Context, r oauth2.Requester, code string) (err error)
}

type UserCodeStrategy interface {
	RFC8628UserCodeSignature(ctx context.Context, code string) (signature string, err error)
	GenerateRFC8628UserCode(ctx context.Context) (code string, signature string, err error)
	ValidateRFC8628UserCode(ctx context.Context, r oauth2.Requester, code string) (err error)
}
