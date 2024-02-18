package rfc8693

import (
	"context"
	"time"

	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
)

type Storage interface {
	hoauth2.CoreStorage

	// SetTokenExchangeCustomJWT marks a JTI as known for the given
	// expiry time. It should atomically check if the JTI
	// already exists and fail the request, if found.
	SetTokenExchangeCustomJWT(ctx context.Context, jti string, exp time.Time) error

	// GetSubjectForTokenExchange computes the session subject and is used for token types where there is no way
	// to know the subject value. For some token types, such as access and refresh tokens, the subject is well-defined
	// and this function is not called.
	GetSubjectForTokenExchange(ctx context.Context, requester oauth2.Requester, subjectToken map[string]any) (string, error)
}
