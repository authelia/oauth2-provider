// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc8693

import (
	"context"
	"time"

	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
)

type Storage interface {
	hoauth2.CoreStorage

	// GetClient loads the current registration of the client a refresh token was issued to, returning
	// oauth2.ErrNotFound when the client does not exist.
	GetClient(ctx context.Context, id string) (client oauth2.Client, err error)

	// SetTokenExchangeCustomJWT marks a JTI as known for the issuer until the given expiry time. It should atomically
	// check if the JTI already exists for the issuer and fail the request if found. A JTI is only unique among the
	// JWTs produced by one issuer per RFC 7519 Section 4.1.7, so the JTI must be scoped to the issuer.
	SetTokenExchangeCustomJWT(ctx context.Context, issuer, jti string, exp time.Time) (err error)

	// GetSubjectForTokenExchange computes the session subject and is used for token types where there is no way
	// to know the subject value. For some token types, such as access and refresh tokens, the subject is well-defined
	// and this function is not called.
	GetSubjectForTokenExchange(ctx context.Context, request oauth2.Requester, subjectToken map[string]any) (subject string, err error)
}
