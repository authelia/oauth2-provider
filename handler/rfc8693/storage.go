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

// CustomJWTStorage records the custom JWTs consumed by a token exchange, for a *JWTType whose Validate sets ValidateJTI.
type CustomJWTStorage interface {
	// SetTokenExchangeCustomJWT marks a JTI as known for the issuer until the given expiry time. It should atomically
	// check if the JTI already exists for the issuer and MUST return an error matching oauth2.ErrJTIKnown if found. Any
	// other error is answered as a server error rather than a replay. A JTI is only unique among the JWTs produced by one
	// issuer per RFC 7519 Section 4.1.7, so the JTI must be scoped to the issuer.
	SetTokenExchangeCustomJWT(ctx context.Context, issuer, jti string, exp time.Time) (err error)
}

// IDJAGRelationshipStorage resolves the 'audience' of an ID-JAG request, as idjag.IssueStorage does. When the Storage
// of a RefreshTokenTypeHandler implements it, an 'audience' that resolves to this server is compared with the refresh
// token as the issuer identifier is (draft-ietf-oauth-identity-assertion-authz-grant-06 Section 4.3.3).
//
// An 'audience' which identifies no known Resource Authorization Server MUST return oauth2.ErrNotFound, which skips the
// comparison. A client-facing oauth2.RFC6749Error is returned unchanged. Any other error is answered as a server error.
type IDJAGRelationshipStorage interface {
	GetIDJAGRelationship(ctx context.Context, request oauth2.AccessRequester, audience string) (relationship *oauth2.IDJAGRelationship, err error)
}

type Storage interface {
	hoauth2.CoreStorage

	// GetClient loads the current registration of the client a refresh token was issued to, returning
	// oauth2.ErrNotFound when the client does not exist.
	GetClient(ctx context.Context, id string) (client oauth2.Client, err error)

	CustomJWTStorage

	// GetSubjectForTokenExchange computes the session subject and is used for token types where there is no way
	// to know the subject value. For some token types, such as access and refresh tokens, the subject is well-defined
	// and this function is not called.
	//
	// A subject token which does not identify a subject MUST return oauth2.ErrNotFound or a client-facing
	// oauth2.RFC6749Error such as oauth2.ErrInvalidRequest. Any other error is answered as a server error.
	GetSubjectForTokenExchange(ctx context.Context, request oauth2.Requester, subjectToken map[string]any) (subject string, err error)
}
