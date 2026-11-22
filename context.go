// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"net/http"
)

// NewContext returns a fresh background context suitable for use as the root context of an OAuth 2.0 request flow.
func NewContext() context.Context {
	return context.Background()
}

// ContextKey is the type of keys used to store values on a [context.Context].
type ContextKey string

const (
	// RequestContextKey is the context key for the [http.Request].
	RequestContextKey = ContextKey("request")
	// AccessRequestContextKey is the context key for the AccessRequester.
	AccessRequestContextKey = ContextKey("accessRequest")
	// AccessResponseContextKey is the context key for the AccessResponder.
	AccessResponseContextKey = ContextKey("accessResponse")
	// AuthorizeRequestContextKey is the context key for the AuthorizeRequester.
	AuthorizeRequestContextKey = ContextKey("authorizeRequest")
	// AuthorizeResponseContextKey is the context key for the AuthorizeResponder.
	AuthorizeResponseContextKey = ContextKey("authorizeResponse")
	// PushedAuthorizeResponseContextKey is the context key for the PushedAuthorizeResponder.
	PushedAuthorizeResponseContextKey = ContextKey("pushedAuthorizeResponse")
	// DPoPProofContextKey is the context key for the DPoP proof.
	DPoPProofContextKey = ContextKey("dpopProof")
	// DPoPProofClientContextKey is the context key for the Client a DPoP proof is validated for.
	DPoPProofClientContextKey = ContextKey("dpopProofClient")
	// SkipStatelessIntrospectionContextKey is the context key which, when set to true, makes the stateless JWT Profile
	// access token introspector decline every token so it is resolved from storage instead.
	SkipStatelessIntrospectionContextKey = ContextKey("skipStatelessIntrospection")
)

// RequestFromContext returns the [http.Request] stored under RequestContextKey, or nil if there is none.
func RequestFromContext(ctx context.Context) *http.Request {
	r, _ := ctx.Value(RequestContextKey).(*http.Request)

	return r
}
