// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package goauth2

import (
	"context"
)

func NewContext() context.Context {
	return context.Background()
}

type ContextKey string

const (
	RequestContextKey           = ContextKey("request")
	AccessRequestContextKey     = ContextKey("accessRequest")
	AccessResponseContextKey    = ContextKey("accessResponse")
	AuthorizeRequestContextKey  = ContextKey("authorizeRequest")
	AuthorizeResponseContextKey = ContextKey("authorizeResponse")
	// PushedAuthorizeResponseContextKey is the response context
	PushedAuthorizeResponseContextKey = ContextKey("pushedAuthorizeResponse")
)
