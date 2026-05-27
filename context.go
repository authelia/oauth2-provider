// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
)

func NewContext() context.Context {
	return context.Background()
}

type ContextKey string

const (
	RequestContextKey                 = ContextKey("request")
	AccessRequestContextKey           = ContextKey("accessRequest")
	AccessResponseContextKey          = ContextKey("accessResponse")
	AuthorizeRequestContextKey        = ContextKey("authorizeRequest")
	AuthorizeResponseContextKey       = ContextKey("authorizeResponse")
	PushedAuthorizeResponseContextKey = ContextKey("pushedAuthorizeResponse")
)
