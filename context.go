// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
)

// NewContext returns a fresh background context suitable for use as the root context of an OAuth 2.0 request flow.
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
