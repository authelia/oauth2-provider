// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"authelia.com/provider/oauth2"
)

var (
	// ContextKeySkipStatelessIntrospection is utilized to communicate skipping StatelessJWTValidator. It is an alias of
	// oauth2.SkipStatelessIntrospectionContextKey.
	ContextKeySkipStatelessIntrospection = oauth2.SkipStatelessIntrospectionContextKey
)
