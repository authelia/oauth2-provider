// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package consts

const (
	ScopeOpenID        = "openid"
	ScopeOffline       = "offline"
	ScopeOfflineAccess = "offline_access"
	ScopeEmail         = "email"
	ScopeBoundKey      = "bound_key"
)

// The following scopes are special scopes for particular purposes.
const (
	ScopeClientRegistration = "authelia:oauth2:client_registration"
	ScopeIntrospection      = "authelia:oauth2:token_introspection"
)
