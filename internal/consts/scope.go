// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package consts

const (
	ScopeOpenID             = "openid"
	ScopeOffline            = "offline"
	ScopeOfflineAccess      = "offline_access"
	ScopeEmail              = "email"
	ScopeClientRegistration = "client_registration"

	// ScopeIntrospection is the scope an Access Token must carry to authenticate a request to the token
	// introspection endpoint. RFC 7662 defines no such scope, so this value is specific to this implementation and
	// interoperates with nothing. It is named after the endpoint it guards, symmetric with ScopeClientRegistration.
	ScopeIntrospection = "token_introspection"
)
