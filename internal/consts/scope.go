// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package consts

const (
	// ScopeOpenID is the openid scope from OpenID Connect Core 1.0.
	ScopeOpenID = "openid"
	// ScopeOffline is the offline scope, a legacy alias of ScopeOfflineAccess.
	ScopeOffline = "offline"
	// ScopeOfflineAccess is the offline_access scope from OpenID Connect Core 1.0.
	ScopeOfflineAccess = "offline_access"
	// ScopeEmail is the email scope from OpenID Connect Core 1.0.
	ScopeEmail = "email"
	// ScopeBoundKey is the bound_key scope.
	ScopeBoundKey = "bound_key"

	// ScopeUserinfoCredentialDraft00 is the scope requesting a userinfo credential, from an early draft specification.
	ScopeUserinfoCredentialDraft00 = "userinfo_credential_draft_00"
)

// The following scopes are special scopes for particular purposes.
const (
	ScopeClientRegistration = "authelia:oauth2:dynamic-client-registration"
	ScopeIntrospection      = "authelia:oauth2:token_introspection"
	ScopeSSFRead            = "ssf.read"
	ScopeSSFManage          = "ssf.manage"
)
