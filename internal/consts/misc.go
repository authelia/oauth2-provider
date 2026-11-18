// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package consts

const (
	// AccessResponseRefreshToken is the refresh_token token response parameter from RFC 6749.
	AccessResponseRefreshToken = valueRefreshToken
	// AccessResponseAccessToken is the access_token token response parameter from RFC 6749.
	AccessResponseAccessToken = valueAccessToken
	// AccessResponseIDToken is the id_token token response parameter from OpenID Connect Core 1.0.
	AccessResponseIDToken = valueIDToken
	// AccessResponseExpiresIn is the expires_in token response parameter from RFC 6749.
	AccessResponseExpiresIn = "expires_in"
	// AccessResponseRefreshTokenTimeout is the refresh_token_timeout token response parameter.
	AccessResponseRefreshTokenTimeout = "refresh_token_timeout"
	// AccessResponseAuthorizationExpiresIn is the authorization_expires_in token response parameter.
	AccessResponseAuthorizationExpiresIn = "authorization_expires_in"
	// AccessResponseScope is the scope token response parameter from RFC 6749.
	AccessResponseScope = valueScope
	// AccessResponseAuthorizationCode is the code response parameter carrying an authorization code.
	AccessResponseAuthorizationCode = valueCode
	// AccessResponseTokenType is the token_type token response parameter from RFC 6749.
	AccessResponseTokenType = "token_type"
	// AccessResponseAuthorizationDetails is the authorization_details token response parameter from RFC 9396.
	AccessResponseAuthorizationDetails = valueAuthorizationDetails
	// AccessResponseGrantID is the grant_id token response parameter from Grant Management for OAuth 2.0.
	AccessResponseGrantID = valueGrantID
)

const (
	// DeviceCodeResponseExpiresIn is the expires_in device authorization response parameter from RFC 8628.
	DeviceCodeResponseExpiresIn = valueExpiresIn
	// DeviceCodeResponseStatus is the status device authorization response parameter, a non-standard extension.
	DeviceCodeResponseStatus = "status"
	// DeviceCodeResponseDeviceCode is the device_code device authorization response parameter from RFC 8628.
	DeviceCodeResponseDeviceCode = valueDeviceCode
	// DeviceCodeResponseUserCode is the user_code device authorization response parameter from RFC 8628.
	DeviceCodeResponseUserCode = valueUserCode
	// DeviceCodeResponseVerificationURI is the verification_uri device authorization response parameter from RFC 8628.
	DeviceCodeResponseVerificationURI = "verification_uri"
	// DeviceCodeResponseVerificationURIComplete is the verification_uri_complete device authorization response parameter from RFC 8628.
	DeviceCodeResponseVerificationURIComplete = "verification_uri_complete"
	// DeviceCodeResponseInterval is the interval device authorization response parameter from RFC 8628.
	DeviceCodeResponseInterval = "interval"
)

// Grant management actions.
//
// See: https://openid.net/specs/oauth-v2-grant-management.html#section-5.2
//
// See: https://openid.net/specs/oauth-v2-grant-management.html#section-7.1
const (
	GrantManagementActionCreate  = "create"
	GrantManagementActionMerge   = "merge"
	GrantManagementActionReplace = "replace"
	GrantManagementActionQuery   = "query"
	GrantManagementActionRevoke  = "revoke"
)

// Parties which update a grant.
//
// See: https://openid.net/specs/oauth-v2-grant-management.html#section-5.6
const (
	GrantUpdatedByClient              = "client"
	GrantUpdatedByAuthorizationServer = "authorization_server"
)

// ErrorInvalidGrantID is the invalid_grant_id authorization error code from Grant Management for OAuth 2.0.
//
// See: https://openid.net/specs/oauth-v2-grant-management.html#section-5.4
const ErrorInvalidGrantID = "invalid_grant_id"

// CIBA token delivery modes.
//
// See: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#section-4
const (
	CIBAModePoll = "poll"
	CIBAModePing = "ping"
	CIBAModePush = "push"
)
