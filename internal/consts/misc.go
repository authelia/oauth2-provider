// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package consts

const (
	AccessResponseRefreshToken           = valueRefreshToken
	AccessResponseAccessToken            = valueAccessToken
	AccessResponseIDToken                = valueIDToken
	AccessResponseExpiresIn              = "expires_in"
	AccessResponseRefreshTokenTimeout    = "refresh_token_timeout"
	AccessResponseAuthorizationExpiresIn = "authorization_expires_in"
	AccessResponseScope                  = valueScope
	AccessResponseAuthorizationCode      = valueCode
	AccessResponseTokenType              = "token_type"
	AccessResponseAuthorizationDetails   = valueAuthorizationDetails
)

const (
	DeviceCodeResponseExpiresIn               = valueExpiresIn
	DeviceCodeResponseStatus                  = "status"
	DeviceCodeResponseDeviceCode              = valueDeviceCode
	DeviceCodeResponseUserCode                = valueUserCode
	DeviceCodeResponseVerificationURI         = "verification_uri"
	DeviceCodeResponseVerificationURIComplete = "verification_uri_complete"
	DeviceCodeResponseInterval                = "interval"
)

// CIBA token delivery modes.
//
// See: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#section-4
const (
	CIBAModePoll = "poll"
	CIBAModePing = "ping"
	CIBAModePush = "push"
)
