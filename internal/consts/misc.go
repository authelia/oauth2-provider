// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package consts

const (
	AccessResponseRefreshToken      = valueRefreshToken
	AccessResponseAccessToken       = valueAccessToken
	AccessResponseIDToken           = valueIDToken
	AccessResponseExpiresIn         = "expires_in"
	AccessResponseScope             = valueScope
	AccessResponseAuthorizationCode = valueCode
	AccessResponseTokenType         = "token_type"
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

const (
	CIBAResponseAuthRequestID = "auth_req_id"
	CIBAResponseExpiresIn     = valueExpiresIn
	CIBAResponseInterval      = "interval"
)

// OpenID Connect CIBA backchannel token delivery modes per Section 4 of the specification.
const (
	CIBATokenDeliveryModePoll = "poll"
	CIBATokenDeliveryModePing = "ping"
	CIBATokenDeliveryModePush = "push"
)

// OpenID Connect CIBA client notification payload fields per Sections 10.2 and 10.3 of the specification.
const (
	CIBANotificationAuthRequestID    = "auth_req_id"
	CIBANotificationAccessToken      = valueAccessToken
	CIBANotificationTokenType        = "token_type"
	CIBANotificationRefreshToken     = valueRefreshToken
	CIBANotificationExpiresIn        = valueExpiresIn
	CIBANotificationIDToken          = valueIDToken
	CIBANotificationScope            = valueScope
	CIBANotificationError            = "error"
	CIBANotificationErrorDescription = "error_description"
)
