// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package consts

const (
	// PromptTypeNone is the none prompt value from OpenID Connect Core 1.0.
	PromptTypeNone = valueNone
	// PromptTypeLogin is the login prompt value from OpenID Connect Core 1.0.
	PromptTypeLogin = "login"
	// PromptTypeConsent is the consent prompt value from OpenID Connect Core 1.0.
	PromptTypeConsent = "consent"
	// PromptTypeSelectAccount is the select_account prompt value from OpenID Connect Core 1.0.
	PromptTypeSelectAccount = "select_account"
)

// Proof Key Code Exchange Challenge SignatureAlgorithm strings.
const (
	PKCEChallengeMethodPlain  = "plain"
	PKCEChallengeMethodSHA256 = "S256"
)

const (
	// ClientAssertionTypeJWTBearer is the JWT bearer client assertion type from RFC 7523.
	ClientAssertionTypeJWTBearer = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" //nolint:gosec
)

const (
	// PrefixRequestURI is the request_uri prefix for pushed authorization requests from RFC 9126.
	PrefixRequestURI = "urn:ietf:params:oauth:request_uri:"
)

const (
	// CodeDevice is the device_code value.
	CodeDevice = valueDeviceCode
	// CodeUser is the user_code value.
	CodeUser = "user_code"
)
