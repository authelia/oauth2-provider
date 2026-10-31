// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc7591

import "errors"

const (
	testEndpoint = "https://auth.example.com/register"
	testClientID = "abc"

	testOnboardingClientID = "onboarding"
	testManagedClientID    = "client-a"
	testCaseSurfacePolicy  = "ShouldSurfaceThePolicy"

	testAuthorizationDetailsTypeUnknown = "unknown"
	testAuthorizationDetailsTypeOther   = "other"

	testRegistrationScope    = "authelia:oauth2:dynamic-client-registration"
	testJWTIssuer            = "https://auth.example.com"
	testJWTOtherIssuer       = "https://auth.example.co"
	testJWTCounterKey        = "session:" + testJWTRequestID
	testJWTRequestID         = "creation-token-request"
	testJWTTrustedIssuer     = "https://trusted.example.com"
	testJWTTrustedCounterKey = `jwt:["https://trusted.example.com","j1"]`
	testScopeRead            = "read"
	testAudienceWrong        = "urn:wrong"
)

var (
	errTestCreateSessionFailed = errors.New("create access token session failed")
	errTestUpdateClientFailed  = errors.New("update client failed")
	errTestGetClientFailed     = errors.New("get client failed")
)
