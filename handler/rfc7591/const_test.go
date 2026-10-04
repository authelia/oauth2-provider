// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc7591

import "errors"

const (
	testEndpoint = "https://auth.example.com/register"
	testClientID = "abc"

	testAuthorizationDetailsTypeUnknown = "unknown"
	testAuthorizationDetailsTypeOther   = "other"
)

var (
	errTestCreateSessionFailed = errors.New("create access token session failed")
	errTestUpdateClientFailed  = errors.New("update client failed")
	errTestGetClientFailed     = errors.New("get client failed")
)
