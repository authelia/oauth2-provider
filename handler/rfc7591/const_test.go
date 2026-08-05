// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc7591

import "errors"

var (
	errTestCreateSessionFailed = errors.New("create access token session failed")
	errTestUpdateClientFailed  = errors.New("update client failed")
)

const (
	testEndpoint = "https://auth.example.com/register"
	testClientID = "abc"
)
