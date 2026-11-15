// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package errorsx

const (
	fieldError            = "error"
	fieldErrorDescription = "error_description"
	fieldErrorHint        = "error_hint"
	fieldStatusCode       = "status_code"
)

// RFCError is an error that carries the members of an RFC 6749 error response.
type RFCError interface {
	GetDescription() string
	Error() string
	Reason() string
	StatusCode() int
}
