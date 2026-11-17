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
	// GetDescription returns the description of the error, the 'error_description' member.
	GetDescription() string
	// Error returns the error code, the 'error' member.
	Error() string
	// Reason returns the hint of the error, the 'error_hint' member.
	Reason() string
	// StatusCode returns the HTTP status code of the response.
	StatusCode() int
}
