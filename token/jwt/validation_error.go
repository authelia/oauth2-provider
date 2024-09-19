// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package jwt

// Validation provides a backwards compatible error definition
// from `jwt-go` to `go-jose`.
// The sourcecode was taken from https://github.com/dgrijalva/jwt-go/blob/master/errors.go
//
// > The errors that might occur when parsing and validating a token
const (
	ValidationErrorMalformed        uint32 = 1 << iota // Token is malformed
	ValidationErrorUnverifiable                        // Token could not be verified because of signing problems
	ValidationErrorSignatureInvalid                    // Signature validation failed

	// Standard Claim validation errors
	ValidationErrorId               // Claim JTI validation failed
	ValidationErrorAudience         // Claim AUD validation failed
	ValidationErrorExpired          // Claim EXP validation failed
	ValidationErrorIssuedAt         // Claim IAT validation failed
	ValidationErrorNotValidYet      // Claim NBF validation failed
	ValidationErrorIssuer           // Claim ISS validation failed
	ValidationErrorSubject          // Claim SUB validation failed
	ValidationErrorTypInvalid       // Header TYP invalid error
	ValidationErrorKeyIDInvalid     // Header KID invalid error
	ValidationErrorAlgorithmInvalid // Header ALG invalid error
	ValidationErrorClaimsInvalid    // Generic claims validation error
)

// The error from Parse if token is not valid
type ValidationError struct {
	Inner  error  // stores the error returned by external dependencies, i.e.: KeyFunc
	Errors uint32 // bitfield.  see ValidationError... constants
	text   string // errors that do not have a valid error just have text
}

// Validation error is an error type
func (e ValidationError) Error() string {
	switch {
	case e.Inner != nil:
		return e.Inner.Error()
	case len(e.text) != 0:
		return e.text
	default:
		return "token is invalid"
	}
}

// No errors
func (e *ValidationError) valid() bool {
	return e.Errors == 0
}

func (e *ValidationError) Has(verr uint32) bool {
	return (e.Errors & verr) != 0
}
