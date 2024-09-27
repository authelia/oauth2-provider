// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package jwt

// Validation provides a backwards compatible error definition
// from `jwt-go` to `go-jose`.
const (
	ValidationErrorMalformed                      uint32 = 1 << iota // Token is malformed
	ValidationErrorMalformedNotCompactSerialized                     // Token is malformed specifically it does not have the compact serialized format.
	ValidationErrorUnverifiable                                      // Token could not be verified because of signing problems
	ValidationErrorSignatureInvalid                                  // Signature validation failed.
	ValidationErrorHeaderKeyIDInvalid                                // Header KID invalid error.
	ValidationErrorHeaderAlgorithmInvalid                            // Header ALG invalid error.
	ValidationErrorHeaderTypeInvalid                                 // Header TYP invalid error.
	ValidationErrorHeaderEncryptionTypeInvalid                       // Header TYP invalid error (JWE).
	ValidationErrorHeaderContentTypeInvalid                          // Header TYP invalid error (JWE).
	ValidationErrorHeaderEncryptionKeyIDInvalid                      // Header KID invalid error (JWE).
	ValidationErrorHeaderKeyAlgorithmInvalid                         // Header ALG invalid error (JWE).
	ValidationErrorHeaderContentEncryptionInvalid                    // Header ENC invalid error (JWE).
	ValidationErrorId                                                // Claim JTI validation failed.
	ValidationErrorAudience                                          // Claim AUD validation failed.
	ValidationErrorExpired                                           // Claim EXP validation failed.
	ValidationErrorIssuedAt                                          // Claim IAT validation failed.
	ValidationErrorNotValidYet                                       // Claim NBF validation failed.
	ValidationErrorIssuer                                            // Claim ISS validation failed.
	ValidationErrorSubject                                           // Claim SUB validation failed.
	ValidationErrorClaimsInvalid                                     // Generic claims validation error.
)

// The ValidationError is an error implementation from Parse if token is not valid.
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
