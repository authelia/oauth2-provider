// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package jwt

import "errors"

// IsTimingValidationError reports that err is a validation failure of only the 'iat' or 'nbf' claim. The parser returns
// an error of the key function as it is, so this establishes that a signature was verified only if the caller also knows
// the key function returned a key.
func IsTimingValidationError(err error) bool {
	validation, ok := errors.AsType[*ValidationError](err)
	if !ok || validation.Errors == 0 {
		return false
	}

	return validation.Errors&^(ValidationErrorIssuedAt|ValidationErrorNotValidYet) == 0
}
