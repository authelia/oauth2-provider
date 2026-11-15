// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package jwt

import "time"

var (
	// MarshalSingleStringAsArray controls whether a ClaimStrings with a single value marshals as an array rather than a string.
	MarshalSingleStringAsArray = true
	// TimePrecision is the precision used when converting times to a NumericDate.
	TimePrecision = time.Second
	// TimeFunc returns the current time when validating claims.
	TimeFunc = time.Now
)
