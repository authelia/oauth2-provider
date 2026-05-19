// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package jwt

import "time"

var (
	MarshalSingleStringAsArray = true
	TimePrecision              = time.Second
	TimeFunc                   = time.Now
)
