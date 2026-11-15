// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package openid

import (
	"github.com/pkg/errors"
)

var (
	// ErrInvalidSession is returned when a session is not the expected type.
	ErrInvalidSession = errors.New("Session type mismatch")
)
