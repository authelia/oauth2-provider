// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

// Package iox provides helpers for reading from an [io.Reader].
package iox

import (
	"io"
	"math"
)

// ReadLimited reads the reader to the end and returns the bytes read, or reports large without them when there are
// more than limit bytes. A limit of zero permits only an empty read, and a negative limit permits none.
// One byte over the limit is read to tell a read of the limit from a longer one, except at a limit of [math.MaxInt64]
// which is read without a bound.
func ReadLimited(reader io.Reader, limit int64) (data []byte, large bool, err error) {
	if limit < 0 {
		return nil, true, nil
	}

	if limit < math.MaxInt64 {
		reader = io.LimitReader(reader, limit+1)
	}

	if data, err = io.ReadAll(reader); err != nil {
		return nil, false, err
	}

	if int64(len(data)) > limit {
		return nil, true, nil
	}

	return data, false, nil
}
