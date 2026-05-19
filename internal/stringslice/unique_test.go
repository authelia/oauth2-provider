// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package stringslice

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUnique(t *testing.T) {
	assert.EqualValues(t, []string{"foo", "bar", "baz"}, Unique([]string{"foo", "foo", "bar", "baz", "bar"}))
}
