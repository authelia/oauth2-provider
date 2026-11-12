// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package slicesx

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUnique(t *testing.T) {
	type named []string

	assert.Equal(t, []string{"c", "a", "b"}, Unique([]string{"c", "c", "a", "b", "a"}))
	assert.Equal(t, named{"b", "a"}, Unique(named{"b", "a", "b"}))
	assert.Equal(t, []int{}, Unique([]int(nil)))
}
