// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package slicesx

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSubset(t *testing.T) {
	assert.True(t, Subset([]string{"a", "b"}, []string{"b"}))
	assert.True(t, Subset([]string{"a", "b"}, []string{"b", "b", "a"}))
	assert.True(t, Subset([]string{"a"}, nil))
	assert.True(t, Subset[string](nil, nil))
	assert.False(t, Subset([]string{"a", "b"}, []string{"A"}))
	assert.False(t, Subset([]string{"a"}, []string{"a", "c"}))
	assert.False(t, Subset(nil, []int{1}))
}
