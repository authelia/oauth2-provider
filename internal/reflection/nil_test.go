// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package reflection

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsNil(t *testing.T) {
	type example struct{}

	var (
		typed    *example
		iface    any = typed
		m        map[string]string
		nonempty = &example{}
	)

	assert.True(t, IsNil(nil))
	assert.True(t, IsNil(typed))
	assert.True(t, IsNil(iface))
	assert.True(t, IsNil(m))
	assert.False(t, IsNil(nonempty))
	assert.False(t, IsNil(example{}))
	assert.False(t, IsNil(1))
}
