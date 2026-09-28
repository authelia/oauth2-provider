// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewDeviceAuthorizeResponse(t *testing.T) {
	t.Run("ShouldAddHeader", func(t *testing.T) {
		response := NewDeviceAuthorizeResponse()

		require.NotPanics(t, func() {
			response.AddHeader("foo", "bar")
		})

		assert.Equal(t, "bar", response.GetHeader().Get("foo"))
	})
}
