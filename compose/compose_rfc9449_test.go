// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package compose

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/handler/rfc9449"
	"authelia.com/provider/oauth2/storage"
)

func TestDPoPFactory(t *testing.T) {
	config := &oauth2.Config{DPoPEnabled: true}
	store := storage.NewMemoryStore()

	h := DPoPFactory(config, store, nil)

	require.IsType(t, &rfc9449.Handler{}, h)
	assert.NotNil(t, config.DPoPStrategy)

	var _ oauth2.TokenEndpointHandler = h.(*rfc9449.Handler)
	var _ oauth2.AuthorizeEndpointHandler = h.(*rfc9449.Handler)
}

func TestDPoPFactoryPanicsWithoutUsableStrategy(t *testing.T) {
	config := &oauth2.Config{DPoPEnabled: true}

	assert.Panics(t, func() {
		DPoPFactory(config, struct{}{}, nil)
	})

	assert.Nil(t, config.DPoPStrategy)
}
