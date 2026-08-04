// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package compose

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/storage"
)

type composeAuthorizeBinder struct{}

func (c *composeAuthorizeBinder) BindAuthorizeRequest(context.Context, oauth2.AuthorizeRequester) error {
	return nil
}

type composeTokenBinder struct{}

func (c *composeTokenBinder) BindAccessRequest(context.Context, oauth2.AccessRequester) error {
	return nil
}

func (c *composeTokenBinder) PopulateBoundTokenEndpointResponse(context.Context, oauth2.AccessRequester, oauth2.AccessResponder) error {
	return nil
}

func TestComposeRegistersBindingHandlers(t *testing.T) {
	config := &oauth2.Config{GlobalSecret: []byte("some-cool-secret-that-is-32bytes")}

	Compose(
		config,
		storage.NewMemoryStore(),
		nil,
		func(oauth2.Configurator, any, any) any { return &composeAuthorizeBinder{} },
		func(oauth2.Configurator, any, any) any { return &composeTokenBinder{} },
	)

	assert.Len(t, config.GetAuthorizeEndpointBindingHandlers(context.Background()), 1)
	assert.Len(t, config.GetTokenEndpointBindingHandlers(context.Background()), 1)

	assert.Empty(t, config.GetAuthorizeEndpointHandlers(context.Background()))
	assert.Empty(t, config.GetTokenEndpointHandlers(context.Background()))
}
