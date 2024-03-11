// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package compose

import (
	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/handler/pkce"
)

// OAuth2PKCEFactory creates a PKCE handler.
func OAuth2PKCEFactory(config oauth2.Configurator, storage any, strategy any) any {
	return &pkce.Handler{
		AuthorizeCodeStrategy: strategy.(hoauth2.AuthorizeCodeStrategy),
		Storage:               storage.(pkce.Storage),
		Config:                config,
	}
}
