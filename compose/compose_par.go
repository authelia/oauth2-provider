// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package compose

import (
	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/handler/par"
)

// PushedAuthorizeHandlerFactory creates the basic PAR handler
func PushedAuthorizeHandlerFactory(config oauth2.Configurator, storage any, strategy any) any {
	return &par.PushedAuthorizeHandler{
		Storage: storage,
		Config:  config,
	}
}
