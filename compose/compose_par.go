// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package compose

import (
	"github.com/authelia/goauth2"
	"github.com/authelia/goauth2/handler/par"
)

// PushedAuthorizeHandlerFactory creates the basic PAR handler
func PushedAuthorizeHandlerFactory(config goauth2.Configurator, storage interface{}, strategy interface{}) interface{} {
	return &par.PushedAuthorizeHandler{
		Storage: storage,
		Config:  config,
	}
}
