// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package compose

import (
	"github.com/authelia/goauth2"
	"github.com/authelia/goauth2/handler/oauth2"
	"github.com/authelia/goauth2/handler/rfc7523"
)

// RFC7523AssertionGrantFactory creates an OAuth2 Authorize JWT Grant (using JWTs as Authorization Grants) handler
// and registers an access token, refresh token and authorize code validator.
func RFC7523AssertionGrantFactory(config goauth2.Configurator, storage interface{}, strategy interface{}) interface{} {
	return &rfc7523.Handler{
		Storage: storage.(rfc7523.RFC7523KeyStorage),
		HandleHelper: &oauth2.HandleHelper{
			AccessTokenStrategy: strategy.(oauth2.AccessTokenStrategy),
			AccessTokenStorage:  storage.(oauth2.AccessTokenStorage),
			Config:              config,
		},
		Config: config,
	}
}
