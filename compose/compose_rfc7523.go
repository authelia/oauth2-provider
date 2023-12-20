// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package compose

import (
	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/handler/rfc7523"
)

// RFC7523AssertionGrantFactory creates an OAuth2 Authorize JWT Grant (using JWTs as Authorization Grants) handler
// and registers an access token, refresh token and authorize code validator.
func RFC7523AssertionGrantFactory(config oauth2.Configurator, storage any, strategy any) any {
	return &rfc7523.Handler{
		Storage: storage.(rfc7523.RFC7523KeyStorage),
		HandleHelper: &hoauth2.HandleHelper{
			AccessTokenStrategy: strategy.(hoauth2.AccessTokenStrategy),
			AccessTokenStorage:  storage.(hoauth2.AccessTokenStorage),
			Config:              config,
		},
		Config: config,
	}
}
