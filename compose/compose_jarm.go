// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package compose

import (
	"context"
	"errors"

	"authelia.com/provider/oauth2"
)

// ErrJWTSecuredAuthorizeResponseModeIssuer is returned by ValidateJWTSecuredAuthorizeResponseMode when the JWT Secured
// Authorization Response Mode is enabled without an issuer.
var ErrJWTSecuredAuthorizeResponseModeIssuer = errors.New("oauth2: the JWT Secured Authorization Response Mode requires an issuer: set JWTSecuredAuthorizeResponseModeIssuer or IDTokenIssuer")

// ValidateJWTSecuredAuthorizeResponseMode returns ErrJWTSecuredAuthorizeResponseModeIssuer when the JWT Secured
// Authorization Response Mode is enabled, by setting JWTSecuredAuthorizeResponseModeStrategy, but no issuer resolves.
// JARM Section 2.1 requires every response, including an error response issued before a session exists, to carry the
// issuer. Compose calls it and panics on an error; a configuration which does not use Compose should call it once
// configured.
func ValidateJWTSecuredAuthorizeResponseMode(config *oauth2.Config) (err error) {
	ctx := context.Background()

	if config.GetJWTSecuredAuthorizeResponseModeStrategy(ctx) == nil || config.GetJWTSecuredAuthorizeResponseModeIssuer(ctx) != "" {
		return nil
	}

	return ErrJWTSecuredAuthorizeResponseModeIssuer
}
