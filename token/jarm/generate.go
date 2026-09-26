// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package jarm

import (
	"context"
	"errors"
	"net/url"

	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/token/jwt"
)

// EncodeParameters takes the result from jarm.Generate and turns it into parameters in the form of url.Values.
func EncodeParameters(token, _ string, tErr error) (parameters url.Values, err error) {
	if tErr != nil {
		return nil, tErr
	}

	return url.Values{consts.FormParameterResponse: []string{token}}, nil
}

// Generate generates the token and signature for a JARM response. The issuer is always the configured JARM issuer, and
// the session argument is not used.
func Generate(ctx context.Context, config Configurator, client Client, _ any, parameters url.Values) (token, signature string, err error) {
	headers := map[string]any{}

	if alg := client.GetAuthorizationSignedResponseAlg(); len(alg) > 0 {
		headers[jwt.JSONWebTokenHeaderAlgorithm] = alg
	}

	if kid := client.GetAuthorizationSignedResponseKeyID(); len(kid) > 0 {
		headers[jwt.JSONWebTokenHeaderKeyIdentifier] = kid
	}

	// JARM Section 2.1: every response, including an error response issued before a session exists, carries 'iss'.
	issuer := config.GetJWTSecuredAuthorizeResponseModeIssuer(ctx)
	if len(issuer) == 0 {
		return "", "", errors.New("the JARM response modes require the JWTSecuredAuthorizeResponseModeIssuerProvider to return an issuer but it didn't")
	}

	claims := jwt.NewJARMClaims(issuer, jwt.ClaimStrings{client.GetID()}, config.GetJWTSecuredAuthorizeResponseModeLifespan(ctx))

	for param, values := range parameters {
		switch len(values) {
		case 0:
			continue
		case 1:
			claims.Extra[param] = values[0]
		default:
			claims.Extra[param] = values
		}
	}

	var strategy jwt.Strategy

	if strategy = config.GetJWTSecuredAuthorizeResponseModeStrategy(ctx); strategy == nil {
		return "", "", errors.New("The JARM response modes require the JWTSecuredAuthorizeResponseModeSignerProvider to return a jwt.Strategy but it didn't.")
	}

	return strategy.Encode(ctx, claims.ToMapClaims(), jwt.WithHeaders(&jwt.Headers{Extra: headers}), jwt.WithJARMClient(client))
}
