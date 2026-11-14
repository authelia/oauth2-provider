// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"slices"
	"time"

	"authelia.com/provider/jose"

	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/x/errorsx"
)

const (
	// FAPI2SecurityProfileMaximumAuthorizeCodeLifespan is the longest lifetime the FAPI 2.0 Security Profile permits
	// for an authorization code.
	//
	// See: https://openid.net/specs/fapi-security-profile-2_0-final.html#section-5.3.2.1
	FAPI2SecurityProfileMaximumAuthorizeCodeLifespan = time.Minute

	// FAPI2SecurityProfileMaximumPushedAuthorizeContextLifespan is the longest pushed authorization request lifetime
	// below the 600 second 'expires_in' the FAPI 2.0 Security Profile requires it to be less than.
	//
	// See: https://openid.net/specs/fapi-security-profile-2_0-final.html#section-5.3.2.2
	FAPI2SecurityProfileMaximumPushedAuthorizeContextLifespan = 10*time.Minute - time.Second
)

var (
	// FAPI2SecurityProfileSigningAlgValues are the JWS algorithms the FAPI 2.0 Security Profile permits: PS256, ES256,
	// and EdDSA using the Ed25519 variant, also identified by the fully-specified Ed25519 of RFC 9864.
	//
	// See: https://openid.net/specs/fapi-security-profile-2_0-final.html#section-5.4.1
	FAPI2SecurityProfileSigningAlgValues = []string{string(jose.PS256), string(jose.ES256), string(jose.EdDSA), string(jose.Ed25519)}

	// FAPI2SecurityProfileClientAuthMethods are the client authentication methods the FAPI 2.0 Security Profile
	// permits.
	//
	// See: https://openid.net/specs/fapi-security-profile-2_0-final.html#section-5.3.2.1
	FAPI2SecurityProfileClientAuthMethods = []string{consts.ClientAuthMethodPrivateKeyJWT, consts.ClientAuthMethodTLSClientAuth, consts.ClientAuthMethodSelfSignedTLSClientAuth}

	// FAPICIBASigningAlgValues are the JWS algorithms the FAPI-CIBA profile permits clients and authorization servers
	// to use: PS256 and ES256.
	//
	// See: https://openid.net/specs/fapi-ciba.html#section-5.10
	FAPICIBASigningAlgValues = []string{string(jose.PS256), string(jose.ES256)}
)

// FAPI2SecurityProfileClient is a client held to the FAPI 2.0 Security Profile at every request it makes, whatever the
// provider-wide options. Such a client must authenticate with private_key_jwt or mutual-TLS, push its authorization
// requests with a redirect URI, use the 'code' response type and PKCE with S256, and sign its client assertions and
// request objects with a permitted algorithm. Its access tokens are sender-constrained, its refresh tokens are not
// rotated, its authorization codes last at most 60 seconds, and its pushed authorization requests expire in less than
// 600 seconds. The options which apply to every client, such as the RFC 9207 'iss' parameter and the DPoP proof
// algorithms, are left to the configuration; see compose.ValidateFAPI2SecurityProfile.
//
// See: https://openid.net/specs/fapi-security-profile-2_0-final.html#section-5.3.2
type FAPI2SecurityProfileClient interface {
	// GetFAPI2SecurityProfile should return true if this client is held to the FAPI 2.0 Security Profile.
	GetFAPI2SecurityProfile() (enabled bool)

	Client
}

// IsFAPI2SecurityProfileClient returns true if the client is a FAPI2SecurityProfileClient held to the profile.
func IsFAPI2SecurityProfileClient(client Client) (enabled bool) {
	c, ok := client.(FAPI2SecurityProfileClient)

	return ok && c.GetFAPI2SecurityProfile()
}

// GetAuthorizeCodeLifespan returns the lifetime of an authorization code issued to the client: the configured lifespan,
// at most FAPI2SecurityProfileMaximumAuthorizeCodeLifespan for a client held to the FAPI 2.0 Security Profile.
//
// See: https://openid.net/specs/fapi-security-profile-2_0-final.html#section-5.3.2.1
func GetAuthorizeCodeLifespan(ctx context.Context, config AuthorizeCodeLifespanProvider, client Client) (lifespan time.Duration) {
	lifespan = config.GetAuthorizeCodeLifespan(ctx)

	if IsFAPI2SecurityProfileClient(client) {
		return min(lifespan, FAPI2SecurityProfileMaximumAuthorizeCodeLifespan)
	}

	return lifespan
}

// GetPushedAuthorizeContextLifespan returns the lifetime of a pushed authorization request from the client: its own
// when it is a PushedAuthorizationRequestClient returning a positive duration, otherwise the configured lifespan, and
// at most FAPI2SecurityProfileMaximumPushedAuthorizeContextLifespan for a client held to the FAPI 2.0 Security Profile.
//
// See: https://openid.net/specs/fapi-security-profile-2_0-final.html#section-5.3.2.2
func GetPushedAuthorizeContextLifespan(ctx context.Context, config PushedAuthorizeRequestConfigProvider, client Client) (lifespan time.Duration) {
	lifespan = config.GetPushedAuthorizeContextLifespan(ctx)

	if c, ok := client.(PushedAuthorizationRequestClient); ok && c.GetPushedAuthorizeContextLifespan() > 0 {
		lifespan = c.GetPushedAuthorizeContextLifespan()
	}

	if IsFAPI2SecurityProfileClient(client) {
		return min(lifespan, FAPI2SecurityProfileMaximumPushedAuthorizeContextLifespan)
	}

	return lifespan
}

func validateFAPI2ResponseTypes(client Client, responseTypes Arguments) (err error) {
	if !IsFAPI2SecurityProfileClient(client) || responseTypes.ExactOne(consts.ResponseTypeAuthorizationCodeFlow) {
		return nil
	}

	return errorsx.WithStack(ErrUnsupportedResponseType.WithHint("The OAuth 2.0 Client is not allowed to request the value of the 'response_type' parameter.").WithDebugf("The client with id '%s' is held to the FAPI 2.0 Security Profile, which permits only the 'code' response type.", client.GetID()))
}

func fapi2SigningAlgValues(client Client, algs []string) []string {
	if !IsFAPI2SecurityProfileClient(client) {
		return algs
	}

	return slices.DeleteFunc(slices.Clone(algs), func(alg string) bool { return !slices.Contains(FAPI2SecurityProfileSigningAlgValues, alg) })
}
