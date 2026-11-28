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
	"authelia.com/provider/oauth2/token/jwt"
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

	// FAPI2SecurityProfileMinimumClockSkew is the shortest time into the future the FAPI 2.0 Security Profile requires
	// an 'iat' or 'nbf' claim to be accepted.
	//
	// See: https://openid.net/specs/fapi-security-profile-2_0-final.html#section-5.3.2.1
	FAPI2SecurityProfileMinimumClockSkew = 10 * time.Second

	// FAPI2SecurityProfileMaximumClockSkew is the time into the future beyond which the FAPI 2.0 Security Profile
	// requires an 'iat' or 'nbf' claim to be rejected.
	//
	// See: https://openid.net/specs/fapi-security-profile-2_0-final.html#section-5.3.2.1
	FAPI2SecurityProfileMaximumClockSkew = time.Minute
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
// requests with a redirect URI, use the 'code' response type and PKCE with S256, and never use the resource owner
// password credentials grant. Its client assertions must carry the issuer as their sole audience, as a string. The
// JWTs it sends, being client assertions, request objects, JWT bearer grant assertions and DPoP proofs, must use a
// permitted algorithm, and an 'iat' or 'nbf' claim is accepted up to between 10 and 60 seconds in the future. The JWTs
// issued to it must be signed with a permitted algorithm, so its registered response algorithms must be permitted
// ones. Its authorization responses carry the RFC 9207 'iss' parameter when an issuer is configured. Its access tokens
// are sender-constrained and refused when presented unbound, its refresh tokens are not rotated, its authorization
// codes last at most 60 seconds, and its pushed authorization requests expire in less than 600 seconds. What the
// handlers registered determine, such as the response types served, is left to the configuration; see
// compose.ValidateFAPI2SecurityProfile.
//
// See: https://openid.net/specs/fapi-security-profile-2_0-final.html#section-5.3.2
type FAPI2SecurityProfileClient interface {
	// GetFAPI2SecurityProfile should return true if this client is held to the FAPI 2.0 Security Profile.
	GetFAPI2SecurityProfile() (enabled bool)

	Client
}

// IsFAPI2SecurityProfile returns true if config is a FAPI2SecurityProfileProvider holding the whole authorization
// server to the FAPI 2.0 Security Profile, or ctx is one the authorization server passes to a strategy it calls while
// held to the profile, such as a SecurityEventTokenStrategy, which can therefore apply the profile with a nil config.
func IsFAPI2SecurityProfile(ctx context.Context, config any) (enabled bool) {
	if held, _ := ctx.Value(fapi2SecurityProfileContextKey).(bool); held {
		return true
	}

	p, ok := config.(FAPI2SecurityProfileProvider)

	return ok && p.GetFAPI2SecurityProfile(ctx)
}

const fapi2SecurityProfileContextKey = ContextKey("fapi2SecurityProfile")

func newFAPI2SecurityProfileContext(ctx context.Context, config any) context.Context {
	if !IsFAPI2SecurityProfile(ctx, config) {
		return ctx
	}

	return context.WithValue(ctx, fapi2SecurityProfileContextKey, true)
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
// at most FAPI2SecurityProfileMaximumPushedAuthorizeContextLifespan when the client or the authorization server is held
// to the FAPI 2.0 Security Profile.
//
// See: https://openid.net/specs/fapi-security-profile-2_0-final.html#section-5.3.2.2
func GetPushedAuthorizeContextLifespan(ctx context.Context, config PushedAuthorizeRequestConfigProvider, client Client) (lifespan time.Duration) {
	lifespan = config.GetPushedAuthorizeContextLifespan(ctx)

	if c, ok := client.(PushedAuthorizationRequestClient); ok && c.GetPushedAuthorizeContextLifespan() > 0 {
		lifespan = c.GetPushedAuthorizeContextLifespan()
	}

	if IsFAPI2SecurityProfile(ctx, config) || IsFAPI2SecurityProfileClient(client) {
		return min(lifespan, FAPI2SecurityProfileMaximumPushedAuthorizeContextLifespan)
	}

	return lifespan
}

// GetJWTClockSkew returns how far into the future an 'iat' or 'nbf' claim may be in a JWT received from the client: the
// configured clock skew, held between FAPI2SecurityProfileMinimumClockSkew and FAPI2SecurityProfileMaximumClockSkew for
// a client held to the FAPI 2.0 Security Profile.
//
// See: https://openid.net/specs/fapi-security-profile-2_0-final.html#section-5.3.2.1
func GetJWTClockSkew(ctx context.Context, config JWTClockSkewProvider, client Client) (skew time.Duration) {
	return fapi2ClockSkew(client, config.GetJWTClockSkew(ctx))
}

// DPoPClockSkewProvider returns the provider for configuring the clock skew permitted when validating a DPoP proof.
type DPoPClockSkewProvider interface {
	// GetDPoPClockSkew returns the tolerance allowed when judging the 'iat' claim of a DPoP proof.
	GetDPoPClockSkew(ctx context.Context) (skew time.Duration)
}

// GetDPoPClockSkew returns the tolerance allowed when judging the 'iat' claim of a DPoP proof from the client: the
// configured clock skew, held between FAPI2SecurityProfileMinimumClockSkew and FAPI2SecurityProfileMaximumClockSkew for
// a client held to the FAPI 2.0 Security Profile.
//
// See: https://openid.net/specs/fapi-security-profile-2_0-final.html#section-5.3.2.1
func GetDPoPClockSkew(ctx context.Context, config DPoPClockSkewProvider, client Client) (skew time.Duration) {
	return fapi2ClockSkew(client, config.GetDPoPClockSkew(ctx))
}

// FilterFAPI2SecurityProfileSigningAlgValues returns the algs which FAPI2SecurityProfileSigningAlgValues holds for a
// client held to the FAPI 2.0 Security Profile, and the algs unchanged for any other client.
//
// See: https://openid.net/specs/fapi-security-profile-2_0-final.html#section-5.4.1
func FilterFAPI2SecurityProfileSigningAlgValues(client Client, algs []string) (permitted []string) {
	if !IsFAPI2SecurityProfileClient(client) {
		return algs
	}

	return slices.DeleteFunc(slices.Clone(algs), func(alg string) bool { return !slices.Contains(FAPI2SecurityProfileSigningAlgValues, alg) })
}

// FAPI2SecurityProfileEncodeOptions returns the jwt.Strategy options which make Encode refuse to issue a JWT that is
// unsigned or signed with an algorithm outside FAPI2SecurityProfileSigningAlgValues when config holds the whole
// authorization server to the FAPI 2.0 Security Profile or the client is held to it, and nil otherwise.
//
// See: https://openid.net/specs/fapi-security-profile-2_0-final.html#section-5.4.1
func FAPI2SecurityProfileEncodeOptions(ctx context.Context, config any, client Client) (opts []jwt.StrategyOpt) {
	if !IsFAPI2SecurityProfile(ctx, config) && !IsFAPI2SecurityProfileClient(client) {
		return nil
	}

	return []jwt.StrategyOpt{jwt.WithSigAlgorithm(jwt.ToSignatureAlgorithms(FAPI2SecurityProfileSigningAlgValues)...)}
}

// NewDPoPProofClientContext returns a context carrying the client a DPoP proof is validated for, which lets a
// DPoPStrategy apply the client's own policy to the proof.
func NewDPoPProofClientContext(ctx context.Context, client Client) context.Context {
	if client == nil {
		return ctx
	}

	return context.WithValue(ctx, DPoPProofClientContextKey, client)
}

// DPoPProofClientFromContext returns the client stored by NewDPoPProofClientContext, or nil if there is none.
func DPoPProofClientFromContext(ctx context.Context) (client Client) {
	client, _ = ctx.Value(DPoPProofClientContextKey).(Client)

	return client
}

func validateFAPI2ResponseTypes(client Client, responseTypes Arguments) (err error) {
	if !IsFAPI2SecurityProfileClient(client) || responseTypes.ExactOne(consts.ResponseTypeAuthorizationCodeFlow) {
		return nil
	}

	return errorsx.WithStack(ErrUnsupportedResponseType.WithHint("The OAuth 2.0 Client is not allowed to request the value of the 'response_type' parameter.").WithDebugf("The client with id '%s' is held to the FAPI 2.0 Security Profile, which permits only the 'code' response type.", client.GetID()))
}

func fapi2ClockSkew(client Client, skew time.Duration) time.Duration {
	if !IsFAPI2SecurityProfileClient(client) {
		return skew
	}

	return min(max(skew, FAPI2SecurityProfileMinimumClockSkew), FAPI2SecurityProfileMaximumClockSkew)
}
