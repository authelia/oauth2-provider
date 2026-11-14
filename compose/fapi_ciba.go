// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package compose

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"authelia.com/provider/jose"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/handler/openid"
	"authelia.com/provider/oauth2/handler/rfc7523"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/token/jwt"
)

const (
	fapiCIBADocument                     = "FAPI-CIBA Profile"
	fapiCIBASectionAuthorizationServer   = "4.1.1"
	fapiCIBASectionAlgorithms            = "5.10"
	fapiCIBASectionEncryptionAlgorithms  = "5.11"
	fapiCIBAMaximumSignedRequestLifetime = 60 * time.Minute
)

// ApplyFAPICIBAProfile applies the FAPI-CIBA profile (editor's copy 2026-06-26) on top of ApplyFAPI2SecurityProfile,
// which must be applied first. It removes the push token delivery mode and adds the poll mode, requires a
// 'binding_message' unless the request carries authorization details of a type which identifies a unique
// authorization context, bounds a signed authentication request to a lifetime of at most 60 minutes, requires the
// issuer as the sole client assertion audience at the backchannel authentication endpoint, permits only the PS256 and
// ES256 JWS algorithms for signed authentication requests, client assertions, request objects, DPoP proofs, JWT bearer
// grant assertions, and signed authorization and introspection responses, and removes the RSA1_5 JWE algorithm from
// every response encryption, client assertion decryption and request object decryption algorithm list. A value
// already within the profile is kept.
//
// It does not register handlers or require 'request_context', which the profile leaves optional, or restrict the keys
// which sign the ID Tokens, UserInfo responses and JWT access tokens the server issues, which must use PS256 or ES256,
// so ValidateFAPICIBAProfile must still be called once the provider is composed.
//
// See: https://openid.net/specs/fapi-ciba.html#section-4.1.1
func ApplyFAPICIBAProfile(config *oauth2.Config) {
	modes := slices.DeleteFunc(slices.Clone(config.CIBATokenDeliveryModes), func(mode string) bool {
		return mode == consts.CIBAModePush
	})

	switch {
	case len(modes) == 0:
		modes = append(modes, consts.CIBAModePoll, consts.CIBAModePing)
	case !slices.Contains(modes, consts.CIBAModePoll):
		modes = append(modes, consts.CIBAModePoll)
	}

	config.CIBATokenDeliveryModes = modes
	config.CIBARequireBindingMessage = true
	config.CIBARequireSingleAudienceAssertion = true

	if config.CIBASignedRequestMaximumLifetime <= 0 || config.CIBASignedRequestMaximumLifetime > fapiCIBAMaximumSignedRequestLifetime {
		config.CIBASignedRequestMaximumLifetime = fapiCIBAMaximumSignedRequestLifetime
	}

	// See: https://openid.net/specs/fapi-ciba.html#section-5.10
	config.CIBARequestSigningAlgValues = fapi2Permitted(config.CIBARequestSigningAlgValues, oauth2.FAPICIBASigningAlgValues)
	config.ClientAssertionSigningAlgValues = fapi2Permitted(config.ClientAssertionSigningAlgValues, oauth2.FAPICIBASigningAlgValues)
	config.RequestObjectSigningAlgValues = fapi2Permitted(config.RequestObjectSigningAlgValues, oauth2.FAPICIBASigningAlgValues)
	config.DPoPAllowedJWSAlgorithms = fapi2Permitted(config.DPoPAllowedJWSAlgorithms, oauth2.FAPICIBASigningAlgValues)
	config.RFC7523AssertionSigningAlgValues = fapi2Permitted(config.RFC7523AssertionSigningAlgValues, oauth2.FAPICIBASigningAlgValues)
	config.AuthorizationSignedResponseAlgValues = fapi2Permitted(config.AuthorizationSignedResponseAlgValues, oauth2.FAPICIBASigningAlgValues)
	config.IntrospectionSignedResponseAlgValues = fapi2Permitted(config.IntrospectionSignedResponseAlgValues, oauth2.FAPICIBASigningAlgValues)

	if len(config.RevocationEndpointAuthSigningAlgValues) != 0 {
		config.RevocationEndpointAuthSigningAlgValues = fapi2Permitted(config.RevocationEndpointAuthSigningAlgValues, oauth2.FAPICIBASigningAlgValues)
	}

	if len(config.IntrospectionEndpointAuthSigningAlgValues) != 0 {
		config.IntrospectionEndpointAuthSigningAlgValues = fapi2Permitted(config.IntrospectionEndpointAuthSigningAlgValues, oauth2.FAPICIBASigningAlgValues)
	}

	ctx := context.Background()

	fapiCIBAWithoutRSA15(&config.ClientAssertionEncryptionAlgValues, func() []string { return config.GetClientAssertionEncryptionAlgValues(ctx) })
	fapiCIBAWithoutRSA15(&config.RequestObjectEncryptionAlgValues, func() []string { return config.GetRequestObjectEncryptionAlgValues(ctx) })

	for _, target := range fapiCIBAResponseEncryptionTargets {
		algs := config.ResponseEncryptionAlgValues[target]

		fapiCIBAWithoutRSA15(&algs, func() []string {
			if len(algs) != 0 {
				return algs
			}

			defaults := make([]string, len(jwt.EncryptionKeyAlgorithms))

			for i, alg := range jwt.EncryptionKeyAlgorithms {
				defaults[i] = string(alg)
			}

			return defaults
		})

		if len(algs) == 0 {
			continue
		}

		if config.ResponseEncryptionAlgValues == nil {
			config.ResponseEncryptionAlgValues = map[oauth2.ResponseEncryptionTarget][]string{}
		}

		config.ResponseEncryptionAlgValues[target] = algs
	}
}

// ValidateFAPICIBAProfile returns an error joining every way the configuration and the handlers registered with it
// fail the authorization server requirements of the FAPI-CIBA profile on a FAPI 2.0 base, including those
// ValidateFAPI2SecurityProfile returns, or nil when they meet them. Call it once the provider is composed. It does not
// check the clients, which must be confidential and register the poll or ping token delivery mode, or the keys which
// sign the ID Tokens, UserInfo responses and JWT access tokens the server issues and their signing algorithms, which
// the configuration does not expose.
//
// See: https://openid.net/specs/fapi-ciba.html#section-4.1.1
func ValidateFAPICIBAProfile(ctx context.Context, config oauth2.Configurator) (err error) {
	v := &fapi2Violations{document: fapiCIBADocument}

	if err = ValidateFAPI2SecurityProfile(ctx, config); err != nil {
		v.fail(fapiCIBASectionAuthorizationServer, "the FAPI 2.0 Security Profile requirements must be met, but they are not")
		v.errs = append(v.errs, err)
	}

	v.cibaAuthorizationServer(ctx, config)
	v.cibaAlgorithms(ctx, config)
	v.cibaEncryptionAlgorithms(ctx, config)

	return errors.Join(v.errs...)
}

func (v *fapi2Violations) cibaAuthorizationServer(ctx context.Context, config oauth2.Configurator) {
	if methods := oauth2.SupportedEndpointAuthMethods(ctx, config, oauth2.ClientAuthEndpointBackChannelAuthentication); slices.Contains(methods, consts.ClientAuthMethodNone) {
		v.fail(fapiCIBASectionAuthorizationServer, "only confidential clients may be supported, but the %s endpoint accepts the client authentication method '%s'", oauth2.ClientAuthEndpointBackChannelAuthentication, consts.ClientAuthMethodNone)
	}

	if !config.GetCIBARequireBindingMessage(ctx) {
		v.fail(fapiCIBASectionAuthorizationServer, "a unique authorization context or a 'binding_message' must be required, but CIBARequireBindingMessage is not set")
	}

	modes := config.GetCIBATokenDeliveryModes(ctx)

	if slices.Contains(modes, consts.CIBAModePush) {
		v.fail(fapiCIBASectionAuthorizationServer, "the push token delivery mode must not be supported, but the token delivery modes are '%s'", strings.Join(modes, "', '"))
	}

	if !slices.Contains(modes, consts.CIBAModePoll) {
		v.fail(fapiCIBASectionAuthorizationServer, "the poll token delivery mode must be supported, but the token delivery modes are '%s'", strings.Join(modes, "', '"))
	}

	if !fapi2Registered[*openid.OpenIDConnectCIBAHandler](config.GetTokenEndpointHandlers(ctx)) {
		v.fail(fapiCIBASectionAuthorizationServer, "the 'acr' claim must be returned in the ID Token when requested, but the OpenID Connect CIBA handler is not registered")
	}

	if lifetime := config.GetCIBASignedRequestMaximumLifetime(ctx); lifetime > fapiCIBAMaximumSignedRequestLifetime {
		v.fail(fapiCIBASectionAuthorizationServer, "a signed authentication request must have a lifetime of at most %s, but CIBASignedRequestMaximumLifetime is %s", fapiCIBAMaximumSignedRequestLifetime, lifetime)
	}

	if config.GetDisableClientAssertionIssuerAudience(ctx) {
		v.fail(fapiCIBASectionAuthorizationServer, "the issuer must be the sole client assertion audience, but DisableClientAssertionIssuerAudience is set")
	}
}

func (v *fapi2Violations) cibaAlgorithms(ctx context.Context, config oauth2.Configurator) {
	permitted := oauth2.FAPICIBASigningAlgValues

	// An empty list means signed authentication requests are not supported, which the profile permits on FAPI 2.0.
	if algs := config.GetCIBARequestSigningAlgValues(ctx); len(algs) != 0 && !fapi2Subset(algs, permitted) {
		v.fail(fapiCIBASectionAlgorithms, "the signed authentication request algorithms '%s' include one not permitted", strings.Join(algs, "', '"))
	}

	if algs := config.GetClientAssertionSigningAlgValues(ctx); !fapi2Subset(algs, permitted) {
		v.fail(fapiCIBASectionAlgorithms, "the client assertion algorithms '%s' include one not permitted", strings.Join(algs, "', '"))
	}

	if algs := oauth2.SupportedEndpointAuthSigningAlgValues(ctx, config, oauth2.ClientAuthEndpointRevocation); !fapi2Subset(algs, permitted) {
		v.fail(fapiCIBASectionAlgorithms, "the revocation endpoint client assertion algorithms '%s' include one not permitted", strings.Join(algs, "', '"))
	}

	if len(config.GetTokenIntrospectionHandlers(ctx)) != 0 {
		if algs := oauth2.SupportedEndpointAuthSigningAlgValues(ctx, config, oauth2.ClientAuthEndpointIntrospection); !fapi2Subset(algs, permitted) {
			v.fail(fapiCIBASectionAlgorithms, "the introspection endpoint client assertion algorithms '%s' include one not permitted", strings.Join(algs, "', '"))
		}
	}

	if algs := config.GetRequestObjectSigningAlgValues(ctx); !fapi2Subset(algs, permitted) {
		v.fail(fapiCIBASectionAlgorithms, "the request object algorithms '%s' include one not permitted", strings.Join(algs, "', '"))
	}

	if config.GetDPoPEnabled(ctx) {
		if algs := config.GetDPoPAllowedJWSAlgorithms(ctx); !fapi2Subset(algs, permitted) {
			v.fail(fapiCIBASectionAlgorithms, "the DPoP proof algorithms '%s' include one not permitted", strings.Join(algs, "', '"))
		}
	}

	if fapi2Registered[*rfc7523.Handler](config.GetTokenEndpointHandlers(ctx)) {
		if p, ok := config.(oauth2.GrantAssertionAlgorithmsProvider); ok {
			if algs := p.GetRFC7523AssertionSigningAlgValues(ctx); !fapi2Subset(algs, permitted) {
				v.fail(fapiCIBASectionAlgorithms, "the JWT bearer grant assertion algorithms '%s' include one not permitted", strings.Join(algs, "', '"))
			}
		}
	}

	// An empty list means the response is not signed by this server.
	if algs := oauth2.SupportedAuthorizationSignedResponseAlgValues(ctx, config); len(algs) != 0 && !fapi2Subset(algs, permitted) {
		v.fail(fapiCIBASectionAlgorithms, "the authorization response algorithms '%s' include one not permitted, set through AuthorizationSignedResponseAlgValues", strings.Join(algs, "', '"))
	}

	if algs := oauth2.SupportedIntrospectionSignedResponseAlgValues(ctx, config); len(algs) != 0 && !fapi2Subset(algs, permitted) {
		v.fail(fapiCIBASectionAlgorithms, "the introspection response algorithms '%s' include one not permitted, set through IntrospectionSignedResponseAlgValues", strings.Join(algs, "', '"))
	}
}

func (v *fapi2Violations) cibaEncryptionAlgorithms(ctx context.Context, config oauth2.Configurator) {
	if algs := config.GetClientAssertionEncryptionAlgValues(ctx); slices.Contains(algs, string(jose.RSA1_5)) {
		v.fail(fapiCIBASectionEncryptionAlgorithms, "the RSA1_5 algorithm must not be used, but the client assertion encryption algorithms are '%s'", strings.Join(algs, "', '"))
	}

	if algs := config.GetRequestObjectEncryptionAlgValues(ctx); slices.Contains(algs, string(jose.RSA1_5)) {
		v.fail(fapiCIBASectionEncryptionAlgorithms, "the RSA1_5 algorithm must not be used, but the request object encryption algorithms are '%s'", strings.Join(algs, "', '"))
	}

	for _, target := range fapiCIBAResponseEncryptionTargets {
		if algs := config.GetResponseEncryptionAlgValues(ctx, target); slices.Contains(algs, string(jose.RSA1_5)) {
			v.fail(fapiCIBASectionEncryptionAlgorithms, "the RSA1_5 algorithm must not be used, but the %s response encryption algorithms are '%s'", target, strings.Join(algs, "', '"))
		}
	}
}

var fapiCIBAResponseEncryptionTargets = []oauth2.ResponseEncryptionTarget{
	oauth2.ResponseEncryptionTargetIDToken,
	oauth2.ResponseEncryptionTargetUserInfo,
	oauth2.ResponseEncryptionTargetAuthorization,
	oauth2.ResponseEncryptionTargetIntrospection,
	oauth2.ResponseEncryptionTargetAccessToken,
}

func fapiCIBAWithoutRSA15(configured *[]string, effective func() []string) {
	isRSA15 := func(alg string) bool { return alg == string(jose.RSA1_5) }

	if !slices.ContainsFunc(effective(), isRSA15) {
		return
	}

	kept := slices.DeleteFunc(slices.Clone(*configured), isRSA15)

	if len(kept) == 0 {
		*configured = nil
		kept = slices.DeleteFunc(slices.Clone(effective()), isRSA15)
	}

	*configured = kept
}
