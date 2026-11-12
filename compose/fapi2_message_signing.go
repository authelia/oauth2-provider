// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package compose

import (
	"context"
	"errors"
	"strings"
	"time"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/handler/par"
)

// FAPI2MessageSigningParts selects the parts of FAPI 2.0 Message Signing, which a deployment may implement separately.
//
// See: https://openid.net/specs/fapi-message-signing-2_0-final.html#section-5.1
type FAPI2MessageSigningParts uint8

const (
	// FAPI2MessageSigningRequests is signed authorization requests.
	//
	// See: https://openid.net/specs/fapi-message-signing-2_0-final.html#section-5.3
	FAPI2MessageSigningRequests FAPI2MessageSigningParts = 1 << iota

	// FAPI2MessageSigningResponses is signed authorization responses.
	//
	// See: https://openid.net/specs/fapi-message-signing-2_0-final.html#section-5.4
	FAPI2MessageSigningResponses

	// FAPI2MessageSigningIntrospection is signed introspection responses, and the restriction of the introspection
	// endpoint to resource servers which comes with them.
	//
	// See: https://openid.net/specs/fapi-message-signing-2_0-final.html#section-5.5
	// See: https://openid.net/specs/fapi-message-signing-2_0-final.html#section-6.2
	FAPI2MessageSigningIntrospection

	// FAPI2MessageSigningAll is every part of FAPI 2.0 Message Signing.
	FAPI2MessageSigningAll = FAPI2MessageSigningRequests | FAPI2MessageSigningResponses | FAPI2MessageSigningIntrospection
)

const fapi2MaximumRequestObjectLifetime = 60 * time.Minute

// ApplyFAPI2MessageSigning sets the options of config which the selected parts of FAPI 2.0 Message Signing require of
// an authorization server. For signed requests: request objects signed with a permitted algorithm are required, also at
// the pushed authorization request endpoint, which is required, with an 'aud', 'nbf' and 'exp' bounding them to at
// most 60 minutes. For signed responses: JWT Secured Authorization Response Mode responses are signed only with
// permitted algorithms. For signed introspection: introspection responses are signed only with permitted algorithms,
// and only a permitted client may call the endpoint. A value already within the profile is kept.
//
// It does not set Issuer or the strategies which sign responses, and cannot require a client to use JWT Secured
// Authorization Response Mode, which it does by registering only JWT response modes, so
// ValidateFAPI2MessageSigning must still be called once the provider is composed.
//
// See: https://openid.net/specs/fapi-message-signing-2_0-final.html#section-5
func ApplyFAPI2MessageSigning(config *oauth2.Config, parts FAPI2MessageSigningParts) {
	if parts&FAPI2MessageSigningRequests != 0 {
		config.RequireSignedRequestObject = true
		config.RequireSignedRequestObjectSkipPushedAuthorizationRequests = false
		config.RequirePushedAuthorizationRequests = true
		config.RequireRequestObjectAudienceAndLifetime = true
		config.RequestObjectSigningAlgValues = fapi2Permitted(config.RequestObjectSigningAlgValues, oauth2.FAPI2SecurityProfileSigningAlgValues)

		if config.RequestObjectMaximumLifetime < 0 || config.RequestObjectMaximumLifetime > fapi2MaximumRequestObjectLifetime {
			config.RequestObjectMaximumLifetime = 0
		}
	}

	if parts&FAPI2MessageSigningResponses != 0 {
		config.AuthorizationSignedResponseAlgValues = fapi2Permitted(config.AuthorizationSignedResponseAlgValues, oauth2.FAPI2SecurityProfileSigningAlgValues)
	}

	if parts&FAPI2MessageSigningIntrospection != 0 {
		config.IntrospectionSignedResponseAlgValues = fapi2Permitted(config.IntrospectionSignedResponseAlgValues, oauth2.FAPI2SecurityProfileSigningAlgValues)
		config.EnforceIntrospectionPermission = true
	}
}

// ValidateFAPI2MessageSigning returns an error joining every way the configuration and the handlers registered with it
// fail the authorization server requirements of the selected parts of FAPI 2.0 Message Signing, or nil when they meet
// them. Call it once the provider is composed. It does not check the clients, which must register only JWT response
// modes to be required to use JWT Secured Authorization Response Mode, and be permitted to introspect when they are
// resource servers.
//
// See: https://openid.net/specs/fapi-message-signing-2_0-final.html#section-5
func ValidateFAPI2MessageSigning(ctx context.Context, config oauth2.Configurator, parts FAPI2MessageSigningParts) (err error) {
	v := &fapi2Violations{document: "FAPI 2.0 Message Signing"}

	if parts&FAPI2MessageSigningRequests != 0 {
		v.signedRequests(ctx, config)
	}

	if parts&FAPI2MessageSigningResponses != 0 {
		v.signedResponses(ctx, config)
	}

	if parts&FAPI2MessageSigningIntrospection != 0 {
		v.signedIntrospection(ctx, config)
	}

	return errors.Join(v.errs...)
}

func (v *fapi2Violations) signedRequests(ctx context.Context, config oauth2.Configurator) {
	const section = "5.3.1"

	if !config.GetRequireSignedRequestObject(ctx) {
		v.fail(section, "signed request objects must be required, but RequireSignedRequestObject is not set")
	}

	if config.GetRequireSignedRequestObjectSkipPushedAuthorizationRequests(ctx) {
		v.fail(section, "signed request objects must be required at the pushed authorization request endpoint, but RequireSignedRequestObjectSkipPushedAuthorizationRequests is set")
	}

	if !config.GetRequirePushedAuthorizationRequests(ctx) {
		v.fail(section, "signed request objects must be sent to the pushed authorization request endpoint, but RequirePushedAuthorizationRequests is not set")
	}

	if !fapi2Registered[*par.PushedAuthorizeHandler](config.GetPushedAuthorizeEndpointHandlers(ctx)) {
		v.fail(section, "signed request objects must be sent to the pushed authorization request endpoint, but the pushed authorization request handler is not registered")
	}

	if !config.GetRequireRequestObjectAudienceAndLifetime(ctx) {
		v.fail(section, "request objects must carry 'aud', 'nbf' and 'exp', but RequireRequestObjectAudienceAndLifetime is not set")
	}

	if config.GetIssuer(ctx) == "" {
		v.fail(section, "request objects must carry the issuer as 'aud', but Issuer is not set")
	}

	if lifetime := config.GetRequestObjectMaximumLifetime(ctx); lifetime <= 0 || lifetime > fapi2MaximumRequestObjectLifetime {
		v.fail(section, "the request object lifetime must be bounded to at most %s, but is bounded to %s", fapi2MaximumRequestObjectLifetime, lifetime)
	}

	if algs := config.GetRequestObjectSigningAlgValues(ctx); !fapi2Subset(algs, oauth2.FAPI2SecurityProfileSigningAlgValues) {
		v.fail(section, "the request object algorithms '%s' include one not permitted", strings.Join(algs, "', '"))
	}
}

func (v *fapi2Violations) signedResponses(ctx context.Context, config oauth2.Configurator) {
	const section = "5.4.1"

	if config.GetJWTSecuredAuthorizeResponseModeStrategy(ctx) == nil {
		v.fail(section, "signed authorization responses must be supported, but no JWT Secured Authorization Response Mode strategy is configured")

		return
	}

	if config.GetIssuer(ctx) == "" {
		v.fail(section, "signed authorization responses must carry 'iss', but Issuer is not set")
	}

	if algs := oauth2.SupportedAuthorizationSignedResponseAlgValues(ctx, config); len(algs) == 0 {
		v.fail(section, "signed authorization responses must be supported, but the JWT Secured Authorization Response Mode strategy supports none of the algorithms permitted by AuthorizationSignedResponseAlgValues")
	} else if !fapi2Subset(algs, oauth2.FAPI2SecurityProfileSigningAlgValues) {
		v.fail(section, "the authorization response algorithms '%s' must be permitted ones, set through AuthorizationSignedResponseAlgValues", strings.Join(algs, "', '"))
	}
}

func (v *fapi2Violations) signedIntrospection(ctx context.Context, config oauth2.Configurator) {
	if len(config.GetTokenIntrospectionHandlers(ctx)) == 0 {
		v.fail("5.5.1", "introspection responses must be signed, but no introspection handler is registered")
	}

	if config.GetIntrospectionJWTResponseStrategy(ctx) == nil {
		v.fail("5.5.1", "introspection responses must be signed, but no introspection JWT response strategy is configured")
	} else if algs := oauth2.SupportedIntrospectionSignedResponseAlgValues(ctx, config); len(algs) == 0 {
		v.fail("5.5.1", "introspection responses must be signed, but the introspection JWT response strategy supports none of the algorithms permitted by IntrospectionSignedResponseAlgValues")
	} else if !fapi2Subset(algs, oauth2.FAPI2SecurityProfileSigningAlgValues) {
		v.fail("5.5.1", "the introspection response algorithms '%s' must be permitted ones, set through IntrospectionSignedResponseAlgValues", strings.Join(algs, "', '"))
	}

	if config.GetIssuer(ctx) == "" {
		v.fail("5.5.1", "signed introspection responses must carry 'iss', but Issuer is not set")
	}

	if p, ok := config.(oauth2.IntrospectionPermissionProvider); !ok || !p.GetEnforceIntrospectionPermission(ctx) {
		v.fail("6.2", "only resource servers may call the introspection endpoint, but EnforceIntrospectionPermission is not set")
	}
}
