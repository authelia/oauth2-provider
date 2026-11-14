// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc7591

import (
	"context"
	"slices"

	"authelia.com/provider/jose"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/token/jwt"
	"authelia.com/provider/oauth2/x/errorsx"
)

// validateCIBA checks the OpenID Connect CIBA client metadata. The rules apply only when the metadata registers a
// 'backchannel_token_delivery_mode' or the CIBA grant type; any other registration is unaffected. The RSA1_5 JWE
// algorithm is never permitted for the ID Token of such a client. The 'backchannel_user_code_parameter' is accepted
// whatever the server supports, as it only applies when the server supports the user code.
//
// See: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.4
// See: https://openid.net/specs/fapi-ciba.html#section-5.11
func validateCIBA(ctx context.Context, config LocalValidatorConfig, metadata *oauth2.ClientRegistrationMetadata) (err error) {
	mode := metadata.BackChannelTokenDeliveryMode
	hasGrant := slices.Contains(metadata.GrantTypes, consts.GrantTypeOpenIDCIBA)

	if mode == "" && !hasGrant {
		return nil
	}

	if mode == "" {
		return errorsx.WithStack(oauth2.ErrInvalidClientMetadata.WithHintf("The '%s' value '%s' requires the '%s' to be registered.", consts.ClientMetadataGrantTypes, consts.GrantTypeOpenIDCIBA, consts.ClientMetadataBackChannelTokenDeliveryMode))
	}

	if err = validateCIBAMode(ctx, config, mode); err != nil {
		return err
	}

	// The push mode never uses the token endpoint, so it does not register the grant type.
	if mode != consts.CIBAModePush && !hasGrant {
		return errorsx.WithStack(oauth2.ErrInvalidClientMetadata.WithHintf("The '%s' value '%s' requires the '%s' to include '%s'.", consts.ClientMetadataBackChannelTokenDeliveryMode, mode, consts.ClientMetadataGrantTypes, consts.GrantTypeOpenIDCIBA))
	}

	if err = validateCIBANotificationEndpoint(mode, metadata); err != nil {
		return err
	}

	if err = validateCIBASigningAlg(ctx, config, metadata); err != nil {
		return err
	}

	if metadata.TokenEndpointAuthMethod == consts.ClientAuthMethodNone {
		return errorsx.WithStack(oauth2.ErrInvalidClientMetadata.WithHintf("The '%s' value '%s' is not permitted with the '%s' as the backchannel authentication endpoint requires client authentication.", consts.ClientMetadataTokenEndpointAuthMethod, consts.ClientAuthMethodNone, consts.ClientMetadataBackChannelTokenDeliveryMode))
	}

	if metadata.IDTokenEncryptedResponseAlg == string(jose.RSA1_5) {
		return errorsx.WithStack(oauth2.ErrInvalidClientMetadata.WithHintf("The '%s' value '%s' is not permitted with the '%s'.", consts.ClientMetadataIDTokenEncryptedResponseAlg, metadata.IDTokenEncryptedResponseAlg, consts.ClientMetadataBackChannelTokenDeliveryMode))
	}

	return validateCIBAPairwise(mode, metadata)
}

// validateCIBASigningAlg requires the registered request signing algorithm to be asymmetric and supported.
//
// See: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.1.1
func validateCIBASigningAlg(ctx context.Context, config LocalValidatorConfig, metadata *oauth2.ClientRegistrationMetadata) (err error) {
	if alg := metadata.BackChannelAuthenticationRequestSigningAlg; alg != "" {
		if alg == jwt.JSONWebTokenAlgNone || jwt.IsSignedJWTClientSecretAlgStr(alg) {
			return errorsx.WithStack(oauth2.ErrInvalidClientMetadata.WithHintf("The '%s' value '%s' must be an asymmetric signing algorithm.", consts.ClientMetadataBackChannelAuthenticationRequestSigningAlg, alg))
		}

		if err = validateValueSupported(consts.ClientMetadataBackChannelAuthenticationRequestSigningAlg, alg, config.GetCIBARequestSigningAlgValues(ctx)); err != nil {
			return err
		}
	}

	return nil
}

// validateCIBANotificationEndpoint requires an https notification endpoint for the ping and push modes.
//
// See: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.4
func validateCIBANotificationEndpoint(mode string, metadata *oauth2.ClientRegistrationMetadata) (err error) {
	if mode != consts.CIBAModePoll {
		if metadata.BackChannelClientNotificationEndpoint == "" {
			return errorsx.WithStack(oauth2.ErrInvalidClientMetadata.WithHintf("The '%s' value '%s' requires the '%s' to be registered.", consts.ClientMetadataBackChannelTokenDeliveryMode, mode, consts.ClientMetadataBackChannelClientNotificationEndpoint))
		}

		if err = validateURI(consts.ClientMetadataBackChannelClientNotificationEndpoint, metadata.BackChannelClientNotificationEndpoint, true); err != nil {
			return err
		}
	}

	return nil
}

// validateCIBAMode requires the delivery mode to be a defined mode which the server supports.
//
// See: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.4
func validateCIBAMode(ctx context.Context, config LocalValidatorConfig, mode string) (err error) {
	switch mode {
	case consts.CIBAModePoll, consts.CIBAModePing, consts.CIBAModePush:
	default:
		return errUnsupportedValue(consts.ClientMetadataBackChannelTokenDeliveryMode, mode)
	}

	if err = validateValueSupported(consts.ClientMetadataBackChannelTokenDeliveryMode, mode, config.GetCIBATokenDeliveryModes(ctx)); err != nil {
		return err
	}

	return nil
}

// validateCIBAPairwise requires a pairwise poll or ping client to register a 'jwks_uri', whether or not it registers a
// 'sector_identifier_uri'. An inline 'jwks' does not satisfy this rule.
//
// See: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.4
func validateCIBAPairwise(mode string, metadata *oauth2.ClientRegistrationMetadata) (err error) {
	if metadata.SubjectType == consts.SubjectTypePairwise && mode != consts.CIBAModePush && metadata.JSONWebKeysURI == "" {
		return errorsx.WithStack(oauth2.ErrInvalidClientMetadata.WithHintf("The '%s' value '%s' with the '%s' value '%s' requires the '%s' to be registered.", consts.ClientMetadataSubjectType, consts.SubjectTypePairwise, consts.ClientMetadataBackChannelTokenDeliveryMode, mode, consts.ClientMetadataJSONWebKeysURI))
	}

	return nil
}
