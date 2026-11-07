// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package cimd

import (
	"context"
	"slices"
	"strings"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
)

var fallbackScopeStrategies = []oauth2.ScopeStrategy{
	oauth2.ExactScopeStrategy,
	oauth2.HierarchicScopeStrategy,
	oauth2.WildcardScopeStrategy,
}

func (r *Resolver) applyCeiling(ctx context.Context, metadata *oauth2.ClientRegistrationMetadata) (err error) {
	if err = r.applyBounds(ctx, metadata); err != nil {
		return err
	}

	if err = r.selectAuthMethod(metadata); err != nil {
		return err
	}

	if err = validateAuthKeys(metadata); err != nil {
		return err
	}

	// These are privileges at this authorization server which a document can not assert, and the sector identifier
	// is not verified for a document.
	metadata.Audience = nil
	metadata.Resource = nil
	metadata.AuthorizationDetailsTypes = nil
	metadata.TokenExchangePermittedClientIDs = nil
	metadata.SectorIdentifierURI = ""

	return nil
}

func (r *Resolver) applyBounds(ctx context.Context, metadata *oauth2.ClientRegistrationMetadata) (err error) {
	var scopes []string

	for _, scope := range metadata.GetScopes() {
		if !slices.Contains(r.config.Scopes, scope) || slices.Contains(scopes, scope) {
			continue
		}

		// A client registration scope is never given to a document client, even when Scopes lists it.
		if r.isRegistrationScope(ctx, scope) {
			continue
		}

		scopes = append(scopes, scope)
	}

	metadata.Scope = strings.Join(scopes, " ")

	var grantTypes []string

	for _, grantType := range metadata.GrantTypes {
		if slices.Contains(r.config.GrantTypes, grantType) && !slices.Contains(grantTypes, grantType) {
			grantTypes = append(grantTypes, grantType)
		}
	}

	if len(grantTypes) == 0 {
		return errDocument("The Client ID Metadata Document 'grant_types' member has no value this authorization server permits such a client to use.")
	}

	metadata.GrantTypes = grantTypes

	// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-06#section-8
	if !hasIDJAGGrantTypes(grantTypes) {
		metadata.AuthorizationGrantProfilesSupported = slices.DeleteFunc(slices.Clone(metadata.AuthorizationGrantProfilesSupported), func(profile string) bool {
			return profile == consts.GrantProfileIDJAG
		})
	}

	var responseTypes []string

	// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-03#section-6
	// See: https://www.rfc-editor.org/rfc/rfc7591#section-2.1
	for _, responseType := range metadata.ResponseTypes {
		if r.isPermittedResponseType(responseType) && isUsableResponseType(responseType, grantTypes) && !slices.ContainsFunc(responseTypes, func(rt string) bool { return isSameResponseType(rt, responseType) }) {
			responseTypes = append(responseTypes, responseType)
		}
	}

	// A grant type which does not use the authorization endpoint needs no response type.
	//
	// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-03#section-4.2
	// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-03#section-6
	if len(responseTypes) == 0 && (slices.Contains(grantTypes, consts.GrantTypeAuthorizationCode) || slices.Contains(grantTypes, consts.GrantTypeImplicit)) {
		return errDocument("The Client ID Metadata Document 'response_types' member has no value this authorization server permits such a client to use.")
	}

	metadata.ResponseTypes = responseTypes

	return nil
}

// selectAuthMethod sets the token endpoint authentication method from the document's
// 'token_endpoint_auth_methods_supported': 'private_key_jwt' when the document declares it and it is one of
// TokenEndpointAuthMethods, and otherwise the first of TokenEndpointAuthMethods the document declares. Without that
// member, the 'token_endpoint_auth_method' of the document, which is 'none' when omitted, must be one of
// TokenEndpointAuthMethods.
//
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-03#section-5
func (r *Resolver) selectAuthMethod(metadata *oauth2.ClientRegistrationMetadata) (err error) {
	supported, ok := authMethodsSupported(metadata)

	if !ok {
		if metadata.TokenEndpointAuthMethod == "" {
			metadata.TokenEndpointAuthMethod = consts.ClientAuthMethodNone
		}

		if !slices.Contains(r.config.TokenEndpointAuthMethods, metadata.TokenEndpointAuthMethod) {
			return errDocument("The Client ID Metadata Document %q member has the value %q which this authorization server does not support for such a client.", consts.ClientMetadataTokenEndpointAuthMethod, metadata.TokenEndpointAuthMethod)
		}

		return nil
	}

	if slices.Contains(supported, consts.ClientAuthMethodPrivateKeyJWT) && slices.Contains(r.config.TokenEndpointAuthMethods, consts.ClientAuthMethodPrivateKeyJWT) {
		metadata.TokenEndpointAuthMethod = consts.ClientAuthMethodPrivateKeyJWT

		return nil
	}

	for _, method := range r.config.TokenEndpointAuthMethods {
		if slices.Contains(supported, method) {
			metadata.TokenEndpointAuthMethod = method

			return nil
		}
	}

	return errDocument("The Client ID Metadata Document %q member has no value this authorization server supports for such a client.", memberAuthMethodsSupported)
}

func (r *Resolver) isRegistrationScope(ctx context.Context, scope string) (is bool) {
	registration := []string{consts.ScopeClientRegistration}

	if r.config.ValidatorConfig != nil {
		registration = append(registration, r.config.ValidatorConfig.GetRFC7591ClientRegistrationScopes(ctx)...)
	}

	if slices.Contains(registration, scope) {
		return true
	}

	strategies := fallbackScopeStrategies

	if r.config.ValidatorConfig != nil {
		strategies = []oauth2.ScopeStrategy{oauth2.GetScopeStrategy(ctx, r.config.ValidatorConfig, nil)}
	}

	for _, strategy := range strategies {
		for _, value := range registration {
			if strategy([]string{scope}, value) {
				return true
			}
		}
	}

	return false
}

func (r *Resolver) isPermittedResponseType(responseType string) (permitted bool) {
	return slices.ContainsFunc(r.config.ResponseTypes, func(rt string) bool { return isSameResponseType(rt, responseType) })
}

func isSameResponseType(a, b string) (same bool) {
	x, y := strings.Fields(a), strings.Fields(b)

	slices.Sort(x)
	slices.Sort(y)

	return len(x) != 0 && slices.Equal(slices.Compact(x), slices.Compact(y))
}

func isUsableResponseType(responseType string, grantTypes []string) (usable bool) {
	parts := strings.Fields(responseType)

	if len(parts) == 0 {
		return false
	}

	for _, part := range parts {
		switch part {
		case consts.ResponseTypeAuthorizationCodeFlow:
			if !slices.Contains(grantTypes, consts.GrantTypeAuthorizationCode) {
				return false
			}
		case consts.ResponseTypeNone:
			// The 'none' response type issues nothing, but is only served by the authorization endpoint.
			//
			// See: https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#none
			if !slices.Contains(grantTypes, consts.GrantTypeAuthorizationCode) && !slices.Contains(grantTypes, consts.GrantTypeImplicit) {
				return false
			}
		default:
			if !slices.Contains(grantTypes, consts.GrantTypeImplicit) {
				return false
			}
		}
	}

	return true
}
