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

	if err = r.selectAuthMethod(ctx, metadata); err != nil {
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

//nolint:gocyclo
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

	permittedGrantTypes := r.permittedGrantTypes(ctx)

	for _, grantType := range metadata.GrantTypes {
		if slices.Contains(permittedGrantTypes, grantType) && !slices.Contains(grantTypes, grantType) {
			grantTypes = append(grantTypes, grantType)
		}
	}

	if len(grantTypes) == 0 {
		return errDocument("The Client ID Metadata Document 'grant_types' member has no value this authorization server permits such a client to use.")
	}

	metadata.GrantTypes = grantTypes

	// The poll and ping token delivery modes use the CIBA grant type, and the push token delivery mode uses none, so the
	// permitted grant types decide it.
	//
	// See: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.4
	if !slices.Contains(r.config.GrantTypes, consts.GrantTypeOpenIDCIBA) || (metadata.BackChannelTokenDeliveryMode != consts.CIBAModePush && !slices.Contains(grantTypes, consts.GrantTypeOpenIDCIBA)) {
		metadata.BackChannelTokenDeliveryMode = ""
		metadata.BackChannelClientNotificationEndpoint = ""
		metadata.BackChannelAuthenticationRequestSigningAlg = ""
		metadata.BackChannelUserCodeParameter = false
		metadata.BackChannelEndpointLoginHintTokenTypes = nil
	}

	// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-06#section-8
	if !hasIDJAGGrantTypes(grantTypes) {
		metadata.AuthorizationGrantProfilesSupported = slices.DeleteFunc(slices.Clone(metadata.AuthorizationGrantProfilesSupported), func(profile string) bool {
			return profile == consts.GrantProfileIDJAG
		})
	}

	var responseTypes []string

	permittedResponseTypes := r.permittedResponseTypes(ctx)

	// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-03#section-6
	// See: https://www.rfc-editor.org/rfc/rfc7591#section-2.1
	for _, responseType := range metadata.ResponseTypes {
		if containsResponseType(permittedResponseTypes, responseType) && isUsableResponseType(responseType, grantTypes) && !slices.ContainsFunc(responseTypes, func(rt string) bool { return isSameResponseType(rt, responseType) }) {
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

	return r.applyResponseModeBounds(ctx, metadata)
}

func (r *Resolver) applyResponseModeBounds(ctx context.Context, metadata *oauth2.ClientRegistrationMetadata) (err error) {
	if len(metadata.ResponseModes) == 0 || r.config.ValidatorConfig == nil {
		return nil
	}

	supported := oauth2.SupportedResponseModes(ctx, r.config.ValidatorConfig)

	var responseModes []string

	for _, responseMode := range metadata.ResponseModes {
		if slices.Contains(supported, responseMode) && !slices.Contains(responseModes, responseMode) {
			responseModes = append(responseModes, responseMode)
		}
	}

	// A client with no response mode may use every response mode, so a document left with none is not served.
	if len(responseModes) == 0 {
		return errDocument("The Client ID Metadata Document %q member has no value this authorization server supports.", consts.ClientMetadataResponseModes)
	}

	metadata.ResponseModes = responseModes

	return nil
}

func (r *Resolver) permittedGrantTypes(ctx context.Context) (grantTypes []string) {
	if r.config.ValidatorConfig == nil {
		return r.config.GrantTypes
	}

	supported := oauth2.SupportedGrantTypes(ctx, r.config.ValidatorConfig)

	for _, grantType := range r.config.GrantTypes {
		if slices.Contains(supported, grantType) {
			grantTypes = append(grantTypes, grantType)
		}
	}

	return grantTypes
}

func (r *Resolver) permittedResponseTypes(ctx context.Context) (responseTypes []string) {
	if r.config.ValidatorConfig == nil {
		return r.config.ResponseTypes
	}

	supported := oauth2.SupportedResponseTypes(ctx, r.config.ValidatorConfig)

	for _, responseType := range r.config.ResponseTypes {
		if containsResponseType(supported, responseType) {
			responseTypes = append(responseTypes, responseType)
		}
	}

	return responseTypes
}

func (r *Resolver) permittedAuthMethods(ctx context.Context) (methods []string) {
	if r.config.ValidatorConfig == nil {
		return r.config.TokenEndpointAuthMethods
	}

	supported := oauth2.SupportedTokenEndpointAuthMethods(ctx, r.config.ValidatorConfig)

	for _, method := range r.config.TokenEndpointAuthMethods {
		if slices.Contains(supported, method) {
			methods = append(methods, method)
		}
	}

	return methods
}

// selectAuthMethod sets the token endpoint authentication method from the document's
// 'token_endpoint_auth_methods_supported'. The methods it may select are those of TokenEndpointAuthMethods the token
// endpoint supports. It selects 'private_key_jwt' when the document declares it and it is one of them, and otherwise the
// first of them the document declares and has the members for: a certificate subject for 'tls_client_auth', and 'jwks'
// or 'jwks_uri' for 'self_signed_tls_client_auth'. The other values the document declares are not an error. Without
// that member, the 'token_endpoint_auth_method' of the document, which is 'none' when omitted, must be one of them.
//
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-03#section-5
// See: https://datatracker.ietf.org/doc/html/rfc8705#section-2.1.2
// See: https://datatracker.ietf.org/doc/html/rfc8705#section-2.2.2
func (r *Resolver) selectAuthMethod(ctx context.Context, metadata *oauth2.ClientRegistrationMetadata) (err error) {
	permitted := r.permittedAuthMethods(ctx)

	declared, ok := authMethodsSupported(metadata)

	if !ok {
		if metadata.TokenEndpointAuthMethod == "" {
			metadata.TokenEndpointAuthMethod = consts.ClientAuthMethodNone
		}

		if !slices.Contains(permitted, metadata.TokenEndpointAuthMethod) {
			return errDocument("The Client ID Metadata Document %q member has the value %q which this authorization server does not support for such a client.", consts.ClientMetadataTokenEndpointAuthMethod, metadata.TokenEndpointAuthMethod)
		}

		clearUnusedTLSClientAuthSubject(metadata)

		return nil
	}

	if slices.Contains(declared, consts.ClientAuthMethodPrivateKeyJWT) && slices.Contains(permitted, consts.ClientAuthMethodPrivateKeyJWT) {
		metadata.TokenEndpointAuthMethod = consts.ClientAuthMethodPrivateKeyJWT

		clearUnusedTLSClientAuthSubject(metadata)

		return nil
	}

	for _, method := range permitted {
		if slices.Contains(declared, method) && hasAuthMethodMembers(metadata, method) {
			metadata.TokenEndpointAuthMethod = method

			clearUnusedTLSClientAuthSubject(metadata)

			return nil
		}
	}

	return errDocument("The Client ID Metadata Document %q member has no value this authorization server supports for such a client.", memberAuthMethodsSupported)
}

func hasAuthMethodMembers(metadata *oauth2.ClientRegistrationMetadata, method string) (has bool) {
	switch method {
	case consts.ClientAuthMethodTLSClientAuth:
		return len(tlsClientAuthSubjects(metadata)) == 1
	case consts.ClientAuthMethodSelfSignedTLSClientAuth:
		return metadata.JSONWebKeys != nil || metadata.JSONWebKeysURI != ""
	default:
		return true
	}
}

func tlsClientAuthSubjects(metadata *oauth2.ClientRegistrationMetadata) (subjects []string) {
	for _, subject := range []string{metadata.TLSClientAuthSubjectDN, metadata.TLSClientAuthSANDNS, metadata.TLSClientAuthSANURI, metadata.TLSClientAuthSANIP, metadata.TLSClientAuthSANEmail} {
		if subject != "" {
			subjects = append(subjects, subject)
		}
	}

	return subjects
}

func clearUnusedTLSClientAuthSubject(metadata *oauth2.ClientRegistrationMetadata) {
	for _, method := range []string{metadata.TokenEndpointAuthMethod, metadata.IntrospectionEndpointAuthMethod, metadata.RevocationEndpointAuthMethod} {
		if method == consts.ClientAuthMethodTLSClientAuth {
			return
		}
	}

	metadata.TLSClientAuthSubjectDN = ""
	metadata.TLSClientAuthSANDNS = ""
	metadata.TLSClientAuthSANURI = ""
	metadata.TLSClientAuthSANIP = ""
	metadata.TLSClientAuthSANEmail = ""
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

func containsResponseType(responseTypes []string, responseType string) (contains bool) {
	return slices.ContainsFunc(responseTypes, func(rt string) bool { return isSameResponseType(rt, responseType) })
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
