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

	// These are privileges at this authorization server which a document can not assert, and the sector identifier
	// is not verified for a document.
	metadata.Audience = nil
	metadata.Resource = nil
	metadata.AuthorizationDetailsTypes = nil
	metadata.AuthorizationGrantProfilesSupported = nil
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

	var responseTypes []string

	// See: https://www.rfc-editor.org/rfc/rfc7591#section-2.1
	for _, responseType := range metadata.ResponseTypes {
		if isUsableResponseType(responseType, grantTypes) {
			responseTypes = append(responseTypes, responseType)
		}
	}

	metadata.ResponseTypes = responseTypes

	return nil
}

func (r *Resolver) isRegistrationScope(ctx context.Context, scope string) (is bool) {
	registration := []string{consts.ScopeClientRegistration}

	if provider, ok := r.config.ValidatorConfig.(interface {
		GetRFC7591ClientRegistrationScopes(ctx context.Context) (scopes []string)
	}); ok {
		registration = append(registration, provider.GetRFC7591ClientRegistrationScopes(ctx)...)
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

func isUsableResponseType(responseType string, grantTypes []string) (usable bool) {
	parts := strings.Fields(responseType)

	if len(parts) == 0 {
		return false
	}

	for _, part := range parts {
		grantType := consts.GrantTypeImplicit

		if part == consts.ResponseTypeAuthorizationCodeFlow {
			grantType = consts.GrantTypeAuthorizationCode
		}

		if !slices.Contains(grantTypes, grantType) {
			return false
		}
	}

	return true
}
