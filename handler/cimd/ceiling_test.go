// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package cimd

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
)

func TestApplyCeilingScope(t *testing.T) {
	testCases := []struct {
		name     string
		config   Config
		scope    string
		expected string
	}{
		{
			name:     "ShouldPermitNoScopeByDefault",
			config:   Config{ValidatorConfig: &oauth2.Config{}},
			scope:    "openid admin",
			expected: "",
		},
		{
			name:     "ShouldReduceToTheConfiguredScopesInDocumentOrder",
			config:   Config{ValidatorConfig: &oauth2.Config{}, Scopes: []string{"openid", "offline", "profile"}},
			scope:    "profile admin openid profile",
			expected: "profile openid",
		},
		{
			name:     "ShouldNotMatchByPrefixOrCase",
			config:   Config{ValidatorConfig: &oauth2.Config{}, Scopes: []string{"openid"}},
			scope:    "OpenID openid.admin open",
			expected: "",
		},
		{
			name:     "ShouldRemoveTheRegistrationScopeEvenWhenConfigured",
			config:   Config{ValidatorConfig: &oauth2.Config{}, Scopes: []string{"openid", consts.ScopeClientRegistration}},
			scope:    consts.ScopeClientRegistration + " openid",
			expected: "openid",
		},
		{
			name: "ShouldRemoveTheConfiguredRegistrationScopesAndTheDefaultOne",
			config: Config{
				ValidatorConfig: &oauth2.Config{RFC7591ClientRegistrationScopes: []string{"register", "enrol"}},
				Scopes:          []string{"openid", "register", "enrol", consts.ScopeClientRegistration},
			},
			scope:    "register openid enrol " + consts.ScopeClientRegistration,
			expected: "openid",
		},
		{
			name: "ShouldRemoveAScopeTheWildcardStrategyMatchesAgainstARegistrationScope",
			config: Config{
				ValidatorConfig: &oauth2.Config{ScopeStrategy: oauth2.WildcardScopeStrategy, RFC7591ClientRegistrationScopes: []string{"clients.register"}},
				Scopes:          []string{"openid", "clients.*", "*", "users.*"},
			},
			scope:    "clients.* openid * users.*",
			expected: "openid users.*",
		},
		{
			name: "ShouldRemoveAScopeTheHierarchicStrategyMatchesAgainstARegistrationScope",
			config: Config{
				ValidatorConfig: &oauth2.Config{ScopeStrategy: oauth2.HierarchicScopeStrategy, RFC7591ClientRegistrationScopes: []string{"clients.register"}},
				Scopes:          []string{"openid", "clients", "users"},
			},
			scope:    "clients openid users",
			expected: "openid users",
		},
		{
			name: "ShouldKeepAWildcardScopeTheExactStrategyDoesNotMatch",
			config: Config{
				ValidatorConfig: &oauth2.Config{ScopeStrategy: oauth2.ExactScopeStrategy, RFC7591ClientRegistrationScopes: []string{"clients.register"}},
				Scopes:          []string{"clients.*"},
			},
			scope:    "clients.*",
			expected: "clients.*",
		},
		{
			name:     "ShouldRemoveTheRegistrationScopeWithoutAValidatorConfig",
			config:   Config{Scopes: []string{"openid", consts.ScopeClientRegistration, "*"}},
			scope:    "* openid " + consts.ScopeClientRegistration,
			expected: "openid",
		},
		{
			name:     "ShouldRemoveTheRegistrationScopeWhenTheConfigDoesNotProvideRegistrationScopes",
			config:   Config{ValidatorConfig: scopeOnlyConfig{}, Scopes: []string{"openid", consts.ScopeClientRegistration}},
			scope:    "openid " + consts.ScopeClientRegistration,
			expected: "openid",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tc.config.GrantTypes = []string{consts.GrantTypeAuthorizationCode}

			metadata := &oauth2.ClientRegistrationMetadata{Scope: tc.scope, GrantTypes: []string{consts.GrantTypeAuthorizationCode}}

			require.NoError(t, (&Resolver{config: tc.config}).applyCeiling(t.Context(), metadata))

			assert.Equal(t, tc.expected, metadata.Scope)
		})
	}
}

func TestApplyCeilingGrantAndResponseTypes(t *testing.T) {
	testCases := []struct {
		name          string
		permitted     []string
		grantTypes    []string
		responseTypes []string
		expectedGrant []string
		expectedResp  []string
		rejected      bool
	}{
		{
			name:          "ShouldReduceToThePermittedGrantTypes",
			permitted:     []string{"authorization_code", "refresh_token"},
			grantTypes:    []string{"refresh_token", "client_credentials", "authorization_code", "urn:ietf:params:oauth:grant-type:token-exchange"},
			responseTypes: []string{"code"},
			expectedGrant: []string{"refresh_token", "authorization_code"},
			expectedResp:  []string{"code"},
		},
		{
			name:       "ShouldRejectADocumentLeftWithNoGrantType",
			permitted:  []string{"authorization_code", "refresh_token"},
			grantTypes: []string{"client_credentials"},
			rejected:   true,
		},
		{
			name:       "ShouldRejectAGrantTypeDifferingOnlyByCase",
			permitted:  []string{"authorization_code"},
			grantTypes: []string{"Authorization_Code"},
			rejected:   true,
		},
		{
			name:          "ShouldRemoveResponseTypesNeedingTheImplicitGrant",
			permitted:     []string{"authorization_code", "refresh_token"},
			grantTypes:    []string{"authorization_code", "implicit"},
			responseTypes: []string{"code", "token", "id_token", "code id_token", "code token", "id_token token", "none", ""},
			expectedGrant: []string{"authorization_code"},
			expectedResp:  []string{"code"},
		},
		{
			name:          "ShouldRemoveTheCodeResponseTypeWithoutTheAuthorizationCodeGrant",
			permitted:     []string{"implicit", "client_credentials"},
			grantTypes:    []string{"authorization_code", "implicit"},
			responseTypes: []string{"code", "token", "code token", "id_token token"},
			expectedGrant: []string{"implicit"},
			expectedResp:  []string{"token", "id_token token"},
		},
		{
			name:          "ShouldKeepHybridResponseTypesWithBothGrants",
			permitted:     []string{"authorization_code", "implicit"},
			grantTypes:    []string{"authorization_code", "implicit"},
			responseTypes: []string{"code", "code id_token", "id_token"},
			expectedGrant: []string{"authorization_code", "implicit"},
			expectedResp:  []string{"code", "code id_token", "id_token"},
		},
		{
			name:          "ShouldLeaveNoResponseTypeForAClientCredentialsClient",
			permitted:     []string{"client_credentials"},
			grantTypes:    []string{"client_credentials"},
			responseTypes: []string{"code"},
			expectedGrant: []string{"client_credentials"},
			expectedResp:  nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			resolver := &Resolver{config: Config{ValidatorConfig: &oauth2.Config{}, GrantTypes: tc.permitted}}

			metadata := &oauth2.ClientRegistrationMetadata{GrantTypes: tc.grantTypes, ResponseTypes: tc.responseTypes}

			err := resolver.applyCeiling(t.Context(), metadata)

			if tc.rejected {
				require.ErrorIs(t, err, oauth2.ErrInvalidClient)
				assert.Equal(t, "The Client ID Metadata Document could not be used.", oauth2.ErrorToRFC6749Error(err).HintField)

				return
			}

			require.NoError(t, err)

			assert.Equal(t, tc.expectedGrant, metadata.GrantTypes)
			assert.Equal(t, tc.expectedResp, metadata.ResponseTypes)
		})
	}
}

func TestApplyCeilingClearsPrivilegesAndKeepsRestrictions(t *testing.T) {
	resolver := &Resolver{config: Config{ValidatorConfig: &oauth2.Config{}, GrantTypes: []string{"authorization_code"}}}

	metadata := &oauth2.ClientRegistrationMetadata{
		GrantTypes:                            []string{"authorization_code"},
		RedirectURIs:                          []string{"https://client.example.com/cb"},
		Audience:                              []string{"https://api.example.com"},
		Resource:                              []string{"https://resource.example.com"},
		AuthorizationDetailsTypes:             []string{"payment_initiation"},
		AuthorizationGrantProfilesSupported:   []string{"urn:ietf:params:oauth:grant-profile:id-jag"},
		SectorIdentifierURI:                   "https://victim.example.com/sector.json",
		SubjectType:                           "pairwise",
		RequirePushedAuthorizationRequests:    true,
		DPoPBoundAccessTokens:                 true,
		TLSClientCertificateBoundAccessTokens: true,
		RequireSignedRequestObject:            true,
		TokenExchangeSubjectTokenTypes:        []string{"urn:ietf:params:oauth:token-type:access_token"},
		TokenExchangePermittedClientIDs:       []string{"other"},
	}

	require.NoError(t, resolver.applyCeiling(t.Context(), metadata))

	assert.Nil(t, metadata.Audience)
	assert.Nil(t, metadata.Resource)
	assert.Nil(t, metadata.AuthorizationDetailsTypes)
	assert.Nil(t, metadata.AuthorizationGrantProfilesSupported)
	assert.Empty(t, metadata.SectorIdentifierURI)

	assert.Equal(t, []string{"https://client.example.com/cb"}, metadata.RedirectURIs)
	assert.Equal(t, "pairwise", metadata.SubjectType)
	assert.True(t, metadata.RequirePushedAuthorizationRequests)
	assert.True(t, metadata.DPoPBoundAccessTokens)
	assert.True(t, metadata.TLSClientCertificateBoundAccessTokens)
	assert.True(t, metadata.RequireSignedRequestObject)
	assert.Equal(t, []string{"urn:ietf:params:oauth:token-type:access_token"}, metadata.TokenExchangeSubjectTokenTypes)
	assert.Equal(t, []string{"other"}, metadata.TokenExchangePermittedClientIDs)
}

type scopeOnlyConfig struct{}

func (scopeOnlyConfig) GetScopeStrategy(_ context.Context) oauth2.ScopeStrategy {
	return nil
}

func (scopeOnlyConfig) GetAudienceStrategy(_ context.Context) oauth2.AudienceStrategy {
	return nil
}

func (scopeOnlyConfig) GetRFC7591ClientRegistrationGrantTypes(_ context.Context) []string {
	return nil
}
