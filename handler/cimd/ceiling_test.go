// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package cimd

import (
	"context"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
)

const testGrantProfile = "urn:example:profile"

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

			metadata := &oauth2.ClientRegistrationMetadata{Scope: tc.scope, GrantTypes: []string{consts.GrantTypeAuthorizationCode}, ResponseTypes: []string{consts.ResponseTypeAuthorizationCodeFlow}}

			require.NoError(t, (&Resolver{config: withDefaults(tc.config)}).applyCeiling(t.Context(), metadata))

			assert.Equal(t, tc.expected, metadata.Scope)
		})
	}
}

func TestApplyCeilingGrantAndResponseTypes(t *testing.T) {
	all := []string{"code", "token", "id_token", "code id_token", "code token", "id_token token", "code id_token token", "none"}

	testCases := []struct {
		name          string
		permitted     []string
		permittedResp []string
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
			responseTypes: []string{"code", "token", "id_token", "code id_token", "code token", "id_token token", ""},
			expectedGrant: []string{"authorization_code"},
			expectedResp:  []string{"code"},
		},
		{
			name:          "ShouldKeepTheNoneResponseTypeWithTheAuthorizationCodeGrant",
			permitted:     []string{"authorization_code", "refresh_token"},
			grantTypes:    []string{"authorization_code"},
			responseTypes: []string{"code", "none"},
			expectedGrant: []string{"authorization_code"},
			expectedResp:  []string{"code", "none"},
		},
		{
			name:          "ShouldKeepTheNoneResponseTypeWithTheImplicitGrant",
			permitted:     []string{"implicit"},
			grantTypes:    []string{"implicit"},
			responseTypes: []string{"token", "none"},
			expectedGrant: []string{"implicit"},
			expectedResp:  []string{"token", "none"},
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
			name:          "ShouldReduceToThePermittedResponseTypes",
			permitted:     []string{"authorization_code", "implicit"},
			permittedResp: []string{"code", "id_token code"},
			grantTypes:    []string{"authorization_code", "implicit"},
			responseTypes: []string{"token", "code id_token", "code", "code token"},
			expectedGrant: []string{"authorization_code", "implicit"},
			expectedResp:  []string{"code id_token", "code"},
		},
		{
			name:          "ShouldRemoveADuplicateResponseTypeInAnotherOrder",
			permitted:     []string{"authorization_code", "implicit"},
			permittedResp: []string{"code id_token"},
			grantTypes:    []string{"authorization_code", "implicit"},
			responseTypes: []string{"code id_token", "id_token code"},
			expectedGrant: []string{"authorization_code", "implicit"},
			expectedResp:  []string{"code id_token"},
		},
		{
			name:          "ShouldPermitOnlyTheCodeResponseTypeByDefault",
			permitted:     []string{"authorization_code", "implicit"},
			permittedResp: []string{"code"},
			grantTypes:    []string{"authorization_code", "implicit"},
			responseTypes: []string{"code", "token", "code id_token"},
			expectedGrant: []string{"authorization_code", "implicit"},
			expectedResp:  []string{"code"},
		},
		{
			name:          "ShouldRejectADocumentLeftWithNoPermittedResponseType",
			permitted:     []string{"authorization_code", "implicit"},
			permittedResp: []string{"code"},
			grantTypes:    []string{"authorization_code", "implicit"},
			responseTypes: []string{"code id_token"},
			rejected:      true,
		},
		{
			name:          "ShouldRejectAnAuthorizationCodeDocumentWithNoResponseType",
			permitted:     []string{"authorization_code"},
			permittedResp: []string{"code"},
			grantTypes:    []string{"authorization_code"},
			rejected:      true,
		},
		{
			name:          "ShouldLeaveNoResponseTypeForAClientCredentialsClient",
			permitted:     []string{"client_credentials"},
			grantTypes:    []string{"client_credentials"},
			responseTypes: []string{"code", "none"},
			expectedGrant: []string{"client_credentials"},
			expectedResp:  nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			permittedResp := tc.permittedResp
			if permittedResp == nil {
				permittedResp = all
			}

			resolver := &Resolver{config: withDefaults(Config{ValidatorConfig: &oauth2.Config{}, GrantTypes: tc.permitted, ResponseTypes: permittedResp})}

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
	resolver := &Resolver{config: withDefaults(Config{ValidatorConfig: &oauth2.Config{}, GrantTypes: []string{"authorization_code"}})}

	metadata := &oauth2.ClientRegistrationMetadata{
		GrantTypes:                            []string{"authorization_code"},
		ResponseTypes:                         []string{"code"},
		RedirectURIs:                          []string{"https://client.example.com/cb"},
		Audience:                              []string{"https://api.example.com"},
		Resource:                              []string{"https://resource.example.com"},
		AuthorizationDetailsTypes:             []string{"payment_initiation"},
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
	assert.Nil(t, metadata.TokenExchangePermittedClientIDs)
	assert.Empty(t, metadata.SectorIdentifierURI)

	assert.Equal(t, []string{"https://client.example.com/cb"}, metadata.RedirectURIs)
	assert.Equal(t, "pairwise", metadata.SubjectType)
	assert.True(t, metadata.RequirePushedAuthorizationRequests)
	assert.True(t, metadata.DPoPBoundAccessTokens)
	assert.True(t, metadata.TLSClientCertificateBoundAccessTokens)
	assert.True(t, metadata.RequireSignedRequestObject)
	assert.Equal(t, []string{"urn:ietf:params:oauth:token-type:access_token"}, metadata.TokenExchangeSubjectTokenTypes)
}

type scopeOnlyConfig struct{}

func TestApplyCeilingAuthorizationGrantProfiles(t *testing.T) {
	const (
		profile       = consts.GrantProfileIDJAG
		tokenExchange = consts.GrantTypeOAuthTokenExchange
		jwtBearer     = consts.GrantTypeOAuthJWTBearer
	)

	testCases := []struct {
		name      string
		permitted []string
		profiles  []string
		expected  []string
	}{
		{
			name:      "ShouldKeepTheIDJAGProfileWhenBothGrantTypesArePermitted",
			permitted: []string{tokenExchange, jwtBearer},
			profiles:  []string{profile, testGrantProfile},
			expected:  []string{profile, testGrantProfile},
		},
		{
			name:      "ShouldDropOnlyTheIDJAGProfileWhenTokenExchangeIsNotPermitted",
			permitted: []string{jwtBearer},
			profiles:  []string{profile, testGrantProfile},
			expected:  []string{testGrantProfile},
		},
		{
			name:      "ShouldKeepOtherProfiles",
			permitted: []string{"authorization_code"},
			profiles:  []string{testGrantProfile},
			expected:  []string{testGrantProfile},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			resolver := &Resolver{config: withDefaults(Config{ValidatorConfig: &oauth2.Config{}, GrantTypes: tc.permitted})}

			profiles := slices.Clone(tc.profiles)

			metadata := &oauth2.ClientRegistrationMetadata{
				GrantTypes:                          []string{"authorization_code", tokenExchange, jwtBearer},
				ResponseTypes:                       []string{"code"},
				AuthorizationGrantProfilesSupported: profiles,
			}

			require.NoError(t, resolver.applyCeiling(t.Context(), metadata))

			assert.Equal(t, tc.expected, metadata.AuthorizationGrantProfilesSupported)
			assert.Equal(t, tc.profiles, profiles)
		})
	}
}

func TestSelectAuthMethod(t *testing.T) {
	testCases := []struct {
		name      string
		permitted []string
		document  string
		expected  string
		err       string
	}{
		{"ShouldDefaultToNone", nil, ``, "none", ""},
		{"ShouldKeepAPermittedSingularMethod", nil, `"token_endpoint_auth_method":"private_key_jwt"`, "private_key_jwt", ""},
		{"ShouldRejectASingularMethodNotPermitted", []string{"private_key_jwt"}, ``, "", "has the value 'none' which this authorization server does not support"},
		{"ShouldSelectTheFirstPermittedMethodInPreferenceOrder", nil, `"token_endpoint_auth_methods_supported":["none","private_key_jwt"]`, "private_key_jwt", ""},
		{"ShouldSelectByTheConfiguredOrder", []string{"none", "tls_client_auth"}, `"token_endpoint_auth_methods_supported":["tls_client_auth","none"]`, "none", ""},
		{"ShouldRequirePrivateKeyJWTOverTheConfiguredOrder", []string{"none", "private_key_jwt"}, `"token_endpoint_auth_methods_supported":["none","private_key_jwt"]`, "private_key_jwt", ""},
		{"ShouldNotRequirePrivateKeyJWTWhenNotPermitted", []string{"none"}, `"token_endpoint_auth_methods_supported":["private_key_jwt","none"]`, "none", ""},
		{"ShouldSelectTheListOverTheSingularMethod", nil, `"token_endpoint_auth_methods_supported":["none","private_key_jwt"],"token_endpoint_auth_method":"none"`, "private_key_jwt", ""},
		{"ShouldIgnoreUnsupportedMethods", nil, `"token_endpoint_auth_methods_supported":["example_method","none"]`, "none", ""},
		{"ShouldRejectWhenNoMethodIsPermitted", []string{"none"}, `"token_endpoint_auth_methods_supported":["private_key_jwt","example_method"]`, "", "'token_endpoint_auth_methods_supported' member has no value"},
		{"ShouldRejectAnEmptyList", nil, `"token_endpoint_auth_methods_supported":[]`, "", "'token_endpoint_auth_methods_supported' member has no value"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			body := `"grant_types":["authorization_code"],"jwks_uri":"https://client.example.com/jwks.json"`

			if tc.document != "" {
				body += "," + tc.document
			}

			metadata, err := parseDocument(testClientID, document(body))
			require.NoError(t, err)

			config := withDefaults(Config{ValidatorConfig: &oauth2.Config{}, GrantTypes: []string{"authorization_code"}})

			if tc.permitted != nil {
				config.TokenEndpointAuthMethods = tc.permitted
			}

			err = (&Resolver{config: config}).applyCeiling(t.Context(), metadata)

			if tc.err != "" {
				require.ErrorIs(t, err, oauth2.ErrInvalidClient)
				assert.Contains(t, oauth2.ErrorToDebugRFC6749Error(err).Error(), tc.err)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.expected, metadata.TokenEndpointAuthMethod)
		})
	}
}

func TestApplyCeilingRequiresKeysForPrivateKeyJWT(t *testing.T) {
	testCases := []struct {
		name     string
		document string
		err      bool
	}{
		{"ShouldAcceptJWKSURI", `"token_endpoint_auth_method":"private_key_jwt","jwks_uri":"https://client.example.com/jwks.json"`, false},
		{"ShouldAcceptJWKS", `"token_endpoint_auth_method":"private_key_jwt","jwks":{"keys":[]}`, false},
		{"ShouldRejectSingularMethodWithoutKeys", `"token_endpoint_auth_method":"private_key_jwt"`, true},
		{"ShouldRejectSelectedMethodWithoutKeys", `"token_endpoint_auth_methods_supported":["none","private_key_jwt"]`, true},
		{"ShouldAcceptNoneWithoutKeys", `"token_endpoint_auth_methods_supported":["none"]`, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			metadata, err := parseDocument(testClientID, document(tc.document))
			require.NoError(t, err)

			err = (&Resolver{config: withDefaults(Config{ValidatorConfig: &oauth2.Config{}, GrantTypes: []string{"authorization_code"}})}).applyCeiling(t.Context(), metadata)

			if tc.err {
				require.ErrorIs(t, err, oauth2.ErrInvalidClient)
				assert.Contains(t, oauth2.ErrorToDebugRFC6749Error(err).Error(), "requires the 'jwks' or 'jwks_uri' member")

				return
			}

			require.NoError(t, err)
		})
	}
}

func TestApplyCeilingRejectsNoUsableResponseType(t *testing.T) {
	testCases := []struct {
		name      string
		permitted []string
		document  string
		expected  []string
		err       bool
	}{
		{"ShouldRejectDeclaredResponseTypesNeedingAnUnpermittedGrant", []string{"authorization_code"}, `"grant_types":["authorization_code"],"response_types":["token"]`, nil, true},
		{"ShouldKeepTheUsableResponseTypes", []string{"authorization_code"}, `"grant_types":["authorization_code"],"response_types":["token","code"]`, []string{"code"}, false},
		{"ShouldAcceptNoResponseTypeWhenNoGrantUsesOne", []string{"client_credentials"}, `"grant_types":["authorization_code","client_credentials"],"token_endpoint_auth_method":"private_key_jwt","jwks_uri":"https://client.example.com/jwks.json"`, nil, false},
		{"ShouldAcceptAnUndeclaredResponseTypeForClientCredentials", []string{"client_credentials"}, `"grant_types":["client_credentials"],"token_endpoint_auth_method":"private_key_jwt","jwks_uri":"https://client.example.com/jwks.json"`, nil, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			metadata, err := parseDocument(testClientID, document(tc.document))
			require.NoError(t, err)

			err = (&Resolver{config: withDefaults(Config{ValidatorConfig: &oauth2.Config{}, GrantTypes: tc.permitted})}).applyCeiling(t.Context(), metadata)

			if tc.err {
				require.ErrorIs(t, err, oauth2.ErrInvalidClient)
				assert.Contains(t, oauth2.ErrorToDebugRFC6749Error(err).Error(), "'response_types' member has no value")

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.expected, metadata.ResponseTypes)
		})
	}
}

func (scopeOnlyConfig) GetScopeStrategy(_ context.Context) oauth2.ScopeStrategy {
	return nil
}

func (scopeOnlyConfig) GetAudienceStrategy(_ context.Context) oauth2.AudienceStrategy {
	return nil
}

func (scopeOnlyConfig) GetRFC7591ClientRegistrationGrantTypes(_ context.Context) []string {
	return nil
}

func withDefaults(config Config) Config {
	config.TokenEndpointAuthMethods = DefaultTokenEndpointAuthMethods

	if config.ResponseTypes == nil {
		config.ResponseTypes = []string{"code"}
	}

	return config
}
