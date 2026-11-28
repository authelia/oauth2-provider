// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package compose

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/jose"

	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/handler/openid"
	"authelia.com/provider/oauth2/handler/rfc8693"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/gen"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestApplyFAPI2SecurityProfileMinParameterEntropy(t *testing.T) {
	testCases := []struct {
		name     string
		value    int
		expected int
	}{
		{name: "ShouldResetAMinimumOver64", value: 65, expected: 0},
		{name: "ShouldKeepAMinimumOf64", value: 64, expected: 64},
		{name: "ShouldKeepTheDefault", value: 0, expected: 0},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := &oauth2.Config{MinParameterEntropy: tc.value}

			ApplyFAPI2SecurityProfile(config)

			assert.Equal(t, tc.expected, config.MinParameterEntropy)
		})
	}
}

func TestApplyFAPI2SecurityProfileGrantAlgorithms(t *testing.T) {
	config := &oauth2.Config{CIBARequestSigningAlgValues: []string{string(jose.RS256), string(jose.PS256)}}

	ApplyFAPI2SecurityProfile(config)

	assert.Equal(t, []string{string(jose.PS256)}, config.CIBARequestSigningAlgValues)
	assert.Equal(t, oauth2.FAPI2SecurityProfileSigningAlgValues, config.IDJAGRedeemSigningAlgValues)

	config = &oauth2.Config{IDJAGRedeemSigningAlgValues: []string{string(jose.RS256), string(jose.ES256)}}

	ApplyFAPI2SecurityProfile(config)

	assert.Nil(t, config.CIBARequestSigningAlgValues)
	assert.Equal(t, []string{string(jose.ES256)}, config.IDJAGRedeemSigningAlgValues)
}

func TestApplyFAPI2SecurityProfileDefaultTrustedIssuerAlgorithms(t *testing.T) {
	config := &oauth2.Config{}

	ApplyFAPI2SecurityProfile(config)

	assert.Equal(t, oauth2.FAPI2SecurityProfileSigningAlgValues, config.RFC7591TrustedIssuerSigningAlgValues)
}

func TestValidateFAPI2SecurityProfile(t *testing.T) {
	testCases := []struct {
		name       string
		modify     func(config *oauth2.Config)
		factories  []Factory
		strategies func(config *oauth2.Config) []any
		expected   []string
	}{
		{
			name: "ShouldPassWithDPoP",
		},
		{
			name:   "ShouldPassWithMTLS",
			modify: func(config *oauth2.Config) { config.DPoPEnabled = false; config.MTLSEnabled = true },
		},
		{
			name:      "ShouldRejectThePasswordGrant",
			factories: []Factory{OAuth2ResourceOwnerPasswordCredentialsFactory},
			expected:  []string{"Section 5.3.2.1: the resource owner password credentials grant handler must not be registered"},
		},
		{
			name:      "ShouldRejectTheImplicitFlow",
			factories: []Factory{OAuth2AuthorizeImplicitFactory},
			expected:  []string{"Section 5.3.2.2: the response type must be 'code', but the '*oauth2.AuthorizeImplicitGrantTypeHandler' authorize endpoint handler is registered"},
		},
		{
			name: "ShouldRejectAClientSecretMethod",
			modify: func(config *oauth2.Config) {
				config.TokenEndpointAuthMethods = []string{consts.ClientAuthMethodClientSecretBasic}
			},
			expected: []string{"Section 5.3.2.1: the token endpoint accepts the client authentication methods 'client_secret_basic'"},
		},
		{
			name:     "ShouldRejectUnrestrictedClientAuthentication",
			modify:   func(config *oauth2.Config) { config.RevocationEndpointAuthMethods = nil },
			expected: []string{"Section 5.3.2.1: the revocation endpoint accepts the client authentication methods"},
		},
		{
			name:     "ShouldRejectBearerAccessTokens",
			modify:   func(config *oauth2.Config) { config.EnforceSenderConstrainedAccessTokens = false },
			expected: []string{"Section 5.3.2.1: only sender-constrained access tokens may be issued"},
		},
		{
			name:     "ShouldRejectNeitherDPoPNorMTLS",
			modify:   func(config *oauth2.Config) { config.DPoPEnabled = false },
			expected: []string{"Section 5.3.2.1: access tokens must be sender-constrained by DPoP or mTLS, but neither is enabled"},
		},
		{
			name:     "ShouldRejectAnArrayClientAssertionAudience",
			modify:   func(config *oauth2.Config) { config.DisableClientAssertionIssuerAudience = true },
			expected: []string{"Section 5.3.2.1: the issuer must be the sole client assertion audience"},
		},
		{
			name:      "ShouldRejectSkippedJWTBearerClientAuthentication",
			modify:    func(config *oauth2.Config) { config.GrantTypeJWTBearerCanSkipClientAuth = true },
			factories: []Factory{RFC7523AssertionGrantFactory},
			expected:  []string{"Section 5.3.2.1: clients must authenticate, but GrantTypeJWTBearerCanSkipClientAuth is set"},
		},
		{
			name:   "ShouldPassSkippedJWTBearerClientAuthenticationWithoutTheGrant",
			modify: func(config *oauth2.Config) { config.GrantTypeJWTBearerCanSkipClientAuth = true },
		},
		{
			name: "ShouldRejectHS256AuthorizationResponses",
			modify: func(config *oauth2.Config) {
				config.AuthorizationSignedResponseAlgValues = []string{string(jose.HS256)}
			},
			expected: []string{"Section 5.4.1: the authorization response algorithms 'HS256' include one not permitted"},
		},
		{
			name: "ShouldRejectHS256IntrospectionResponses",
			modify: func(config *oauth2.Config) {
				config.IntrospectionSignedResponseAlgValues = []string{string(jose.HS256)}
			},
			expected: []string{"Section 5.4.1: the introspection response algorithms 'HS256' include one not permitted"},
		},
		{
			name:     "ShouldRejectWithoutTheProfileFlag",
			modify:   func(config *oauth2.Config) { config.FAPI2SecurityProfile = false },
			expected: []string{"Section 5.4.1: the discovery metadata must list only the permitted algorithms, but FAPI2SecurityProfile is not set"},
		},
		{
			name:     "ShouldRejectQueryAccessTokens",
			modify:   func(config *oauth2.Config) { config.AccessTokenURIQueryParameterEnabled = true },
			expected: []string{"Section 5.3.4: access tokens in the URI query must not be accepted, but AccessTokenURIQueryParameterEnabled is set"},
		},
		{
			name:     "ShouldRejectRefreshTokenRotation",
			modify:   func(config *oauth2.Config) { config.DisableRefreshTokenRotation = false },
			expected: []string{"Section 5.3.2.1: refresh tokens must not be rotated"},
		},
		{
			name:     "ShouldRejectALongAuthorizationCodeLifetime",
			modify:   func(config *oauth2.Config) { config.AuthorizeCodeLifespan = 2 * time.Minute },
			expected: []string{"Section 5.3.2.1: the authorization code lifetime must be at most 1m0s, but is 2m0s"},
		},
		{
			name:     "ShouldRejectAShortJWTClockSkew",
			modify:   func(config *oauth2.Config) { config.JWTClockSkew = time.Second },
			expected: []string{"Section 5.3.2.1: the JWT clock skew must be between 10s and 1m0s, but is 1s"},
		},
		{
			name:     "ShouldRejectALongDPoPClockSkew",
			modify:   func(config *oauth2.Config) { config.DPoPClockSkew = 2 * time.Minute },
			expected: []string{"Section 5.3.2.1: the DPoP clock skew must be between 10s and 1m0s, but is 2m0s"},
		},
		{
			name:     "ShouldRejectUnpushedAuthorizationRequests",
			modify:   func(config *oauth2.Config) { config.RequirePushedAuthorizationRequests = false },
			expected: []string{"Section 5.3.2.2: authorization requests must be pushed"},
		},
		{
			name:     "ShouldRejectPushedAuthorizationRequestsWithoutARedirectURI",
			modify:   func(config *oauth2.Config) { config.RequireRedirectURIPushedAuthorizationRequests = false },
			expected: []string{"Section 5.3.2.2: pushed authorization requests must carry 'redirect_uri'"},
		},
		{
			name:     "ShouldRejectALongPushedAuthorizationRequestLifetime",
			modify:   func(config *oauth2.Config) { config.PushedAuthorizeContextLifespan = 10 * time.Minute },
			expected: []string{"Section 5.3.2.2: the pushed authorization request 'expires_in' must be less than 10m0s, but is 10m0s"},
		},
		{
			name:     "ShouldRejectOptionalPKCE",
			modify:   func(config *oauth2.Config) { config.EnforcePKCE = false },
			expected: []string{"Section 5.3.2.2: PKCE is required, but EnforcePKCE is not set"},
		},
		{
			name:     "ShouldRejectThePlainPKCEMethod",
			modify:   func(config *oauth2.Config) { config.EnablePKCEPlainChallengeMethod = true },
			expected: []string{"Section 5.3.2.2: PKCE must use S256"},
		},
		{
			name:     "ShouldRejectAMissingIssuer",
			modify:   func(config *oauth2.Config) { config.Issuer = "" },
			expected: []string{"Section 5.3.2.2: the 'iss' authorization response parameter must be returned, but Issuer is not set"},
		},
		{
			name:     "ShouldRejectDisabledIssuerIdentification",
			modify:   func(config *oauth2.Config) { config.DisableAuthorizationServerIdentification = true },
			expected: []string{"Section 5.3.2.2: the 'iss' authorization response parameter must be returned, but DisableAuthorizationServerIdentification is set"},
		},
		{
			name:     "ShouldRejectRS256ClientAssertions",
			modify:   func(config *oauth2.Config) { config.ClientAssertionSigningAlgValues = []string{string(jose.RS256)} },
			expected: []string{"Section 5.4.1: the client assertion algorithms 'RS256' include one not permitted", "Section 5.4.1: the revocation endpoint client assertion algorithms 'RS256' include one not permitted"},
		},
		{
			name: "ShouldRejectUnsignedRequestObjects",
			modify: func(config *oauth2.Config) {
				config.RequestObjectSigningAlgValues = []string{"none", string(jose.PS256)}
			},
			expected: []string{"Section 5.4.1: the request object algorithms 'none', 'PS256' include one not permitted"},
		},
		{
			name:      "ShouldPassWithTheJWTBearerGrant",
			factories: []Factory{RFC7523AssertionGrantFactory},
		},
		{
			name:      "ShouldRejectRS256JWTBearerGrantAssertions",
			modify:    func(config *oauth2.Config) { config.RFC7523AssertionSigningAlgValues = []string{string(jose.RS256)} },
			factories: []Factory{RFC7523AssertionGrantFactory},
			expected:  []string{"Section 5.4.1: the JWT bearer grant assertion algorithms 'RS256' include one not permitted"},
		},
		{
			name:     "ShouldNotCheckJWTBearerGrantAssertionsWithoutTheGrant",
			modify:   func(config *oauth2.Config) { config.RFC7523AssertionSigningAlgValues = []string{string(jose.RS256)} },
			expected: nil,
		},
		{
			name: "ShouldPassWithIntrospection",
			modify: func(config *oauth2.Config) {
				config.IntrospectionEndpointAuthMethods = []string{consts.ClientAuthMethodPrivateKeyJWT, consts.AuthSchemeBearer}
			},
			factories: []Factory{OAuth2TokenIntrospectionFactory},
		},
		{
			name:      "ShouldRejectUnrestrictedIntrospection",
			factories: []Factory{OAuth2TokenIntrospectionFactory},
			expected:  []string{"Section 5.3.2.1: the introspection endpoint accepts the client authentication methods 'client_secret_basic'"},
		},
		{
			name: "ShouldPassWithBearerIntrospection",
			modify: func(config *oauth2.Config) {
				config.IntrospectionEndpointAuthMethods = []string{consts.AuthSchemeBearer}
			},
			factories: []Factory{OAuth2TokenIntrospectionFactory},
		},
		{
			name: "ShouldRejectAClientSecretMethodAtIntrospection",
			modify: func(config *oauth2.Config) {
				config.IntrospectionEndpointAuthMethods = []string{consts.ClientAuthMethodClientSecretBasic, consts.AuthSchemeBearer}
			},
			factories: []Factory{OAuth2TokenIntrospectionFactory},
			expected:  []string{"Section 5.3.2.1: the introspection endpoint accepts the client authentication methods 'client_secret_basic', but only"},
		},
		{
			name: "ShouldRejectRS256IntrospectionClientAssertions",
			modify: func(config *oauth2.Config) {
				config.IntrospectionEndpointAuthSigningAlgValues = []string{string(jose.RS256)}
			},
			factories: []Factory{OAuth2TokenIntrospectionFactory},
			expected:  []string{"Section 5.4.1: the introspection endpoint client assertion algorithms 'RS256' include one not permitted"},
		},
		{
			name:     "ShouldRejectAClientAssertionAudienceWhichMayBeAnArray",
			modify:   func(config *oauth2.Config) { config.RequireStringClientAssertionAudience = false },
			expected: []string{"Section 5.3.2.1: the issuer must be the client assertion audience as a string, but RequireStringClientAssertionAudience is not set"},
		},
		{
			name: "ShouldRejectRS256IssuerSigningKeys",
			modify: func(config *oauth2.Config) {
				config.JWTStrategy = &jwt.DefaultStrategy{Config: config, Issuer: jwt.NewDefaultIssuerUnverifiedFromJWKS(&jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
					{Key: gen.MustRSAKey(), KeyID: "rs256", Algorithm: string(jose.RS256), Use: consts.JSONWebTokenUseSignature},
					{Key: gen.MustES256Key(), KeyID: "es256", Algorithm: string(jose.ES256), Use: consts.JSONWebTokenUseSignature},
				}})}
			},
			expected: []string{"Section 5.4.1: the issuer signing algorithms 'ES256', 'RS256' include one not permitted"},
		},
		{
			name: "ShouldPassWithES256IssuerSigningKeys",
			modify: func(config *oauth2.Config) {
				config.JWTStrategy = &jwt.DefaultStrategy{Config: config, Issuer: jwt.NewDefaultIssuerUnverifiedFromJWKS(&jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
					{Key: gen.MustES256Key(), KeyID: "es256", Algorithm: string(jose.ES256), Use: consts.JSONWebTokenUseSignature},
				}})}
			},
		},
		{
			name:   "ShouldNotCheckIssuerSigningKeysTheStrategyDoesNotReport",
			modify: func(config *oauth2.Config) { config.JWTStrategy = &jwt.DefaultStrategy{Config: config} },
		},
		{
			name: "ShouldRejectRS256TrustedIssuerAlgorithms",
			modify: func(config *oauth2.Config) {
				config.RFC7591ClientRegistrationTrustedIssuers = []oauth2.RFC7591TrustedIssuer{{Issuer: "https://other.example.com"}}
				config.RFC7591TrustedIssuerSigningAlgValues = []string{string(jose.RS256)}
			},
			expected: []string{"Section 5.4.1: the software statement and trusted issuer algorithms 'RS256' include one not permitted"},
		},
		{
			name: "ShouldPassWithTrustedIssuers",
			modify: func(config *oauth2.Config) {
				config.RFC7591ClientRegistrationTrustedIssuers = []oauth2.RFC7591TrustedIssuer{{Issuer: "https://other.example.com"}}
			},
		},
		{
			name: "ShouldRejectTheDefaultTransactionTokenAlgorithm",
			modify: func(config *oauth2.Config) {
				config.RFC8693TokenTypes = map[string]oauth2.RFC8693TokenType{
					consts.TokenTypeRFC8693TxnToken: &rfc8693.TxnTokenType{Name: consts.TokenTypeRFC8693TxnToken, Domains: map[string]*rfc8693.TxnTokenTrustDomain{"https://td.example.com": {}}},
				}
			},
			expected: []string{"Section 5.4.1: the transaction token type '" + consts.TokenTypeRFC8693TxnToken + "' signs the tokens of the trust domain 'https://td.example.com' with 'RS256', which is not permitted"},
		},
		{
			name: "ShouldSkipANilTransactionTokenTrustDomain",
			modify: func(config *oauth2.Config) {
				config.RFC8693TokenTypes = map[string]oauth2.RFC8693TokenType{
					consts.TokenTypeRFC8693TxnToken: &rfc8693.TxnTokenType{Name: consts.TokenTypeRFC8693TxnToken, Domains: map[string]*rfc8693.TxnTokenTrustDomain{"https://td.example.com": nil}},
				}
			},
		},
		{
			name: "ShouldPassWithAPermittedTransactionTokenAlgorithm",
			modify: func(config *oauth2.Config) {
				config.RFC8693TokenTypes = map[string]oauth2.RFC8693TokenType{
					consts.TokenTypeRFC8693TxnToken: &rfc8693.TxnTokenType{Name: consts.TokenTypeRFC8693TxnToken, Domains: map[string]*rfc8693.TxnTokenTrustDomain{"https://td.example.com": {SigningAlg: string(jose.ES256)}}},
				}
			},
		},
		{
			name: "ShouldRejectTheDefaultSecurityEventTokenAlgorithm",
			modify: func(config *oauth2.Config) {
				config.SSF = &oauth2.SSFConfig{TokenStrategy: &oauth2.DefaultSecurityEventTokenStrategy{}}
			},
			expected: []string{"Section 5.4.1: security event tokens are signed with 'RS256', which is not permitted"},
		},
		{
			name: "ShouldRejectTheCAEPInteroperabilityProfile",
			modify: func(config *oauth2.Config) {
				config.SSF = &oauth2.SSFConfig{TokenStrategy: &oauth2.DefaultSecurityEventTokenStrategy{SigningAlg: string(jose.ES256)}, EnforceCAEPInteroperabilityProfile: true}
			},
			expected: []string{"Section 5.4.1: security event tokens must use a permitted algorithm, but EnforceCAEPInteroperabilityProfile requires RS256"},
		},
		{
			name: "ShouldPassWithAPermittedSecurityEventTokenAlgorithm",
			modify: func(config *oauth2.Config) {
				config.SSF = &oauth2.SSFConfig{TokenStrategy: &oauth2.DefaultSecurityEventTokenStrategy{SigningAlg: string(jose.ES256)}}
			},
		},
		{
			name: "ShouldRejectStatelessIntrospectionWithoutAStatefulOne",
			modify: func(config *oauth2.Config) {
				config.IntrospectionEndpointAuthMethods = []string{consts.ClientAuthMethodPrivateKeyJWT}
			},
			factories: []Factory{OAuth2StatelessJWTIntrospectionFactory},
			expected:  []string{"Section 5.3.4: the revocation status of access tokens must be verified, but the stateless JWT introspection handler is registered without a storage-backed one"},
		},
		{
			name: "ShouldPassStatelessIntrospectionWithAStatefulOne",
			modify: func(config *oauth2.Config) {
				config.IntrospectionEndpointAuthMethods = []string{consts.ClientAuthMethodPrivateKeyJWT}
			},
			factories: []Factory{OAuth2StatelessJWTIntrospectionFactory, OAuth2TokenIntrospectionFactory},
		},
		{
			name:     "ShouldRejectAMinimumNonceLengthOver64",
			modify:   func(config *oauth2.Config) { config.MinParameterEntropy = 65 },
			expected: []string{"Section 5.3.2.2: 'nonce' values of up to 64 characters must be accepted, but MinParameterEntropy is 65"},
		},
		{
			name:   "ShouldPassWithAMinimumNonceLengthOf64",
			modify: func(config *oauth2.Config) { config.MinParameterEntropy = 64 },
		},
		{
			name:      "ShouldRejectRS256CIBARequestAlgorithms",
			modify:    func(config *oauth2.Config) { config.CIBARequestSigningAlgValues = []string{string(jose.RS256)} },
			factories: CIBAFactories(),
			expected:  []string{"Section 5.4.1: the CIBA signed authentication request algorithms 'RS256' include one not permitted"},
		},
		{
			name:   "ShouldNotCheckCIBARequestAlgorithmsWithoutCIBA",
			modify: func(config *oauth2.Config) { config.CIBARequestSigningAlgValues = []string{string(jose.RS256)} },
		},
		{
			name:      "ShouldRejectRS256IDJAGRedemptionAlgorithms",
			modify:    func(config *oauth2.Config) { config.IDJAGRedeemSigningAlgValues = []string{string(jose.RS256)} },
			factories: []Factory{IDJAGRedeemFactory},
			expected:  []string{"Section 5.4.1: the Identity Assertion JWT Authorization Grant redemption algorithms 'RS256' include one not permitted"},
		},
		{
			name: "ShouldRejectTheDefaultJWTAuthorizationGrantAlgorithm",
			modify: func(config *oauth2.Config) {
				config.RFC8693TokenTypes = map[string]oauth2.RFC8693TokenType{
					"urn:example:grant": &rfc8693.JWTType{Name: "urn:example:grant", Issue: &rfc8693.JWTIssueConfig{Issuer: "https://grants.example.com", AuthorizationGrant: true}},
				}
			},
			expected: []string{"Section 5.4.1: the JWT authorization grant type 'urn:example:grant' is signed with 'RS256', which is not permitted"},
		},
		{
			name: "ShouldPassWithAPermittedJWTAuthorizationGrantAlgorithm",
			modify: func(config *oauth2.Config) {
				config.RFC8693TokenTypes = map[string]oauth2.RFC8693TokenType{
					"urn:example:grant": &rfc8693.JWTType{Name: "urn:example:grant", Issue: &rfc8693.JWTIssueConfig{Issuer: "https://grants.example.com", AuthorizationGrant: true, SigningAlg: string(jose.ES256)}},
				}
			},
		},
		{
			name: "ShouldNotCheckAJWTTypeThatIsNotAnAuthorizationGrant",
			modify: func(config *oauth2.Config) {
				config.RFC8693TokenTypes = map[string]oauth2.RFC8693TokenType{
					"urn:example:jwt": &rfc8693.JWTType{Name: "urn:example:jwt", Issue: &rfc8693.JWTIssueConfig{Issuer: "https://jwt.example.com"}},
				}
			},
		},
		{
			name: "ShouldRejectRS256JARMSigningKeys",
			modify: func(config *oauth2.Config) {
				config.JWTSecuredAuthorizeResponseModeStrategy = newFAPI2TestSigner(config, jose.RS256)
			},
			expected: []string{"Section 5.4.1: the JARM signing algorithms 'RS256' include one not permitted"},
		},
		{
			name: "ShouldRejectRS256IntrospectionResponseSigningKeys",
			modify: func(config *oauth2.Config) {
				config.IntrospectionJWTResponseStrategy = newFAPI2TestSigner(config, jose.RS256)
			},
			expected: []string{"Section 5.4.1: the introspection response signing algorithms 'RS256' include one not permitted"},
		},
		{
			name: "ShouldRejectRS256LogoutTokenSigningKeys",
			modify: func(config *oauth2.Config) {
				config.BackChannelLogoutTokenStrategy = &openid.DefaultStrategy{Strategy: newFAPI2TestSigner(config, jose.RS256), Config: config}
			},
			expected: []string{"Section 5.4.1: the Logout Token signing algorithms 'RS256' include one not permitted"},
		},
		{
			name: "ShouldRejectAnRS256ComposedStrategy",
			strategies: func(config *oauth2.Config) []any {
				return []any{&CommonStrategy{
					CoreStrategy:               NewOAuth2HMACStrategy(config),
					OpenIDConnectTokenStrategy: &openid.DefaultStrategy{Strategy: newFAPI2TestSigner(config, jose.RS256), Config: config},
					Strategy:                   newFAPI2TestSigner(config, jose.PS256),
				}}
			},
			expected: []string{"Section 5.4.1: the strategy 1 OpenID Connect signing algorithms 'RS256' include one not permitted"},
		},
		{
			name: "ShouldRejectAnRS256ComposedStrategyValue",
			strategies: func(config *oauth2.Config) []any {
				return []any{CommonStrategy{
					CoreStrategy:               NewOAuth2HMACStrategy(config),
					OpenIDConnectTokenStrategy: &openid.DefaultStrategy{Strategy: newFAPI2TestSigner(config, jose.RS256), Config: config},
					Strategy:                   newFAPI2TestSigner(config, jose.PS256),
				}}
			},
			expected: []string{"Section 5.4.1: the strategy 1 OpenID Connect signing algorithms 'RS256' include one not permitted"},
		},
		{
			name: "ShouldRejectAnRS256Strategy",
			strategies: func(config *oauth2.Config) []any {
				return []any{newFAPI2TestSigner(config, jose.PS256), newFAPI2TestSigner(config, jose.RS256)}
			},
			expected: []string{"Section 5.4.1: the strategy 2 signing algorithms 'RS256' include one not permitted"},
		},
		{
			name: "ShouldPassWithAPermittedComposedStrategy",
			strategies: func(config *oauth2.Config) []any {
				return []any{&CommonStrategy{
					CoreStrategy:               NewOAuth2HMACStrategy(config),
					OpenIDConnectTokenStrategy: &openid.DefaultStrategy{Strategy: newFAPI2TestSigner(config, jose.ES256), Config: config},
					Strategy:                   newFAPI2TestSigner(config, jose.PS256),
				}}
			},
		},
		{
			name: "ShouldNotCheckNilStrategies",
			strategies: func(config *oauth2.Config) []any {
				return []any{nil, (*jwt.DefaultStrategy)(nil), &openid.DefaultStrategy{}, &hoauth2.JWTProfileCoreStrategy{}, (*CommonStrategy)(nil), &CommonStrategy{}, CommonStrategy{}}
			},
		},
		{
			name:     "ShouldRejectRS256DPoPProofs",
			modify:   func(config *oauth2.Config) { config.DPoPAllowedJWSAlgorithms = []string{string(jose.RS256)} },
			expected: []string{"Section 5.4.1: the DPoP proof algorithms 'RS256' include one not permitted"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := newFAPI2Config()

			ApplyFAPI2SecurityProfile(config)

			if tc.modify != nil {
				tc.modify(config)
			}

			composeFAPI2(t, config, tc.factories...)

			var strategies []any

			if tc.strategies != nil {
				strategies = tc.strategies(config)
			}

			err := ValidateFAPI2SecurityProfile(context.Background(), config, strategies...)

			if len(tc.expected) == 0 {
				assert.NoError(t, err)

				return
			}

			require.Error(t, err)

			for _, expected := range tc.expected {
				assert.Contains(t, err.Error(), expected)
			}
		})
	}
}

func TestValidateFAPI2SecurityProfileWithoutTheProfile(t *testing.T) {
	config := newFAPI2Config()
	config.RFC7591ClientRegistrationGlobalSecret = []byte("a-completely-different-secret-at-least-32b")

	ComposeAllEnabled(config, storage.NewMemoryStore(), gen.MustRSAKey())

	err := ValidateFAPI2SecurityProfile(context.Background(), config)
	require.Error(t, err)

	for _, expected := range []string{
		"the response type must be 'code'",
		"only sender-constrained access tokens may be issued",
		"refresh tokens must not be rotated",
		"the authorization code lifetime must be at most 1m0s, but is 2m0s",
		"authorization requests must be pushed",
		"PKCE is required, but EnforcePKCE is not set",
		"the token endpoint accepts the client authentication methods",
		"the client assertion algorithms",
	} {
		assert.Contains(t, err.Error(), expected)
	}
}

func TestValidateFAPI2SecurityProfileMissingHandlers(t *testing.T) {
	config := newFAPI2Config()
	config.MTLSEnabled = true

	ApplyFAPI2SecurityProfile(config)

	Compose(config, storage.NewMemoryStore(), NewOAuth2HMACStrategy(config), OAuth2AuthorizeExplicitFactory)

	err := ValidateFAPI2SecurityProfile(context.Background(), config)
	require.Error(t, err)

	for _, expected := range []string{
		"Section 5.3.2.1: DPoP is enabled, but the DPoP token endpoint handler is not registered",
		"Section 5.3.2.1: DPoP is enabled, but the DPoP authorization code binding handler is not registered",
		"Section 5.3.2.1: mTLS is enabled, but the mTLS certificate-bound access token handler is not registered",
		"Section 5.3.2.2: pushed authorization requests must be supported, but the pushed authorization request handler is not registered",
		"Section 5.3.2.2: PKCE is required, but the PKCE handler is not registered",
	} {
		assert.Contains(t, err.Error(), expected)
	}
}

func TestApplyFAPI2SecurityProfile(t *testing.T) {
	config := &oauth2.Config{
		AuthorizeCodeLifespan:                    5 * time.Minute,
		PushedAuthorizeContextLifespan:           time.Hour,
		JWTClockSkew:                             -1,
		DPoPClockSkew:                            30 * time.Second,
		DisableAuthorizationServerIdentification: true,
		DisableClientAssertionIssuerAudience:     true,
		EnablePKCEPlainChallengeMethod:           true,
		TokenEndpointAuthMethods:                 []string{consts.ClientAuthMethodClientSecretBasic, consts.ClientAuthMethodPrivateKeyJWT},
		RevocationEndpointAuthMethods:            []string{consts.ClientAuthMethodClientSecretBasic},
		ClientAssertionSigningAlgValues:          []string{string(jose.RS256), string(jose.ES256)},
		RevocationEndpointAuthSigningAlgValues:   []string{string(jose.RS256)},
		IntrospectionEndpointAuthMethods:         []string{consts.ClientAuthMethodClientSecretBasic, consts.ClientAuthMethodPrivateKeyJWT, consts.AuthSchemeBearer},
		RFC7523AssertionSigningAlgValues:         []string{string(jose.RS256), string(jose.PS256)},
		GrantTypeJWTBearerCanSkipClientAuth:      true,
		AccessTokenURIQueryParameterEnabled:      true,
		AuthorizationSignedResponseAlgValues:     []string{string(jose.HS256), string(jose.ES256)},
		RFC7591TrustedIssuerSigningAlgValues:     []string{string(jose.RS256), string(jose.EdDSA)},
		IntrospectionSignedResponseAlgValues:     []string{string(jose.RS256), string(jose.PS256)},
	}

	ApplyFAPI2SecurityProfile(config)

	assert.False(t, config.GrantTypeJWTBearerCanSkipClientAuth)
	assert.False(t, config.AccessTokenURIQueryParameterEnabled)
	assert.True(t, config.FAPI2SecurityProfile)
	assert.Equal(t, []string{string(jose.ES256)}, config.AuthorizationSignedResponseAlgValues)
	assert.Equal(t, []string{string(jose.EdDSA)}, config.RFC7591TrustedIssuerSigningAlgValues)
	assert.Equal(t, []string{string(jose.PS256)}, config.IntrospectionSignedResponseAlgValues)

	assert.Equal(t, time.Minute, config.AuthorizeCodeLifespan)
	assert.Equal(t, time.Duration(0), config.PushedAuthorizeContextLifespan)
	assert.Equal(t, time.Duration(0), config.JWTClockSkew)
	assert.Equal(t, 30*time.Second, config.DPoPClockSkew)
	assert.True(t, config.RequirePushedAuthorizationRequests)
	assert.True(t, config.RequireRedirectURIPushedAuthorizationRequests)
	assert.True(t, config.EnforcePKCE)
	assert.False(t, config.EnablePKCEPlainChallengeMethod)
	assert.False(t, config.DisableAuthorizationServerIdentification)
	assert.False(t, config.DisableClientAssertionIssuerAudience)
	assert.True(t, config.RequireStringClientAssertionAudience)
	assert.True(t, config.DisableRefreshTokenRotation)
	assert.True(t, config.EnforceSenderConstrainedAccessTokens)
	assert.Equal(t, []string{consts.ClientAuthMethodPrivateKeyJWT}, config.TokenEndpointAuthMethods)
	assert.Equal(t, oauth2.FAPI2SecurityProfileClientAuthMethods, config.RevocationEndpointAuthMethods)
	assert.Equal(t, []string{string(jose.ES256)}, config.ClientAssertionSigningAlgValues)
	assert.Equal(t, oauth2.FAPI2SecurityProfileSigningAlgValues, config.RequestObjectSigningAlgValues)
	assert.Equal(t, oauth2.FAPI2SecurityProfileSigningAlgValues, config.DPoPAllowedJWSAlgorithms)
	assert.Equal(t, oauth2.FAPI2SecurityProfileSigningAlgValues, config.RevocationEndpointAuthSigningAlgValues)
	assert.Equal(t, []string{consts.ClientAuthMethodPrivateKeyJWT, consts.AuthSchemeBearer}, config.IntrospectionEndpointAuthMethods)
	assert.Equal(t, []string{string(jose.PS256)}, config.RFC7523AssertionSigningAlgValues)
	assert.Nil(t, config.IntrospectionEndpointAuthSigningAlgValues)

	for _, tc := range []struct {
		name     string
		methods  []string
		expected []string
	}{
		{"ShouldKeepAnUnsetIntrospectionList", nil, nil},
		{"ShouldKeepABearerOnlyIntrospectionList", []string{consts.AuthSchemeBearer}, []string{consts.AuthSchemeBearer}},
		{"ShouldKeepATokenOnlyIntrospectionList", []string{consts.AuthSchemeBearer, consts.AuthSchemeDPoP}, []string{consts.AuthSchemeBearer, consts.AuthSchemeDPoP}},
		{"ShouldReplaceIntrospectionClientMethodsNonePermitted", []string{consts.ClientAuthMethodClientSecretBasic, consts.AuthSchemeBearer}, append(slices.Clone(oauth2.FAPI2SecurityProfileClientAuthMethods), consts.AuthSchemeBearer)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := &oauth2.Config{IntrospectionEndpointAuthMethods: tc.methods}

			ApplyFAPI2SecurityProfile(config)

			assert.Equal(t, tc.expected, config.IntrospectionEndpointAuthMethods)
		})
	}
}

func newFAPI2TestSigner(config *oauth2.Config, alg jose.SignatureAlgorithm) *jwt.DefaultStrategy {
	var key any

	switch alg {
	case jose.ES256:
		key = gen.MustES256Key()
	default:
		key = gen.MustRSAKey()
	}

	return &jwt.DefaultStrategy{Config: config, Issuer: jwt.NewDefaultIssuerUnverifiedFromJWKS(&jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
		{Key: key, KeyID: string(alg), Algorithm: string(alg), Use: consts.JSONWebTokenUseSignature},
	}})}
}

func newFAPI2Config() *oauth2.Config {
	return &oauth2.Config{
		Issuer:       "https://as.example.com",
		DPoPEnabled:  true,
		GlobalSecret: []byte("some-cool-secret-that-is-32bytes"),
	}
}

func composeFAPI2(t *testing.T, config *oauth2.Config, extra ...Factory) {
	t.Helper()

	key := gen.MustRSAKey()

	keyGetter := func(context.Context) (any, error) {
		return key, nil
	}

	strategy := &jwt.DefaultStrategy{
		Config: config,
		Issuer: jwt.NewDefaultIssuerRS256Unverified(key),
	}

	factories := append([]Factory{
		OAuth2AuthorizeExplicitFactory,
		OAuth2RefreshTokenGrantFactory,
		OAuth2PKCEFactory,
		PushedAuthorizeHandlerFactory,
		OpenIDConnectExplicitFactory,
		OpenIDConnectRefreshFactory,
		DPoPAuthorizeFactory,
		DPoPTokenFactory,
		RFC8705Factory,
	}, extra...)

	Compose(
		config,
		storage.NewMemoryStore(),
		&CommonStrategy{
			CoreStrategy:               NewOAuth2HMACStrategy(config),
			OpenIDConnectTokenStrategy: NewOpenIDConnectStrategy(keyGetter, strategy, config),
			Strategy:                   strategy,
		},
		factories...,
	)
}
