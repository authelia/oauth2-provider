// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/jose"

	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/internal"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/gen"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestProtectedResourceMetadataMarshalJSON(t *testing.T) {
	testCases := []struct {
		name     string
		have     oauth2.ProtectedResourceMetadata
		expected string
		err      string
	}{
		{
			name:     "ShouldMarshalOnlyResource",
			have:     oauth2.ProtectedResourceMetadata{Resource: "https://rs.example.com"},
			expected: `{"resource":"https://rs.example.com"}`,
		},
		{
			name:     "ShouldOmitZeroValues",
			have:     oauth2.ProtectedResourceMetadata{Resource: "https://rs.example.com", AuthorizationServers: []string{}, ScopesSupported: []string{}, Extra: map[string]any{}},
			expected: `{"resource":"https://rs.example.com"}`,
		},
		{
			name:     "ShouldKeepEmptyBearerMethodsSupported",
			have:     oauth2.ProtectedResourceMetadata{Resource: "https://rs.example.com", BearerMethodsSupported: []string{}},
			expected: `{"resource":"https://rs.example.com","bearer_methods_supported":[]}`,
		},
		{
			name: "ShouldMarshalEveryMember",
			have: oauth2.ProtectedResourceMetadata{
				Resource:                              "https://rs.example.com",
				AuthorizationServers:                  []string{"https://auth.example.com"},
				JWKSURI:                               "https://rs.example.com/jwks.json",
				ScopesSupported:                       []string{"read", "write"},
				BearerMethodsSupported:                []string{"header"},
				ResourceSigningAlgValuesSupported:     []string{"ES256"},
				ResourceName:                          "Example",
				ResourceDocumentation:                 "https://rs.example.com/docs",
				ResourcePolicyURI:                     "https://rs.example.com/policy",
				ResourceTOSURI:                        "https://rs.example.com/tos",
				TLSClientCertificateBoundAccessTokens: true,
				AuthorizationDetailsTypesSupported:    []string{"payment_initiation"},
				DPoPSigningAlgValuesSupported:         []string{"ES256"},
				DPoPBoundAccessTokensRequired:         true,
				SignedMetadata:                        "a.b.c",
			},
			expected: `{"resource":"https://rs.example.com","authorization_servers":["https://auth.example.com"],"jwks_uri":"https://rs.example.com/jwks.json","scopes_supported":["read","write"],"bearer_methods_supported":["header"],"resource_signing_alg_values_supported":["ES256"],"resource_name":"Example","resource_documentation":"https://rs.example.com/docs","resource_policy_uri":"https://rs.example.com/policy","resource_tos_uri":"https://rs.example.com/tos","tls_client_certificate_bound_access_tokens":true,"authorization_details_types_supported":["payment_initiation"],"dpop_signing_alg_values_supported":["ES256"],"dpop_bound_access_tokens_required":true,"signed_metadata":"a.b.c"}`,
		},
		{
			name:     "ShouldMarshalExtraAtTopLevel",
			have:     oauth2.ProtectedResourceMetadata{Resource: "https://rs.example.com", ResourceName: "Example", Extra: map[string]any{"resource_name#ja": "例", "resource_name#en": "Example", "custom": []string{"a"}}},
			expected: `{"resource":"https://rs.example.com","resource_name":"Example","custom":["a"],"resource_name#en":"Example","resource_name#ja":"例"}`,
		},
		{
			name:     "ShouldMarshalOnlyExtra",
			have:     oauth2.ProtectedResourceMetadata{Extra: map[string]any{"custom": true}},
			expected: `{"custom":true}`,
		},
		{
			name: "ShouldErrorOnExtraCollidingWithSetMember",
			have: oauth2.ProtectedResourceMetadata{Resource: "https://rs.example.com", Extra: map[string]any{"resource": "x"}},
			err:  "the protected resource metadata extra parameter 'resource' collides with a defined parameter",
		},
		{
			name: "ShouldErrorOnExtraCollidingWithUnsetMember",
			have: oauth2.ProtectedResourceMetadata{Resource: "https://rs.example.com", Extra: map[string]any{"signed_metadata": "a.b.c"}},
			err:  "the protected resource metadata extra parameter 'signed_metadata' collides with a defined parameter",
		},
		{
			name: "ShouldErrorOnExtraValueNotMarshalable",
			have: oauth2.ProtectedResourceMetadata{Resource: "https://rs.example.com", Extra: map[string]any{"custom": make(chan int)}},
			err:  "json: unsupported type: chan int",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			for _, have := range []any{tc.have, &tc.have} {
				actual, err := json.Marshal(have)

				if tc.err != "" {
					assert.ErrorContains(t, err, tc.err)

					continue
				}

				require.NoError(t, err)
				assert.Equal(t, tc.expected, string(actual))
			}
		})
	}
}

func TestProtectedResourceMetadataMarshalJSONExtraCollisions(t *testing.T) {
	typ := reflect.TypeFor[oauth2.ProtectedResourceMetadata]()

	n := 0

	for i := range typ.NumField() {
		name, _, _ := strings.Cut(typ.Field(i).Tag.Get("json"), ",")
		if name == "-" {
			continue
		}

		n++

		t.Run(name, func(t *testing.T) {
			require.NotEmpty(t, name)

			_, err := json.Marshal(oauth2.ProtectedResourceMetadata{Extra: map[string]any{name: "x"}})

			assert.ErrorContains(t, err, "collides with a defined parameter")
		})
	}

	assert.Equal(t, 15, n)
}

func TestProtectedResourceMetadataUnmarshalJSON(t *testing.T) {
	testCases := []struct {
		name     string
		have     string
		expected oauth2.ProtectedResourceMetadata
		err      string
	}{
		{
			name:     "ShouldUnmarshalOnlyResource",
			have:     `{"resource":"https://rs.example.com"}`,
			expected: oauth2.ProtectedResourceMetadata{Resource: "https://rs.example.com"},
		},
		{
			name:     "ShouldKeepEmptyBearerMethodsSupported",
			have:     `{"resource":"https://rs.example.com","bearer_methods_supported":[]}`,
			expected: oauth2.ProtectedResourceMetadata{Resource: "https://rs.example.com", BearerMethodsSupported: []string{}},
		},
		{
			name: "ShouldUnmarshalUnknownMembersIntoExtra",
			have: `{"resource":"https://rs.example.com","resource_name":"Example","resource_name#ja":"例","custom":["a"],"dpop_bound_access_tokens_required":true}`,
			expected: oauth2.ProtectedResourceMetadata{
				Resource:                      "https://rs.example.com",
				ResourceName:                  "Example",
				DPoPBoundAccessTokensRequired: true,
				Extra:                         map[string]any{"resource_name#ja": "例", "custom": []any{"a"}},
			},
		},
		{
			name:     "ShouldNotMatchMemberNamesCaseInsensitively",
			have:     `{"resource":"https://rs.example.com","Resource_Name":"Example"}`,
			expected: oauth2.ProtectedResourceMetadata{Resource: "https://rs.example.com", Extra: map[string]any{"Resource_Name": "Example"}},
		},
		{
			name: "ShouldErrorOnMemberOfWrongType",
			have: `{"resource":["https://rs.example.com"]}`,
			err:  "json: cannot unmarshal array",
		},
		{
			name: "ShouldErrorOnNonObject",
			have: `["https://rs.example.com"]`,
			err:  "json: cannot unmarshal array",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := oauth2.ProtectedResourceMetadata{ResourceName: "stale", Extra: map[string]any{"stale": true}}

			err := json.Unmarshal([]byte(tc.have), &actual)

			if tc.err != "" {
				assert.ErrorContains(t, err, tc.err)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.expected, actual)

			data, err := json.Marshal(actual)
			require.NoError(t, err)

			assert.JSONEq(t, tc.have, string(data))
		})
	}
}

func TestProtectedResourceMetadataUnmarshalJSONLargeIntegers(t *testing.T) {
	testCases := []struct {
		name     string
		have     string
		expected map[string]any
	}{
		{
			name:     "ShouldPreserveTopLevelLargeInteger",
			have:     `{"resource":"https://rs.example.com","custom":9007199254740993}`,
			expected: map[string]any{"custom": json.Number("9007199254740993")},
		},
		{
			name:     "ShouldPreserveNestedLargeInteger",
			have:     `{"resource":"https://rs.example.com","custom":{"values":[9007199254740993]}}`,
			expected: map[string]any{"custom": map[string]any{"values": []any{json.Number("9007199254740993")}}},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var actual oauth2.ProtectedResourceMetadata

			require.NoError(t, json.Unmarshal([]byte(tc.have), &actual))
			assert.Equal(t, tc.expected, actual.Extra)

			data, err := json.Marshal(actual)
			require.NoError(t, err)

			assert.Equal(t, tc.have, string(data))
		})
	}
}

func TestOAuth2AuthorizationServerMetadataProtectedResources(t *testing.T) {
	testCases := []struct {
		name     string
		have     []string
		expected any
	}{
		{
			name:     "ShouldIncludeProtectedResources",
			have:     []string{"https://rs.example.com"},
			expected: []any{"https://rs.example.com"},
		},
		{
			name:     "ShouldSortAndDeduplicateProtectedResources",
			have:     []string{"https://rs.example.com", "https://api.example.com", "https://rs.example.com"},
			expected: []any{"https://api.example.com", "https://rs.example.com"},
		},
		{
			name: "ShouldOmitProtectedResourcesWhenNil",
		},
		{
			name: "ShouldOmitProtectedResourcesWhenEmpty",
			have: []string{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			key := gen.MustRSAKey()

			config := newDiscoveryOpenIDConfig(key)
			config.ProtectedResources = tc.have

			provider := composeDiscoveryOpenID(config, &jwt.DefaultStrategy{Config: config, Issuer: jwt.NewDefaultIssuerRS256Unverified(key)})

			as, err := provider.NewOAuth2AuthorizationServerMetadata(context.Background())
			require.NoError(t, err)

			op, err := provider.NewOpenIDConnectProviderMetadata(context.Background())
			require.NoError(t, err)

			for _, metadata := range []any{as, op} {
				members := marshalMembers(t, metadata)

				if tc.expected == nil {
					assert.NotContains(t, members, consts.DiscoveryProtectedResources)
				} else {
					assert.Equal(t, tc.expected, members[consts.DiscoveryProtectedResources])
				}
			}
		})
	}
}

func TestOAuth2AuthorizationServerMetadataProtectedResourcesNotProvided(t *testing.T) {
	key := gen.MustRSAKey()

	base := newDiscoveryOpenIDConfig(key)
	base.ProtectedResources = []string{"https://rs.example.com"}

	config := &noProtectedResourcesConfig{Configurator: base}

	provider, ok := composeDiscoveryOpenID(base, &jwt.DefaultStrategy{Config: base, Issuer: jwt.NewDefaultIssuerRS256Unverified(key)}).(*oauth2.Fosite)
	require.True(t, ok)

	provider.Config = config

	_, ok = any(config).(oauth2.ProtectedResourcesProvider)
	require.False(t, ok)

	metadata, err := provider.NewOAuth2AuthorizationServerMetadata(context.Background())
	require.NoError(t, err)

	assert.NotContains(t, marshalMembers(t, metadata), consts.DiscoveryProtectedResources)
}

func TestConfigGetProtectedResources(t *testing.T) {
	var provider oauth2.ProtectedResourcesProvider = &oauth2.Config{ProtectedResources: []string{"https://rs.example.com"}}

	assert.Equal(t, []string{"https://rs.example.com"}, provider.GetProtectedResources(context.Background()))
	assert.Nil(t, (&oauth2.Config{}).GetProtectedResources(context.Background()))
}

func TestNewProtectedResourceMetadata(t *testing.T) {
	testCases := []struct {
		name     string
		config   oauth2.Configurator
		resource string
		expected *oauth2.ProtectedResourceMetadata
		err      string
	}{
		{
			name:     "ShouldSetOnlyResourceWithoutConfiguration",
			config:   &oauth2.Config{},
			resource: "https://rs.example.com",
			expected: &oauth2.ProtectedResourceMetadata{Resource: "https://rs.example.com"},
		},
		{
			name:     "ShouldSetAuthorizationServersFromIssuer",
			config:   &oauth2.Config{Issuer: "https://auth.example.com"},
			resource: "https://rs.example.com",
			expected: &oauth2.ProtectedResourceMetadata{Resource: "https://rs.example.com", AuthorizationServers: []string{"https://auth.example.com"}},
		},
		{
			name:     "ShouldKeepResourcePathAndQuery",
			config:   &oauth2.Config{},
			resource: "https://rs.example.com:8443/api?tenant=a",
			expected: &oauth2.ProtectedResourceMetadata{Resource: "https://rs.example.com:8443/api?tenant=a"},
		},
		{
			name:     "ShouldSetDPoPSigningAlgValuesWhenEnabled",
			config:   &oauth2.Config{DPoPEnabled: true, DPoPStrategy: dpopResourceStrategy{}, DPoPAllowedJWSAlgorithms: []string{"ES256", "RS256"}},
			resource: "https://rs.example.com",
			expected: &oauth2.ProtectedResourceMetadata{Resource: "https://rs.example.com", DPoPSigningAlgValuesSupported: []string{"ES256", "RS256"}},
		},
		{
			name:     "ShouldOmitDPoPWithoutResourceStrategy",
			config:   &oauth2.Config{DPoPEnforce: true, DPoPStrategy: dpopStrategy{}, DPoPAllowedJWSAlgorithms: []string{"ES256", "RS256"}},
			resource: "https://rs.example.com",
			expected: &oauth2.ProtectedResourceMetadata{Resource: "https://rs.example.com"},
		},
		{
			name:     "ShouldOmitDPoPWithoutStrategy",
			config:   &oauth2.Config{DPoPEnforce: true, DPoPAllowedJWSAlgorithms: []string{"ES256", "RS256"}},
			resource: "https://rs.example.com",
			expected: &oauth2.ProtectedResourceMetadata{Resource: "https://rs.example.com"},
		},
		{
			name:     "ShouldOmitDPoPSigningAlgValuesWhenDisabled",
			config:   &oauth2.Config{DPoPAllowedJWSAlgorithms: []string{"ES256", "RS256"}},
			resource: "https://rs.example.com",
			expected: &oauth2.ProtectedResourceMetadata{Resource: "https://rs.example.com"},
		},
		{
			name:     "ShouldRequireDPoPBoundAccessTokensWhenEnforced",
			config:   &oauth2.Config{DPoPEnforce: true, DPoPStrategy: dpopResourceStrategy{}, DPoPAllowedJWSAlgorithms: []string{"ES256", "RS256"}},
			resource: "https://rs.example.com",
			expected: &oauth2.ProtectedResourceMetadata{Resource: "https://rs.example.com", DPoPSigningAlgValuesSupported: []string{"ES256", "RS256"}, DPoPBoundAccessTokensRequired: true},
		},
		{
			name:     "ShouldSetTLSClientCertificateBoundAccessTokensWhenMutualTLSEnabled",
			config:   &oauth2.Config{MTLSEnabled: true},
			resource: "https://rs.example.com",
			expected: &oauth2.ProtectedResourceMetadata{Resource: "https://rs.example.com", TLSClientCertificateBoundAccessTokens: true},
		},
		{
			name:     "ShouldNotRequireDPoPBoundAccessTokensWhenEnforcedButDisabled",
			config:   &dpopDisabledConfig{Config: &oauth2.Config{DPoPEnforce: true, DPoPStrategy: dpopResourceStrategy{}}},
			resource: "https://rs.example.com",
			expected: &oauth2.ProtectedResourceMetadata{Resource: "https://rs.example.com"},
		},
		{
			name:     "ShouldOmitAuthorizationDetailsTypesWithoutTokenEndpointHandler",
			config:   &oauth2.Config{AuthorizationDetailsTypeHandlers: []oauth2.AuthorizationDetailsTypeHandler{internal.PaymentInitiationTypeHandler{}, otherRARTypeHandler{}}},
			resource: "https://rs.example.com",
			expected: &oauth2.ProtectedResourceMetadata{Resource: "https://rs.example.com"},
		},
		{
			name: "ShouldSetSortedAuthorizationDetailsTypes",
			config: &oauth2.Config{
				AuthorizationDetailsTypeHandlers: []oauth2.AuthorizationDetailsTypeHandler{internal.PaymentInitiationTypeHandler{}, otherRARTypeHandler{}},
				TokenEndpointHandlers:            oauth2.TokenEndpointHandlers{&hoauth2.ClientCredentialsGrantHandler{}},
			},
			resource: "https://rs.example.com",
			expected: &oauth2.ProtectedResourceMetadata{Resource: "https://rs.example.com", AuthorizationDetailsTypesSupported: []string{testRARTypeOther, internal.AuthorizationDetailsTypePaymentInitiation}},
		},
		{
			name:     "ShouldErrorOnResourceWithoutHTTPS",
			config:   &oauth2.Config{},
			resource: "http://rs.example.com",
			err:      "the resource 'http://rs.example.com' must use the 'https' scheme",
		},
		{
			name:     "ShouldErrorOnRelativeResource",
			config:   &oauth2.Config{},
			resource: "rs.example.com",
			err:      "the resource 'rs.example.com' must be an absolute URL",
		},
		{
			name:     "ShouldErrorOnEmptyResource",
			config:   &oauth2.Config{},
			resource: "",
			err:      "the resource '' must be an absolute URL",
		},
		{
			name:     "ShouldErrorOnResourceWithEmptyHostname",
			config:   &oauth2.Config{},
			resource: "https://:8443/x",
			err:      "the resource 'https://:8443/x' must be an absolute URL",
		},
		{
			name:     "ShouldErrorOnResourceWithFragment",
			config:   &oauth2.Config{},
			resource: "https://rs.example.com#f",
			err:      "the resource 'https://rs.example.com#f' must not have a fragment component",
		},
		{
			name:     "ShouldErrorOnResourceWithEmptyFragment",
			config:   &oauth2.Config{},
			resource: "https://rs.example.com#",
			err:      "the resource 'https://rs.example.com#' must not have a fragment component",
		},
		{
			name:     "ShouldErrorOnResourceWithUserInfo",
			config:   &oauth2.Config{},
			resource: "https://user@rs.example.com",
			err:      "the resource 'https://user@rs.example.com' must not have a userinfo component",
		},
		{
			name:     "ShouldErrorOnInvalidResource",
			config:   &oauth2.Config{},
			resource: "https://rs.example.com/%zz",
			err:      "the resource 'https://rs.example.com/%zz' is not a valid URL",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			provider := &oauth2.Fosite{Config: tc.config}

			actual, err := provider.NewProtectedResourceMetadata(context.Background(), tc.resource)

			if tc.err != "" {
				assert.ErrorContains(t, err, tc.err)
				assert.Nil(t, actual)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.expected, actual)
			assert.Nil(t, actual.ScopesSupported)
			assert.Nil(t, actual.BearerMethodsSupported)
		})
	}
}

func TestProtectedResourceMetadataWellKnownURL(t *testing.T) {
	testCases := []struct {
		name     string
		have     string
		expected string
		err      string
	}{
		{name: "ShouldInsertWithoutPath", have: "https://rs.example.com", expected: "https://rs.example.com/.well-known/oauth-protected-resource"},
		{name: "ShouldRemoveTerminatingSlashAfterHost", have: "https://rs.example.com/", expected: "https://rs.example.com/.well-known/oauth-protected-resource"},
		{name: "ShouldInsertBeforePath", have: "https://rs.example.com/resource1", expected: "https://rs.example.com/.well-known/oauth-protected-resource/resource1"},
		{name: "ShouldKeepPathTerminatingSlash", have: "https://rs.example.com/resource1/", expected: "https://rs.example.com/.well-known/oauth-protected-resource/resource1/"},
		{name: "ShouldKeepQuery", have: "https://rs.example.com/api?tenant=a", expected: "https://rs.example.com/.well-known/oauth-protected-resource/api?tenant=a"},
		{name: "ShouldKeepQueryVerbatim", have: "https://rs.example.com/api?b=%2F&a=x+y", expected: "https://rs.example.com/.well-known/oauth-protected-resource/api?b=%2F&a=x+y"},
		{name: "ShouldKeepQueryWithoutPath", have: "https://rs.example.com?tenant=a", expected: "https://rs.example.com/.well-known/oauth-protected-resource?tenant=a"},
		{name: "ShouldKeepQueryAfterTerminatingSlash", have: "https://rs.example.com/?tenant=a", expected: "https://rs.example.com/.well-known/oauth-protected-resource?tenant=a"},
		{name: "ShouldTreatEmptyQueryAsNoQuery", have: "https://rs.example.com/x?", expected: "https://rs.example.com/.well-known/oauth-protected-resource/x"},
		{name: "ShouldKeepPort", have: "https://rs.example.com:8443/x", expected: "https://rs.example.com:8443/.well-known/oauth-protected-resource/x"},
		{name: "ShouldKeepEscapedPath", have: "https://rs.example.com/a%2Fb/c%20d", expected: "https://rs.example.com/.well-known/oauth-protected-resource/a%2Fb/c%20d"},
		{name: "ShouldErrorOnFragment", have: "https://rs.example.com/x#f", err: "the resource 'https://rs.example.com/x#f' must not have a fragment component"},
		{name: "ShouldErrorOnEmptyFragment", have: "https://rs.example.com/x#", err: "the resource 'https://rs.example.com/x#' must not have a fragment component"},
		{name: "ShouldErrorOnRelativeURL", have: "/resource1", err: "the resource '/resource1' must be an absolute URL"},
		{name: "ShouldErrorOnMissingHost", have: "https:///resource1", err: "the resource 'https:///resource1' must be an absolute URL"},
		{name: "ShouldErrorOnEmptyHostname", have: "https://:8443/x", err: "the resource 'https://:8443/x' must be an absolute URL"},
		{name: "ShouldErrorOnHTTP", have: "http://rs.example.com", err: "the resource 'http://rs.example.com' must use the 'https' scheme"},
		{name: "ShouldErrorOnUserInfo", have: "https://user@rs.example.com/x", err: "must not have a userinfo component"},
		{name: "ShouldErrorOnInvalidURL", have: "https://rs.example.com/%zz", err: "the resource 'https://rs.example.com/%zz' is not a valid URL"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual, err := oauth2.ProtectedResourceMetadataWellKnownURL(tc.have)

			if tc.err != "" {
				assert.ErrorContains(t, err, tc.err)
				assert.Empty(t, actual)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.expected, actual)
		})
	}
}

func TestSignProtectedResourceMetadata(t *testing.T) {
	testCases := []struct {
		name     string
		issuer   func() *jwt.DefaultIssuer
		have     string
		previous string
		expected string
		err      string
	}{
		{
			name: "ShouldSignWithRS256",
			issuer: func() *jwt.DefaultIssuer {
				return jwt.NewDefaultIssuerRS256Unverified(gen.MustRSAKey())
			},
			have:     "https://auth.example.com",
			expected: "RS256",
		},
		{
			name: "ShouldPreferRS256",
			issuer: func() *jwt.DefaultIssuer {
				return jwt.NewDefaultIssuerUnverifiedFromJWKS(&jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
					{Key: gen.MustES256Key(), KeyID: "ec", Use: jwt.JSONWebTokenUseSignature, Algorithm: string(jose.ES256)},
					{Key: gen.MustRSAKey(), KeyID: "rsa", Use: jwt.JSONWebTokenUseSignature, Algorithm: string(jose.RS256)},
				}})
			},
			have:     "https://auth.example.com",
			expected: "RS256",
		},
		{
			name: "ShouldSignWithES256WhenOnlyES256",
			issuer: func() *jwt.DefaultIssuer {
				return jwt.NewDefaultIssuerUnverifiedFromJWKS(&jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
					{Key: gen.MustES256Key(), KeyID: "ec", Use: jwt.JSONWebTokenUseSignature, Algorithm: string(jose.ES256)},
				}})
			},
			have:     "https://auth.example.com",
			expected: "ES256",
		},
		{
			name: "ShouldNotSignPreviousSignedMetadata",
			issuer: func() *jwt.DefaultIssuer {
				return jwt.NewDefaultIssuerRS256Unverified(gen.MustRSAKey())
			},
			have:     "https://auth.example.com",
			previous: "a.b.c",
			expected: "RS256",
		},
		{
			name: "ShouldErrorWithoutStrategy",
			have: "https://auth.example.com",
			err:  "unable to sign the protected resource metadata: the discovery metadata signing strategy is not configured",
		},
		{
			name:     "ShouldErrorWithoutStrategyAndClearPrevious",
			have:     "https://auth.example.com",
			previous: "a.b.c",
			err:      "unable to sign the protected resource metadata: the discovery metadata signing strategy is not configured",
		},
		{
			name: "ShouldErrorWithoutIssuer",
			issuer: func() *jwt.DefaultIssuer {
				return jwt.NewDefaultIssuerRS256Unverified(gen.MustRSAKey())
			},
			previous: "a.b.c",
			err:      "unable to sign the protected resource metadata: the issuer is not configured",
		},
		{
			name: "ShouldErrorWithoutSigningAlgorithms",
			issuer: func() *jwt.DefaultIssuer {
				return jwt.NewDefaultIssuerUnverifiedFromJWKS(&jose.JSONWebKeySet{})
			},
			have:     "https://auth.example.com",
			previous: "a.b.c",
			err:      "unable to sign the protected resource metadata: the signing strategy has no signing algorithms",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := &oauth2.Config{Issuer: tc.have}

			if tc.issuer != nil {
				config.DiscoveryMetadataSigningStrategy = &jwt.DefaultStrategy{Config: config, Issuer: tc.issuer()}
			}

			provider := &oauth2.Fosite{Config: config}

			metadata := &oauth2.ProtectedResourceMetadata{
				Resource:             "https://rs.example.com",
				AuthorizationServers: []string{"https://auth.example.com"},
				SignedMetadata:       tc.previous,
				Extra:                map[string]any{"resource_name#en": "Example"},
			}

			err := provider.SignProtectedResourceMetadata(context.Background(), metadata)
			if tc.err != "" {
				assert.EqualError(t, err, tc.err)
				assert.Empty(t, metadata.SignedMetadata)

				return
			}

			require.NoError(t, err)
			require.NotEmpty(t, metadata.SignedMetadata)
			assert.NotEqual(t, tc.previous, metadata.SignedMetadata)

			parts := strings.Split(metadata.SignedMetadata, ".")
			require.Len(t, parts, 3)

			raw, err := base64.RawURLEncoding.DecodeString(parts[0])
			require.NoError(t, err)

			header := map[string]any{}
			require.NoError(t, json.Unmarshal(raw, &header))

			assert.Equal(t, tc.expected, header["alg"])

			raw, err = base64.RawURLEncoding.DecodeString(parts[1])
			require.NoError(t, err)

			claims := map[string]any{}
			require.NoError(t, json.Unmarshal(raw, &claims))

			assert.Equal(t, "https://auth.example.com", claims["iss"])
			assert.Equal(t, "https://rs.example.com", claims["resource"])
			assert.Equal(t, []any{"https://auth.example.com"}, claims["authorization_servers"])
			assert.Equal(t, "Example", claims["resource_name#en"])
			assert.NotContains(t, claims, "signed_metadata")

			strategy := config.DiscoveryMetadataSigningStrategy

			_, err = strategy.Decode(context.Background(), metadata.SignedMetadata)
			require.NoError(t, err)

			forged := base64.RawURLEncoding.EncodeToString([]byte(strings.Replace(string(raw), "https://rs.example.com", "https://rs.example.org", 1)))

			_, err = strategy.Decode(context.Background(), parts[0]+"."+forged+"."+parts[2])
			assert.Error(t, err)
		})
	}
}

func TestSignProtectedResourceMetadataNil(t *testing.T) {
	provider := &oauth2.Fosite{Config: &oauth2.Config{Issuer: "https://auth.example.com"}}

	assert.EqualError(t, provider.SignProtectedResourceMetadata(context.Background(), nil), "unable to sign the protected resource metadata: the metadata is nil")
}

func TestSignProtectedResourceMetadataExtraCollision(t *testing.T) {
	config := &oauth2.Config{Issuer: "https://auth.example.com"}
	config.DiscoveryMetadataSigningStrategy = &jwt.DefaultStrategy{Config: config, Issuer: jwt.NewDefaultIssuerRS256Unverified(gen.MustRSAKey())}

	provider := &oauth2.Fosite{Config: config}

	metadata := &oauth2.ProtectedResourceMetadata{
		Resource:       "https://rs.example.com",
		SignedMetadata: "a.b.c",
		Extra:          map[string]any{"resource": "https://other.example.com"},
	}

	err := provider.SignProtectedResourceMetadata(context.Background(), metadata)

	assert.ErrorContains(t, err, "unable to marshal the protected resource metadata for signing: ")
	assert.ErrorContains(t, err, "the protected resource metadata extra parameter 'resource' collides with a defined parameter")
	assert.Empty(t, metadata.SignedMetadata)
}

func TestWriteProtectedResourceMetadata(t *testing.T) {
	provider := &oauth2.Fosite{Config: &oauth2.Config{}}

	have := &oauth2.ProtectedResourceMetadata{
		Resource:               "https://rs.example.com",
		AuthorizationServers:   []string{"https://auth.example.com"},
		BearerMethodsSupported: []string{"header"},
		SignedMetadata:         "a.b.c",
		Extra:                  map[string]any{"resource_name#en": "Example"},
	}

	rw := httptest.NewRecorder()
	provider.WriteProtectedResourceMetadata(context.Background(), rw, have)

	assert.Equal(t, http.StatusOK, rw.Code)
	assert.Equal(t, "application/json;charset=UTF-8", rw.Header().Get("Content-Type"))

	actual := &oauth2.ProtectedResourceMetadata{}

	require.NoError(t, json.Unmarshal(rw.Body.Bytes(), actual))
	assert.Equal(t, have, actual)

	rw = httptest.NewRecorder()
	provider.WriteProtectedResourceMetadata(context.Background(), rw, &oauth2.ProtectedResourceMetadata{Extra: map[string]any{"resource": "https://other.example.com"}})

	assert.Equal(t, http.StatusInternalServerError, rw.Code)
	assert.Empty(t, rw.Body.String())

	rw = httptest.NewRecorder()
	provider.WriteProtectedResourceMetadata(context.Background(), rw, nil)

	assert.Equal(t, http.StatusInternalServerError, rw.Code)
	assert.Empty(t, rw.Body.String())
}

type noProtectedResourcesConfig struct {
	oauth2.Configurator
}

type dpopDisabledConfig struct {
	*oauth2.Config
}

func (c *dpopDisabledConfig) GetDPoPEnabled(_ context.Context) bool {
	return false
}

type dpopStrategy struct {
	oauth2.DPoPStrategy
}

type dpopResourceStrategy struct {
	oauth2.DPoPStrategy
}

func (dpopResourceStrategy) ValidateResourceAccess(_ context.Context, _ *http.Request, _, _ string, _ bool, _ ...string) (*oauth2.DPoPProof, error) {
	return nil, nil
}
