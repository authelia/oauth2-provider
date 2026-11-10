// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2/internal/consts"
)

func TestGetClient(t *testing.T) {
	const url = "https://client.example.com/metadata.json"

	registered := &DefaultClient{ID: "registered"}
	registeredURL := &DefaultClient{ID: url}
	resolved := &stubDocumentClient{Client: &DefaultClient{ID: url}, document: true}
	failure := errors.New("the store is unavailable")

	testCases := []struct {
		name     string
		store    stubClientGetter
		config   any
		id       string
		expected Client
		err      error
		resolves int
	}{
		{
			name:     "ShouldReturnRegisteredClient",
			store:    stubClientGetter{clients: map[string]Client{"registered": registered}},
			config:   &Config{Issuer: testIssuer, ClientIDMetadataDocumentResolver: &stubResolver{client: resolved}},
			id:       "registered",
			expected: registered,
		},
		{
			name:     "ShouldPreferRegisteredClientForURL",
			store:    stubClientGetter{clients: map[string]Client{url: registeredURL}},
			config:   &Config{Issuer: testIssuer, ClientIDMetadataDocumentResolver: &stubResolver{client: resolved}},
			id:       url,
			expected: registeredURL,
		},
		{
			name:     "ShouldResolveUnknownURL",
			store:    stubClientGetter{},
			config:   &Config{Issuer: testIssuer, ClientIDMetadataDocumentResolver: &stubResolver{client: resolved}},
			id:       url,
			expected: resolved,
			resolves: 1,
		},
		{
			name:   "ShouldNotResolveWhenDisabled",
			store:  stubClientGetter{},
			config: &Config{},
			id:     url,
			err:    ErrNotFound,
		},
		{
			name:   "ShouldNotResolveWhenConfigIsNotAProvider",
			store:  stubClientGetter{},
			config: struct{}{},
			id:     url,
			err:    ErrNotFound,
		},
		{
			name:   "ShouldNotResolveNilConfig",
			store:  stubClientGetter{},
			config: nil,
			id:     url,
			err:    ErrNotFound,
		},
		{
			name:   "ShouldNotResolveOpaqueIdentifier",
			store:  stubClientGetter{},
			config: &Config{Issuer: testIssuer, ClientIDMetadataDocumentResolver: &stubResolver{client: resolved}},
			id:     "unknown",
			err:    ErrNotFound,
		},
		{
			name:   "ShouldNotResolveInvalidURL",
			store:  stubClientGetter{},
			config: &Config{Issuer: testIssuer, ClientIDMetadataDocumentResolver: &stubResolver{client: resolved}},
			id:     "https://client.example.com/a/../b",
			err:    ErrNotFound,
		},
		{
			name:   "ShouldNotResolveOnStoreFailure",
			store:  stubClientGetter{err: failure},
			config: &Config{Issuer: testIssuer, ClientIDMetadataDocumentResolver: &stubResolver{client: resolved}},
			id:     url,
			err:    failure,
		},
		{
			name:     "ShouldReturnResolverError",
			store:    stubClientGetter{},
			config:   &Config{Issuer: testIssuer, ClientIDMetadataDocumentResolver: &stubResolver{err: ErrInvalidClient}},
			id:       url,
			err:      ErrInvalidClient,
			resolves: 1,
		},
		{
			name:     "ShouldRefuseNilResolverResult",
			store:    stubClientGetter{},
			config:   &Config{Issuer: testIssuer, ClientIDMetadataDocumentResolver: &stubResolver{}},
			id:       url,
			err:      ErrServerError,
			resolves: 1,
		},
		{
			name:     "ShouldRefuseResolverResultWithAnotherIdentifier",
			store:    stubClientGetter{},
			config:   &Config{Issuer: testIssuer, ClientIDMetadataDocumentResolver: &stubResolver{client: &stubDocumentClient{Client: &DefaultClient{ID: url + "x"}, document: true}}},
			id:       url,
			err:      ErrServerError,
			resolves: 1,
		},
		{
			name:     "ShouldRefuseResolverResultWithTheIdentifierOfARegisteredClient",
			store:    stubClientGetter{clients: map[string]Client{"registered": registered}},
			config:   &Config{Issuer: testIssuer, ClientIDMetadataDocumentResolver: &stubResolver{client: &stubDocumentClient{Client: registered, document: true}}},
			id:       url,
			err:      ErrServerError,
			resolves: 1,
		},
		{
			name:     "ShouldRefuseUnmarkedResolverResult",
			store:    stubClientGetter{},
			config:   &Config{Issuer: testIssuer, ClientIDMetadataDocumentResolver: &stubResolver{client: &DefaultClient{ID: url}}},
			id:       url,
			err:      ErrServerError,
			resolves: 1,
		},
		{
			name:     "ShouldRefuseResolverResultReportingItIsNotADocumentClient",
			store:    stubClientGetter{},
			config:   &Config{Issuer: testIssuer, ClientIDMetadataDocumentResolver: &stubResolver{client: &stubDocumentClient{Client: &DefaultClient{ID: url}}}},
			id:       url,
			err:      ErrServerError,
			resolves: 1,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			client, err := GetClient(t.Context(), tc.config, tc.store, tc.id)

			if tc.err != nil {
				require.ErrorIs(t, err, tc.err)
				assert.Nil(t, client)
			} else {
				require.NoError(t, err)
				assert.Same(t, tc.expected, client)
			}

			if config, ok := tc.config.(*Config); ok && config.ClientIDMetadataDocumentResolver != nil {
				assert.Equal(t, tc.resolves, config.ClientIDMetadataDocumentResolver.(*stubResolver).calls)
			}
		})
	}
}

func TestGetClientAllowedDomainSuffixes(t *testing.T) {
	testCases := []struct {
		name     string
		suffixes []string
		id       string
		allowed  bool
	}{
		{"ShouldAllowAnyHostWithoutSuffixes", nil, "https://client.example.org/c", true},
		{"ShouldAllowAnyHostWithEmptySuffixes", []string{}, "https://client.example.org/c", true},
		{"ShouldAllowAnyHostWithOnlyBlankSuffixes", []string{"", "."}, "https://client.example.org/c", true},
		{"ShouldAllowTheDomainItself", []string{"example.com"}, "https://example.com/c", true},
		{"ShouldAllowASubdomain", []string{"example.com"}, "https://app.example.com/c", true},
		{"ShouldAllowADeepSubdomain", []string{"example.com"}, "https://a.b.example.com/c", true},
		{"ShouldAllowAnySuffixInTheList", []string{"example.org", "example.com"}, "https://app.example.com/c", true},
		{"ShouldIgnoreBlankSuffixesBesideOthers", []string{"", "example.com"}, "https://app.example.org/c", false},
		{"ShouldIgnoreThePort", []string{"example.com"}, "https://app.example.com:8443/c", true},
		{"ShouldIgnoreHostCase", []string{"example.com"}, "https://APP.Example.COM/c", true},
		{"ShouldIgnoreSuffixCase", []string{"Example.COM"}, "https://app.example.com/c", true},
		{"ShouldIgnoreATrailingDotOnTheHost", []string{"example.com"}, "https://app.example.com./c", true},
		{"ShouldIgnoreATrailingDotOnTheSuffix", []string{"example.com."}, "https://app.example.com/c", true},
		{"ShouldRefuseAnotherDomain", []string{"example.com"}, "https://client.example.org/c", false},
		{"ShouldRefuseASuffixWithoutALabelBoundary", []string{"example.com"}, "https://badexample.com/c", false},
		{"ShouldRefuseTheSuffixAsAPrefix", []string{"example.com"}, "https://example.com.attacker.org/c", false},
		{"ShouldRefuseAParentDomain", []string{"app.example.com"}, "https://example.com/c", false},
		{"ShouldAllowASubdomainForALeadingDot", []string{".example.com"}, "https://app.example.com/c", true},
		{"ShouldRefuseTheDomainItselfForALeadingDot", []string{".example.com"}, "https://example.com/c", false},
		{"ShouldRefuseAnIPv4Literal", []string{"example.com"}, "https://203.0.113.10/c", false},
		{"ShouldRefuseAnIPv4LiteralMatchingTextually", []string{"113.10"}, "https://203.0.113.10/c", false},
		{"ShouldRefuseAnIPv6Literal", []string{"example.com"}, "https://[2001:db8::1]/c", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			resolver := &stubResolver{client: &stubDocumentClient{Client: &DefaultClient{ID: tc.id}, document: true}}

			config := &Config{
				Issuer:                           testIssuer,
				ClientIDMetadataDocumentResolver: resolver,
				ClientIDMetadataDocumentAllowedDomainSuffixes: tc.suffixes,
			}

			client, err := GetClient(t.Context(), config, stubClientGetter{}, tc.id)

			if tc.allowed {
				require.NoError(t, err)
				assert.Equal(t, tc.id, client.GetID())
				assert.Equal(t, 1, resolver.calls)
			} else {
				require.ErrorIs(t, err, ErrNotFound)
				assert.Nil(t, client)
				assert.Equal(t, 0, resolver.calls)
			}
		})
	}
}

func TestGetClientAllowedDomainSuffixesDoNotApplyToRegisteredClients(t *testing.T) {
	const id = "https://client.example.org/c"

	registered := &DefaultClient{ID: id}
	resolver := &stubResolver{}

	config := &Config{
		ClientIDMetadataDocumentResolver:              resolver,
		ClientIDMetadataDocumentAllowedDomainSuffixes: []string{"example.com"},
	}

	client, err := GetClient(t.Context(), config, stubClientGetter{clients: map[string]Client{id: registered}}, id)

	require.NoError(t, err)
	assert.Same(t, registered, client)
	assert.Equal(t, 0, resolver.calls)
}

func TestGetClientRequiresAnIssuer(t *testing.T) {
	const id = "https://client.example.com/metadata.json"

	resolver := &stubResolver{client: &stubDocumentClient{Client: &DefaultClient{ID: id}, document: true}}

	testCases := []struct {
		name   string
		config *Config
	}{
		{"ShouldRefuseWithoutAnIssuer", &Config{ClientIDMetadataDocumentResolver: resolver}},
		{"ShouldRefuseWhenAuthorizationServerIdentificationIsDisabled", &Config{Issuer: testIssuer, DisableAuthorizationServerIdentification: true, ClientIDMetadataDocumentResolver: resolver}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			client, err := GetClient(t.Context(), tc.config, stubClientGetter{}, id)

			require.ErrorIs(t, err, ErrServerError)
			assert.Nil(t, client)
			assert.Contains(t, ErrorToDebugRFC6749Error(err).Error(), "RFC 9207 authorization server issuer identification is disabled or no issuer is configured")
			assert.Equal(t, 0, resolver.calls)
		})
	}
}

func TestSetClientIDMetadataDocumentIssuer(t *testing.T) {
	document := &stubDocumentClient{Client: &DefaultClient{ID: "https://client.example.com/metadata.json"}, document: true}
	registered := &DefaultClient{ID: "registered"}

	testCases := []struct {
		name     string
		config   *Config
		client   Client
		mode     ResponseModeType
		existing string
		expected string
	}{
		{"ShouldSetTheIssuerForADocumentClient", &Config{Issuer: testIssuer, ClientIDMetadataDocumentResolver: &stubResolver{}}, document, ResponseModeQuery, "", testIssuer},
		{"ShouldSetTheIssuerForTheDefaultMode", &Config{Issuer: testIssuer, ClientIDMetadataDocumentResolver: &stubResolver{}}, document, ResponseModeDefault, "", testIssuer},
		{"ShouldSetTheIssuerForFormPost", &Config{Issuer: testIssuer, ClientIDMetadataDocumentResolver: &stubResolver{}}, document, ResponseModeFormPost, "", testIssuer},
		{"ShouldKeepAnIssuerAlreadySet", &Config{Issuer: testIssuer, ClientIDMetadataDocumentResolver: &stubResolver{}}, document, ResponseModeFragment, "https://other.example.com", "https://other.example.com"},
		{"ShouldNotSetTheIssuerForAJWTMode", &Config{Issuer: testIssuer, ClientIDMetadataDocumentResolver: &stubResolver{}}, document, ResponseModeQueryJWT, "", ""},
		{"ShouldNotSetTheIssuerForARegisteredClient", &Config{Issuer: testIssuer, ClientIDMetadataDocumentResolver: &stubResolver{}}, registered, ResponseModeQuery, "", ""},
		{"ShouldNotSetTheIssuerWhenDisabled", &Config{Issuer: testIssuer}, document, ResponseModeQuery, "", ""},
		{"ShouldNotSetAnEmptyIssuer", &Config{ClientIDMetadataDocumentResolver: &stubResolver{}}, document, ResponseModeQuery, "", ""},
		{"ShouldNotSetTheIssuerWhenAuthorizationServerIdentificationIsDisabled", &Config{Issuer: testIssuer, DisableAuthorizationServerIdentification: true, ClientIDMetadataDocumentResolver: &stubResolver{}}, document, ResponseModeQuery, "", ""},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			request := NewAuthorizeRequest()
			request.Client = tc.client

			parameters := url.Values{}

			if tc.existing != "" {
				parameters.Set(consts.FormParameterIssuer, tc.existing)
			}

			setClientIDMetadataDocumentIssuer(t.Context(), tc.config, request, tc.mode, parameters)

			assert.Equal(t, tc.expected, parameters.Get(consts.FormParameterIssuer))
		})
	}
}

func TestGetClientReservedIdentifiers(t *testing.T) {
	const id = "https://auth.example.com/oauth2"

	testCases := []struct {
		name   string
		config *Config
	}{
		{"ShouldRejectTheIssuer", &Config{Issuer: id}},
		{"ShouldRejectAnAllowedJWTAssertionAudience", &Config{AllowedJWTAssertionAudiences: []string{"https://auth.example.com/token", id}}},
		{"ShouldRejectAnAllowedIntrospectionAudience", &Config{AllowedIntrospectionAudiences: []string{id}}},
		{"ShouldRejectTheIntrospectionEndpointURL", &Config{EndpointURLs: EndpointURLs{Introspection: id}}},
		{"ShouldRejectTheIntrospectionEndpointMutualTLSAlias", &Config{EndpointURLs: EndpointURLs{MutualTLSAliases: RFC8705MutualTLSEndpointAliases{Introspection: id}}}},
		{"ShouldRejectTheRegistrationEndpointURL", &Config{EndpointURLs: EndpointURLs{Registration: id}}},
		{"ShouldRejectTheRegistrationEndpointMutualTLSAlias", &Config{EndpointURLs: EndpointURLs{MutualTLSAliases: RFC8705MutualTLSEndpointAliases{Registration: id}}}},
		{"ShouldRejectARegistrationEndpointAudience", &Config{RFC7591ClientRegistrationEndpointAudiences: []string{id}}},
		{"ShouldRejectAReservedIdentifier", &Config{ClientIDMetadataDocumentReservedIdentifiers: []string{"https://rs.example.com/api", id}}},
		{"ShouldRejectATokenTypeIdentifier", &Config{RFC8693TokenTypes: map[string]RFC8693TokenType{"urn:example:jwt": &stubIdentifiersTokenType{identifiers: []string{"", "https://idp.example.com", id}}}}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			resolver := &stubResolver{client: &stubDocumentClient{Client: &DefaultClient{ID: id}, document: true}}

			tc.config.ClientIDMetadataDocumentResolver = resolver

			if tc.config.Issuer == "" {
				tc.config.Issuer = testIssuer
			}

			client, err := GetClient(t.Context(), tc.config, stubClientGetter{}, id)

			require.ErrorIs(t, err, ErrInvalidClient)
			assert.Nil(t, client)
			assert.Contains(t, ErrorToDebugRFC6749Error(err).Error(), "is the identifier of this authorization server or of a party it trusts")
			assert.Equal(t, 0, resolver.calls)
		})
	}

	t.Run("ShouldIgnoreATokenTypeWithoutIdentifiers", func(t *testing.T) {
		resolver := &stubResolver{client: &stubDocumentClient{Client: &DefaultClient{ID: id}, document: true}}

		client, err := GetClient(t.Context(), &Config{Issuer: testIssuer, ClientIDMetadataDocumentResolver: resolver, RFC8693TokenTypes: map[string]RFC8693TokenType{"urn:example:other": stubTokenType{}}}, stubClientGetter{}, id)

		require.NoError(t, err)
		assert.Equal(t, id, client.GetID())
	})

	t.Run("ShouldUseSimpleStringComparison", func(t *testing.T) {
		resolver := &stubResolver{client: &stubDocumentClient{Client: &DefaultClient{ID: id + "/"}, document: true}}

		client, err := GetClient(t.Context(), &Config{Issuer: id, ClientIDMetadataDocumentResolver: resolver}, stubClientGetter{}, id+"/")

		require.NoError(t, err)
		assert.Equal(t, id+"/", client.GetID())
	})

	t.Run("ShouldPreferARegisteredClient", func(t *testing.T) {
		registered := &DefaultClient{ID: id}
		resolver := &stubResolver{}

		client, err := GetClient(t.Context(), &Config{Issuer: id, ClientIDMetadataDocumentResolver: resolver}, stubClientGetter{clients: map[string]Client{id: registered}}, id)

		require.NoError(t, err)
		assert.Equal(t, registered, client)
		assert.Equal(t, 0, resolver.calls)
	})
}

func TestAuthenticateClientReportsATransientDocumentFailure(t *testing.T) {
	id := "https://client.example.com/metadata.json"

	testCases := []struct {
		name     string
		err      error
		expected *RFC6749Error
		status   int
	}{
		{"ShouldReportTemporarilyUnavailable", ErrTemporarilyUnavailable.WithHint("The Client ID Metadata Document could not be retrieved."), ErrTemporarilyUnavailable, http.StatusServiceUnavailable},
		{"ShouldReportInvalidClient", ErrInvalidClient.WithHint("The Client ID Metadata Document could not be used."), ErrInvalidClient, http.StatusUnauthorized},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			strategy := &DefaultClientAuthenticationStrategy{Store: newMTLSClientStore(), Config: &Config{Issuer: testIssuer, ClientIDMetadataDocumentResolver: &stubResolver{err: tc.err}}}

			form := url.Values{consts.FormParameterClientID: {id}}

			client, _, err := strategy.AuthenticateClient(t.Context(), &http.Request{Header: http.Header{}, PostForm: form, Form: form}, form, &TokenEndpointClientAuthStrategy{})

			require.ErrorIs(t, err, tc.expected)
			assert.Nil(t, client)
			assert.Equal(t, tc.status, ErrorToRFC6749Error(err).CodeField)
		})
	}
}

func TestErrClientLookup(t *testing.T) {
	fallback := ErrInvalidClient.WithHint("fallback")

	transient := ErrTemporarilyUnavailable.WithWrap(errors.New("timeout"))

	assert.Equal(t, transient, errClientLookup(transient, fallback))

	err := errClientLookup(ErrNotFound, fallback)

	require.ErrorIs(t, err, ErrInvalidClient)
	assert.Equal(t, "fallback", ErrorToRFC6749Error(err).HintField)
}

const testIssuer = "https://as.example.com"

type stubClientGetter struct {
	clients map[string]Client
	err     error
}

func (s stubClientGetter) GetClient(_ context.Context, id string) (Client, error) {
	if s.err != nil {
		return nil, s.err
	}

	if client, ok := s.clients[id]; ok {
		return client, nil
	}

	return nil, ErrNotFound
}

type stubResolver struct {
	client Client
	err    error
	calls  int
}

func (s *stubResolver) ResolveClientIDMetadataDocumentClient(_ context.Context, _ string) (Client, error) {
	s.calls++

	return s.client, s.err
}

type stubDocumentClient struct {
	Client

	document bool
}

func (c *stubDocumentClient) IsClientIDMetadataDocumentClient() (is bool) {
	return c.document
}

type stubIdentifiersTokenType struct {
	identifiers []string
}

func (s *stubIdentifiersTokenType) GetName(_ context.Context) string {
	return "urn:example:jwt"
}

func (s *stubIdentifiersTokenType) GetType(_ context.Context) string {
	return consts.TokenTypeRFC8693JWT
}

func (s *stubIdentifiersTokenType) GetIdentifiers(_ context.Context) []string {
	return s.identifiers
}

type stubTokenType struct{}

func (stubTokenType) GetName(_ context.Context) string {
	return "urn:example:other"
}

func (stubTokenType) GetType(_ context.Context) string {
	return consts.TokenTypeRFC8693JWT
}
