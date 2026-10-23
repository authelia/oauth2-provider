// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
			config:   &Config{ClientIDMetadataDocumentResolver: &stubResolver{client: resolved}},
			id:       "registered",
			expected: registered,
		},
		{
			name:     "ShouldPreferRegisteredClientForURL",
			store:    stubClientGetter{clients: map[string]Client{url: registeredURL}},
			config:   &Config{ClientIDMetadataDocumentResolver: &stubResolver{client: resolved}},
			id:       url,
			expected: registeredURL,
		},
		{
			name:     "ShouldResolveUnknownURL",
			store:    stubClientGetter{},
			config:   &Config{ClientIDMetadataDocumentResolver: &stubResolver{client: resolved}},
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
			config: &Config{ClientIDMetadataDocumentResolver: &stubResolver{client: resolved}},
			id:     "unknown",
			err:    ErrNotFound,
		},
		{
			name:   "ShouldNotResolveInvalidURL",
			store:  stubClientGetter{},
			config: &Config{ClientIDMetadataDocumentResolver: &stubResolver{client: resolved}},
			id:     "https://client.example.com/a/../b",
			err:    ErrNotFound,
		},
		{
			name:   "ShouldNotResolveOnStoreFailure",
			store:  stubClientGetter{err: failure},
			config: &Config{ClientIDMetadataDocumentResolver: &stubResolver{client: resolved}},
			id:     url,
			err:    failure,
		},
		{
			name:     "ShouldReturnResolverError",
			store:    stubClientGetter{},
			config:   &Config{ClientIDMetadataDocumentResolver: &stubResolver{err: ErrInvalidClient}},
			id:       url,
			err:      ErrInvalidClient,
			resolves: 1,
		},
		{
			name:     "ShouldRefuseNilResolverResult",
			store:    stubClientGetter{},
			config:   &Config{ClientIDMetadataDocumentResolver: &stubResolver{}},
			id:       url,
			err:      ErrServerError,
			resolves: 1,
		},
		{
			name:     "ShouldRefuseResolverResultWithAnotherIdentifier",
			store:    stubClientGetter{},
			config:   &Config{ClientIDMetadataDocumentResolver: &stubResolver{client: &stubDocumentClient{Client: &DefaultClient{ID: url + "x"}, document: true}}},
			id:       url,
			err:      ErrServerError,
			resolves: 1,
		},
		{
			name:     "ShouldRefuseResolverResultWithTheIdentifierOfARegisteredClient",
			store:    stubClientGetter{clients: map[string]Client{"registered": registered}},
			config:   &Config{ClientIDMetadataDocumentResolver: &stubResolver{client: &stubDocumentClient{Client: registered, document: true}}},
			id:       url,
			err:      ErrServerError,
			resolves: 1,
		},
		{
			name:     "ShouldRefuseUnmarkedResolverResult",
			store:    stubClientGetter{},
			config:   &Config{ClientIDMetadataDocumentResolver: &stubResolver{client: &DefaultClient{ID: url}}},
			id:       url,
			err:      ErrServerError,
			resolves: 1,
		},
		{
			name:     "ShouldRefuseResolverResultReportingItIsNotADocumentClient",
			store:    stubClientGetter{},
			config:   &Config{ClientIDMetadataDocumentResolver: &stubResolver{client: &stubDocumentClient{Client: &DefaultClient{ID: url}}}},
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
				ClientIDMetadataDocumentResolver:              resolver,
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
