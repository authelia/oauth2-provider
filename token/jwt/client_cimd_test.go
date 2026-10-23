// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package jwt

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/jose"
)

func TestIsClientIDMetadataDocumentClient(t *testing.T) {
	assert.False(t, IsClientIDMetadataDocumentClient(nil))
	assert.False(t, IsClientIDMetadataDocumentClient(struct{}{}))
	assert.False(t, IsClientIDMetadataDocumentClient(markedClient(false)))
	assert.True(t, IsClientIDMetadataDocumentClient(markedClient(true)))
}

func TestDecoratedClientsForwardTheMarker(t *testing.T) {
	testCases := map[string]Client{
		"JAR":                   &decoratedJARClient{JARClient: markedJARClient{}},
		"IDToken":               &decoratedIDTokenClient{IDTokenClient: markedIDTokenClient{}},
		"JARM":                  &decoratedJARMClient{JARMClient: markedJARMClient{}},
		"UserInfo":              &decoratedUserInfoClient{UserInfoClient: markedUserInfoClient{}},
		"JWTProfileAccessToken": &decoratedJWTProfileAccessTokenClient{JWTProfileAccessTokenClient: markedJWTProfileAccessTokenClient{}},
		"Introspection":         &decoratedIntrospectionClient{IntrospectionClient: markedIntrospectionClient{}},
	}

	for name, client := range testCases {
		t.Run(name, func(t *testing.T) {
			assert.True(t, IsClientIDMetadataDocumentClient(client))
		})
	}

	assert.False(t, IsClientIDMetadataDocumentClient(&decoratedJARClient{}))
}

func TestClientJWKSFetcherStrategy(t *testing.T) {
	shared := &clientStubFetcher{name: "shared"}
	guarded := &clientStubFetcher{name: "guarded"}

	t.Run("ShouldUseSharedFetcherForRegisteredClient", func(t *testing.T) {
		config := &stubFetcherConfig{shared: shared, guarded: guarded}

		assert.Same(t, shared, ClientJWKSFetcherStrategy(t.Context(), config, markedClient(false)))
	})

	t.Run("ShouldUseGuardedFetcherForDocumentClient", func(t *testing.T) {
		config := &stubFetcherConfig{shared: shared, guarded: guarded}

		assert.Same(t, guarded, ClientJWKSFetcherStrategy(t.Context(), config, markedClient(true)))
	})

	t.Run("ShouldFailClosedWithoutGuardedFetcher", func(t *testing.T) {
		config := &stubFetcherConfig{shared: shared}

		fetcher := ClientJWKSFetcherStrategy(t.Context(), config, markedClient(true))

		require.NotNil(t, fetcher)
		assert.NotSame(t, shared, fetcher)

		_, err := fetcher.Resolve(t.Context(), "https://client.example.com/jwks.json", false)
		assert.Error(t, err)
	})

	t.Run("ShouldFailClosedWhenConfigIsNotAProvider", func(t *testing.T) {
		config := stubSharedOnlyConfig{shared: shared}

		fetcher := ClientJWKSFetcherStrategy(t.Context(), config, markedClient(true))

		_, err := fetcher.Resolve(t.Context(), "https://client.example.com/jwks.json", false)
		assert.Error(t, err)

		assert.Same(t, shared, ClientJWKSFetcherStrategy(t.Context(), config, markedClient(false)))
	})
}

func TestStrategyFetchesTheJWKSURIOfADocumentClientOnlyWithItsOwnFetcher(t *testing.T) {
	const location = "https://client.example.com/jwks.json"

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	jwks := &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
		{Key: &key.PublicKey, KeyID: "sig", Algorithm: "RS256", Use: JSONWebTokenUseSignature},
		{Key: &key.PublicKey, KeyID: "enc", Algorithm: "RSA-OAEP-256", Use: JSONWebTokenUseEncryption},
	}}

	assertion, _, err := EncodeCompactSigned(t.Context(), MapClaims{"iss": "client"}, nil, &jose.JSONWebKey{Key: key, KeyID: "sig", Algorithm: "RS256", Use: JSONWebTokenUseSignature})
	require.NoError(t, err)

	idToken := &stubIDTokenClient{stubBase: stubBase{id: "client", jwksURI: location}, sigAlg: "RS256", encAlg: "RSA-OAEP-256", encEnc: "A128GCM"}
	jar := &stubJARClient{stubBase: stubBase{id: "client", jwksURI: location}, sigAlg: "RS256"}

	encode := func(strategy *DefaultStrategy, client any) error {
		token, _, err := strategy.Encode(t.Context(), MapClaims{"sub": "peter"}, WithIDTokenClient(client))

		if err == nil {
			assert.True(t, IsEncryptedJWT(token))
		}

		return err
	}

	decode := func(strategy *DefaultStrategy, client any) error {
		_, err := strategy.Decode(t.Context(), assertion, WithJARClient(client))

		return err
	}

	sites := []struct {
		name       string
		run        func(strategy *DefaultStrategy, client any) error
		registered any
		document   any
	}{
		{"Encryption", encode, idToken, markedIDTokenClient{IDTokenClient: idToken}},
		{"Verification", decode, jar, markedJARClient{JARClient: jar}},
	}

	for _, site := range sites {
		t.Run(site.name, func(t *testing.T) {
			t.Run("ShouldUseTheSharedFetcherForARegisteredClient", func(t *testing.T) {
				config := &countingFetcherConfig{shared: &countingFetcher{jwks: jwks}}

				require.NoError(t, site.run(&DefaultStrategy{Config: config, Issuer: MustGenDefaultIssuer()}, site.registered))
				assert.Equal(t, 1, config.shared.calls)
			})

			t.Run("ShouldUseTheGuardedFetcherForADocumentClient", func(t *testing.T) {
				config := &countingFetcherConfig{shared: &countingFetcher{jwks: jwks}, guarded: &countingFetcher{jwks: jwks}}

				require.NoError(t, site.run(&DefaultStrategy{Config: config, Issuer: MustGenDefaultIssuer()}, site.document))
				assert.Equal(t, 0, config.shared.calls)
				assert.Equal(t, 1, config.guarded.calls)
			})

			t.Run("ShouldFailClosedForADocumentClientWithoutAGuardedFetcher", func(t *testing.T) {
				config := &countingFetcherConfig{shared: &countingFetcher{jwks: jwks}}

				require.Error(t, site.run(&DefaultStrategy{Config: config, Issuer: MustGenDefaultIssuer()}, site.document))
				assert.Equal(t, 0, config.shared.calls)
			})

			t.Run("ShouldFailClosedForADocumentClientWhenTheConfigIsNotAProvider", func(t *testing.T) {
				shared := &countingFetcher{jwks: jwks}

				require.Error(t, site.run(&DefaultStrategy{Config: stubSharedOnlyConfig{shared: shared}, Issuer: MustGenDefaultIssuer()}, site.document))
				assert.Equal(t, 0, shared.calls)

				require.NoError(t, site.run(&DefaultStrategy{Config: stubSharedOnlyConfig{shared: shared}, Issuer: MustGenDefaultIssuer()}, site.registered))
				assert.Equal(t, 1, shared.calls)
			})
		})
	}
}

type markedClient bool

func (m markedClient) IsClientIDMetadataDocumentClient() bool { return bool(m) }

type markedJARClient struct{ JARClient }

func (markedJARClient) IsClientIDMetadataDocumentClient() bool { return true }

type markedIDTokenClient struct{ IDTokenClient }

func (markedIDTokenClient) IsClientIDMetadataDocumentClient() bool { return true }

type markedJARMClient struct{ JARMClient }

func (markedJARMClient) IsClientIDMetadataDocumentClient() bool { return true }

type markedUserInfoClient struct{ UserInfoClient }

func (markedUserInfoClient) IsClientIDMetadataDocumentClient() bool { return true }

type markedJWTProfileAccessTokenClient struct{ JWTProfileAccessTokenClient }

func (markedJWTProfileAccessTokenClient) IsClientIDMetadataDocumentClient() bool { return true }

type markedIntrospectionClient struct{ IntrospectionClient }

func (markedIntrospectionClient) IsClientIDMetadataDocumentClient() bool { return true }

type clientStubFetcher struct{ name string }

func (s *clientStubFetcher) Resolve(_ context.Context, _ string, _ bool) (*jose.JSONWebKeySet, error) {
	return &jose.JSONWebKeySet{}, nil
}

type stubSharedOnlyConfig struct{ shared JWKSFetcherStrategy }

func (s stubSharedOnlyConfig) GetJWKSFetcherStrategy(_ context.Context) JWKSFetcherStrategy {
	return s.shared
}

type stubFetcherConfig struct{ shared, guarded *clientStubFetcher }

func (s *stubFetcherConfig) GetJWKSFetcherStrategy(_ context.Context) JWKSFetcherStrategy {
	return s.shared
}

func (s *stubFetcherConfig) GetClientJWKSFetcherStrategy(_ context.Context, client any) JWKSFetcherStrategy {
	if IsClientIDMetadataDocumentClient(client) {
		if s.guarded == nil {
			return nil
		}

		return s.guarded
	}

	return s.shared
}

type countingFetcher struct {
	jwks  *jose.JSONWebKeySet
	calls int
}

func (f *countingFetcher) Resolve(_ context.Context, _ string, _ bool) (*jose.JSONWebKeySet, error) {
	f.calls++

	return f.jwks, nil
}

type countingFetcherConfig struct{ shared, guarded *countingFetcher }

func (c *countingFetcherConfig) GetJWKSFetcherStrategy(_ context.Context) JWKSFetcherStrategy {
	return c.shared
}

func (c *countingFetcherConfig) GetClientJWKSFetcherStrategy(_ context.Context, client any) JWKSFetcherStrategy {
	if !IsClientIDMetadataDocumentClient(client) {
		return c.shared
	}

	if c.guarded == nil {
		return nil
	}

	return c.guarded
}
