// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package cimd

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/handler/rfc7591"
	"authelia.com/provider/oauth2/internal"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestNewResolver(t *testing.T) {
	client := oauth2.NewSpecialUseAddressGuardedHTTPClient()
	store := storage.NewMemoryStore()

	_, err := NewResolver(Config{HTTPClient: client, ValidatorConfig: &oauth2.Config{}})
	assert.Error(t, err)

	_, err = NewResolver(Config{Storage: store, ValidatorConfig: &oauth2.Config{}})
	assert.Error(t, err)

	_, err = NewResolver(Config{Storage: store, HTTPClient: client})
	assert.Error(t, err)

	_, err = NewResolver(Config{Storage: store, HTTPClient: client, Validators: []oauth2.ClientRegistrationValidator{}})
	assert.NoError(t, err)

	resolver, err := NewResolver(Config{Storage: store, HTTPClient: client, ValidatorConfig: &oauth2.Config{}})
	require.NoError(t, err)

	assert.Equal(t, int64(5120), resolver.config.MaxBodyBytes)
	assert.Equal(t, 24*time.Hour, resolver.config.MaxLifespan)
	assert.Equal(t, time.Hour, resolver.config.DefaultLifespan)
	assert.Len(t, resolver.config.Validators, 1)
	assert.IsType(t, DefaultClientStrategy{}, resolver.config.Strategy)
	assert.Empty(t, resolver.config.Scopes)
	assert.Equal(t, []string{"authorization_code", "refresh_token"}, resolver.config.GrantTypes)
	assert.Equal(t, 16, resolver.config.MaxConcurrentFetches)
	assert.Equal(t, 16, cap(resolver.fetches))

	resolver, err = NewResolver(Config{Storage: store, HTTPClient: client, ValidatorConfig: &oauth2.Config{}, GrantTypes: []string{}, MaxConcurrentFetches: -1})
	require.NoError(t, err)

	assert.Equal(t, []string{"authorization_code", "refresh_token"}, resolver.config.GrantTypes)
	assert.Equal(t, 16, resolver.config.MaxConcurrentFetches)

	resolver, err = NewResolver(Config{Storage: store, HTTPClient: client, ValidatorConfig: &oauth2.Config{}, GrantTypes: []string{"client_credentials"}, MaxConcurrentFetches: 2})
	require.NoError(t, err)

	assert.Equal(t, []string{"client_credentials"}, resolver.config.GrantTypes)
	assert.Equal(t, 2, cap(resolver.fetches))

	assert.Equal(t, DefaultTokenEndpointAuthMethods, resolver.config.TokenEndpointAuthMethods)
	assert.Equal(t, DefaultStaleGracePeriod, resolver.config.StaleGracePeriod)
	assert.Equal(t, DefaultMaxDocumentsPerDomain, resolver.config.MaxDocumentsPerDomain)

	resolver, err = NewResolver(Config{Storage: store, HTTPClient: client, ValidatorConfig: &oauth2.Config{}, TokenEndpointAuthMethods: []string{"none"}, StaleGracePeriod: -1})
	require.NoError(t, err)

	assert.Equal(t, []string{"none"}, resolver.config.TokenEndpointAuthMethods)
	assert.Equal(t, time.Duration(0), resolver.config.StaleGracePeriod)

	resolver, err = NewResolver(Config{Storage: store, HTTPClient: client, ValidatorConfig: &oauth2.Config{}, MaxDocumentsPerDomain: -1})
	require.NoError(t, err)

	assert.Equal(t, 0, resolver.config.MaxDocumentsPerDomain)

	_, err = NewResolver(Config{Storage: store, HTTPClient: client, ValidatorConfig: &oauth2.Config{}, TokenEndpointAuthMethods: []string{"none", "Client_Secret_Basic"}})
	assert.EqualError(t, err, "cimd: the token endpoint authentication method 'Client_Secret_Basic' requires a client secret")
}

func TestResolverResolvesADocument(t *testing.T) {
	env := newResolverEnv(t, nil)

	id := env.server.URL + "/ok"

	before := time.Now()

	client, err := env.resolver.ResolveClientIDMetadataDocumentClient(t.Context(), id)

	require.NoError(t, err)

	assert.Equal(t, id, client.GetID())
	assert.True(t, client.IsPublic())
	assert.True(t, jwt.IsClientIDMetadataDocumentClient(client))
	assert.Equal(t, []string{"https://client.example.com/cb"}, client.GetRedirectURIs())
	assert.Implements(t, (*oauth2.ClientIDMetadataDocumentClient)(nil), client)

	record, err := env.store.GetClientIDMetadataDocument(t.Context(), id)

	require.NoError(t, err)

	assert.Equal(t, id, record.ID)
	assert.WithinDuration(t, before.Add(10*time.Minute), record.ExpiresAt, 5*time.Second)
	assert.Equal(t, int64(1), env.hits.Load())
	assert.Equal(t, "application/json", env.accept.Load())
}

func TestResolverCachesAFreshDocument(t *testing.T) {
	env := newResolverEnv(t, nil)

	id := env.server.URL + "/ok"

	first, err := env.resolver.ResolveClientIDMetadataDocumentClient(t.Context(), id)
	require.NoError(t, err)

	second, err := env.resolver.ResolveClientIDMetadataDocumentClient(t.Context(), id)
	require.NoError(t, err)

	assert.Equal(t, int64(1), env.hits.Load())
	assert.NotSame(t, first, second)

	first.(*Client).RedirectURIs[0] = "https://attacker.example.com/cb"

	assert.Equal(t, []string{"https://client.example.com/cb"}, second.GetRedirectURIs())
}

func TestResolverRefetchesAnExpiredDocument(t *testing.T) {
	env := newResolverEnv(t, nil)

	id := env.server.URL + "/ok"

	expired := time.Now().Add(-time.Minute)

	require.NoError(t, env.store.SetClientIDMetadataDocument(t.Context(), &oauth2.ClientIDMetadataDocumentRecord{
		ID:        id,
		Metadata:  &oauth2.ClientRegistrationMetadata{RedirectURIs: []string{"https://old.example.com/cb"}},
		FetchedAt: expired.Add(-time.Hour),
		ExpiresAt: expired,
	}))

	client, err := env.resolver.ResolveClientIDMetadataDocumentClient(t.Context(), id)

	require.NoError(t, err)

	assert.Equal(t, []string{"https://client.example.com/cb"}, client.GetRedirectURIs())
	assert.Equal(t, int64(1), env.hits.Load())

	record, err := env.store.GetClientIDMetadataDocument(t.Context(), id)

	require.NoError(t, err)
	assert.True(t, record.ExpiresAt.After(time.Now()))
}

func TestResolverTreatsAnUnusableRecordAsAMiss(t *testing.T) {
	testCases := map[string]func(id string) *oauth2.ClientIDMetadataDocumentRecord{
		"NilMetadata": func(id string) *oauth2.ClientIDMetadataDocumentRecord {
			return &oauth2.ClientIDMetadataDocumentRecord{ID: id, ExpiresAt: time.Now().Add(time.Hour)}
		},
		"MismatchedID": func(id string) *oauth2.ClientIDMetadataDocumentRecord {
			return &oauth2.ClientIDMetadataDocumentRecord{ID: id + "x", Metadata: &oauth2.ClientRegistrationMetadata{}, ExpiresAt: time.Now().Add(time.Hour)}
		},
		"NilRecord": func(id string) *oauth2.ClientIDMetadataDocumentRecord {
			return nil
		},
	}

	for name, record := range testCases {
		t.Run(name, func(t *testing.T) {
			env := newResolverEnv(t, nil)

			id := env.server.URL + "/ok"

			env.resolver.config.Storage = &fixedStorage{ClientIDMetadataDocumentStorage: env.store, record: record(id)}

			client, err := env.resolver.ResolveClientIDMetadataDocumentClient(t.Context(), id)

			require.NoError(t, err)
			assert.Equal(t, id, client.GetID())
			assert.Equal(t, int64(1), env.hits.Load())
		})
	}
}

func TestResolverFailures(t *testing.T) {
	testCases := []struct {
		name string
		path string
	}{
		{"ShouldRejectRedirect", "/redirect"},
		{"ShouldRejectNotFound", "/missing"},
		{"ShouldRejectNoContent", "/no-content"},
		{"ShouldRejectWrongContentType", "/text"},
		{"ShouldRejectMissingContentType", "/no-content-type"},
		{"ShouldRejectOversizeBody", "/big"},
		{"ShouldRejectMismatchedClientID", "/mismatch"},
		{"ShouldRejectClientSecret", "/secret"},
		{"ShouldRejectDocumentFailingTheValidators", "/bad-redirect"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			env := newResolverEnv(t, nil)

			id := env.server.URL + tc.path

			client, err := env.resolver.ResolveClientIDMetadataDocumentClient(t.Context(), id)

			require.ErrorIs(t, err, oauth2.ErrInvalidClient)
			assert.Nil(t, client)
			assert.Equal(t, "The Client ID Metadata Document could not be used.", oauth2.ErrorToRFC6749Error(err).HintField)

			if tc.path == "/bad-redirect" {
				assert.NotContains(t, oauth2.ErrorToRFC6749Error(err).HintField, "http://client.example.com/cb")
				assert.ErrorIs(t, err, oauth2.ErrInvalidRedirectURI)
			}

			_, err = env.store.GetClientIDMetadataDocument(t.Context(), id)
			assert.ErrorIs(t, err, oauth2.ErrNotFound)
		})
	}
}

func TestResolverRespectsCacheDirectives(t *testing.T) {
	t.Run("ShouldNotStoreANoStoreDocument", func(t *testing.T) {
		env := newResolverEnv(t, nil)

		id := env.server.URL + "/no-store"

		for range 2 {
			client, err := env.resolver.ResolveClientIDMetadataDocumentClient(t.Context(), id)

			require.NoError(t, err)
			assert.Equal(t, id, client.GetID())
		}

		assert.Equal(t, int64(2), env.hits.Load())

		_, err := env.store.GetClientIDMetadataDocument(t.Context(), id)
		assert.ErrorIs(t, err, oauth2.ErrNotFound)
	})

	t.Run("ShouldDeleteTheRecordANoStoreDocumentReplaces", func(t *testing.T) {
		env := newResolverEnv(t, nil)

		id := env.server.URL + "/no-store"

		env.setExpiredAt(t, id, time.Now().Add(-time.Minute))

		client, err := env.resolver.ResolveClientIDMetadataDocumentClient(t.Context(), id)

		require.NoError(t, err)
		assert.Equal(t, []string{"https://client.example.com/cb"}, client.GetRedirectURIs())

		_, err = env.store.GetClientIDMetadataDocument(t.Context(), id)
		assert.ErrorIs(t, err, oauth2.ErrNotFound)
	})

	t.Run("ShouldFetchANoCacheDocumentOnEveryUse", func(t *testing.T) {
		env := newResolverEnv(t, nil)

		id := env.server.URL + "/no-cache"

		for range 2 {
			_, err := env.resolver.ResolveClientIDMetadataDocumentClient(t.Context(), id)

			require.NoError(t, err)
		}

		assert.Equal(t, int64(2), env.hits.Load())

		record, err := env.store.GetClientIDMetadataDocument(t.Context(), id)

		require.NoError(t, err)
		assert.True(t, record.MustRevalidate)
		assert.Equal(t, record.FetchedAt, record.ExpiresAt)
	})

	t.Run("ShouldFetchADocumentWithNoLifespanOnEveryUse", func(t *testing.T) {
		env := newResolverEnv(t, nil)

		id := env.server.URL + "/stale-at-once"

		for range 2 {
			_, err := env.resolver.ResolveClientIDMetadataDocumentClient(t.Context(), id)

			require.NoError(t, err)
		}

		assert.Equal(t, int64(2), env.hits.Load())

		record, err := env.store.GetClientIDMetadataDocument(t.Context(), id)

		require.NoError(t, err)
		assert.False(t, record.MustRevalidate)
	})

	t.Run("ShouldNotServeARecordWhichMustBeRevalidatedAfterATransientFailure", func(t *testing.T) {
		env := newResolverEnv(t, nil)

		id := env.server.URL + "/error"

		env.setRecord(t, id, time.Now().Add(-time.Minute), true)

		client, err := env.resolver.ResolveClientIDMetadataDocumentClient(t.Context(), id)

		require.ErrorIs(t, err, oauth2.ErrTemporarilyUnavailable)
		assert.Nil(t, client)

		_, err = env.store.GetClientIDMetadataDocument(t.Context(), id)
		assert.NoError(t, err)
	})
}

func TestResolverTransientFailures(t *testing.T) {
	paths := []struct {
		name string
		path string
	}{
		{"ServerError", "/error"},
		{"TooManyRequests", "/busy"},
		{"ConnectionReset", "/reset"},
	}

	for _, p := range paths {
		t.Run("ShouldReportTemporarilyUnavailableWithoutARecord"+p.name, func(t *testing.T) {
			env := newResolverEnv(t, nil)

			client, err := env.resolver.ResolveClientIDMetadataDocumentClient(t.Context(), env.server.URL+p.path)

			require.ErrorIs(t, err, oauth2.ErrTemporarilyUnavailable)
			assert.NotErrorIs(t, err, oauth2.ErrInvalidClient)
			assert.Nil(t, client)
			assert.Equal(t, "The Client ID Metadata Document could not be retrieved.", oauth2.ErrorToRFC6749Error(err).HintField)
		})

		t.Run("ShouldServeAnExpiredRecordWithinTheGracePeriod"+p.name, func(t *testing.T) {
			env := newResolverEnv(t, nil)

			id := env.server.URL + p.path

			env.setExpiredAt(t, id, time.Now().Add(-time.Hour))

			client, err := env.resolver.ResolveClientIDMetadataDocumentClient(t.Context(), id)

			require.NoError(t, err)
			assert.Equal(t, id, client.GetID())
			assert.Equal(t, []string{"https://old.example.com/cb"}, client.GetRedirectURIs())

			_, err = env.store.GetClientIDMetadataDocument(t.Context(), id)
			assert.NoError(t, err)
		})

		t.Run("ShouldKeepARecordPastTheGracePeriod"+p.name, func(t *testing.T) {
			env := newResolverEnv(t, nil)

			id := env.server.URL + p.path

			env.setExpiredAt(t, id, time.Now().Add(-DefaultStaleGracePeriod-time.Minute))
			env.resolver.pruneAt.Store(time.Now().Add(time.Hour).UnixNano())

			client, err := env.resolver.ResolveClientIDMetadataDocumentClient(t.Context(), id)

			require.ErrorIs(t, err, oauth2.ErrTemporarilyUnavailable)
			assert.Nil(t, client)

			_, err = env.store.GetClientIDMetadataDocument(t.Context(), id)
			assert.NoError(t, err)
		})
	}

	t.Run("ShouldNotServeAnExpiredRecordWhenTheGracePeriodIsDisabled", func(t *testing.T) {
		env := newResolverEnv(t, func(config *Config) {
			config.StaleGracePeriod = -1
		})

		id := env.server.URL + "/error"

		env.setExpiredAt(t, id, time.Now().Add(-time.Second))

		client, err := env.resolver.ResolveClientIDMetadataDocumentClient(t.Context(), id)

		require.ErrorIs(t, err, oauth2.ErrTemporarilyUnavailable)
		assert.Nil(t, client)

		_, err = env.store.GetClientIDMetadataDocument(t.Context(), id)
		assert.NoError(t, err)
	})

	t.Run("ShouldServeAnExpiredRecordWhenAFetchLimitIsReached", func(t *testing.T) {
		env := newResolverEnv(t, func(config *Config) {
			config.FetchRatePerDomain = 1
			config.FetchBurstPerDomain = 1
		})

		_, err := env.resolver.ResolveClientIDMetadataDocumentClient(t.Context(), env.server.URL+"/missing")
		require.ErrorIs(t, err, oauth2.ErrInvalidClient)

		id := env.server.URL + "/ok"

		env.setExpiredAt(t, id, time.Now().Add(-time.Hour))

		client, err := env.resolver.ResolveClientIDMetadataDocumentClient(t.Context(), id)

		require.NoError(t, err)
		assert.Equal(t, []string{"https://old.example.com/cb"}, client.GetRedirectURIs())
		assert.Equal(t, int64(1), env.hits.Load())
	})

	t.Run("ShouldNotServeAnExpiredRecordWhenTheFailureIsTerminal", func(t *testing.T) {
		env := newResolverEnv(t, nil)

		id := env.server.URL + "/missing"

		env.setExpiredAt(t, id, time.Now().Add(-time.Hour))

		client, err := env.resolver.ResolveClientIDMetadataDocumentClient(t.Context(), id)

		require.ErrorIs(t, err, oauth2.ErrInvalidClient)
		assert.Nil(t, client)

		_, err = env.store.GetClientIDMetadataDocument(t.Context(), id)
		assert.ErrorIs(t, err, oauth2.ErrNotFound)
	})
}

func TestResolverRevokesRefreshTokensOnClientIDMismatch(t *testing.T) {
	t.Run("ShouldRevokeOnAMismatchedClientID", func(t *testing.T) {
		env := newResolverEnv(t, nil)

		faulty := &faultyStorage{ClientIDMetadataDocumentStorage: env.store}

		env.resolver.config.Storage = faulty

		id := env.server.URL + "/mismatch"

		env.setExpiredAt(t, id, time.Now().Add(-time.Hour))

		request := oauth2.NewRequest()
		request.Client = &oauth2.DefaultClient{ID: id}
		request.Session = &oauth2.DefaultSession{}

		require.NoError(t, env.store.CreateRefreshTokenSession(t.Context(), "refresh", "", request))

		client, err := env.resolver.ResolveClientIDMetadataDocumentClient(t.Context(), id)

		require.ErrorIs(t, err, oauth2.ErrInvalidClient)
		assert.Nil(t, client)
		assert.Equal(t, []string{id}, faulty.revoked)

		_, err = env.store.GetRefreshTokenSession(t.Context(), "refresh", &oauth2.DefaultSession{})
		assert.ErrorIs(t, err, oauth2.ErrInactiveToken)

		_, err = env.store.GetClientIDMetadataDocument(t.Context(), id)
		assert.ErrorIs(t, err, oauth2.ErrNotFound)
	})

	t.Run("ShouldReportARevocationFailure", func(t *testing.T) {
		env := newResolverEnv(t, nil)

		faulty := &faultyStorage{ClientIDMetadataDocumentStorage: env.store, revokeErr: errors.New("the database is unavailable")}

		env.resolver.config.Storage = faulty

		_, err := env.resolver.ResolveClientIDMetadataDocumentClient(t.Context(), env.server.URL+"/mismatch")

		require.ErrorIs(t, err, oauth2.ErrInvalidClient)
		assert.ErrorIs(t, err, faulty.revokeErr)
		assert.Contains(t, oauth2.ErrorToDebugRFC6749Error(err).Error(), "could not be revoked")
	})

	for _, path := range []string{"/missing", "/secret", "/bad-redirect", "/error"} {
		t.Run("ShouldNotRevokeOnAnotherFailure"+path, func(t *testing.T) {
			env := newResolverEnv(t, nil)

			faulty := &faultyStorage{ClientIDMetadataDocumentStorage: env.store}

			env.resolver.config.Storage = faulty

			_, err := env.resolver.ResolveClientIDMetadataDocumentClient(t.Context(), env.server.URL+path)

			require.Error(t, err)
			assert.Empty(t, faulty.revoked)
		})
	}
}

func TestResolverBoundsTheDocumentsPerDomain(t *testing.T) {
	t.Run("ShouldRefuseANewDocumentAtTheLimit", func(t *testing.T) {
		env := newResolverEnv(t, func(config *Config) {
			config.MaxDocumentsPerDomain = 2
		})

		for _, path := range []string{"/ok", "/suffix"} {
			_, err := env.resolver.ResolveClientIDMetadataDocumentClient(t.Context(), env.server.URL+path)
			require.NoError(t, err)
		}

		record, err := env.store.GetClientIDMetadataDocument(t.Context(), env.server.URL+"/ok")
		require.NoError(t, err)
		assert.Equal(t, "127.0.0.1", record.Domain)

		client, err := env.resolver.ResolveClientIDMetadataDocumentClient(t.Context(), env.server.URL+"/limit")

		require.ErrorIs(t, err, oauth2.ErrInvalidClient)
		assert.Nil(t, client)
		assert.Contains(t, oauth2.ErrorToDebugRFC6749Error(err).Error(), "limit of 2 documents stored for its domain")
		assert.Equal(t, int64(2), env.hits.Load())

		record.ExpiresAt = time.Now().Add(-time.Minute)
		require.NoError(t, env.store.SetClientIDMetadataDocument(t.Context(), record))

		client, err = env.resolver.ResolveClientIDMetadataDocumentClient(t.Context(), env.server.URL+"/ok")

		require.NoError(t, err)
		assert.Equal(t, env.server.URL+"/ok", client.GetID())
		assert.Equal(t, int64(3), env.hits.Load())

		require.NoError(t, env.store.DeleteClientIDMetadataDocument(t.Context(), env.server.URL+"/suffix"))

		_, err = env.resolver.ResolveClientIDMetadataDocumentClient(t.Context(), env.server.URL+"/limit")
		require.NoError(t, err)
	})

	t.Run("ShouldNotBoundWhenDisabled", func(t *testing.T) {
		env := newResolverEnv(t, func(config *Config) {
			config.MaxDocumentsPerDomain = -1
		})

		for _, path := range []string{"/ok", "/suffix", "/limit"} {
			_, err := env.resolver.ResolveClientIDMetadataDocumentClient(t.Context(), env.server.URL+path)
			require.NoError(t, err)
		}
	})

	t.Run("ShouldReportACountFailure", func(t *testing.T) {
		env := newResolverEnv(t, nil)

		faulty := &faultyStorage{ClientIDMetadataDocumentStorage: env.store, countErr: errors.New("the database is unavailable")}

		env.resolver.config.Storage = faulty

		_, err := env.resolver.ResolveClientIDMetadataDocumentClient(t.Context(), env.server.URL+"/ok")

		require.ErrorIs(t, err, oauth2.ErrServerError)
		assert.ErrorIs(t, err, faulty.countErr)
		assert.Equal(t, int64(0), env.hits.Load())
	})
}

func TestResolverAcceptsSuffixedJSONContentType(t *testing.T) {
	env := newResolverEnv(t, nil)

	client, err := env.resolver.ResolveClientIDMetadataDocumentClient(t.Context(), env.server.URL+"/suffix")

	require.NoError(t, err)
	assert.Equal(t, env.server.URL+"/suffix", client.GetID())
}

func TestResolverAcceptsBodyAtTheLimit(t *testing.T) {
	env := newResolverEnv(t, nil)

	client, err := env.resolver.ResolveClientIDMetadataDocumentClient(t.Context(), env.server.URL+"/limit")

	require.NoError(t, err)
	assert.Equal(t, env.server.URL+"/limit", client.GetID())
}

func TestResolverFailedRefetchDeletesTheRecordAndIsNotServed(t *testing.T) {
	rejected := errors.New("the filter refused the document")

	testCases := []struct {
		name      string
		path      string
		configure func(config *Config)
	}{
		{"ShouldDeleteWhenTheDocumentIsGone", "/missing", nil},
		{"ShouldDeleteWhenTheDocumentIsRedirected", "/redirect", nil},
		{"ShouldDeleteWhenTheDocumentIsInvalid", "/secret", nil},
		{"ShouldDeleteWhenTheCeilingLeavesNoGrantType", "/credentials", nil},
		{"ShouldDeleteWhenTheFilterRejects", "/ok", func(config *Config) {
			config.Filter = filterFunc(func(_ *oauth2.ClientRegistrationMetadata) error { return rejected })
		}},
		{"ShouldDeleteWhenAValidatorRejects", "/bad-redirect", nil},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			env := newResolverEnv(t, tc.configure)

			id := env.server.URL + tc.path

			env.setExpired(t, id)

			client, err := env.resolver.ResolveClientIDMetadataDocumentClient(t.Context(), id)

			require.ErrorIs(t, err, oauth2.ErrInvalidClient)
			assert.Nil(t, client)
			assert.Equal(t, int64(1), env.hits.Load())

			_, err = env.store.GetClientIDMetadataDocument(t.Context(), id)

			assert.ErrorIs(t, err, oauth2.ErrNotFound)
		})
	}
}

func TestResolverFailedRefetchDeletesAnUnusableRecord(t *testing.T) {
	env := newResolverEnv(t, nil)

	id := env.server.URL + "/missing"

	require.NoError(t, env.store.SetClientIDMetadataDocument(t.Context(), &oauth2.ClientIDMetadataDocumentRecord{ID: id, ExpiresAt: time.Now().Add(time.Hour)}))

	_, err := env.resolver.ResolveClientIDMetadataDocumentClient(t.Context(), id)

	require.ErrorIs(t, err, oauth2.ErrInvalidClient)

	_, err = env.store.GetClientIDMetadataDocument(t.Context(), id)

	assert.ErrorIs(t, err, oauth2.ErrNotFound)
}

func TestResolverFailedRefetchReportsTheFetchErrorWhenTheDeleteFails(t *testing.T) {
	env := newResolverEnv(t, nil)

	faulty := &faultyStorage{ClientIDMetadataDocumentStorage: env.store, deleteErr: errors.New("the database is unavailable")}

	env.resolver.config.Storage = faulty

	id := env.server.URL + "/missing"

	env.setExpired(t, id)

	_, err := env.resolver.ResolveClientIDMetadataDocumentClient(t.Context(), id)

	require.ErrorIs(t, err, oauth2.ErrInvalidClient)
	assert.NotErrorIs(t, err, faulty.deleteErr)
	assert.Contains(t, oauth2.ErrorToDebugRFC6749Error(err).Error(), "status code 404")
	assert.Equal(t, int64(1), faulty.deletes.Load())
}

func TestResolverFailedFetchWithoutARecordDoesNotDelete(t *testing.T) {
	env := newResolverEnv(t, nil)

	faulty := &faultyStorage{ClientIDMetadataDocumentStorage: env.store}

	env.resolver.config.Storage = faulty

	_, err := env.resolver.ResolveClientIDMetadataDocumentClient(t.Context(), env.server.URL+"/missing")

	require.ErrorIs(t, err, oauth2.ErrInvalidClient)
	assert.Equal(t, int64(0), faulty.deletes.Load())
}

func TestResolverKeepsTheRecordWhenTheRefetchedDocumentCouldNotBeStored(t *testing.T) {
	env := newResolverEnv(t, nil)

	faulty := &faultyStorage{ClientIDMetadataDocumentStorage: env.store, setErr: errors.New("the database is unavailable")}

	id := env.server.URL + "/ok"

	env.setExpired(t, id)

	env.resolver.config.Storage = faulty

	_, err := env.resolver.ResolveClientIDMetadataDocumentClient(t.Context(), id)

	require.ErrorIs(t, err, oauth2.ErrServerError)
	assert.Equal(t, int64(0), faulty.deletes.Load())
}

func TestResolverDiscardKeepsARecordWhichBecameFresh(t *testing.T) {
	env := newResolverEnv(t, nil)

	id := env.server.URL + "/ok"

	require.NoError(t, env.store.SetClientIDMetadataDocument(t.Context(), &oauth2.ClientIDMetadataDocumentRecord{
		ID:        id,
		Metadata:  &oauth2.ClientRegistrationMetadata{},
		ExpiresAt: time.Now().Add(time.Hour),
	}))

	env.resolver.discard(t.Context(), id)

	_, err := env.store.GetClientIDMetadataDocument(t.Context(), id)

	assert.NoError(t, err)
}

func TestResolverBoundsConcurrentFetches(t *testing.T) {
	env := newResolverEnv(t, func(config *Config) {
		config.MaxConcurrentFetches = 1
		config.StaleGracePeriod = -1
	})

	slow := env.server.URL + "/slow"
	other := env.server.URL + "/ok"

	env.setExpired(t, other)

	results := make(chan error, 2)

	resolve := func() {
		_, err := env.resolver.ResolveClientIDMetadataDocumentClient(t.Context(), slow)

		results <- err
	}

	go resolve()

	<-env.entered

	started := time.Now()

	client, err := env.resolver.ResolveClientIDMetadataDocumentClient(t.Context(), other)

	require.ErrorIs(t, err, oauth2.ErrTemporarilyUnavailable)
	assert.Nil(t, client)
	assert.Less(t, time.Since(started), time.Second)
	assert.Equal(t, "The Client ID Metadata Document could not be retrieved.", oauth2.ErrorToRFC6749Error(err).HintField)
	assert.Contains(t, oauth2.ErrorToDebugRFC6749Error(err).Error(), "limit of 1 concurrent fetches")
	assert.Equal(t, int64(1), env.hits.Load())

	_, err = env.store.GetClientIDMetadataDocument(t.Context(), other)
	assert.NoError(t, err)

	go resolve()

	time.Sleep(50 * time.Millisecond)
	close(env.release)

	require.NoError(t, <-results)
	require.NoError(t, <-results)

	client, err = env.resolver.ResolveClientIDMetadataDocumentClient(t.Context(), other)

	require.NoError(t, err)
	assert.Equal(t, other, client.GetID())
	assert.Equal(t, int64(2), env.hits.Load())
	assert.Empty(t, env.resolver.fetches)
}

func TestResolverReleasesTheFetchLimitAfterAFailureOrPanic(t *testing.T) {
	env := newResolverEnv(t, func(config *Config) {
		config.MaxConcurrentFetches = 1
		config.Validators = []oauth2.ClientRegistrationValidator{panicValidator{}}
	})

	for range 3 {
		_, err := env.resolver.ResolveClientIDMetadataDocumentClient(t.Context(), env.server.URL+"/ok")
		require.ErrorIs(t, err, oauth2.ErrServerError)

		_, err = env.resolver.ResolveClientIDMetadataDocumentClient(t.Context(), env.server.URL+"/missing")
		require.ErrorIs(t, err, oauth2.ErrInvalidClient)
	}

	assert.Equal(t, int64(6), env.hits.Load())
	assert.Empty(t, env.resolver.fetches)
}

func TestResolverAppliesTheCeilingBeforeTheFilterAndValidators(t *testing.T) {
	var seen oauth2.ClientRegistrationMetadata

	env := newResolverEnv(t, func(config *Config) {
		config.Scopes = []string{"oauth2", "authelia:oauth2:dynamic-client-registration"}
		config.Filter = filterFunc(func(metadata *oauth2.ClientRegistrationMetadata) error {
			seen = *metadata

			return nil
		})
	})

	id := env.server.URL + "/greedy"

	client, err := env.resolver.ResolveClientIDMetadataDocumentClient(t.Context(), id)

	require.NoError(t, err)

	assert.Equal(t, "oauth2", seen.Scope)
	assert.Nil(t, seen.Audience)

	assert.Equal(t, oauth2.Arguments{"oauth2"}, client.GetScopes())
	assert.Empty(t, client.GetAudience())
	assert.Equal(t, oauth2.Arguments{"authorization_code", "refresh_token"}, client.GetGrantTypes())
	assert.Equal(t, oauth2.Arguments{"code"}, client.GetResponseTypes())

	record, err := env.store.GetClientIDMetadataDocument(t.Context(), id)

	require.NoError(t, err)

	assert.Equal(t, "oauth2", record.Metadata.Scope)
	assert.Empty(t, record.Metadata.Audience)
	assert.Empty(t, record.Metadata.Resource)
	assert.Empty(t, record.Metadata.AuthorizationDetailsTypes)
	assert.Equal(t, []string{testGrantProfile}, record.Metadata.AuthorizationGrantProfilesSupported)
	assert.Empty(t, record.Metadata.SectorIdentifierURI)
	assert.Equal(t, []string{"authorization_code", "refresh_token"}, record.Metadata.GrantTypes)
}

func TestResolverRejectsADocumentLeftWithNoGrantType(t *testing.T) {
	env := newResolverEnv(t, nil)

	id := env.server.URL + "/credentials"

	_, err := env.resolver.ResolveClientIDMetadataDocumentClient(t.Context(), id)

	require.ErrorIs(t, err, oauth2.ErrInvalidClient)
	assert.Contains(t, oauth2.ErrorToDebugRFC6749Error(err).Error(), "grant_types")

	_, err = env.store.GetClientIDMetadataDocument(t.Context(), id)
	assert.ErrorIs(t, err, oauth2.ErrNotFound)
}

func TestResolverAuthorizationGrantProfiles(t *testing.T) {
	testCases := []struct {
		name      string
		permitted []string
		expected  []string
	}{
		{"ShouldKeepTheIDJAGProfileAtAnIdentityProvider", []string{consts.GrantTypeOAuthTokenExchange, consts.GrantTypeOAuthJWTBearer}, []string{consts.GrantProfileIDJAG}},
		{"ShouldResolveWithoutTheIDJAGProfileAtAResourceAuthorizationServer", []string{consts.GrantTypeOAuthJWTBearer}, nil},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			env := newResolverEnv(t, func(config *Config) {
				config.GrantTypes = tc.permitted
			})

			client, err := env.resolver.ResolveClientIDMetadataDocumentClient(t.Context(), env.server.URL+"/idjag")

			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

			resolved, ok := client.(*Client)

			require.True(t, ok)

			assert.Equal(t, oauth2.Arguments(tc.permitted), resolved.GetGrantTypes())
			assert.Equal(t, tc.expected, resolved.GetAuthorizationGrantProfilesSupported())
		})
	}
}

func TestResolverRejectsADocumentLeftWithNoPermittedResponseType(t *testing.T) {
	env := newResolverEnv(t, func(config *Config) {
		config.ResponseTypes = []string{"code id_token"}
	})

	id := env.server.URL + "/ok"

	_, err := env.resolver.ResolveClientIDMetadataDocumentClient(t.Context(), id)

	require.ErrorIs(t, err, oauth2.ErrInvalidClient)
	assert.Contains(t, oauth2.ErrorToDebugRFC6749Error(err).Error(), "response_types")

	_, err = env.store.GetClientIDMetadataDocument(t.Context(), id)
	assert.ErrorIs(t, err, oauth2.ErrNotFound)
}

func TestResolverAcceptsNativeLoopbackRedirectURIsWithTheSameOriginValidator(t *testing.T) {
	env := newResolverEnv(t, func(config *Config) {
		config.Validators = []oauth2.ClientRegistrationValidator{rfc7591.NewLocalValidator(&oauth2.Config{}), RedirectURISameOriginValidator{}}
	})

	client, err := env.resolver.ResolveClientIDMetadataDocumentClient(t.Context(), env.server.URL+"/native")

	require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

	for _, raw := range []string{"http://127.0.0.1:51004/cb", "http://[::1]:61023/cb"} {
		_, err = oauth2.MatchRedirectURIWithClientRedirectURIs(raw, client)

		assert.NoError(t, err, raw)
	}

	_, err = oauth2.MatchRedirectURIWithClientRedirectURIs("http://127.0.0.1:51004/other", client)

	assert.Error(t, err)
}

func TestResolverReappliesTheDefaultsAndTheSecretMethodCheckAfterTheFilter(t *testing.T) {
	t.Run("ShouldDefaultWhatTheFilterEmptied", func(t *testing.T) {
		env := newResolverEnv(t, func(config *Config) {
			config.Filter = filterFunc(func(metadata *oauth2.ClientRegistrationMetadata) error {
				metadata.TokenEndpointAuthMethod = ""
				metadata.GrantTypes = nil
				metadata.ResponseTypes = nil

				return nil
			})
		})

		id := env.server.URL + "/ok"

		_, err := env.resolver.ResolveClientIDMetadataDocumentClient(t.Context(), id)

		require.NoError(t, err)

		record, err := env.store.GetClientIDMetadataDocument(t.Context(), id)

		require.NoError(t, err)

		assert.Equal(t, "none", record.Metadata.TokenEndpointAuthMethod)
		assert.Equal(t, []string{"authorization_code"}, record.Metadata.GrantTypes)
		assert.Equal(t, []string{"code"}, record.Metadata.ResponseTypes)
	})

	for _, method := range []string{"client_secret_basic", "client_secret_post", "client_secret_jwt", "CLIENT_SECRET_BASIC"} {
		t.Run("ShouldRejectFilterSetting/"+method, func(t *testing.T) {
			for _, member := range []string{"token", "introspection", "revocation"} {
				env := newResolverEnv(t, func(config *Config) {
					config.Filter = filterFunc(func(metadata *oauth2.ClientRegistrationMetadata) error {
						switch member {
						case "token":
							metadata.TokenEndpointAuthMethod = method
						case "introspection":
							metadata.IntrospectionEndpointAuthMethod = method
						default:
							metadata.RevocationEndpointAuthMethod = method
						}

						return nil
					})
				})

				id := env.server.URL + "/ok"

				_, err := env.resolver.ResolveClientIDMetadataDocumentClient(t.Context(), id)

				require.ErrorIs(t, err, oauth2.ErrInvalidClient, member)

				_, err = env.store.GetClientIDMetadataDocument(t.Context(), id)
				assert.ErrorIs(t, err, oauth2.ErrNotFound, member)
			}
		})
	}

	t.Run("ShouldRejectFilterSettingPrivateKeyJWTWithoutKeys", func(t *testing.T) {
		env := newResolverEnv(t, func(config *Config) {
			config.Filter = filterFunc(func(metadata *oauth2.ClientRegistrationMetadata) error {
				metadata.TokenEndpointAuthMethod = "private_key_jwt"

				return nil
			})
		})

		id := env.server.URL + "/ok"

		_, err := env.resolver.ResolveClientIDMetadataDocumentClient(t.Context(), id)

		require.ErrorIs(t, err, oauth2.ErrInvalidClient)
		assert.Contains(t, oauth2.ErrorToDebugRFC6749Error(err).Error(), "requires the 'jwks' or 'jwks_uri' member")
	})
}

func TestResolverAppliesTheCeilingToAStoredRecord(t *testing.T) {
	env := newResolverEnv(t, func(config *Config) {
		config.Scopes = []string{"oauth2", "authelia:oauth2:dynamic-client-registration"}
	})

	id := env.server.URL + "/ok"

	require.NoError(t, env.store.SetClientIDMetadataDocument(t.Context(), &oauth2.ClientIDMetadataDocumentRecord{
		ID: id,
		Metadata: &oauth2.ClientRegistrationMetadata{
			RedirectURIs:            []string{"https://client.example.com/cb"},
			TokenEndpointAuthMethod: "none",
			Scope:                   "oauth2 admin authelia:oauth2:dynamic-client-registration",
			GrantTypes:              []string{"client_credentials", "authorization_code"},
			ResponseTypes:           []string{"code", "token"},
		},
		FetchedAt: time.Now().Add(-time.Minute),
		ExpiresAt: time.Now().Add(time.Hour),
	}))

	for range 2 {
		client, err := env.resolver.ResolveClientIDMetadataDocumentClient(t.Context(), id)

		require.NoError(t, err)

		assert.Equal(t, oauth2.Arguments{"oauth2"}, client.GetScopes())
		assert.Equal(t, oauth2.Arguments{"authorization_code"}, client.GetGrantTypes())
		assert.Equal(t, oauth2.Arguments{"code"}, client.GetResponseTypes())
	}

	assert.Equal(t, int64(0), env.hits.Load())
}

func TestResolverRefusesAStoredRecordLeftWithNoGrantType(t *testing.T) {
	env := newResolverEnv(t, nil)

	id := env.server.URL + "/ok"

	require.NoError(t, env.store.SetClientIDMetadataDocument(t.Context(), &oauth2.ClientIDMetadataDocumentRecord{
		ID: id,
		Metadata: &oauth2.ClientRegistrationMetadata{
			TokenEndpointAuthMethod: "none",
			GrantTypes:              []string{"client_credentials"},
		},
		FetchedAt: time.Now().Add(-time.Minute),
		ExpiresAt: time.Now().Add(time.Hour),
	}))

	client, err := env.resolver.ResolveClientIDMetadataDocumentClient(t.Context(), id)

	require.ErrorIs(t, err, oauth2.ErrInvalidClient)
	assert.Nil(t, client)
	assert.Equal(t, "The Client ID Metadata Document could not be used.", oauth2.ErrorToRFC6749Error(err).HintField)
	assert.Equal(t, int64(0), env.hits.Load())
}

func TestResolverBoundsTheScopesAndGrantTypesAFilterAdds(t *testing.T) {
	env := newResolverEnv(t, func(config *Config) {
		config.Scopes = []string{"oauth2"}
		config.Filter = filterFunc(func(metadata *oauth2.ClientRegistrationMetadata) error {
			metadata.Scope = "oauth2 admin"
			metadata.GrantTypes = append(metadata.GrantTypes, "client_credentials")
			metadata.Audience = []string{"https://api.example.com"}
			metadata.AuthorizationDetailsTypes = []string{"payment_initiation"}
			metadata.TokenExchangePermittedClientIDs = []string{"other"}

			return nil
		})
	})

	id := env.server.URL + "/ok"

	for range 2 {
		client, err := env.resolver.ResolveClientIDMetadataDocumentClient(t.Context(), id)

		require.NoError(t, err)

		assert.Equal(t, oauth2.Arguments{"oauth2"}, client.GetScopes())
		assert.NotContains(t, client.GetGrantTypes(), "client_credentials")
		assert.Equal(t, oauth2.Arguments{"https://api.example.com"}, client.GetAudience())
		assert.Equal(t, []string{"payment_initiation"}, client.(*Client).AuthorizationDetailsTypes)
		assert.Equal(t, []string{"other"}, client.(*Client).TokenExchangePermittedClientIDs)
	}

	assert.Equal(t, int64(1), env.hits.Load())
}

func TestResolverBoundsConcurrentFetchesPerDomain(t *testing.T) {
	env := newResolverEnv(t, func(config *Config) {
		config.MaxConcurrentFetches = 4
		config.MaxConcurrentFetchesPerDomain = 1
	})

	slow := env.server.URL + "/slow"
	other := env.server.URL + "/ok"

	result := make(chan error, 1)

	go func() {
		_, err := env.resolver.ResolveClientIDMetadataDocumentClient(t.Context(), slow)

		result <- err
	}()

	<-env.entered

	started := time.Now()

	client, err := env.resolver.ResolveClientIDMetadataDocumentClient(t.Context(), other)

	require.ErrorIs(t, err, oauth2.ErrTemporarilyUnavailable)
	assert.Nil(t, client)
	assert.Less(t, time.Since(started), time.Second)
	assert.Equal(t, "The Client ID Metadata Document could not be retrieved.", oauth2.ErrorToRFC6749Error(err).HintField)
	assert.Contains(t, oauth2.ErrorToDebugRFC6749Error(err).Error(), "limit of 1 concurrent fetches from its domain")
	assert.Equal(t, int64(1), env.hits.Load())

	close(env.release)

	require.NoError(t, <-result)

	client, err = env.resolver.ResolveClientIDMetadataDocumentClient(t.Context(), other)

	require.NoError(t, err)
	assert.Equal(t, other, client.GetID())
	assert.Equal(t, int64(2), env.hits.Load())
}

func TestNewResolverBoundsTheFetchesPerDomain(t *testing.T) {
	base := Config{Storage: storage.NewMemoryStore(), HTTPClient: oauth2.NewSpecialUseAddressGuardedHTTPClient(), ValidatorConfig: &oauth2.Config{}}

	resolver, err := NewResolver(base)
	require.NoError(t, err)
	assert.Equal(t, 16, resolver.config.MaxConcurrentFetches)
	assert.Equal(t, 4, resolver.config.MaxConcurrentFetchesPerDomain)

	base.MaxConcurrentFetches = 2
	resolver, err = NewResolver(base)
	require.NoError(t, err)
	assert.Equal(t, 2, resolver.config.MaxConcurrentFetchesPerDomain)

	base.MaxConcurrentFetches = 8
	base.MaxConcurrentFetchesPerDomain = 32
	resolver, err = NewResolver(base)
	require.NoError(t, err)
	assert.Equal(t, 8, resolver.config.MaxConcurrentFetchesPerDomain)

	base.MaxConcurrentFetchesPerDomain = 3
	resolver, err = NewResolver(base)
	require.NoError(t, err)
	assert.Equal(t, 3, resolver.config.MaxConcurrentFetchesPerDomain)
}

func TestFetchDomain(t *testing.T) {
	testCases := []struct {
		name     string
		id       string
		expected string
	}{
		{name: "ShouldGroupSubdomains", id: "https://a1.evil.example.com/c", expected: "example.com"},
		{name: "ShouldGroupNestedSubdomains", id: "https://x.a1.evil.example.com/c", expected: "example.com"},
		{name: "ShouldIgnoreThePort", id: "https://client.example.com:8443/c", expected: "example.com"},
		{name: "ShouldIgnoreCaseAndTheTrailingDot", id: "https://Client.Example.COM./c", expected: "example.com"},
		{name: "ShouldUseTheMultiLabelPublicSuffix", id: "https://a.client.example.co.uk/c", expected: "example.co.uk"},
		{name: "ShouldSeparatePrivateSuffixDomains", id: "https://alice.github.io/c", expected: "alice.github.io"},
		{name: "ShouldFallBackToTheHostForAPublicSuffix", id: "https://co.uk/c", expected: "co.uk"},
		{name: "ShouldUseTheIPv4Address", id: "https://203.0.113.10/c", expected: "203.0.113.10"},
		{name: "ShouldUseTheIPv4AddressOfAMappedIPv6Address", id: "https://[::ffff:203.0.113.10]/c", expected: "203.0.113.10"},
		{name: "ShouldUseTheIPv6Prefix", id: "https://[2001:db8:1:2:3::4]:8443/c", expected: "2001:db8:1::/48"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, fetchDomain(tc.id))
		})
	}
}

func TestResolverBoundsTheFetchDuration(t *testing.T) {
	env := newResolverEnv(t, nil)

	assert.Equal(t, DefaultFetchTimeout, env.resolver.config.FetchTimeout)

	env = newResolverEnv(t, func(config *Config) {
		config.FetchTimeout = 100 * time.Millisecond
	})

	started := time.Now()

	client, err := env.resolver.ResolveClientIDMetadataDocumentClient(t.Context(), env.server.URL+"/slow")

	require.ErrorIs(t, err, oauth2.ErrTemporarilyUnavailable)
	assert.Nil(t, client)
	assert.Less(t, time.Since(started), time.Second)
}

func TestResolverBoundsTheFetchRatePerDomain(t *testing.T) {
	env := newResolverEnv(t, func(config *Config) {
		config.FetchRatePerDomain = 1
		config.FetchBurstPerDomain = 2
	})

	for _, path := range []string{"/missing", "/missing"} {
		_, err := env.resolver.ResolveClientIDMetadataDocumentClient(t.Context(), env.server.URL+path)
		require.ErrorIs(t, err, oauth2.ErrInvalidClient)
	}

	assert.Equal(t, int64(2), env.hits.Load())

	domain := fetchDomain(env.server.URL)

	env.resolver.mu.Lock()
	env.resolver.buckets[domain].at = time.Now().Add(time.Hour)
	env.resolver.mu.Unlock()

	client, err := env.resolver.ResolveClientIDMetadataDocumentClient(t.Context(), env.server.URL+"/ok")

	require.ErrorIs(t, err, oauth2.ErrTemporarilyUnavailable)
	assert.Nil(t, client)
	assert.Contains(t, oauth2.ErrorToDebugRFC6749Error(err).Error(), "limit of 1 fetches per second from its domain")
	assert.Equal(t, int64(2), env.hits.Load())

	env.resolver.mu.Lock()
	env.resolver.buckets[domain].tokens = 1
	env.resolver.mu.Unlock()

	client, err = env.resolver.ResolveClientIDMetadataDocumentClient(t.Context(), env.server.URL+"/ok")

	require.NoError(t, err)
	assert.Equal(t, env.server.URL+"/ok", client.GetID())
	assert.Equal(t, int64(3), env.hits.Load())

	_, err = env.resolver.ResolveClientIDMetadataDocumentClient(t.Context(), env.server.URL+"/ok")

	require.NoError(t, err)
	assert.Equal(t, int64(3), env.hits.Load())
}

func TestResolverFetchRateBuckets(t *testing.T) {
	env := newResolverEnv(t, func(config *Config) {
		config.FetchRatePerDomain = 2
		config.FetchBurstPerDomain = 4
	})

	assert.Equal(t, float64(DefaultFetchRatePerDomain), newResolverEnv(t, nil).resolver.config.FetchRatePerDomain)
	assert.Equal(t, DefaultFetchBurstPerDomain, newResolverEnv(t, nil).resolver.config.FetchBurstPerDomain)
	assert.Equal(t, float64(DefaultFetchRatePerDomain), newResolverEnv(t, func(config *Config) { config.FetchRatePerDomain = math.NaN() }).resolver.config.FetchRatePerDomain)

	now := time.Now()

	env.resolver.mu.Lock()
	defer env.resolver.mu.Unlock()

	bucket := env.resolver.bucket("example.com", now)
	assert.Equal(t, float64(4), bucket.tokens)

	bucket.tokens = 0

	assert.Equal(t, float64(1), env.resolver.bucket("example.com", now.Add(500*time.Millisecond)).tokens)

	env.resolver.sweepAt = now.Add(2 * time.Hour)

	assert.Equal(t, float64(4), env.resolver.bucket("example.com", now.Add(time.Hour)).tokens)

	env.resolver.sweepAt = time.Time{}

	env.resolver.buckets["example.com"].tokens = 0
	env.resolver.bucket("example.org", now.Add(time.Hour))

	assert.Contains(t, env.resolver.buckets, "example.com")

	env.resolver.bucket("example.org", now.Add(2*time.Hour))

	assert.NotContains(t, env.resolver.buckets, "example.com")
	assert.Contains(t, env.resolver.buckets, "example.org")
}

func TestResolverPrunesExpiredRecordsAtAnInterval(t *testing.T) {
	pruned := make(chan time.Time, 4)

	env := newResolverEnv(t, func(config *Config) {
		config.Storage = &pruneStorage{ClientIDMetadataDocumentStorage: config.Storage, pruned: pruned}
	})

	id := env.server.URL + "/ok"

	started := time.Now()

	_, err := env.resolver.ResolveClientIDMetadataDocumentClient(t.Context(), id)
	require.NoError(t, err)

	select {
	case before := <-pruned:
		assert.WithinDuration(t, started.Add(-DefaultStaleGracePeriod), before, time.Second)
	case <-time.After(time.Second):
		require.Fail(t, "the expired records were not pruned")
	}

	_, err = env.resolver.ResolveClientIDMetadataDocumentClient(t.Context(), id)
	require.NoError(t, err)

	select {
	case <-pruned:
		require.Fail(t, "the expired records were pruned again within the interval")
	case <-time.After(100 * time.Millisecond):
	}

	env.resolver.pruneAt.Store(0)

	_, err = env.resolver.ResolveClientIDMetadataDocumentClient(t.Context(), id)
	require.NoError(t, err)

	select {
	case <-pruned:
	case <-time.After(time.Second):
		require.Fail(t, "the expired records were not pruned after the interval")
	}
}

func TestResolverDoesNotFetchAnInvalidOrRefusedIdentifier(t *testing.T) {
	refused := errors.New("the host is not allowed")

	env := newResolverEnv(t, func(config *Config) {
		config.Policy = func(_ context.Context, id *url.URL) error {
			if strings.HasSuffix(id.Path, "/refused") {
				return refused
			}

			return nil
		}
	})

	_, err := env.resolver.ResolveClientIDMetadataDocumentClient(t.Context(), env.server.URL+"/a/../ok")
	require.ErrorIs(t, err, oauth2.ErrInvalidClient)

	_, err = env.resolver.ResolveClientIDMetadataDocumentClient(t.Context(), "my-client")
	require.ErrorIs(t, err, oauth2.ErrInvalidClient)

	_, err = env.resolver.ResolveClientIDMetadataDocumentClient(t.Context(), env.server.URL+"/refused")
	require.ErrorIs(t, err, oauth2.ErrInvalidClient)
	require.ErrorIs(t, err, refused)

	assert.Equal(t, int64(0), env.hits.Load())
}

func TestResolverReportsAStorageFailure(t *testing.T) {
	env := newResolverEnv(t, nil)

	env.resolver.config.Storage = &fixedStorage{ClientIDMetadataDocumentStorage: env.store, err: errors.New("the database is unavailable")}

	_, err := env.resolver.ResolveClientIDMetadataDocumentClient(t.Context(), env.server.URL+"/ok")

	require.ErrorIs(t, err, oauth2.ErrServerError)
	assert.Equal(t, int64(0), env.hits.Load())
}

func TestResolverRefusesAnUnmarkedClient(t *testing.T) {
	env := newResolverEnv(t, func(config *Config) {
		config.Strategy = unmarkedStrategy{}
	})

	_, err := env.resolver.ResolveClientIDMetadataDocumentClient(t.Context(), env.server.URL+"/ok")

	require.ErrorIs(t, err, oauth2.ErrServerError)
}

func TestResolverClientMayRequestNoAuthorizationDetailsType(t *testing.T) {
	env := newResolverEnv(t, nil)

	config := &oauth2.Config{AuthorizationDetailsTypeHandlers: []oauth2.AuthorizationDetailsTypeHandler{internal.PaymentInitiationTypeHandler{}}}
	details := oauth2.AuthorizationDetails{{Type: internal.PaymentInitiationTypeHandler{}.Type()}}

	for _, path := range []string{"/greedy", "/greedy"} {
		client, err := env.resolver.ResolveClientIDMetadataDocumentClient(t.Context(), env.server.URL+path)
		require.NoError(t, err)

		types, ok := client.(oauth2.AuthorizationDetailsClient)
		require.True(t, ok)

		assert.NotNil(t, types.GetAuthorizationDetailsTypes())
		assert.Empty(t, types.GetAuthorizationDetailsTypes())

		require.ErrorIs(t, oauth2.ValidateAuthorizationDetailsTypes(t.Context(), config, client, details), oauth2.ErrInvalidAuthorizationDetails)
	}

	assert.Equal(t, int64(1), env.hits.Load())
}

func TestResolverRefusesSpecialUseAddressWithTheGuardedClient(t *testing.T) {
	env := newResolverEnv(t, func(config *Config) {
		config.HTTPClient = oauth2.NewSpecialUseAddressGuardedHTTPClient()
	})

	_, err := env.resolver.ResolveClientIDMetadataDocumentClient(t.Context(), env.server.URL+"/ok")

	require.Error(t, err)
	assert.ErrorIs(t, err, oauth2.ErrSpecialUseAddress)
	assert.Equal(t, int64(0), env.hits.Load())
}

func TestResolverSharesConcurrentFetches(t *testing.T) {
	env := newResolverEnv(t, nil)

	id := env.server.URL + "/slow"

	const callers = 16

	var (
		wg     sync.WaitGroup
		start  = make(chan struct{})
		errs   = make([]error, callers)
		client = make([]oauth2.Client, callers)
	)

	for i := range callers {
		wg.Add(1)

		go func() {
			defer wg.Done()

			<-start

			client[i], errs[i] = env.resolver.ResolveClientIDMetadataDocumentClient(t.Context(), id)
		}()
	}

	close(start)
	time.Sleep(50 * time.Millisecond)
	close(env.release)
	wg.Wait()

	for i := range callers {
		require.NoError(t, errs[i])
		assert.Equal(t, id, client[i].GetID())
	}

	assert.Equal(t, int64(1), env.hits.Load())
}

func TestResolverSharedFetchSurvivesTheFirstCallerCancelling(t *testing.T) {
	env := newResolverEnv(t, nil)

	id := env.server.URL + "/slow"

	ctx, cancel := context.WithCancel(t.Context())

	first := make(chan error, 1)

	go func() {
		_, err := env.resolver.ResolveClientIDMetadataDocumentClient(ctx, id)

		first <- err
	}()

	<-env.entered

	second := make(chan error, 1)

	go func() {
		_, err := env.resolver.ResolveClientIDMetadataDocumentClient(t.Context(), id)

		second <- err
	}()

	time.Sleep(50 * time.Millisecond)
	cancel()

	require.ErrorIs(t, <-first, context.Canceled)

	close(env.release)

	require.NoError(t, <-second)
}

func TestResolverRecoversAPanicInTheSharedFetch(t *testing.T) {
	env := newResolverEnv(t, func(config *Config) {
		config.Validators = []oauth2.ClientRegistrationValidator{panicValidator{}}
	})

	id := env.server.URL + "/slow"

	results := make(chan error, 3)

	resolve := func() {
		_, err := env.resolver.ResolveClientIDMetadataDocumentClient(t.Context(), id)

		results <- err
	}

	go resolve()

	<-env.entered

	go resolve()

	time.Sleep(50 * time.Millisecond)
	close(env.release)

	go func() {
		time.Sleep(200 * time.Millisecond)
		resolve()
	}()

	for range 3 {
		select {
		case err := <-results:
			assert.ErrorIs(t, err, oauth2.ErrServerError)
		case <-time.After(10 * time.Second):
			t.Fatal("a resolution hung after the fetch panicked")
		}
	}

	_, err := env.store.GetClientIDMetadataDocument(t.Context(), id)
	assert.ErrorIs(t, err, oauth2.ErrNotFound)
}

type panicValidator struct{}

func (panicValidator) ValidateClientRegistrationMetadata(_ context.Context, _ oauth2.Client, _ *oauth2.ClientRegistrationMetadata) error {
	panic("hostile document")
}

type resolverEnv struct {
	server   *httptest.Server
	store    *storage.MemoryStore
	resolver *Resolver
	hits     *atomic.Int64
	accept   *atomic.Value
	entered  chan struct{}
	release  chan struct{}
}

func newResolverEnv(t *testing.T, configure func(config *Config)) *resolverEnv {
	t.Helper()

	env := &resolverEnv{
		store:   storage.NewMemoryStore(),
		hits:    &atomic.Int64{},
		accept:  &atomic.Value{},
		entered: make(chan struct{}, 64),
		release: make(chan struct{}),
	}

	env.server = httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		env.hits.Add(1)
		env.accept.Store(r.Header.Get("Accept"))

		id := env.server.URL + r.URL.Path
		body := fmt.Sprintf(`{"client_id":%q,"client_name":"Example","redirect_uris":["https://client.example.com/cb"]}`, id)

		switch r.URL.Path {
		case "/ok":
			rw.Header().Set("Content-Type", "application/json; charset=utf-8")
			rw.Header().Set("Cache-Control", "max-age=600")
			_, _ = rw.Write([]byte(body))
		case "/no-store":
			rw.Header().Set("Content-Type", "application/json")
			rw.Header().Set("Cache-Control", "no-store, max-age=600")
			_, _ = rw.Write([]byte(body))
		case "/no-cache":
			rw.Header().Set("Content-Type", "application/json")
			rw.Header().Set("Cache-Control", "no-cache, max-age=600")
			_, _ = rw.Write([]byte(body))
		case "/stale-at-once":
			rw.Header().Set("Content-Type", "application/json")
			rw.Header().Set("Cache-Control", "max-age=0")
			_, _ = rw.Write([]byte(body))
		case "/suffix":
			rw.Header().Set("Content-Type", "application/cimd+json")
			_, _ = rw.Write([]byte(body))
		case "/slow":
			env.entered <- struct{}{}
			<-env.release

			rw.Header().Set("Content-Type", "application/json")
			_, _ = rw.Write([]byte(body))
		case "/redirect":
			http.Redirect(rw, r, "/ok", http.StatusFound)
		case "/missing":
			http.NotFound(rw, r)
		case "/no-content":
			rw.Header().Set("Content-Type", "application/json")
			rw.WriteHeader(http.StatusNoContent)
		case "/error":
			rw.Header().Set("Content-Type", "application/json")
			rw.WriteHeader(http.StatusInternalServerError)
			_, _ = rw.Write([]byte(body))
		case "/text":
			rw.Header().Set("Content-Type", "text/plain")
			_, _ = rw.Write([]byte(body))
		case "/no-content-type":
			rw.Header()["Content-Type"] = nil
			_, _ = rw.Write([]byte(body))
		case "/big":
			rw.Header().Set("Content-Type", "application/json")
			_, _ = rw.Write([]byte(padDocument(id, 5121)))
		case "/limit":
			rw.Header().Set("Content-Type", "application/json")
			_, _ = rw.Write([]byte(padDocument(id, 5120)))
		case "/mismatch":
			rw.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(rw, `{"client_id":%q}`, env.server.URL+"/ok")
		case "/secret":
			rw.Header().Set("Content-Type", "application/json")
			_, _ = rw.Write([]byte(fmt.Sprintf(`{"client_id":%q,"client_secret":"s"}`, id)))
		case "/greedy":
			rw.Header().Set("Content-Type", "application/json")
			_, _ = rw.Write([]byte(fmt.Sprintf(`{"client_id":%q,"redirect_uris":["https://client.example.com/cb"],"scope":"oauth2 admin authelia:oauth2:dynamic-client-registration","grant_types":["authorization_code","refresh_token","client_credentials","implicit"],"response_types":["code","token","code id_token"],"audience":["https://api.example.com"],"resource":["https://resource.example.com"],"authorization_details_types":["payment_initiation"],"authorization_grant_profiles_supported":["urn:example:profile"],"sector_identifier_uri":"https://victim.example.com/sector.json"}`, id)))
		case "/native":
			rw.Header().Set("Content-Type", "application/json")
			_, _ = rw.Write([]byte(fmt.Sprintf(`{"client_id":%q,"application_type":"native","redirect_uris":["http://127.0.0.1/cb","http://[::1]/cb"]}`, id)))
		case "/idjag":
			rw.Header().Set("Content-Type", "application/json")
			_, _ = rw.Write([]byte(fmt.Sprintf(`{"client_id":%q,"grant_types":["urn:ietf:params:oauth:grant-type:token-exchange","urn:ietf:params:oauth:grant-type:jwt-bearer"],"authorization_grant_profiles_supported":["urn:ietf:params:oauth:grant-profile:id-jag"],"token_endpoint_auth_methods_supported":["private_key_jwt"],"jwks_uri":"https://client.example.com/jwks.json"}`, id)))
		case "/credentials":
			rw.Header().Set("Content-Type", "application/json")
			_, _ = rw.Write([]byte(fmt.Sprintf(`{"client_id":%q,"grant_types":["client_credentials"],"token_endpoint_auth_method":"private_key_jwt","jwks_uri":"https://client.example.com/jwks.json"}`, id)))
		case "/busy":
			rw.WriteHeader(http.StatusTooManyRequests)
		case "/reset":
			if conn, _, err := http.NewResponseController(rw).Hijack(); err == nil {
				_ = conn.Close()
			}
		case "/bad-redirect":
			rw.Header().Set("Content-Type", "application/json")
			_, _ = rw.Write([]byte(fmt.Sprintf(`{"client_id":%q,"redirect_uris":["http://client.example.com/cb"]}`, id)))
		default:
			http.NotFound(rw, r)
		}
	}))

	t.Cleanup(func() {
		select {
		case <-env.release:
		default:
			close(env.release)
		}

		env.server.Close()
	})

	config := Config{
		Storage:         env.store,
		HTTPClient:      loopbackClient(env.server),
		ValidatorConfig: &oauth2.Config{},
	}

	if configure != nil {
		configure(&config)
	}

	var err error

	env.resolver, err = NewResolver(config)

	require.NoError(t, err)

	return env
}

func (e *resolverEnv) setExpired(t *testing.T, id string) {
	t.Helper()

	expired := time.Now().Add(-time.Minute)

	require.NoError(t, e.store.SetClientIDMetadataDocument(t.Context(), &oauth2.ClientIDMetadataDocumentRecord{
		ID:        id,
		Metadata:  &oauth2.ClientRegistrationMetadata{RedirectURIs: []string{"https://old.example.com/cb"}},
		FetchedAt: expired.Add(-time.Hour),
		ExpiresAt: expired,
	}))
}

func (e *resolverEnv) setExpiredAt(t *testing.T, id string, expired time.Time) {
	t.Helper()

	e.setRecord(t, id, expired, false)
}

func (e *resolverEnv) setRecord(t *testing.T, id string, expired time.Time, revalidate bool) {
	t.Helper()

	require.NoError(t, e.store.SetClientIDMetadataDocument(t.Context(), &oauth2.ClientIDMetadataDocumentRecord{
		MustRevalidate: revalidate,
		ID:             id,
		Metadata: &oauth2.ClientRegistrationMetadata{
			RedirectURIs:            []string{"https://old.example.com/cb"},
			GrantTypes:              []string{"authorization_code"},
			ResponseTypes:           []string{"code"},
			TokenEndpointAuthMethod: "none",
		},
		FetchedAt: expired.Add(-time.Hour),
		ExpiresAt: expired,
	}))
}

type filterFunc func(metadata *oauth2.ClientRegistrationMetadata) error

func (f filterFunc) FilterClientRegistrationMetadata(_ context.Context, _ oauth2.Client, metadata *oauth2.ClientRegistrationMetadata) error {
	return f(metadata)
}

type faultyStorage struct {
	oauth2.ClientIDMetadataDocumentStorage

	setErr    error
	deleteErr error
	revokeErr error
	countErr  error
	deletes   atomic.Int64
	revoked   []string
}

func (s *faultyStorage) CountClientIDMetadataDocuments(ctx context.Context, domain string) (int, error) {
	if s.countErr != nil {
		return 0, s.countErr
	}

	return s.ClientIDMetadataDocumentStorage.CountClientIDMetadataDocuments(ctx, domain)
}

func (s *faultyStorage) RevokeClientIDMetadataDocumentRefreshTokens(ctx context.Context, id string) error {
	s.revoked = append(s.revoked, id)

	if s.revokeErr != nil {
		return s.revokeErr
	}

	return s.ClientIDMetadataDocumentStorage.RevokeClientIDMetadataDocumentRefreshTokens(ctx, id)
}

func (s *faultyStorage) SetClientIDMetadataDocument(ctx context.Context, record *oauth2.ClientIDMetadataDocumentRecord) error {
	if s.setErr != nil {
		return s.setErr
	}

	return s.ClientIDMetadataDocumentStorage.SetClientIDMetadataDocument(ctx, record)
}

func (s *faultyStorage) DeleteClientIDMetadataDocument(ctx context.Context, id string) error {
	s.deletes.Add(1)

	if s.deleteErr != nil {
		return s.deleteErr
	}

	return s.ClientIDMetadataDocumentStorage.DeleteClientIDMetadataDocument(ctx, id)
}

type pruneStorage struct {
	oauth2.ClientIDMetadataDocumentStorage

	pruned chan time.Time
}

func (s *pruneStorage) DeleteExpiredClientIDMetadataDocuments(ctx context.Context, before time.Time) error {
	s.pruned <- before

	return s.ClientIDMetadataDocumentStorage.DeleteExpiredClientIDMetadataDocuments(ctx, before)
}

func loopbackClient(server *httptest.Server) *retryablehttp.Client {
	client := oauth2.NewSpecialUseAddressGuardedHTTPClient(oauth2.WithSpecialUseAddressGuardAllowLoopback(netip.MustParseAddr("127.0.0.1")))

	client.HTTPClient.Transport.(*http.Transport).TLSClientConfig = server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()

	return client
}

func padDocument(id string, size int) string {
	prefix := fmt.Sprintf(`{"client_id":%q,"redirect_uris":["https://client.example.com/cb"],"client_name":"`, id)
	suffix := `"}`

	return prefix + strings.Repeat("a", size-len(prefix)-len(suffix)) + suffix
}

type fixedStorage struct {
	oauth2.ClientIDMetadataDocumentStorage

	record *oauth2.ClientIDMetadataDocumentRecord
	err    error
}

func (s *fixedStorage) GetClientIDMetadataDocument(_ context.Context, _ string) (*oauth2.ClientIDMetadataDocumentRecord, error) {
	return s.record, s.err
}

type unmarkedStrategy struct{}

func (unmarkedStrategy) NewClient(_ context.Context, record *oauth2.ClientIDMetadataDocumentRecord) (oauth2.Client, error) {
	return &oauth2.DefaultClient{ID: record.ID}, nil
}
