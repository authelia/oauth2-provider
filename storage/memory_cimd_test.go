// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package storage

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
)

func TestMemoryStoreRevokeClientIDMetadataDocumentRefreshTokens(t *testing.T) {
	const id = "https://client.example.com/metadata.json"

	type store interface {
		oauth2.ClientIDMetadataDocumentStorage

		CreateRefreshTokenSession(ctx context.Context, signature, accessSignature string, request oauth2.Requester) (err error)
		GetRefreshTokenSession(ctx context.Context, signature string, session oauth2.Session) (request oauth2.Requester, err error)
	}

	stores := map[string]store{
		"MemoryStore":          NewMemoryStore(),
		"HydratingMemoryStore": NewHydratingMemoryStore(),
	}

	for name, s := range stores {
		t.Run(name, func(t *testing.T) {
			ctx := t.Context()

			for signature, client := range map[string]string{"document-1": id, "document-2": id, "other": "https://client.example.com/other.json"} {
				request := oauth2.NewRequest()
				request.ID = signature
				request.Client = &oauth2.DefaultClient{ID: client}
				request.Session = &oauth2.DefaultSession{}

				require.NoError(t, s.CreateRefreshTokenSession(ctx, signature, "", request))
			}

			require.NoError(t, s.RevokeClientIDMetadataDocumentRefreshTokens(ctx, id))

			for _, signature := range []string{"document-1", "document-2"} {
				_, err := s.GetRefreshTokenSession(ctx, signature, &oauth2.DefaultSession{})
				assert.ErrorIs(t, err, oauth2.ErrInactiveToken, signature)
			}

			_, err := s.GetRefreshTokenSession(ctx, "other", &oauth2.DefaultSession{})
			assert.NoError(t, err)

			require.NoError(t, s.RevokeClientIDMetadataDocumentRefreshTokens(ctx, "https://client.example.com/none.json"))
		})
	}

	assert.NoError(t, (&MemoryStore{}).RevokeClientIDMetadataDocumentRefreshTokens(t.Context(), id))
}

func TestMemoryStoreCountClientIDMetadataDocuments(t *testing.T) {
	stores := map[string]oauth2.ClientIDMetadataDocumentStorage{
		"MemoryStore":          NewMemoryStore(),
		"HydratingMemoryStore": NewHydratingMemoryStore(),
	}

	for name, store := range stores {
		t.Run(name, func(t *testing.T) {
			ctx := t.Context()

			count, err := store.CountClientIDMetadataDocuments(ctx, "example.com")
			require.NoError(t, err)
			assert.Equal(t, 0, count)

			for id, domain := range map[string]string{
				"https://a.example.com/c": "example.com",
				"https://b.example.com/c": "example.com",
				"https://c.example.org/c": "example.org",
			} {
				require.NoError(t, store.SetClientIDMetadataDocument(ctx, &oauth2.ClientIDMetadataDocumentRecord{ID: id, Domain: domain, Metadata: &oauth2.ClientRegistrationMetadata{}, ExpiresAt: time.Now().Add(-time.Hour)}))
			}

			require.NoError(t, store.SetClientIDMetadataDocument(ctx, &oauth2.ClientIDMetadataDocumentRecord{ID: "https://a.example.com/c", Domain: "example.com", Metadata: &oauth2.ClientRegistrationMetadata{}, ExpiresAt: time.Now().Add(time.Hour)}))

			count, err = store.CountClientIDMetadataDocuments(ctx, "example.com")
			require.NoError(t, err)
			assert.Equal(t, 2, count)

			count, err = store.CountClientIDMetadataDocuments(ctx, "example.org")
			require.NoError(t, err)
			assert.Equal(t, 1, count)

			require.NoError(t, store.DeleteClientIDMetadataDocument(ctx, "https://b.example.com/c"))

			count, err = store.CountClientIDMetadataDocuments(ctx, "example.com")
			require.NoError(t, err)
			assert.Equal(t, 1, count)
		})
	}

	count, err := (&MemoryStore{}).CountClientIDMetadataDocuments(t.Context(), "example.com")
	require.NoError(t, err)
	assert.Equal(t, 0, count)
}

func TestMemoryStoreClientIDMetadataDocument(t *testing.T) {
	const id = "https://client.example.com/metadata.json"

	stores := map[string]oauth2.ClientIDMetadataDocumentStorage{
		"MemoryStore":          NewMemoryStore(),
		"ZeroValueMemoryStore": &MemoryStore{},
		"HydratingMemoryStore": NewHydratingMemoryStore(),
	}

	for name, store := range stores {
		t.Run(name, func(t *testing.T) {
			ctx := t.Context()

			_, err := store.GetClientIDMetadataDocument(ctx, id)
			require.ErrorIs(t, err, oauth2.ErrNotFound)

			fetched := time.Now().UTC().Truncate(time.Second)

			record := &oauth2.ClientIDMetadataDocumentRecord{
				ID: id,
				Metadata: &oauth2.ClientRegistrationMetadata{
					RedirectURIs: []string{"https://client.example.com/cb"},
					Extra:        map[string]any{"client_id": id},
				},
				FetchedAt: fetched,
				ExpiresAt: fetched.Add(time.Hour),
			}

			require.NoError(t, store.SetClientIDMetadataDocument(ctx, record))

			record.Metadata.RedirectURIs[0] = "https://attacker.example.com/cb"

			actual, err := store.GetClientIDMetadataDocument(ctx, id)
			require.NoError(t, err)

			assert.Equal(t, id, actual.ID)
			assert.Equal(t, []string{"https://client.example.com/cb"}, actual.Metadata.RedirectURIs)
			assert.Equal(t, id, actual.Metadata.Extra["client_id"])
			assert.True(t, fetched.Equal(actual.FetchedAt))
			assert.True(t, fetched.Add(time.Hour).Equal(actual.ExpiresAt))

			actual.Metadata.RedirectURIs[0] = "https://attacker.example.com/cb"

			again, err := store.GetClientIDMetadataDocument(ctx, id)
			require.NoError(t, err)
			assert.Equal(t, []string{"https://client.example.com/cb"}, again.Metadata.RedirectURIs)

			require.NoError(t, store.DeleteClientIDMetadataDocument(ctx, id))

			_, err = store.GetClientIDMetadataDocument(ctx, id)
			require.ErrorIs(t, err, oauth2.ErrNotFound)

			require.NoError(t, store.DeleteClientIDMetadataDocument(ctx, id))
			require.Error(t, store.SetClientIDMetadataDocument(ctx, nil))

			for suffix, expires := range map[string]time.Time{"expired": fetched.Add(-time.Hour), "boundary": fetched, "fresh": fetched.Add(time.Hour)} {
				require.NoError(t, store.SetClientIDMetadataDocument(ctx, &oauth2.ClientIDMetadataDocumentRecord{ID: id + "?" + suffix, ExpiresAt: expires}))
			}

			require.NoError(t, store.DeleteExpiredClientIDMetadataDocuments(ctx, fetched))

			_, err = store.GetClientIDMetadataDocument(ctx, id+"?expired")
			require.ErrorIs(t, err, oauth2.ErrNotFound)

			_, err = store.GetClientIDMetadataDocument(ctx, id+"?boundary")
			require.NoError(t, err)

			_, err = store.GetClientIDMetadataDocument(ctx, id+"?fresh")
			require.NoError(t, err)

			require.NoError(t, (&MemoryStore{}).DeleteExpiredClientIDMetadataDocuments(ctx, fetched))
		})
	}
}
