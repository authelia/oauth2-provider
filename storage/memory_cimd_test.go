// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package storage

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
)

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

			fetched := time.Unix(1760000000, 0).UTC()

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
		})
	}
}
