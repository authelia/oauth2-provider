// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package storage_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/jose"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/storage"
)

func TestMemoryStoreRFC7523(t *testing.T) {
	type store interface {
		GetRFC7523TrustedIssuer(ctx context.Context, issuer string) (trusted *oauth2.RFC7523TrustedIssuer, err error)
		ResolveRFC7523Subject(ctx context.Context, client oauth2.Client, trusted *oauth2.RFC7523TrustedIssuer, keyID string, claims map[string]any) (subject string, err error)
	}

	hydrating := storage.NewHydratingMemoryStore()

	stores := []struct {
		name   string
		memory *storage.MemoryStore
		store  store
	}{
		{name: "MemoryStore", memory: storage.NewMemoryStore()},
		{name: "HydratingMemoryStore", memory: hydrating.MemoryStore, store: hydrating},
	}

	for _, s := range stores {
		t.Run(s.name, func(t *testing.T) {
			ctx := t.Context()

			if s.store == nil {
				s.store = s.memory
			}

			s.memory.RFC7523TrustedIssuers[rfc7523TestIssuer] = rfc7523TestTrustedIssuer()
			s.memory.RFC7523Subjects[storage.RFC7523SubjectKey{Issuer: rfc7523TestIssuer, Subject: "alice"}] = "local-alice"

			t.Run("ShouldReturnNotFoundForAnUnknownIssuer", func(t *testing.T) {
				trusted, err := s.store.GetRFC7523TrustedIssuer(ctx, "https://unknown.example")

				assert.ErrorIs(t, err, oauth2.ErrNotFound)
				assert.Nil(t, trusted)
			})

			t.Run("ShouldReturnACopyOfTheTrustedIssuer", func(t *testing.T) {
				trusted, err := s.store.GetRFC7523TrustedIssuer(ctx, rfc7523TestIssuer)

				require.NoError(t, err)
				require.NotNil(t, trusted)
				require.Equal(t, rfc7523TestTrustedIssuer(), *trusted)

				trusted.SigningAlgs[0] = "none"
				trusted.Subjects[0] = "mallory"
				trusted.Scopes[0] = "admin"
				trusted.Audience[0] = "https://evil.example"
				trusted.Clients[0] = "other-client"
				trusted.JSONWebKeys.Keys[0].KeyID = "other-key"

				again, err := s.store.GetRFC7523TrustedIssuer(ctx, rfc7523TestIssuer)

				require.NoError(t, err)
				require.NotNil(t, again)
				assert.Equal(t, rfc7523TestTrustedIssuer(), *again)
			})

			t.Run("ShouldResolveARegisteredSubject", func(t *testing.T) {
				subject, err := s.store.ResolveRFC7523Subject(ctx, nil, &oauth2.RFC7523TrustedIssuer{Issuer: rfc7523TestIssuer}, "key-1", map[string]any{consts.ClaimSubject: "alice"})

				require.NoError(t, err)
				assert.Equal(t, "local-alice", subject)
			})

			testCases := []struct {
				name   string
				issuer string
				claims map[string]any
			}{
				{
					name:   "ShouldReturnNotFoundForAnUnregisteredSubject",
					issuer: rfc7523TestIssuer,
					claims: map[string]any{consts.ClaimSubject: "bob"},
				},
				{
					name:   "ShouldScopeTheSubjectToItsIssuer",
					issuer: "https://other.example",
					claims: map[string]any{consts.ClaimSubject: "alice"},
				},
				{
					name:   "ShouldReturnNotFoundForASubjectThatIsNotAString",
					issuer: rfc7523TestIssuer,
					claims: map[string]any{consts.ClaimSubject: 42},
				},
			}

			for _, tc := range testCases {
				t.Run(tc.name, func(t *testing.T) {
					subject, err := s.store.ResolveRFC7523Subject(ctx, nil, &oauth2.RFC7523TrustedIssuer{Issuer: tc.issuer}, "key-1", tc.claims)

					assert.ErrorIs(t, err, oauth2.ErrNotFound)
					assert.Empty(t, subject)
				})
			}

			t.Run("ShouldReturnNotFoundForANilTrustedIssuer", func(t *testing.T) {
				subject, err := s.store.ResolveRFC7523Subject(ctx, nil, nil, "key-1", map[string]any{consts.ClaimSubject: "alice"})

				assert.ErrorIs(t, err, oauth2.ErrNotFound)
				assert.Empty(t, subject)
			})
		})
	}
}

const rfc7523TestIssuer = "https://as.a.example/grants"

func rfc7523TestTrustedIssuer() oauth2.RFC7523TrustedIssuer {
	return oauth2.RFC7523TrustedIssuer{
		Issuer:         rfc7523TestIssuer,
		JSONWebKeys:    &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{KeyID: "key-1"}}},
		JSONWebKeysURI: "https://as.a.example/jwks.json",
		SigningAlgs:    []string{"ES256"},
		Subjects:       []string{"alice"},
		Scopes:         []string{"orders.read"},
		Audience:       []string{"https://api.b.example"},
		Clients:        []string{"client-1"},
	}
}
