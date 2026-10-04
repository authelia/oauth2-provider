// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package storage_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/jose"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/storage"
)

func TestMemoryStoreIDJAG(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	client := &oauth2.DefaultClient{ID: idjagTestClient}
	request := &oauth2.AccessRequest{Request: oauth2.Request{Client: client}}

	store.IDJAGRelationships[storage.IDJAGRelationshipKey{ClientID: idjagTestClient, Audience: "urn:example:chat"}] = oauth2.IDJAGRelationship{Issuer: "https://chat.example/", ClientID: "f53f", Scopes: []string{"chat.read"}}

	relationship, err := store.GetIDJAGRelationship(ctx, request, "urn:example:chat")
	require.NoError(t, err)
	assert.Equal(t, "f53f", relationship.ClientID)

	relationship.Scopes[0] = idjagTestMutated

	again, err := store.GetIDJAGRelationship(ctx, request, "urn:example:chat")
	require.NoError(t, err)
	assert.Equal(t, "chat.read", again.Scopes[0])

	store.IDJAGRelationships[storage.IDJAGRelationshipKey{ClientID: idjagTestClient, Audience: "urn:example:pay"}] = oauth2.IDJAGRelationship{Issuer: "https://pay.example/", ClientID: "a1", AuthorizationDetailsTypes: []string{internal.AuthorizationDetailsTypePaymentInitiation}}
	store.IDJAGRelationships[storage.IDJAGRelationshipKey{ClientID: idjagTestClient, Audience: "urn:example:none"}] = oauth2.IDJAGRelationship{Issuer: "https://none.example/", ClientID: "a2", AuthorizationDetailsTypes: []string{}}

	relationship, err = store.GetIDJAGRelationship(ctx, request, "urn:example:pay")
	require.NoError(t, err)

	relationship.AuthorizationDetailsTypes[0] = idjagTestMutated

	again, err = store.GetIDJAGRelationship(ctx, request, "urn:example:pay")
	require.NoError(t, err)
	assert.Equal(t, []string{internal.AuthorizationDetailsTypePaymentInitiation}, again.AuthorizationDetailsTypes)

	relationship, err = store.GetIDJAGRelationship(ctx, request, "urn:example:none")
	require.NoError(t, err)
	assert.NotNil(t, relationship.AuthorizationDetailsTypes)
	assert.Empty(t, relationship.AuthorizationDetailsTypes)

	_, err = store.GetIDJAGRelationship(ctx, request, "https://unknown.example/")
	assert.ErrorIs(t, err, oauth2.ErrNotFound)

	_, err = store.GetIDJAGTrustedIssuer(ctx, idjagTestIssuer)
	assert.ErrorIs(t, err, oauth2.ErrNotFound)

	store.IDJAGTrustedIssuers[idjagTestIssuer] = oauth2.IDJAGTrustedIssuer{
		Issuer:      idjagTestIssuer,
		JSONWebKeys: &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{KeyID: "k1"}}},
	}

	trusted, err := store.GetIDJAGTrustedIssuer(ctx, idjagTestIssuer)
	require.NoError(t, err)
	assert.Equal(t, idjagTestIssuer, trusted.Issuer)

	trusted.JSONWebKeys.Keys[0].KeyID = idjagTestMutated
	trusted.JSONWebKeys.Keys = append(trusted.JSONWebKeys.Keys, jose.JSONWebKey{KeyID: "k2"})

	trusted, err = store.GetIDJAGTrustedIssuer(ctx, idjagTestIssuer)
	require.NoError(t, err)
	require.Len(t, trusted.JSONWebKeys.Keys, 1)
	assert.Equal(t, "k1", trusted.JSONWebKeys.Keys[0].KeyID)

	used, err := store.IsIDJAGUsed(ctx, idjagTestIssuer, "j1")
	require.NoError(t, err)
	assert.False(t, used)

	require.NoError(t, store.MarkIDJAGUsed(ctx, idjagTestIssuer, "j1", time.Now().Add(time.Minute)))

	used, err = store.IsIDJAGUsed(ctx, idjagTestIssuer, "j1")
	require.NoError(t, err)
	assert.True(t, used)

	assert.ErrorIs(t, store.MarkIDJAGUsed(ctx, idjagTestIssuer, "j1", time.Now().Add(time.Minute)), oauth2.ErrJTIKnown)
}

func TestMemoryStoreIDJAGSubject(t *testing.T) {
	store := storage.NewMemoryStore()
	request := &oauth2.AccessRequest{Request: oauth2.Request{Session: &oauth2.DefaultSession{Subject: "peter"}}}
	relationship := &oauth2.IDJAGRelationship{Issuer: "https://chat.example/"}

	_, err := store.GetIDJAGSubject(t.Context(), request, relationship)
	require.ErrorIs(t, err, oauth2.ErrNotFound)

	store.IDJAGAudienceSubjects[storage.IDJAGAudienceSubjectKey{Issuer: "https://chat.example/", Subject: "peter"}] = "U019488227"

	subject, err := store.GetIDJAGSubject(t.Context(), request, relationship)
	require.NoError(t, err)
	assert.Equal(t, "U019488227", subject)

	_, err = store.GetIDJAGSubject(t.Context(), request, &oauth2.IDJAGRelationship{Issuer: "https://pay.example/"})
	require.ErrorIs(t, err, oauth2.ErrNotFound)
}

func TestMemoryStoreResolveIDJAGSubject(t *testing.T) {
	store := storage.NewMemoryStore()
	store.IDJAGSubjects[storage.IDJAGSubjectKey{Issuer: idjagTestIssuer, Subject: idjagTestSubject}] = idjagTestAlice
	store.IDJAGSubjects[storage.IDJAGSubjectKey{Issuer: idjagTestIssuer, Tenant: idjagTestTenant, Subject: idjagTestSubject}] = idjagTestBob

	testCases := []struct {
		name     string
		claims   map[string]any
		expected string
		err      error
	}{
		{name: "ShouldResolveTheIssuerSubject", claims: map[string]any{consts.ClaimIssuer: idjagTestIssuer, consts.ClaimSubject: idjagTestSubject}, expected: idjagTestAlice},
		// Section 3.1: a multi-tenant issuer scopes the subject by tenant.
		{name: "ShouldResolveTheTenantSubject", claims: map[string]any{consts.ClaimIssuer: idjagTestIssuer, consts.ClaimTenant: idjagTestTenant, consts.ClaimSubject: idjagTestSubject}, expected: idjagTestBob},
		{name: "ShouldNotResolveAnotherTenant", claims: map[string]any{consts.ClaimIssuer: idjagTestIssuer, consts.ClaimTenant: "other", consts.ClaimSubject: idjagTestSubject}, err: oauth2.ErrNotFound},
		// Section 9.5: an issuer is trusted only for its own subjects.
		{name: "ShouldNotResolveAnotherIssuer", claims: map[string]any{consts.ClaimIssuer: "https://other.example/", consts.ClaimSubject: idjagTestSubject}, err: oauth2.ErrNotFound},
		{name: "ShouldNotResolveAnUnmappedSubject", claims: map[string]any{consts.ClaimIssuer: idjagTestIssuer, consts.ClaimSubject: "U2"}, err: oauth2.ErrNotFound},
		{name: "ShouldNotResolveANonStringTenant", claims: map[string]any{consts.ClaimIssuer: idjagTestIssuer, consts.ClaimTenant: 1, consts.ClaimSubject: idjagTestSubject}, err: oauth2.ErrNotFound},
		{name: "ShouldNotResolveAnEmptyTenant", claims: map[string]any{consts.ClaimIssuer: idjagTestIssuer, consts.ClaimTenant: "", consts.ClaimSubject: idjagTestSubject}, err: oauth2.ErrNotFound},
		{name: "ShouldNotResolveWithoutSubject", claims: map[string]any{consts.ClaimIssuer: idjagTestIssuer}, err: oauth2.ErrNotFound},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			subject, err := store.ResolveIDJAGSubject(t.Context(), &oauth2.DefaultClient{ID: idjagTestClient}, tc.claims)

			if tc.err != nil {
				assert.ErrorIs(t, err, tc.err)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.expected, subject)
		})
	}
}

const (
	idjagTestIssuer  = "https://idp.example/"
	idjagTestClient  = "wiki"
	idjagTestSubject = "U1"
	idjagTestMutated = "mutated"
	idjagTestTenant  = "t1"
	idjagTestAlice   = "alice"
	idjagTestBob     = "bob"
)
