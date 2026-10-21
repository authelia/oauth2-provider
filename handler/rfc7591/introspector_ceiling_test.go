// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc7591

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/storage"
)

func TestIntrospectionDoesNotReportTheCeilingsOfAManagementToken(t *testing.T) {
	stores := map[string]func() (oauth2.Storage, Storage, *storage.MemoryStore){
		"MemoryStore": func() (oauth2.Storage, Storage, *storage.MemoryStore) {
			store := storage.NewMemoryStore()

			return store, store, store
		},
		"HydratingMemoryStore": func() (oauth2.Storage, Storage, *storage.MemoryStore) {
			store := storage.NewHydratingMemoryStore()

			return store, store, store.MemoryStore
		},
	}

	for name, newStore := range stores {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			base, store, memory := newStore()

			config := &oauth2.Config{
				GlobalSecret:                          []byte("super-duper-secret-that-is-at-least-32-bytes"),
				RFC7591ClientRegistrationGlobalSecret: []byte("a-completely-different-secret-at-least-32b"),
				RFC7591ClientRegistrationEndpointURL:  testEndpoint,
				TokenEntropy:                          32,
			}

			strategy := hoauth2.NewHMACCoreStrategy(config, "authelia_%s_")
			client := &oauth2.DefaultClient{ID: "onboarding"}

			token, err := NewClientManagementToken(ctx, strategy, store, config, client, oauth2.Arguments{"admin"}, oauth2.Arguments{"https://api.example.com"}, oauth2.Arguments{"https://resource.example.com"})
			require.NoError(t, err)

			config.TokenIntrospectionHandlers = oauth2.TokenIntrospectionHandlers{
				&ClientRegistrationTokenIntrospector{Store: store, Strategy: strategy, Config: config},
			}

			caller := &oauth2.DefaultClient{ID: "resource-server", ClientSecret: oauth2.NewPlainTextClientSecret("foobarfoobarfoobarfoobarfoobar12")}

			memory.Clients[caller.ID] = caller

			provider := &oauth2.Fosite{Store: base, Config: config}

			r := httptest.NewRequest(http.MethodPost, "https://auth.example.com/introspect", strings.NewReader(url.Values{"token": {token}}.Encode()))
			r.Header.Set(consts.HeaderContentType, "application/x-www-form-urlencoded")
			r.SetBasicAuth(caller.ID, "foobarfoobarfoobarfoobarfoobar12")

			response, err := provider.NewIntrospectionRequest(ctx, r, &oauth2.DefaultSession{})
			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

			recorder := httptest.NewRecorder()
			provider.WriteIntrospectionResponse(ctx, recorder, response)

			var body map[string]any

			require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &body))

			assert.Equal(t, true, body["active"])
			assert.Equal(t, "onboarding", body[consts.ClaimClientIdentifier])
			assert.NotContains(t, body, consts.ClaimScope)
			assert.Equal(t, []any{ClientConfigurationURL(testEndpoint, "onboarding")}, body[consts.ClaimAudience])
		})
	}
}

func TestManagementTokenKeepsItsCeilingsAfterIntrospection(t *testing.T) {
	ctx := context.Background()

	introspector, _, store, strategy, _ := newIntrospectionFixture(t)

	token, err := NewClientManagementToken(ctx, strategy, store, introspector.Config, &oauth2.DefaultClient{ID: "onboarding"}, oauth2.Arguments{"admin"}, oauth2.Arguments{"https://api.example.com"}, nil)
	require.NoError(t, err)

	_, err = introspector.IntrospectToken(ctx, token, oauth2.AccessToken, oauth2.NewAccessRequest(&oauth2.DefaultSession{}), nil)
	require.NoError(t, err)

	stored, err := store.GetClientRegistrationTokenSession(ctx, strategy.ClientRegistrationTokenSignature(ctx, token), &oauth2.DefaultSession{})
	require.NoError(t, err)

	assert.True(t, stored.GetGrantedScopes().Has("admin"))
	assert.True(t, stored.GetGrantedAudience().Has("https://api.example.com"))
}

func TestIntrospectionDoesNotReportThePolicyOfAManagementToken(t *testing.T) {
	ctx := context.Background()

	policy := map[string]any{"client_name": map[string]any{"one_of": []any{"a"}}}

	for name, store := range map[string]Storage{
		"MemoryStore":          storage.NewMemoryStore(),
		"HydratingMemoryStore": storage.NewHydratingMemoryStore(),
	} {
		t.Run(name, func(t *testing.T) {
			config := &oauth2.Config{
				GlobalSecret:                          []byte("super-duper-secret-that-is-at-least-32-bytes"),
				RFC7591ClientRegistrationGlobalSecret: []byte("a-completely-different-secret-at-least-32b"),
				RFC7591ClientRegistrationEndpointURL:  testEndpoint,
				TokenEntropy:                          32,
			}

			strategy := hoauth2.NewHMACCoreStrategy(config, "authelia_%s_")
			introspector := &ClientRegistrationTokenIntrospector{Store: store, Strategy: strategy, Config: config}

			token, err := NewClientManagementTokenWithPolicy(ctx, strategy, store, config, &oauth2.DefaultClient{ID: "onboarding"}, policy)
			require.NoError(t, err)

			request := oauth2.NewAccessRequest(&oauth2.DefaultSession{})

			_, err = introspector.IntrospectToken(ctx, token, oauth2.AccessToken, request, nil)
			require.NoError(t, err)

			reported, ok := request.GetSession().(oauth2.ExtraClaimsSession)
			require.True(t, ok)
			assert.NotContains(t, reported.GetExtraClaims(), consts.ClientRegistrationPolicyInternalKey)

			stored, err := store.GetClientRegistrationTokenSession(ctx, strategy.ClientRegistrationTokenSignature(ctx, token), &oauth2.DefaultSession{})
			require.NoError(t, err)

			session, ok := stored.GetSession().(oauth2.ExtraClaimsSession)
			require.True(t, ok)
			assert.Contains(t, session.GetExtraClaims(), consts.ClientRegistrationPolicyInternalKey)
		})
	}
}
