// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc8693_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/handler/openid"
	. "authelia.com/provider/oauth2/handler/rfc8693"
	"authelia.com/provider/oauth2/handler/rfc9449"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/token/hmac"
)

const (
	bindingJKT      = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"
	bindingJKTOther = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
	bindingX5T      = "A4DtL2JmUMhAsvJj5tAtEqYFn7uHnaMbNKmoNcE7dnE"
)

func TestTokenExchangeInheritsTokenBinding(t *testing.T) {
	testCases := []struct {
		name     string
		subject  func(session *oauth2.DefaultSession)
		actor    func(session *oauth2.DefaultSession)
		expected string
		bound    func(t *testing.T, session *DefaultSession)
	}{
		{
			name:    "ShouldInheritADPoPBindingFromTheSubjectToken",
			subject: func(session *oauth2.DefaultSession) { session.SetDPoPJWKThumbprint(bindingJKT) },
			bound: func(t *testing.T, session *DefaultSession) {
				assert.Equal(t, bindingJKT, session.GetDPoPJWKThumbprint())
			},
		},
		{
			name:    "ShouldInheritACertificateBindingFromTheSubjectToken",
			subject: func(session *oauth2.DefaultSession) { session.SetClientCertificateSHA256Thumbprint(bindingX5T) },
			bound: func(t *testing.T, session *DefaultSession) {
				assert.Equal(t, bindingX5T, session.GetClientCertificateSHA256Thumbprint())
			},
		},
		{
			name:  "ShouldInheritADPoPBindingFromTheActorToken",
			actor: func(session *oauth2.DefaultSession) { session.SetDPoPJWKThumbprint(bindingJKT) },
			bound: func(t *testing.T, session *DefaultSession) {
				assert.Equal(t, bindingJKT, session.GetDPoPJWKThumbprint())
			},
		},
		{
			name:    "ShouldAcceptMatchingBindingsOnBothTokens",
			subject: func(session *oauth2.DefaultSession) { session.SetDPoPJWKThumbprint(bindingJKT) },
			actor:   func(session *oauth2.DefaultSession) { session.SetDPoPJWKThumbprint(bindingJKT) },
			bound: func(t *testing.T, session *DefaultSession) {
				assert.Equal(t, bindingJKT, session.GetDPoPJWKThumbprint())
			},
		},
		{
			name:     "ShouldRejectDifferentDPoPBindingsOnTheTwoTokens",
			subject:  func(session *oauth2.DefaultSession) { session.SetDPoPJWKThumbprint(bindingJKTOther) },
			actor:    func(session *oauth2.DefaultSession) { session.SetDPoPJWKThumbprint(bindingJKT) },
			expected: "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The subject token and the actor token are bound to different keys or certificates, and the issued token can only carry one binding.",
		},
		{
			name:     "ShouldRejectBindingsOfDifferentKindsOnTheTwoTokens",
			subject:  func(session *oauth2.DefaultSession) { session.SetClientCertificateSHA256Thumbprint(bindingX5T) },
			actor:    func(session *oauth2.DefaultSession) { session.SetDPoPJWKThumbprint(bindingJKT) },
			expected: "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The subject token and the actor token are bound to different keys or certificates, and the issued token can only carry one binding.",
		},
		{
			name: "ShouldRecordNothingWhenNeitherTokenIsBound",
			bound: func(t *testing.T, session *DefaultSession) {
				assert.Empty(t, session.GetDPoPJWKThumbprint())
				assert.Empty(t, session.GetClientCertificateSHA256Thumbprint())
			},
		},
	}

	for _, tc := range testCases {
		for _, sc := range bindingExchangeStores() {
			t.Run(tc.name+"/"+sc.name, func(t *testing.T) {
				store := sc.newStore()

				session, err := runBindingExchange(t, store, tc.subject, tc.actor)

				if tc.expected != "" {
					require.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), tc.expected)

					return
				}

				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

				tc.bound(t, session)
			})
		}
	}
}

func TestTokenExchangeDoesNotInheritKeyBinding(t *testing.T) {
	keyBound := func(session *oauth2.DefaultSession) {
		session.SetOIDCKeyBindingGranted(true)
		session.SetDPoPPublicKeyJWK([]byte(`{"kty":"EC","crv":"P-256","x":"x","y":"y"}`))
		session.SetRequestedDPoPJWKThumbprint(bindingJKT)
		session.SetDPoPJWKThumbprint(bindingJKT)
	}

	for _, sc := range bindingExchangeStores() {
		t.Run(sc.name, func(t *testing.T) {
			session, err := runBindingExchange(t, sc.newStore(), keyBound, nil)

			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

			assert.False(t, session.GetOIDCKeyBindingGranted())
			assert.Empty(t, session.GetDPoPPublicKeyJWK())
			assert.Empty(t, session.GetRequestedDPoPJWKThumbprint())
			assert.Equal(t, bindingJKT, session.GetDPoPJWKThumbprint())
		})
	}
}

func TestTokenExchangeInheritedBindingIsEnforced(t *testing.T) {
	for _, sc := range bindingExchangeStores() {
		t.Run(sc.name, func(t *testing.T) {
			store := sc.newStore()

			session, err := runBindingExchange(t, store, func(session *oauth2.DefaultSession) {
				session.SetDPoPJWKThumbprint(bindingJKT)
			}, nil)

			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
			require.Equal(t, bindingJKT, session.GetDPoPJWKThumbprint(), "the binding must be recorded before the binding phase runs")

			config, _ := newBindingExchangeConfig()
			config.DPoPEnabled = true

			request := &oauth2.AccessRequest{
				GrantTypes: oauth2.Arguments{consts.GrantTypeOAuthTokenExchange},
				Request:    oauth2.Request{Session: session},
			}

			ctx := context.WithValue(t.Context(), oauth2.RequestContextKey, httptest.NewRequest(http.MethodPost, "https://auth.example.com/token", nil))
			binder := &rfc9449.Handler{Config: config}

			require.EqualError(t, oauth2.ErrorToDebugRFC6749Error(binder.BindAccessRequest(ctx, request)), "The DPoP proof is missing or invalid. The request requires a DPoP proof but none was provided.")
		})
	}
}

func runBindingExchange(t *testing.T, store rfc8693ExchangeStore, subject, actor func(session *oauth2.DefaultSession)) (session *DefaultSession, err error) {
	t.Helper()

	config, coreStrategy := newBindingExchangeConfig()

	handler := &AccessTokenTypeHandler{
		Config:               config,
		AccessTokenLifespan:  5 * time.Minute,
		RefreshTokenLifespan: 5 * time.Minute,
		CoreStrategy:         coreStrategy,
		ScopeStrategy:        config.ScopeStrategy,
		Storage:              store,
	}

	client := store.GetClients()["my-client"]
	subjectToken := createBoundAccessToken(t.Context(), coreStrategy, store, store.GetClients()["custom-lifespan-client"], subject)

	form := url.Values{
		consts.FormParameterGrantType:        []string{consts.GrantTypeOAuthTokenExchange},
		consts.FormParameterSubjectTokenType: []string{consts.TokenTypeRFC8693AccessToken},
		consts.FormParameterSubjectToken:     []string{subjectToken},
	}

	if actor != nil {
		form.Set(consts.FormParameterActorTokenType, consts.TokenTypeRFC8693AccessToken)
		form.Set(consts.FormParameterActorToken, createBoundAccessToken(t.Context(), coreStrategy, store, client, actor))
	}

	session = &DefaultSession{DefaultSession: &openid.DefaultSession{}}

	request := &oauth2.AccessRequest{
		GrantTypes: oauth2.Arguments{consts.GrantTypeOAuthTokenExchange},
		Request: oauth2.Request{
			ID:      uuid.New().String(),
			Client:  client,
			Form:    form,
			Session: session,
		},
	}

	return session, handler.HandleTokenEndpointRequest(t.Context(), request)
}

func createBoundAccessToken(ctx context.Context, coreStrategy hoauth2.CoreStrategy, store hoauth2.AccessTokenStorage, client oauth2.Client, bind func(session *oauth2.DefaultSession)) string {
	session := &oauth2.DefaultSession{
		Username: "peter",
		Subject:  "peter",
		ExpiresAt: map[oauth2.TokenType]time.Time{
			oauth2.AccessToken: time.Now().UTC().Add(10 * time.Minute),
		},
	}

	if bind != nil {
		bind(session)
	}

	request := &oauth2.AccessRequest{
		GrantTypes: oauth2.Arguments{"password"},
		Request: oauth2.Request{
			Session: session,
			Client:  client,
		},
	}

	token, signature, err := coreStrategy.GenerateAccessToken(ctx, request)
	if err != nil {
		panic(err.Error())
	} else if err = store.CreateAccessTokenSession(ctx, signature, request.Sanitize([]string{})); err != nil {
		panic(err.Error())
	}

	return token
}

func newBindingExchangeConfig() (config *oauth2.Config, coreStrategy hoauth2.CoreStrategy) {
	config = &oauth2.Config{
		ScopeStrategy:    oauth2.HierarchicScopeStrategy,
		AudienceStrategy: oauth2.DefaultAudienceStrategy,
		GlobalSecret:     []byte("some-secret-thats-random-some-secret-thats-random-"),
		RFC8693TokenTypes: map[string]oauth2.RFC8693TokenType{
			consts.TokenTypeRFC8693AccessToken: &DefaultTokenType{Name: consts.TokenTypeRFC8693AccessToken},
		},
		DefaultRequestedTokenType: consts.TokenTypeRFC8693AccessToken,
	}

	return config, &hoauth2.HMACCoreStrategy{
		Enigma: &hmac.HMACStrategy{Config: config},
		Config: config,
	}
}

type rfc8693ExchangeStore interface {
	Storage
	hoauth2.AccessTokenStorage

	GetClients() map[string]oauth2.Client
}

func bindingExchangeStores() []struct {
	name     string
	newStore func() rfc8693ExchangeStore
} {
	return []struct {
		name     string
		newStore func() rfc8693ExchangeStore
	}{
		{
			name:     "MemoryStore",
			newStore: func() rfc8693ExchangeStore { return &exchangeMemoryStore{storage.NewExampleStore()} },
		},
		{
			name: "HydratingMemoryStore",
			newStore: func() rfc8693ExchangeStore {
				store := storage.NewHydratingMemoryStore()
				store.MemoryStore = storage.NewExampleStore()

				return &exchangeHydratingStore{store}
			},
		},
	}
}

type exchangeMemoryStore struct {
	*storage.MemoryStore
}

func (s *exchangeMemoryStore) GetClients() map[string]oauth2.Client {
	return s.Clients
}

type exchangeHydratingStore struct {
	*storage.HydratingMemoryStore
}

func (s *exchangeHydratingStore) GetClients() map[string]oauth2.Client {
	return s.Clients
}
