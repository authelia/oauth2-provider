// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package openid

import (
	"context"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestOpenIDConnectHandlersDetectReusedNonces(t *testing.T) {
	const expected = "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The 'nonce' was already used by this client, a new nonce must be generated for every authentication request. The client with id 'client-a' used a 'nonce' value which it used in an earlier authentication request."

	for _, flow := range newNonceFlows() {
		t.Run(flow.name, func(t *testing.T) {
			t.Run("ShouldRejectANonceTheSameClientUsed", func(t *testing.T) {
				store := storage.NewMemoryStore()

				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(flow.run(t, store, "client-a", testNonce)))

				err := oauth2.ErrorToDebugRFC6749Error(flow.run(t, store, "client-a", testNonce))

				require.EqualError(t, err, expected)
				assert.NotContains(t, err.Error(), testNonce)
			})

			t.Run("ShouldAllowANonceAnotherClientUsed", func(t *testing.T) {
				store := storage.NewMemoryStore()

				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(flow.run(t, store, "client-a", testNonce)))
				assert.NoError(t, oauth2.ErrorToDebugRFC6749Error(flow.run(t, store, "client-b", testNonce)))
			})

			t.Run("ShouldAllowANonceWhoseRecordExpired", func(t *testing.T) {
				store := storage.NewMemoryStore()
				store.OpenIDConnectNonces[storage.ClientValueMarker{ClientID: "client-a", Value: testNonce}] = time.Now().Add(-time.Minute)

				assert.NoError(t, oauth2.ErrorToDebugRFC6749Error(flow.run(t, store, "client-a", testNonce)))
			})

			t.Run("ShouldRecordTheNonceUntilTheExpectedTime", func(t *testing.T) {
				store := storage.NewMemoryStore()

				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(flow.run(t, store, "client-a", testNonce)))

				actual, ok := store.OpenIDConnectNonces[storage.ClientValueMarker{ClientID: "client-a", Value: testNonce}]
				require.True(t, ok)

				assert.WithinDuration(t, flow.expiresAt, actual, time.Second*5)
			})
		})
	}
}

func TestExplicit_HandleAuthorizeEndpointRequestDoesNotRecordAnAbsentNonce(t *testing.T) {
	store := storage.NewMemoryStore()

	require.NoError(t, oauth2.ErrorToDebugRFC6749Error(runNonceExplicit(t, store, "client-a", "", time.Now().Add(time.Hour))))
	require.NoError(t, oauth2.ErrorToDebugRFC6749Error(runNonceExplicit(t, store, "client-a", "", time.Now().Add(time.Hour))))

	assert.Empty(t, store.OpenIDConnectNonces)
}

func TestOpenIDConnectHandlersRecordTheNonceUntilADelayedIDTokenExpires(t *testing.T) {
	testCases := []struct {
		name string
		run  func(t *testing.T, store *storage.MemoryStore, delay time.Duration) *oauth2.AuthorizeResponse
	}{
		{name: "ImplicitFlow", run: runDelayedNonceImplicit},
		{name: "HybridFlow", run: runDelayedNonceHybrid},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			store := storage.NewMemoryStore()

			response := tc.run(t, store, time.Millisecond*1100)

			marker, ok := store.OpenIDConnectNonces[storage.ClientValueMarker{ClientID: "client-a", Value: testNonce}]
			require.True(t, ok)

			claims := map[string]any{}

			_, err := jwt.UnsafeParseSignedAny(response.GetParameters().Get(consts.AccessResponseIDToken), &claims)
			require.NoError(t, err)

			exp, ok := claims[consts.ClaimExpirationTime].(float64)
			require.True(t, ok)

			assert.False(t, time.Unix(int64(exp), 0).After(marker), "the ID Token expires at %s after the nonce record at %s", time.Unix(int64(exp), 0).UTC(), marker)
		})
	}
}

type nonceFlow struct {
	name      string
	run       func(t *testing.T, store *storage.MemoryStore, clientID, nonce string) error
	expiresAt time.Time
}

func newNonceFlows() []nonceFlow {
	codeExpiresAt := time.Now().UTC().Add(time.Minute * 13).Truncate(time.Second)
	deviceExpiresAt := time.Now().UTC().Add(time.Minute * 17).Truncate(time.Second)
	idTokenExpiresAt := time.Now().UTC().Add(time.Hour * 6).Truncate(time.Second)

	return []nonceFlow{
		{
			name: "ExplicitFlow",
			run: func(t *testing.T, store *storage.MemoryStore, clientID, nonce string) error {
				return runNonceExplicit(t, store, clientID, nonce, codeExpiresAt)
			},
			expiresAt: codeExpiresAt,
		},
		{
			name: "ImplicitFlow",
			run: func(t *testing.T, store *storage.MemoryStore, clientID, nonce string) error {
				return runNonceImplicit(t, store, clientID, nonce, time.Hour*2, time.Time{})
			},
			expiresAt: time.Now().UTC().Add(time.Hour * 2),
		},
		{
			name: "ImplicitFlowWithTheDefaultIDTokenLifespan",
			run: func(t *testing.T, store *storage.MemoryStore, clientID, nonce string) error {
				return runNonceImplicit(t, store, clientID, nonce, 0, time.Time{})
			},
			expiresAt: time.Now().UTC().Add(time.Hour),
		},
		{
			name: "ImplicitFlowWithALaterIDTokenExpiry",
			run: func(t *testing.T, store *storage.MemoryStore, clientID, nonce string) error {
				return runNonceImplicit(t, store, clientID, nonce, time.Hour, idTokenExpiresAt)
			},
			expiresAt: idTokenExpiresAt,
		},
		{
			name: "HybridFlowWithTheDefaultIDTokenLifespan",
			run: func(t *testing.T, store *storage.MemoryStore, clientID, nonce string) error {
				return runNonceHybrid(t, store, clientID, nonce, time.Minute*10, 0, time.Time{})
			},
			expiresAt: time.Now().UTC().Add(time.Hour),
		},
		{
			name: "HybridFlowWithALaterIDTokenExpiry",
			run: func(t *testing.T, store *storage.MemoryStore, clientID, nonce string) error {
				return runNonceHybrid(t, store, clientID, nonce, time.Minute*10, time.Hour, idTokenExpiresAt)
			},
			expiresAt: idTokenExpiresAt,
		},
		{
			name: "HybridFlowWithALongerCodeLifespan",
			run: func(t *testing.T, store *storage.MemoryStore, clientID, nonce string) error {
				return runNonceHybrid(t, store, clientID, nonce, time.Hour*3, time.Hour, time.Time{})
			},
			expiresAt: time.Now().UTC().Add(time.Hour * 3),
		},
		{
			name: "HybridFlowWithALongerIDTokenLifespan",
			run: func(t *testing.T, store *storage.MemoryStore, clientID, nonce string) error {
				return runNonceHybrid(t, store, clientID, nonce, time.Hour, time.Hour*4, time.Time{})
			},
			expiresAt: time.Now().UTC().Add(time.Hour * 4),
		},
		{
			name: "DeviceFlow",
			run: func(t *testing.T, store *storage.MemoryStore, clientID, nonce string) error {
				return runNonceDevice(t, store, clientID, nonce, deviceExpiresAt)
			},
			expiresAt: deviceExpiresAt,
		},
	}
}

func runNonceExplicit(t *testing.T, store *storage.MemoryStore, clientID, nonce string, codeExpiresAt time.Time) error {
	handler, _ := makeOpenIDConnectExplicitHandler(gomock.NewController(t), oauth2.MinParameterEntropy)
	handler.OpenIDConnectRequestStorage = store

	session := NewDefaultSession()
	session.Claims.Subject = testSubjectPeter
	session.SetExpiresAt(oauth2.AuthorizeCode, codeExpiresAt)

	request := oauth2.NewAuthorizeRequest()
	request.Client = &oauth2.DefaultClient{ID: clientID}
	request.RequestedScope = oauth2.Arguments{consts.ScopeOpenID}
	request.GrantedScope = oauth2.Arguments{consts.ScopeOpenID}
	request.ResponseTypes = oauth2.Arguments{consts.ResponseTypeAuthorizationCodeFlow}
	request.Session = session
	request.RedirectURI, _ = url.ParseRequestURI("https://example.com")
	request.Form = url.Values{
		consts.FormParameterRedirectURI:  {"https://example.com"},
		consts.FormParameterScope:        {consts.ScopeOpenID},
		consts.FormParameterResponseType: {consts.ResponseTypeAuthorizationCodeFlow},
	}

	if nonce != "" {
		request.Form.Set(consts.FormParameterNonce, nonce)
	}

	response := oauth2.NewAuthorizeResponse()
	response.AddParameter(consts.FormParameterAuthorizationCode, "codeexample")

	return handler.HandleAuthorizeEndpointRequest(t.Context(), request, response)
}

func runNonceImplicit(t *testing.T, store *storage.MemoryStore, clientID, nonce string, idTokenLifespan time.Duration, idTokenExpiresAt time.Time) error {
	handler := makeOpenIDConnectImplicitHandler(oauth2.MinParameterEntropy)
	handler.OpenIDConnectRequestStorage = store
	handler.Config.(*oauth2.Config).IDTokenLifespan = idTokenLifespan

	request := oauth2.NewAuthorizeRequest()
	request.Client = &oauth2.DefaultClientWithCustomTokenLifespans{
		DefaultClient: &oauth2.DefaultClient{
			ID:            clientID,
			Scopes:        oauth2.Arguments{consts.ScopeOpenID},
			ResponseTypes: oauth2.Arguments{consts.ResponseTypeImplicitFlowIDToken},
			GrantTypes:    oauth2.Arguments{consts.GrantTypeImplicit},
		},
		TokenLifespans: &oauth2.ClientLifespanConfig{ImplicitGrantIDTokenLifespan: &idTokenLifespan},
	}
	request.ResponseTypes = oauth2.Arguments{consts.ResponseTypeImplicitFlowIDToken}
	request.RequestedScope = oauth2.Arguments{consts.ScopeOpenID}
	request.GrantedScope = oauth2.Arguments{consts.ScopeOpenID}
	request.Session = &DefaultSession{Claims: &jwt.IDTokenClaims{Subject: testSubjectPeter, ExpirationTime: newNonceIDTokenExpiry(idTokenExpiresAt)}, Headers: &jwt.Headers{}, Subject: testSubjectPeter}
	request.RedirectURI, _ = url.Parse("https://example.com")
	request.Form = url.Values{
		consts.FormParameterRedirectURI: {"https://example.com"},
		consts.FormParameterNonce:       {nonce},
	}

	return handler.HandleAuthorizeEndpointRequest(t.Context(), request, oauth2.NewAuthorizeResponse())
}

func runNonceHybrid(t *testing.T, store *storage.MemoryStore, clientID, nonce string, codeLifespan, idTokenLifespan time.Duration, idTokenExpiresAt time.Time) error {
	handler := makeOpenIDConnectHybridHandler(oauth2.MinParameterEntropy)
	handler.OpenIDConnectRequestStorage = store

	config := handler.Config.(*oauth2.Config)
	config.AuthorizeCodeLifespan = codeLifespan
	config.IDTokenLifespan = idTokenLifespan

	request := oauth2.NewAuthorizeRequest()
	request.Client = &oauth2.DefaultClientWithCustomTokenLifespans{
		DefaultClient: &oauth2.DefaultClient{
			ID:            clientID,
			GrantTypes:    oauth2.Arguments{consts.GrantTypeAuthorizationCode, consts.GrantTypeImplicit},
			ResponseTypes: oauth2.Arguments{consts.ResponseTypeHybridFlowIDToken},
			Scopes:        []string{consts.ScopeOpenID},
		},
		TokenLifespans: &oauth2.ClientLifespanConfig{ImplicitGrantIDTokenLifespan: &idTokenLifespan},
	}
	request.ResponseTypes = oauth2.Arguments{consts.ResponseTypeAuthorizationCodeFlow, consts.ResponseTypeImplicitFlowIDToken}
	request.GrantedScope = oauth2.Arguments{consts.ScopeOpenID}
	request.Session = &DefaultSession{Claims: &jwt.IDTokenClaims{Subject: testSubjectPeter, ExpirationTime: newNonceIDTokenExpiry(idTokenExpiresAt)}, Headers: &jwt.Headers{}, Subject: testSubjectPeter}
	request.RedirectURI, _ = url.ParseRequestURI("https://example.com")
	request.Form = url.Values{
		consts.FormParameterRedirectURI: {"https://example.com"},
		consts.FormParameterNonce:       {nonce},
	}

	return handler.HandleAuthorizeEndpointRequest(t.Context(), request, oauth2.NewAuthorizeResponse())
}

func runNonceDevice(t *testing.T, store *storage.MemoryStore, clientID, nonce string, deviceExpiresAt time.Time) error {
	config := &oauth2.Config{RFC8628CodeLifespan: time.Minute * 24}

	handler := &OpenIDConnectDeviceAuthorizeHandler{
		OpenIDConnectRequestStorage: store,
		Config:                      config,
	}

	session := NewDefaultSession()
	session.SetExpiresAt(oauth2.DeviceCode, deviceExpiresAt)

	request := oauth2.NewDeviceAuthorizeRequest()
	request.Client = &oauth2.DefaultClient{ID: clientID, GrantTypes: []string{string(oauth2.GrantTypeDeviceCode)}}
	request.GrantedScope = oauth2.Arguments{consts.ScopeOpenID}
	request.Session = session
	request.Form = url.Values{consts.FormParameterNonce: {nonce}}
	request.SetDeviceCodeSignature("device-" + clientID)

	return handler.PopulateRFC8628UserAuthorizeEndpointResponse(t.Context(), request, oauth2.NewRFC8628UserAuthorizeResponse())
}

func newNonceIDTokenExpiry(expiresAt time.Time) *jwt.NumericDate {
	if expiresAt.IsZero() {
		return nil
	}

	return jwt.NewNumericDate(expiresAt)
}

type delayedIDTokenStrategy struct {
	OpenIDConnectTokenStrategy

	delay time.Duration
}

func (s *delayedIDTokenStrategy) GenerateIDToken(ctx context.Context, lifespan time.Duration, request oauth2.Requester) (string, error) {
	time.Sleep(s.delay)

	return s.OpenIDConnectTokenStrategy.GenerateIDToken(ctx, lifespan, request)
}

func runDelayedNonceImplicit(t *testing.T, store *storage.MemoryStore, delay time.Duration) *oauth2.AuthorizeResponse {
	handler := makeOpenIDConnectImplicitHandler(oauth2.MinParameterEntropy)
	handler.OpenIDConnectRequestStorage = store
	handler.IDTokenStrategy = &delayedIDTokenStrategy{OpenIDConnectTokenStrategy: handler.IDTokenStrategy, delay: delay}

	request := oauth2.NewAuthorizeRequest()
	request.Client = &oauth2.DefaultClient{ID: "client-a", Scopes: oauth2.Arguments{consts.ScopeOpenID}, ResponseTypes: oauth2.Arguments{consts.ResponseTypeImplicitFlowIDToken}, GrantTypes: oauth2.Arguments{consts.GrantTypeImplicit}}
	request.ResponseTypes = oauth2.Arguments{consts.ResponseTypeImplicitFlowIDToken}
	request.RequestedScope = oauth2.Arguments{consts.ScopeOpenID}
	request.GrantedScope = oauth2.Arguments{consts.ScopeOpenID}
	request.Session = &DefaultSession{Claims: &jwt.IDTokenClaims{Subject: testSubjectPeter}, Headers: &jwt.Headers{}, Subject: testSubjectPeter}
	request.RedirectURI, _ = url.Parse("https://example.com")
	request.Form = url.Values{consts.FormParameterRedirectURI: {"https://example.com"}, consts.FormParameterNonce: {testNonce}}

	response := oauth2.NewAuthorizeResponse()

	require.NoError(t, oauth2.ErrorToDebugRFC6749Error(handler.HandleAuthorizeEndpointRequest(t.Context(), request, response)))

	return response
}

func runDelayedNonceHybrid(t *testing.T, store *storage.MemoryStore, delay time.Duration) *oauth2.AuthorizeResponse {
	handler := makeOpenIDConnectHybridHandler(oauth2.MinParameterEntropy)
	handler.OpenIDConnectRequestStorage = store
	handler.IDTokenHandleHelper = &IDTokenHandleHelper{IDTokenStrategy: &delayedIDTokenStrategy{OpenIDConnectTokenStrategy: handler.IDTokenHandleHelper.IDTokenStrategy, delay: delay}}

	config := handler.Config.(*oauth2.Config)
	config.AuthorizeCodeLifespan = time.Minute

	request := oauth2.NewAuthorizeRequest()
	request.Client = &oauth2.DefaultClient{ID: "client-a", GrantTypes: oauth2.Arguments{consts.GrantTypeAuthorizationCode, consts.GrantTypeImplicit}, ResponseTypes: oauth2.Arguments{consts.ResponseTypeHybridFlowIDToken}, Scopes: []string{consts.ScopeOpenID}}
	request.ResponseTypes = oauth2.Arguments{consts.ResponseTypeAuthorizationCodeFlow, consts.ResponseTypeImplicitFlowIDToken}
	request.GrantedScope = oauth2.Arguments{consts.ScopeOpenID}
	request.Session = &DefaultSession{Claims: &jwt.IDTokenClaims{Subject: testSubjectPeter}, Headers: &jwt.Headers{}, Subject: testSubjectPeter}
	request.RedirectURI, _ = url.ParseRequestURI("https://example.com")
	request.Form = url.Values{consts.FormParameterRedirectURI: {"https://example.com"}, consts.FormParameterNonce: {testNonce}}

	response := oauth2.NewAuthorizeResponse()

	require.NoError(t, oauth2.ErrorToDebugRFC6749Error(handler.HandleAuthorizeEndpointRequest(t.Context(), request, response)))

	return response
}
