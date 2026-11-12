// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package integration_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/compose"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/handler/rfc8693"
	"authelia.com/provider/oauth2/internal"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/storage"
)

func TestTokenExchangeWithAuthorizationDetails(t *testing.T) {
	testCases := []struct {
		name               string
		subject            string
		granted            string
		types              []string
		requestedTokenType string
		details            string
		expected           string
		err                string
	}{
		{
			name:     "ShouldCarryTheDetailsOfAnAccessToken",
			subject:  consts.TokenTypeRFC8693AccessToken,
			granted:  exchangeRARGranted,
			expected: exchangeRARGranted,
		},
		{
			name:     "ShouldCarryTheDetailsOfARefreshToken",
			subject:  consts.TokenTypeRFC8693RefreshToken,
			granted:  exchangeRARGranted,
			expected: exchangeRARGranted,
		},
		{
			name:     "ShouldNarrowToTheRequestedDetails",
			subject:  consts.TokenTypeRFC8693AccessToken,
			granted:  exchangeRARGranted,
			details:  exchangeRARRequestStatus,
			expected: exchangeRARStatus,
		},
		{
			name:     "ShouldSelectTheGrantedDetailsOfARequestedType",
			subject:  consts.TokenTypeRFC8693AccessToken,
			granted:  exchangeRARMixed,
			details:  exchangeRARRequestPayments,
			expected: exchangeRARGranted,
		},
		{
			name:     "ShouldDropTypesTheClientMayNotRequest",
			subject:  consts.TokenTypeRFC8693AccessToken,
			granted:  exchangeRARMixed,
			types:    []string{internal.AuthorizationDetailsTypePaymentInitiation},
			expected: exchangeRARGranted,
		},
		{
			name:    "ShouldIssueNoDetailsWhenTheClientMayRequestNone",
			subject: consts.TokenTypeRFC8693AccessToken,
			granted: exchangeRARGranted,
			types:   []string{},
		},
		{
			name:    "ShouldIssueNoDetailsWhenNoneWereGranted",
			subject: consts.TokenTypeRFC8693AccessToken,
		},
		{
			name:    "ShouldRejectDetailsNotGranted",
			subject: consts.TokenTypeRFC8693AccessToken,
			granted: exchangeRARGranted,
			details: exchangeRARRequestCancel,
			err:     exchangeRARErrorInvalid,
		},
		{
			name:    "ShouldRejectDetailsWhenNoneWereGranted",
			subject: consts.TokenTypeRFC8693AccessToken,
			details: exchangeRARRequestStatus,
			err:     exchangeRARErrorInvalid,
		},
		{
			name:    "ShouldRejectATypeNotGranted",
			subject: consts.TokenTypeRFC8693AccessToken,
			granted: exchangeRARGranted,
			details: exchangeRARRequestAccounts,
			err:     exchangeRARErrorInvalid,
		},
		{
			name:    "ShouldRejectATypeTheClientMayNotRequest",
			subject: consts.TokenTypeRFC8693AccessToken,
			granted: exchangeRARMixed,
			types:   []string{internal.AuthorizationDetailsTypePaymentInitiation},
			details: exchangeRARRequestAccounts,
			err:     exchangeRARErrorInvalid,
		},
		{
			name:               "ShouldRejectDetailsForARefreshTokenRequest",
			subject:            consts.TokenTypeRFC8693RefreshToken,
			granted:            exchangeRARGranted,
			requestedTokenType: consts.TokenTypeRFC8693RefreshToken,
			details:            exchangeRARRequestStatus,
			err:                exchangeRARErrorInvalid,
		},
	}

	for _, sc := range exchangeRARStores() {
		t.Run(sc.name, func(t *testing.T) {
			for _, tc := range testCases {
				t.Run(tc.name, func(t *testing.T) {
					env := newExchangeRAREnvironment(t, sc.new, hmacStrategy, tc.types)

					form := url.Values{
						consts.FormParameterGrantType:        {consts.GrantTypeOAuthTokenExchange},
						consts.FormParameterSubjectToken:     {env.subjectToken(t, tc.subject, parseExchangeRARDetails(t, tc.granted))},
						consts.FormParameterSubjectTokenType: {tc.subject},
						consts.FormParameterScope:            {exchangeRARScopes(tc.subject)},
					}

					if tc.requestedTokenType != "" {
						form.Set(consts.FormParameterRequestedTokenType, tc.requestedTokenType)
					}

					if tc.details != "" {
						form.Set(consts.FormParameterAuthorizationDetails, tc.details)
					}

					token := postTokenEndpoint(t, env.ts, form)

					if tc.err != "" {
						assert.JSONEq(t, `"`+tc.err+`"`, string(token["error"]))

						return
					}

					require.NotContains(t, token, "error", "token response: %v", token)

					var access string

					require.NoError(t, json.Unmarshal(token["access_token"], &access))

					if tc.expected == "" {
						assert.NotContains(t, token, "authorization_details")
						assert.Empty(t, introspectAuthorizationDetails(t, env.ts, access))

						return
					}

					assert.JSONEq(t, tc.expected, string(token["authorization_details"]))
					assert.JSONEq(t, tc.expected, introspectAuthorizationDetails(t, env.ts, access))
				})
			}
		})
	}
}

func TestTokenExchangeRefreshTokenKeepsTheGrantedAuthorizationDetails(t *testing.T) {
	testCases := []struct {
		name               string
		requestedTokenType string
		details            string
		expected           string
	}{
		{name: "ShouldRefreshTheGrantedDetailsAfterNarrowing", details: exchangeRARRequestStatus, expected: exchangeRARStatus},
		{name: "ShouldRefreshTheGrantedDetails", expected: exchangeRARGranted},
		{name: "ShouldRefreshTheGrantedDetailsOfAnIssuedRefreshToken", requestedTokenType: consts.TokenTypeRFC8693RefreshToken},
	}

	for _, sc := range exchangeRARStores() {
		t.Run(sc.name, func(t *testing.T) {
			for _, tc := range testCases {
				t.Run(tc.name, func(t *testing.T) {
					env := newExchangeRAREnvironment(t, sc.new, hmacStrategy, []string{internal.AuthorizationDetailsTypePaymentInitiation})

					form := url.Values{
						consts.FormParameterGrantType:        {consts.GrantTypeOAuthTokenExchange},
						consts.FormParameterSubjectToken:     {env.subjectToken(t, consts.TokenTypeRFC8693RefreshToken, parseExchangeRARDetails(t, exchangeRARMixed))},
						consts.FormParameterSubjectTokenType: {consts.TokenTypeRFC8693RefreshToken},
						consts.FormParameterScope:            {exchangeRARScopes(consts.TokenTypeRFC8693RefreshToken)},
					}

					if tc.requestedTokenType != "" {
						form.Set(consts.FormParameterRequestedTokenType, tc.requestedTokenType)
					}

					if tc.details != "" {
						form.Set(consts.FormParameterAuthorizationDetails, tc.details)
					}

					token := postTokenEndpoint(t, env.ts, form)
					require.NotContains(t, token, "error", "token response: %v", token)

					var refresh string

					if tc.requestedTokenType == consts.TokenTypeRFC8693RefreshToken {
						assert.NotContains(t, token, "authorization_details")
						require.NoError(t, json.Unmarshal(token["access_token"], &refresh))
					} else {
						assert.JSONEq(t, tc.expected, string(token["authorization_details"]))
						require.NoError(t, json.Unmarshal(token["refresh_token"], &refresh))
					}

					refreshed := refreshWithAuthorizationDetails(t, env.ts, refresh, "")
					require.NotContains(t, refreshed, "error", "token response: %v", refreshed)
					assert.JSONEq(t, exchangeRARGranted, string(refreshed["authorization_details"]))
				})
			}
		})
	}
}

func TestTokenExchangeJWTAccessTokenCarriesAuthorizationDetails(t *testing.T) {
	for _, sc := range exchangeRARStores() {
		t.Run(sc.name, func(t *testing.T) {
			strategy := &hoauth2.JWTProfileCoreStrategy{
				Strategy:         jwtStrategy.Strategy,
				Config:           &oauth2.Config{Issuer: exchangeRARIssuer},
				HMACCoreStrategy: hmacStrategy,
			}

			env := newExchangeRAREnvironment(t, sc.new, strategy, nil)
			env.client.EnableJWTProfileOAuthAccessTokens = true
			env.client.Audience = []string{exchangeRARAudience}

			token := postTokenEndpoint(t, env.ts, url.Values{
				consts.FormParameterGrantType:            {consts.GrantTypeOAuthTokenExchange},
				consts.FormParameterSubjectToken:         {env.subjectToken(t, consts.TokenTypeRFC8693AccessToken, parseExchangeRARDetails(t, exchangeRARGranted))},
				consts.FormParameterSubjectTokenType:     {consts.TokenTypeRFC8693AccessToken},
				consts.FormParameterScope:                {exchangeRARScopes(consts.TokenTypeRFC8693AccessToken)},
				consts.FormParameterAudience:             {exchangeRARAudience},
				consts.FormParameterAuthorizationDetails: {exchangeRARRequestStatus},
			})
			require.NotContains(t, token, "error", "token response: %v", token)

			var access string

			require.NoError(t, json.Unmarshal(token["access_token"], &access))

			parts := strings.Split(access, ".")
			require.Len(t, parts, 3)

			payload, err := base64.RawURLEncoding.DecodeString(parts[1])
			require.NoError(t, err)

			claims := map[string]json.RawMessage{}
			require.NoError(t, json.Unmarshal(payload, &claims))

			assert.JSONEq(t, exchangeRARStatus, string(claims[consts.ClaimAuthorizationDetails]))
			assert.JSONEq(t, exchangeRARStatus, string(token["authorization_details"]))
		})
	}
}

const (
	exchangeRARGranted               = `[{"type":"payment_initiation","actions":["initiate","status"],"instructedAmount":{"currency":"EUR","amount":"123.50"}}]`
	exchangeRARStatus                = `[{"type":"payment_initiation","actions":["status"],"instructedAmount":{"currency":"EUR","amount":"123.50"}}]`
	exchangeRARMixed                 = `[{"type":"payment_initiation","actions":["initiate","status"],"instructedAmount":{"currency":"EUR","amount":"123.50"}},{"type":"account_information","actions":["list_accounts"]}]`
	exchangeRARRequestStatus         = `[{"type":"payment_initiation","actions":["status"]}]`
	exchangeRARRequestCancel         = `[{"type":"payment_initiation","actions":["cancel"]}]`
	exchangeRARRequestPayments       = `[{"type":"payment_initiation"}]`
	exchangeRARRequestAccounts       = `[{"type":"account_information"}]`
	exchangeRARErrorInvalid          = "invalid_authorization_details"
	exchangeRARStoreMemory           = "MemoryStore"
	exchangeRARStoreHydrating        = "HydratingMemoryStore"
	exchangeRAROwnerClientID         = "rar-exchange-owner"
	exchangeRARAudience              = "https://resource.example.com"
	exchangeRARIssuer                = "https://issuer.example.com"
	authorizationDetailsTypeAccounts = "account_information"
)

type exchangeRARStore struct {
	name string
	new  func() (hoauth2.CoreStorage, *storage.MemoryStore)
}

func exchangeRARStores() []exchangeRARStore {
	return []exchangeRARStore{
		{name: exchangeRARStoreMemory, new: func() (hoauth2.CoreStorage, *storage.MemoryStore) {
			store := storage.NewMemoryStore()

			return store, store
		}},
		{name: exchangeRARStoreHydrating, new: func() (hoauth2.CoreStorage, *storage.MemoryStore) {
			store := storage.NewHydratingMemoryStore()

			return store, store.MemoryStore
		}},
	}
}

type exchangeRAREnvironment struct {
	ts       *httptest.Server
	store    hoauth2.CoreStorage
	strategy hoauth2.CoreStrategy
	owner    *oauth2.DefaultRegisteredClient
	client   *oauth2.DefaultRegisteredClient
}

func newExchangeRAREnvironment(t *testing.T, newStore func() (hoauth2.CoreStorage, *storage.MemoryStore), strategy hoauth2.CoreStrategy, types []string) *exchangeRAREnvironment {
	t.Helper()

	store, memory := newStore()

	config := &oauth2.Config{
		AuthorizationDetailsTypeHandlers: []oauth2.AuthorizationDetailsTypeHandler{internal.PaymentInitiationTypeHandler{}, accountInformationTypeHandler{}},
		DefaultRequestedTokenType:        consts.TokenTypeRFC8693AccessToken,
		RFC8693TokenTypes: map[string]oauth2.RFC8693TokenType{
			consts.TokenTypeRFC8693AccessToken:  &rfc8693.DefaultTokenType{Name: consts.TokenTypeRFC8693AccessToken},
			consts.TokenTypeRFC8693RefreshToken: &rfc8693.DefaultTokenType{Name: consts.TokenTypeRFC8693RefreshToken},
		},
	}

	provider := compose.Compose(config, store, strategy,
		compose.RFC8693TokenExchangeGrantFactory,
		compose.RFC8693AccessTokenTypeFactory,
		compose.RFC8693RefreshTokenTypeFactory,
		compose.RFC8693ActorTokenValidationFactory,
		compose.OAuth2RefreshTokenGrantFactory,
		compose.OAuth2TokenIntrospectionFactory,
	)

	newSession := func() oauth2.Session { return rfc8693.NewDefaultSession() }

	mux := http.NewServeMux()
	mux.HandleFunc(tokenRelativePath, idjagTokenHandler(provider, newSession))
	mux.HandleFunc("/introspect", tokenIntrospectionHandler(t, provider, newSession()))

	env := &exchangeRAREnvironment{
		ts:       httptest.NewServer(mux),
		store:    store,
		strategy: strategy,
		owner: &oauth2.DefaultRegisteredClient{
			DefaultClient: &oauth2.DefaultClient{
				ID:         exchangeRAROwnerClientID,
				GrantTypes: []string{consts.GrantTypeAuthorizationCode},
				Scopes:     []string{testScopeOAuth2},
			},
		},
		client: &oauth2.DefaultRegisteredClient{
			DefaultClient: &oauth2.DefaultClient{
				ID:           testClientIDRAR,
				ClientSecret: oauth2.NewBCryptClientSecret(`$2a$04$6i/O2OM9CcEVTRLq9uFDtOze4AtISH79iYkZeEUsos4WzWtCnJ52y`),
				GrantTypes:   []string{consts.GrantTypeOAuthTokenExchange, consts.GrantTypeRefreshToken},
				Scopes:       []string{testScopeOAuth2, consts.ScopeOfflineAccess},
			},
			AuthorizationDetailsTypes: types,
			TokenExchangeRefreshToken: true,
		},
	}

	t.Cleanup(env.ts.Close)

	memory.Clients[env.owner.GetID()] = env.owner
	memory.Clients[env.client.GetID()] = env.client

	return env
}

func (env *exchangeRAREnvironment) subjectToken(t *testing.T, tokenType string, details oauth2.AuthorizationDetails) (token string) {
	t.Helper()

	ctx := context.Background()

	session := rfc8693.NewDefaultSession()
	session.SetSubject(testSubject)
	session.SetExpiresAt(oauth2.AccessToken, time.Now().UTC().Add(10*time.Minute))
	session.SetExpiresAt(oauth2.RefreshToken, time.Now().UTC().Add(10*time.Minute))

	request := &oauth2.AccessRequest{
		GrantTypes: oauth2.Arguments{consts.GrantTypeAuthorizationCode},
		Request: oauth2.Request{
			ID:          uuid.New().String(),
			RequestedAt: time.Now().UTC(),
			Session:     session,
		},
	}

	request.SetGrantedAuthorizationDetails(details)

	var (
		signature string
		err       error
	)

	switch tokenType {
	case consts.TokenTypeRFC8693RefreshToken:
		request.Client = env.client
		request.GrantedScope = oauth2.Arguments{testScopeOAuth2, consts.ScopeOfflineAccess}

		token, signature, err = env.strategy.GenerateRefreshToken(ctx, request)
		require.NoError(t, err)
		require.NoError(t, env.store.CreateRefreshTokenSession(ctx, signature, "", request.Sanitize(nil)))
	default:
		request.Client = env.owner
		request.GrantedScope = oauth2.Arguments{testScopeOAuth2}
		request.GrantedAudience = oauth2.Arguments{testClientIDRAR}

		token, signature, err = env.strategy.GenerateAccessToken(ctx, request)
		require.NoError(t, err)
		require.NoError(t, env.store.CreateAccessTokenSession(ctx, signature, request.Sanitize(nil)))
	}

	return token
}

func exchangeRARScopes(subjectTokenType string) string {
	if subjectTokenType == consts.TokenTypeRFC8693RefreshToken {
		return testScopeOAuth2 + " " + consts.ScopeOfflineAccess
	}

	return testScopeOAuth2
}

func parseExchangeRARDetails(t *testing.T, raw string) oauth2.AuthorizationDetails {
	t.Helper()

	details, err := oauth2.ParseAuthorizationDetails(raw)
	require.NoError(t, err)

	return details
}

type accountInformationTypeHandler struct{}

func (accountInformationTypeHandler) Type() string {
	return authorizationDetailsTypeAccounts
}

func (accountInformationTypeHandler) Validate(_ context.Context, _ oauth2.Requester, _ oauth2.AuthorizationDetail) error {
	return nil
}

func (accountInformationTypeHandler) Assign(_ context.Context, _ oauth2.AccessRequester, granted, _ oauth2.AuthorizationDetails) (oauth2.AuthorizationDetails, error) {
	return granted, nil
}
