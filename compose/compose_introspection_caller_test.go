// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package compose

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/storage"
)

const (
	testIntrospectedClientID  = "app"
	testIntrospectingClientID = "rs"
	testIntrospectionEndpoint = "https://as.example.com/introspect"
	testIntrospectionServed   = "https://rs-a.example.com"
	testIntrospectionElsewise = "https://rs-b.example.com"
)

func TestIntrospectionCallerAuthorization(t *testing.T) {
	testCases := []struct {
		name          string
		implements    bool
		enforce       bool
		permitted     bool
		audience      []string
		owner         string
		tokenAudience []string
		unauthorized  bool
		active        bool
	}{
		{name: "ShouldPermitAnyTokenToACallerNotImplementingTheInterface", tokenAudience: []string{testIntrospectionServed}, active: true},
		{name: "ShouldRefuseACallerNotImplementingTheInterfaceWhenEnforced", enforce: true, tokenAudience: []string{testIntrospectionServed}, unauthorized: true},
		{name: "ShouldAnswerActiveForItsOwnTokenToAClientNotPermitted", implements: true, owner: testIntrospectingClientID, tokenAudience: []string{testIntrospectionServed}, active: true},
		{name: "ShouldAnswerInactiveForAnotherClientsTokenToAClientNotPermitted", implements: true, tokenAudience: []string{testIntrospectionServed}},
		{name: "ShouldRefuseAClientNotPermittedWhenEnforced", implements: true, enforce: true, owner: testIntrospectingClientID, unauthorized: true},
		{name: "ShouldAnswerActiveForATokenWithItsClientIDAsAudience", implements: true, permitted: true, tokenAudience: []string{testIntrospectingClientID}, active: true},
		{name: "ShouldAnswerActiveForAServedAudience", implements: true, permitted: true, audience: []string{testIntrospectionServed}, tokenAudience: []string{testIntrospectionServed}, active: true},
		{name: "ShouldAnswerActiveForAServedAudienceWhenEnforced", implements: true, enforce: true, permitted: true, audience: []string{testIntrospectionServed}, tokenAudience: []string{testIntrospectionServed}, active: true},
		{name: "ShouldAnswerInactiveForAnotherAudience", implements: true, permitted: true, audience: []string{testIntrospectionElsewise}, tokenAudience: []string{testIntrospectionServed}},
		{name: "ShouldAnswerInactiveForAnEmptyServedAudience", implements: true, permitted: true, audience: []string{}, tokenAudience: []string{testIntrospectionServed}},
		{name: "ShouldAnswerInactiveForATokenWithoutAudienceToAResourceServer", implements: true, permitted: true, audience: []string{testIntrospectionServed}},
		{name: "ShouldAnswerInactiveForItsOwnTokenWithoutItsAudienceToAResourceServer", implements: true, permitted: true, owner: testIntrospectingClientID, tokenAudience: []string{testIntrospectionServed}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := &oauth2.Config{
				GlobalSecret:                   []byte("some-cool-secret-that-is-32bytes"),
				EnforceIntrospectionPermission: tc.enforce,
			}

			store := storage.NewMemoryStore()
			strategy := NewOAuth2HMACStrategy(config)

			provider := Compose(config, store, strategy, OAuth2TokenIntrospectionFactory)

			var caller oauth2.Client = &oauth2.DefaultClient{ID: testIntrospectingClientID, ClientSecret: oauth2.NewPlainTextClientSecret("rs-secret")}

			if tc.implements {
				caller = &introspectionTestClient{DefaultClient: caller.(*oauth2.DefaultClient), permitted: tc.permitted, audience: tc.audience}
			}

			store.Clients[testIntrospectingClientID] = caller

			owner := tc.owner
			if owner == "" {
				owner = testIntrospectedClientID
			}

			token := newIntrospectionTestToken(t, store, strategy, "introspected", &oauth2.DefaultClient{ID: owner}, tc.tokenAudience, nil)

			r := httptest.NewRequest(http.MethodPost, testIntrospectionEndpoint, strings.NewReader(url.Values{consts.FormParameterToken: {token}}.Encode()))
			r.Header.Set(consts.HeaderContentType, consts.ContentTypeApplicationURLEncodedForm)
			r.SetBasicAuth(testIntrospectingClientID, "rs-secret")

			responder, err := provider.NewIntrospectionRequest(context.Background(), r, &oauth2.DefaultSession{})

			switch {
			case tc.unauthorized:
				assert.ErrorIs(t, err, oauth2.ErrRequestUnauthorized)
			case tc.active:
				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
				assert.True(t, responder.IsActive())
			default:
				assert.ErrorIs(t, err, oauth2.ErrInactiveToken)
				assert.False(t, responder.IsActive())

				rw := httptest.NewRecorder()
				provider.WriteIntrospectionError(context.Background(), rw, err)

				assert.Equal(t, http.StatusOK, rw.Code)
				assert.JSONEq(t, `{"active":false}`, rw.Body.String())
			}
		})
	}
}

func TestIntrospectionCallerAuthorizationUsesTheCurrentRegistration(t *testing.T) {
	resourceServer := func(permitted bool, audience ...string) oauth2.Client {
		return &introspectionTestClient{DefaultClient: &oauth2.DefaultClient{ID: testIntrospectingClientID}, permitted: permitted, audience: audience}
	}

	testCases := []struct {
		name         string
		enforce      bool
		recorded     oauth2.Client
		registered   oauth2.Client
		unauthorized bool
		inactive     bool
	}{
		{name: "ShouldPermitACallerStillPermitted", enforce: true, recorded: resourceServer(true, testIntrospectionServed), registered: resourceServer(true, testIntrospectionServed)},
		{name: "ShouldRefuseACallerNoLongerPermitted", enforce: true, recorded: resourceServer(true, testIntrospectionServed), registered: resourceServer(false), unauthorized: true},
		{name: "ShouldRefuseACallerNoLongerRegistered", enforce: true, recorded: resourceServer(true, testIntrospectionServed), unauthorized: true},
		{name: "ShouldPermitACallerNotImplementingTheInterface", recorded: &oauth2.DefaultClient{ID: testIntrospectingClientID}, registered: &oauth2.DefaultClient{ID: testIntrospectingClientID}},
		{name: "ShouldAnswerInactiveForAnAudienceRestrictedSince", recorded: &oauth2.DefaultClient{ID: testIntrospectingClientID}, registered: resourceServer(true, testIntrospectionElsewise), inactive: true},
		{name: "ShouldAnswerInactiveForACallerRestrictedToItsOwnTokensSince", recorded: &oauth2.DefaultClient{ID: testIntrospectingClientID}, registered: resourceServer(false), inactive: true},
		{name: "ShouldRefuseACallerNoLongerRegisteredWithoutEnforcement", recorded: &oauth2.DefaultClient{ID: testIntrospectingClientID}, unauthorized: true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := &oauth2.Config{
				GlobalSecret:                   []byte("some-cool-secret-that-is-32bytes"),
				EnforceIntrospectionPermission: tc.enforce,
			}

			store := storage.NewMemoryStore()
			strategy := NewOAuth2HMACStrategy(config)

			provider := Compose(config, store, strategy, OAuth2TokenIntrospectionFactory)

			if tc.registered != nil {
				store.Clients[testIntrospectingClientID] = tc.registered
			}

			credential := newIntrospectionTestToken(t, store, strategy, "caller", tc.recorded, []string{testIntrospectionEndpoint}, []string{consts.ScopeIntrospection})
			token := newIntrospectionTestToken(t, store, strategy, "introspected", &oauth2.DefaultClient{ID: testIntrospectedClientID}, []string{testIntrospectionServed}, nil)

			r := httptest.NewRequest(http.MethodPost, testIntrospectionEndpoint, strings.NewReader(url.Values{consts.FormParameterToken: {token}}.Encode()))
			r.Header.Set(consts.HeaderContentType, consts.ContentTypeApplicationURLEncodedForm)
			r.Header.Set(consts.HeaderAuthorization, "Bearer "+credential)

			responder, err := provider.NewIntrospectionRequest(context.Background(), r, &oauth2.DefaultSession{})

			switch {
			case tc.unauthorized:
				assert.ErrorIs(t, err, oauth2.ErrRequestUnauthorized)
			case tc.inactive:
				assert.ErrorIs(t, err, oauth2.ErrInactiveToken)
				assert.False(t, responder.IsActive())
			default:
				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
				assert.True(t, responder.IsActive())
			}
		})
	}
}

func TestIntrospectionCallerAuthorizationWithoutAClient(t *testing.T) {
	for _, enforce := range []bool{false, true} {
		config := &oauth2.Config{
			GlobalSecret:                   []byte("some-cool-secret-that-is-32bytes"),
			EnforceIntrospectionPermission: enforce,
		}

		store := storage.NewMemoryStore()
		strategy := NewOAuth2HMACStrategy(config)

		provider := Compose(config, store, strategy, OAuth2TokenIntrospectionFactory)

		// A credential issued without client authentication records a client without an ID.
		credential := newIntrospectionTestToken(t, store, strategy, "caller", &oauth2.DefaultClient{}, []string{testIntrospectionEndpoint}, []string{consts.ScopeIntrospection})
		token := newIntrospectionTestToken(t, store, strategy, "introspected", &oauth2.DefaultClient{ID: testIntrospectedClientID}, nil, nil)

		r := httptest.NewRequest(http.MethodPost, testIntrospectionEndpoint, strings.NewReader(url.Values{consts.FormParameterToken: {token}}.Encode()))
		r.Header.Set(consts.HeaderContentType, consts.ContentTypeApplicationURLEncodedForm)
		r.Header.Set(consts.HeaderAuthorization, "Bearer "+credential)

		responder, err := provider.NewIntrospectionRequest(context.Background(), r, &oauth2.DefaultSession{})

		if enforce {
			assert.ErrorIs(t, err, oauth2.ErrRequestUnauthorized)
		} else {
			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
			assert.True(t, responder.IsActive())
		}
	}
}

func newIntrospectionTestToken(t *testing.T, store *storage.MemoryStore, strategy *hoauth2.HMACCoreStrategy, id string, client oauth2.Client, audience, scope []string) string {
	t.Helper()

	token, signature, err := strategy.GenerateAccessToken(t.Context(), nil)
	require.NoError(t, err)

	require.NoError(t, store.CreateAccessTokenSession(t.Context(), signature, &oauth2.Request{
		ID:              id,
		Client:          client,
		RequestedAt:     time.Now().UTC(),
		GrantedAudience: audience,
		GrantedScope:    scope,
		Session:         &oauth2.DefaultSession{Subject: id, ExpiresAt: map[oauth2.TokenType]time.Time{oauth2.AccessToken: time.Now().UTC().Add(time.Hour)}},
		Form:            url.Values{},
	}))

	return token
}

type introspectionTestClient struct {
	*oauth2.DefaultClient

	permitted bool
	audience  []string
}

func (c *introspectionTestClient) GetIntrospectionPermitted() bool { return c.permitted }

func (c *introspectionTestClient) GetIntrospectionAudience() []string { return c.audience }

var _ oauth2.IntrospectionClient = (*introspectionTestClient)(nil)
