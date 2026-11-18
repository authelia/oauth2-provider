// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/jose"
	josejwt "authelia.com/provider/jose/jwt"

	. "authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/compose"
	"authelia.com/provider/oauth2/handler/rfc9449"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestGrantManagementQuery(t *testing.T) {
	for _, sc := range grantManagementAPIStores {
		t.Run(sc.name, func(t *testing.T) {
			h := newGrantManagementAPIHarness(t, sc.new)

			id, _ := h.grant()

			grant, err := h.memory.GetGrant(h.ctx, id)
			require.NoError(t, err)

			grant.Permissions.Scopes = []GrantScope{{Scope: "read", Resource: []string{"https://rs.example.com/api"}}, {Scope: "offline_access"}}
			grant.Permissions.Claims = []string{"email", "email_verified"}
			grant.Permissions.Audience = []string{"https://rs.example.com/api"}
			grant.Permissions.AuthorizationDetails = AuthorizationDetails{{Type: "account", Actions: []string{"read"}}}
			grant.CreatedAt = time.Unix(1700000000, 0).UTC()
			grant.UpdatedAt = time.Unix(1700000100, 0).UTC()
			grant.ExpiresAt = time.Now().UTC().Add(time.Hour).Truncate(time.Second)

			require.NoError(t, h.memory.UpdateGrant(h.ctx, grant))

			rw := h.call(http.MethodGet, id, h.token(grantManagementAPIClientA, grantManagementAPIIssuer, consts.ScopeGrantManagementQuery))

			require.Equal(t, http.StatusOK, rw.Code)
			assert.Equal(t, "no-cache, no-store", rw.Header().Get(consts.HeaderCacheControl))
			assert.Equal(t, "application/json", rw.Header().Get(consts.HeaderContentType))

			var raw map[string]any

			require.NoError(t, json.Unmarshal(rw.Body.Bytes(), &raw))

			assert.NotContains(t, raw, "audience")
			assert.ElementsMatch(t, []string{"scopes", "claims", "authorization_details", "created_at", "last_updated_at", "expires_at", "updated_by"}, grantManagementAPIKeys(raw))

			var body GrantManagementResponseBody

			require.NoError(t, json.Unmarshal(rw.Body.Bytes(), &body))

			assert.Equal(t, grant.Permissions.Scopes, body.Scopes)
			assert.Equal(t, []string{"email", "email_verified"}, body.Claims)
			assert.Equal(t, grant.Permissions.AuthorizationDetails, body.AuthorizationDetails)
			assert.Equal(t, int64(1700000000), body.CreatedAt)
			assert.Equal(t, int64(1700000100), body.LastUpdatedAt)
			assert.Equal(t, grant.ExpiresAt.Unix(), body.ExpiresAt)
			assert.Equal(t, GrantUpdatedByClient, body.UpdatedBy)
		})
	}
}

func TestGrantManagementQueryOmitsEmptyMembers(t *testing.T) {
	h := newGrantManagementAPIHarness(t, grantManagementAPIStores[0].new)

	require.NoError(t, h.memory.CreateGrant(h.ctx, &Grant{ID: "bare", ClientID: grantManagementAPIClientA, Subject: "peter"}))

	rw := h.call(http.MethodGet, "bare", h.token(grantManagementAPIClientA, grantManagementAPIIssuer, consts.ScopeGrantManagementQuery))

	require.Equal(t, http.StatusOK, rw.Code)
	assert.JSONEq(t, `{}`, rw.Body.String())
}

func TestGrantManagementOtherClient(t *testing.T) {
	for _, sc := range grantManagementAPIStores {
		for _, method := range []string{http.MethodGet, http.MethodDelete} {
			t.Run(sc.name+"/"+method, func(t *testing.T) {
				h := newGrantManagementAPIHarness(t, sc.new)

				id, issued := h.grant()

				token := h.token(grantManagementAPIClientB, grantManagementAPIIssuer, consts.ScopeGrantManagementQuery, consts.ScopeGrantManagementRevoke)

				unknown := h.call(method, "unknown", token)

				rw := h.call(method, id, token)

				assert.Equal(t, http.StatusNotFound, rw.Code)
				assert.Empty(t, rw.Body.String())

				assert.Equal(t, unknown.Code, rw.Code)
				assert.Equal(t, unknown.Header(), rw.Header())
				assert.Equal(t, unknown.Body.String(), rw.Body.String())

				_, err := h.memory.GetGrant(h.ctx, id)
				require.NoError(t, err)

				assert.True(t, h.active(issued.GetAccessToken()))

				_, err = h.refresh(grantManagementAPIRefreshToken(t, issued))
				require.NoError(t, ErrorToDebugRFC6749Error(err))
			})
		}
	}
}

func TestGrantManagementDPoPBoundToken(t *testing.T) {
	h := newGrantManagementAPIHarness(t, grantManagementAPIStores[0].new)

	id, _ := h.grant()

	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	key := &jose.JSONWebKey{Key: private, Algorithm: string(jose.ES256)}

	jkt, err := jwt.ThumbprintJWK(key)
	require.NoError(t, err)

	issued, err := h.exchangeWithSession(grantManagementAPIClientA, url.Values{
		consts.FormParameterGrantType: []string{consts.GrantTypeClientCredentials},
		consts.FormParameterScope:     []string{consts.ScopeGrantManagementQuery},
		consts.FormParameterAudience:  []string{grantManagementAPIIssuer},
	}, &DefaultSession{JWKThumbprint: jkt})
	require.NoError(t, ErrorToDebugRFC6749Error(err))

	token := issued.GetAccessToken()

	h.config.DPoPEnabled = true
	h.config.DPoPAllowedJWSAlgorithms = []string{"ES256"}
	h.config.DPoPStrategy = rfc9449.NewDefaultStrategy(h.config, h.memory)

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, (&jose.SignerOptions{EmbedJWK: true}).WithType("dpop+jwt"))
	require.NoError(t, err)

	sum := sha256.Sum256([]byte(token))

	proof, err := josejwt.Signed(signer).Claims(map[string]any{
		jwt.ClaimJWTID:      "proof-one",
		jwt.ClaimHTTPMethod: http.MethodGet,
		jwt.ClaimHTTPURI:    "https://as.example.com/grants/" + id,
		jwt.ClaimIssuedAt:   time.Now().Unix(),
		"ath":               base64.RawURLEncoding.EncodeToString(sum[:]),
	}).Serialize()
	require.NoError(t, err)

	rw := h.request(http.MethodGet, id, "DPoP "+token, "")

	assert.Equal(t, http.StatusUnauthorized, rw.Code)
	assert.Contains(t, rw.Header().Get(consts.HeaderWWWAuthenticate), "DPoP ")

	rw = h.request(http.MethodGet, id, "Bearer "+token, "")

	assert.Equal(t, http.StatusUnauthorized, rw.Code)

	rw = h.request(http.MethodGet, id, "DPoP "+token, proof)

	assert.Equal(t, http.StatusOK, rw.Code)
}

func TestGrantManagementRequestRejected(t *testing.T) {
	testCases := []struct {
		name      string
		method    string
		setup     func(h *grantManagementAPIHarness, id string) (grantID, token string)
		code      int
		err       string
		challenge string
		exact     string
		allow     string
	}{
		{
			name:   "ShouldAnswerNotFoundForAnUnknownGrant",
			method: http.MethodGet,
			setup: func(h *grantManagementAPIHarness, _ string) (string, string) {
				return "unknown", h.token(grantManagementAPIClientA, grantManagementAPIIssuer, consts.ScopeGrantManagementQuery)
			},
			code: http.StatusNotFound,
		},
		{
			name:   "ShouldAnswerNotFoundForAnUnknownGrantOnDelete",
			method: http.MethodDelete,
			setup: func(h *grantManagementAPIHarness, _ string) (string, string) {
				return "unknown", h.token(grantManagementAPIClientA, grantManagementAPIIssuer, consts.ScopeGrantManagementRevoke)
			},
			code: http.StatusNotFound,
		},
		{
			name:   "ShouldAnswerNotFoundForAnEmptyGrantID",
			method: http.MethodGet,
			setup: func(h *grantManagementAPIHarness, _ string) (string, string) {
				return "", h.token(grantManagementAPIClientA, grantManagementAPIIssuer, consts.ScopeGrantManagementQuery)
			},
			code: http.StatusNotFound,
		},
		{
			name:   "ShouldAnswerNotFoundForAnExpiredGrant",
			method: http.MethodGet,
			setup: func(h *grantManagementAPIHarness, id string) (string, string) {
				h.expire(id)

				return id, h.token(grantManagementAPIClientA, grantManagementAPIIssuer, consts.ScopeGrantManagementQuery)
			},
			code: http.StatusNotFound,
		},
		{
			name:   "ShouldAnswerNotFoundForAnExpiredGrantOfAnotherClientOnDelete",
			method: http.MethodDelete,
			setup: func(h *grantManagementAPIHarness, id string) (string, string) {
				h.expire(id)

				return id, h.token(grantManagementAPIClientB, grantManagementAPIIssuer, consts.ScopeGrantManagementRevoke)
			},
			code: http.StatusNotFound,
		},
		{
			name:   "ShouldRejectARequestWithoutAToken",
			method: http.MethodGet,
			setup: func(_ *grantManagementAPIHarness, id string) (string, string) {
				return id, ""
			},
			code:  http.StatusUnauthorized,
			err:   "invalid_token",
			exact: "Bearer",
		},
		{
			name:   "ShouldRejectAnUnknownToken",
			method: http.MethodGet,
			setup: func(_ *grantManagementAPIHarness, id string) (string, string) {
				return id, "not-a-token"
			},
			code:      http.StatusUnauthorized,
			err:       "invalid_token",
			challenge: `error="invalid_token"`,
		},
		{
			name:   "ShouldRejectARefreshToken",
			method: http.MethodGet,
			setup: func(h *grantManagementAPIHarness, id string) (string, string) {
				_, issued := h.grant()

				return id, grantManagementAPIRefreshToken(h.t, issued)
			},
			code:      http.StatusUnauthorized,
			err:       "invalid_token",
			challenge: `error="invalid_token"`,
		},
		{
			name:   "ShouldRejectATokenWithoutTheQueryScope",
			method: http.MethodGet,
			setup: func(h *grantManagementAPIHarness, id string) (string, string) {
				return id, h.token(grantManagementAPIClientA, grantManagementAPIIssuer, consts.ScopeGrantManagementRevoke)
			},
			code:      http.StatusForbidden,
			err:       "insufficient_scope",
			challenge: `scope="grant_management_query"`,
		},
		{
			name:   "ShouldRejectATokenWithoutTheRevokeScope",
			method: http.MethodDelete,
			setup: func(h *grantManagementAPIHarness, id string) (string, string) {
				return id, h.token(grantManagementAPIClientA, grantManagementAPIIssuer, consts.ScopeGrantManagementQuery)
			},
			code:      http.StatusForbidden,
			err:       "insufficient_scope",
			challenge: `scope="grant_management_revoke"`,
		},
		{
			name:   "ShouldRejectATokenForAnotherAudience",
			method: http.MethodGet,
			setup: func(h *grantManagementAPIHarness, id string) (string, string) {
				return id, h.token(grantManagementAPIClientA, "https://rs.example.com", consts.ScopeGrantManagementQuery)
			},
			code:      http.StatusUnauthorized,
			err:       "invalid_token",
			challenge: `error="invalid_token"`,
		},
		{
			name:   "ShouldRejectATokenForTheIssuerWhenAnAudienceIsConfigured",
			method: http.MethodGet,
			setup: func(h *grantManagementAPIHarness, id string) (string, string) {
				token := h.token(grantManagementAPIClientA, grantManagementAPIIssuer, consts.ScopeGrantManagementQuery)

				h.config.GrantManagement.Audience = "https://as.example.com/grants"

				return id, token
			},
			code:      http.StatusUnauthorized,
			err:       "invalid_token",
			challenge: `error="invalid_token"`,
		},
		{
			name:   "ShouldRejectAnUnsupportedMethod",
			method: http.MethodPut,
			setup: func(h *grantManagementAPIHarness, id string) (string, string) {
				return id, h.token(grantManagementAPIClientA, grantManagementAPIIssuer, consts.ScopeGrantManagementQuery, consts.ScopeGrantManagementRevoke)
			},
			code:  http.StatusMethodNotAllowed,
			err:   "invalid_request",
			allow: "GET, DELETE",
		},
		{
			name:   "ShouldRejectQueryWhenItIsNotSupported",
			method: http.MethodGet,
			setup: func(h *grantManagementAPIHarness, id string) (string, string) {
				token := h.token(grantManagementAPIClientA, grantManagementAPIIssuer, consts.ScopeGrantManagementQuery)

				h.config.GrantManagement.Actions = []GrantManagementAction{GrantManagementActionCreate, GrantManagementActionRevoke}

				return id, token
			},
			code:  http.StatusMethodNotAllowed,
			err:   "invalid_request",
			allow: "DELETE",
		},
		{
			name:   "ShouldRejectRevokeWhenItIsNotSupported",
			method: http.MethodDelete,
			setup: func(h *grantManagementAPIHarness, id string) (string, string) {
				token := h.token(grantManagementAPIClientA, grantManagementAPIIssuer, consts.ScopeGrantManagementRevoke)

				h.config.GrantManagement.Actions = []GrantManagementAction{GrantManagementActionCreate, GrantManagementActionQuery}

				return id, token
			},
			code:  http.StatusMethodNotAllowed,
			err:   "invalid_request",
			allow: "GET",
		},
		{
			name:   "ShouldFailWhenGrantManagementIsNotConfigured",
			method: http.MethodGet,
			setup: func(h *grantManagementAPIHarness, id string) (string, string) {
				token := h.token(grantManagementAPIClientA, grantManagementAPIIssuer, consts.ScopeGrantManagementQuery)

				h.config.GrantManagement = nil

				return id, token
			},
			code: http.StatusInternalServerError,
			err:  "server_error",
		},
		{
			name:   "ShouldFailWhenTheHandlerIsNotRegistered",
			method: http.MethodGet,
			setup: func(h *grantManagementAPIHarness, id string) (string, string) {
				token := h.token(grantManagementAPIClientA, grantManagementAPIIssuer, consts.ScopeGrantManagementQuery)

				h.config.AuthorizeEndpointBindingHandlers = nil

				return id, token
			},
			code: http.StatusInternalServerError,
			err:  "server_error",
		},
		{
			name:   "ShouldFailWhenTheStorageDoesNotPersistGrants",
			method: http.MethodGet,
			setup: func(h *grantManagementAPIHarness, id string) (string, string) {
				token := h.token(grantManagementAPIClientA, grantManagementAPIIssuer, consts.ScopeGrantManagementQuery)

				h.provider.Store = struct{ ClientManager }{h.memory}

				return id, token
			},
			code: http.StatusInternalServerError,
			err:  "server_error",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			h := newGrantManagementAPIHarness(t, grantManagementAPIStores[0].new)

			id, _ := h.grant()

			grantID, token := tc.setup(h, id)

			rw := h.call(tc.method, grantID, token)

			assert.Equal(t, tc.code, rw.Code)
			assert.Equal(t, tc.allow, rw.Header().Get(consts.HeaderAllow))

			switch {
			case tc.exact != "":
				assert.Equal(t, tc.exact, rw.Header().Get(consts.HeaderWWWAuthenticate))
			case tc.challenge == "":
				assert.Empty(t, rw.Header().Get(consts.HeaderWWWAuthenticate))
			default:
				assert.Contains(t, rw.Header().Get(consts.HeaderWWWAuthenticate), tc.challenge)
			}

			if tc.err == "" {
				assert.Empty(t, rw.Body.String())
			} else {
				var body map[string]any

				require.NoError(t, json.Unmarshal(rw.Body.Bytes(), &body))
				assert.Equal(t, tc.err, body["error"])
			}

			_, err := h.memory.GetGrant(h.ctx, id)
			assert.NoError(t, err)
		})
	}
}

func TestGrantManagementRevoke(t *testing.T) {
	for _, sc := range grantManagementAPIStores {
		t.Run(sc.name, func(t *testing.T) {
			h := newGrantManagementAPIHarness(t, sc.new)

			id, issued := h.grant()

			other, kept := h.grant()

			refreshed, err := h.refresh(grantManagementAPIRefreshToken(t, issued))
			require.NoError(t, ErrorToDebugRFC6749Error(err))

			require.True(t, h.active(refreshed.GetAccessToken()))

			token := h.token(grantManagementAPIClientA, grantManagementAPIIssuer, consts.ScopeGrantManagementQuery, consts.ScopeGrantManagementRevoke)

			rw := h.call(http.MethodDelete, id, token)

			require.Equal(t, http.StatusNoContent, rw.Code)
			assert.Empty(t, rw.Body.String())
			assert.Empty(t, rw.Header().Get(consts.HeaderContentType))

			assert.Equal(t, http.StatusNotFound, h.call(http.MethodGet, id, token).Code)
			assert.Equal(t, http.StatusNotFound, h.call(http.MethodDelete, id, token).Code)

			_, err = h.memory.GetGrant(h.ctx, id)
			require.ErrorIs(t, err, ErrNotFound)

			assert.False(t, h.active(issued.GetAccessToken()))
			assert.False(t, h.active(refreshed.GetAccessToken()))

			_, err = h.refresh(grantManagementAPIRefreshToken(t, refreshed))
			require.ErrorIs(t, err, ErrInvalidGrant)

			assert.Equal(t, http.StatusOK, h.call(http.MethodGet, other, token).Code)
			assert.True(t, h.active(kept.GetAccessToken()))

			_, err = h.refresh(grantManagementAPIRefreshToken(t, kept))
			require.NoError(t, ErrorToDebugRFC6749Error(err))
		})

		t.Run(sc.name+"/ShouldRevokeAnExpiredGrant", func(t *testing.T) {
			h := newGrantManagementAPIHarness(t, sc.new)

			id, issued := h.grant()

			h.expire(id)

			token := h.token(grantManagementAPIClientA, grantManagementAPIIssuer, consts.ScopeGrantManagementQuery, consts.ScopeGrantManagementRevoke)

			assert.Equal(t, http.StatusNotFound, h.call(http.MethodGet, id, token).Code)
			require.True(t, h.active(issued.GetAccessToken()))

			rw := h.call(http.MethodDelete, id, token)

			require.Equal(t, http.StatusNoContent, rw.Code)
			assert.Empty(t, rw.Body.String())

			_, err := h.memory.GetGrant(h.ctx, id)
			require.ErrorIs(t, err, ErrNotFound)

			assert.False(t, h.active(issued.GetAccessToken()))

			_, err = h.refresh(grantManagementAPIRefreshToken(t, issued))
			require.ErrorIs(t, err, ErrInvalidGrant)

			assert.Equal(t, http.StatusNotFound, h.call(http.MethodDelete, id, token).Code)
		})
	}
}

func TestGrantManagementAudienceFallsBackToTheIssuer(t *testing.T) {
	h := newGrantManagementAPIHarness(t, grantManagementAPIStores[0].new)

	id, _ := h.grant()

	token := h.token(grantManagementAPIClientA, grantManagementAPIIssuer, consts.ScopeGrantManagementQuery)

	h.provider.Config = &grantManagementAPIConfig{Config: h.config, grants: &GrantManagementConfig{Actions: []GrantManagementAction{GrantManagementActionQuery}}}

	assert.Equal(t, http.StatusOK, h.call(http.MethodGet, id, token).Code)

	h.config.Issuer = ""

	rw := h.call(http.MethodGet, id, token)

	assert.Equal(t, http.StatusInternalServerError, rw.Code)
}

const (
	grantManagementAPIIssuer       = "https://as.example.com"
	grantManagementAPIClientA      = "grant-client-a"
	grantManagementAPIClientB      = "grant-client-b"
	grantManagementAPIClientSecret = "grant-client-secret"
	grantManagementAPIRedirectURI  = "https://client.example.com/cb"
)

var grantManagementAPIStores = []struct {
	name string
	new  func() (any, *storage.MemoryStore)
}{
	{"MemoryStore", func() (any, *storage.MemoryStore) {
		store := storage.NewMemoryStore()

		return store, store
	}},
	{"HydratingMemoryStore", func() (any, *storage.MemoryStore) {
		store := storage.NewHydratingMemoryStore()

		return store, store.MemoryStore
	}},
}

type grantManagementAPIConfig struct {
	*Config

	grants *GrantManagementConfig
}

func (c *grantManagementAPIConfig) GetGrantManagementConfig(context.Context) *GrantManagementConfig {
	return c.grants
}

type grantManagementAPIHarness struct {
	t        *testing.T
	ctx      context.Context
	provider *Fosite
	config   *Config
	memory   *storage.MemoryStore
}

func newGrantManagementAPIHarness(t *testing.T, stores func() (any, *storage.MemoryStore)) *grantManagementAPIHarness {
	t.Helper()

	store, memory := stores()

	config := &Config{
		Issuer:       grantManagementAPIIssuer,
		GlobalSecret: []byte("some-cool-secret-that-is-32bytes"),
		ClientCredentialsFlowImplicitGrantRequested: true,
		GrantManagement: &GrantManagementConfig{
			Actions: []GrantManagementAction{
				GrantManagementActionCreate,
				GrantManagementActionMerge,
				GrantManagementActionReplace,
				GrantManagementActionQuery,
				GrantManagementActionRevoke,
			},
			Endpoint: "https://as.example.com/grants",
		},
	}

	provider, ok := compose.Compose(config, store, &compose.CommonStrategy{CoreStrategy: compose.NewOAuth2HMACStrategy(config)},
		compose.OAuth2AuthorizeExplicitFactory,
		compose.OAuth2ClientCredentialsGrantFactory,
		compose.OAuth2RefreshTokenGrantFactory,
		compose.OAuth2TokenIntrospectionFactory,
		compose.GrantManagementFactory,
	).(*Fosite)
	require.True(t, ok)

	for _, id := range []string{grantManagementAPIClientA, grantManagementAPIClientB} {
		memory.Clients[id] = &DefaultClient{
			ID:            id,
			ClientSecret:  NewPlainTextClientSecret(grantManagementAPIClientSecret),
			RedirectURIs:  []string{grantManagementAPIRedirectURI},
			ResponseTypes: []string{consts.ResponseTypeAuthorizationCodeFlow},
			GrantTypes:    []string{consts.GrantTypeAuthorizationCode, consts.GrantTypeRefreshToken, consts.GrantTypeClientCredentials},
			Scopes:        []string{"read", "offline_access", consts.ScopeGrantManagementQuery, consts.ScopeGrantManagementRevoke},
			Audience:      []string{grantManagementAPIIssuer, "https://rs.example.com"},
		}
	}

	return &grantManagementAPIHarness{t: t, ctx: context.Background(), provider: provider, config: config, memory: memory}
}

func (h *grantManagementAPIHarness) exchange(clientID string, form url.Values) (AccessResponder, error) {
	h.t.Helper()

	return h.exchangeWithSession(clientID, form, &DefaultSession{})
}

func (h *grantManagementAPIHarness) exchangeWithSession(clientID string, form url.Values, session Session) (AccessResponder, error) {
	h.t.Helper()

	r := httptest.NewRequest(http.MethodPost, "https://as.example.com/token", strings.NewReader(form.Encode()))

	r.Header.Set(consts.HeaderContentType, consts.ContentTypeApplicationURLEncodedForm)
	r.SetBasicAuth(clientID, grantManagementAPIClientSecret)

	access, err := h.provider.NewAccessRequest(h.ctx, r, session)
	if err != nil {
		return nil, err
	}

	return h.provider.NewAccessResponse(h.ctx, access)
}

func (h *grantManagementAPIHarness) grant() (id string, issued AccessResponder) {
	h.t.Helper()

	form := url.Values{
		consts.FormParameterClientID:              []string{grantManagementAPIClientA},
		consts.FormParameterResponseType:          []string{consts.ResponseTypeAuthorizationCodeFlow},
		consts.FormParameterRedirectURI:           []string{grantManagementAPIRedirectURI},
		consts.FormParameterState:                 []string{"some-state-value"},
		consts.FormParameterScope:                 []string{"read offline_access"},
		consts.FormParameterGrantManagementAction: []string{"create"},
	}

	requester, err := h.provider.NewAuthorizeRequest(h.ctx, httptest.NewRequest(http.MethodGet, "https://as.example.com/authorize?"+form.Encode(), nil))
	require.NoError(h.t, ErrorToDebugRFC6749Error(err))

	requester.GrantScope("read")
	requester.GrantScope("offline_access")

	responder, err := h.provider.NewAuthorizeResponse(h.ctx, requester, &DefaultSession{Subject: "peter"})
	require.NoError(h.t, ErrorToDebugRFC6749Error(err))

	issued, err = h.exchange(grantManagementAPIClientA, url.Values{
		consts.FormParameterGrantType:         []string{consts.GrantTypeAuthorizationCode},
		consts.FormParameterAuthorizationCode: []string{responder.GetCode()},
		consts.FormParameterRedirectURI:       []string{grantManagementAPIRedirectURI},
	})
	require.NoError(h.t, ErrorToDebugRFC6749Error(err))

	id, ok := issued.GetExtra("grant_id").(string)
	require.True(h.t, ok)
	require.NotEmpty(h.t, id)

	return id, issued
}

func (h *grantManagementAPIHarness) token(clientID, audience string, scopes ...string) string {
	h.t.Helper()

	issued, err := h.exchange(clientID, url.Values{
		consts.FormParameterGrantType: []string{consts.GrantTypeClientCredentials},
		consts.FormParameterScope:     []string{strings.Join(scopes, " ")},
		consts.FormParameterAudience:  []string{audience},
	})
	require.NoError(h.t, ErrorToDebugRFC6749Error(err))

	return issued.GetAccessToken()
}

func (h *grantManagementAPIHarness) refresh(token string) (AccessResponder, error) {
	h.t.Helper()

	return h.exchange(grantManagementAPIClientA, url.Values{
		consts.FormParameterGrantType:    []string{consts.GrantTypeRefreshToken},
		consts.FormParameterRefreshToken: []string{token},
	})
}

func (h *grantManagementAPIHarness) active(token string) bool {
	h.t.Helper()

	_, _, err := h.provider.IntrospectToken(h.ctx, token, AccessToken, &DefaultSession{})

	return err == nil
}

func (h *grantManagementAPIHarness) expire(id string) {
	h.t.Helper()

	grant, err := h.memory.GetGrant(h.ctx, id)
	require.NoError(h.t, err)

	grant.ExpiresAt = time.Now().UTC().Add(-time.Second)

	require.NoError(h.t, h.memory.UpdateGrant(h.ctx, grant))
}

func (h *grantManagementAPIHarness) call(method, id, token string) *httptest.ResponseRecorder {
	h.t.Helper()

	if token == "" {
		return h.request(method, id, "", "")
	}

	return h.request(method, id, "Bearer "+token, "")
}

func (h *grantManagementAPIHarness) request(method, id, authorization, proof string) *httptest.ResponseRecorder {
	h.t.Helper()

	r := httptest.NewRequest(method, "https://as.example.com/grants/"+id, nil)

	if authorization != "" {
		r.Header.Set(consts.HeaderAuthorization, authorization)
	}

	if proof != "" {
		r.Header.Set(consts.HeaderDPoP, proof)
	}

	rw := httptest.NewRecorder()

	requester, err := h.provider.NewGrantManagementRequest(h.ctx, r, id, &DefaultSession{})
	if err != nil {
		h.provider.WriteGrantManagementError(h.ctx, rw, r, err)

		return rw
	}

	responder, err := h.provider.NewGrantManagementResponse(h.ctx, requester)
	if err != nil {
		h.provider.WriteGrantManagementError(h.ctx, rw, r, err)

		return rw
	}

	h.provider.WriteGrantManagementResponse(h.ctx, rw, requester, responder)

	return rw
}

func grantManagementAPIRefreshToken(t *testing.T, response AccessResponder) string {
	t.Helper()

	token, ok := response.GetExtra(consts.AccessResponseRefreshToken).(string)
	require.True(t, ok)
	require.NotEmpty(t, token)

	return token
}

func grantManagementAPIKeys(m map[string]any) (keys []string) {
	for key := range m {
		keys = append(keys, key)
	}

	return keys
}
