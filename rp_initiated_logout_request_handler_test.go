// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/handler/openid"
	"authelia.com/provider/oauth2/internal/gen"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestNewRPInitiatedLogoutRequest_RejectsBadMethod(t *testing.T) {
	f := newLogoutProvider(t)

	r := httptest.NewRequest(http.MethodPut, "https://op.example/logout", nil)

	_, err := f.NewRPInitiatedLogoutRequest(t.Context(), r)

	require.Error(t, err)
	assert.ErrorIs(t, err, oauth2.ErrInvalidRequest)
	assert.Contains(t, oauth2.ErrorToDebugRFC6749Error(err).Error(), "PUT")
}

func TestNewRPInitiatedLogoutRequest_AcceptsGetAndPost(t *testing.T) {
	f := newLogoutProvider(t)

	t.Run("GET", func(t *testing.T) {
		requester, err := f.NewRPInitiatedLogoutRequest(t.Context(), newLogoutGet(url.Values{}))
		require.NoError(t, err)
		assert.Nil(t, requester.GetClient())
	})

	t.Run("POST", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodPost, "https://op.example/logout", strings.NewReader(""))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		_, err := f.NewRPInitiatedLogoutRequest(t.Context(), r)
		require.NoError(t, err)
	})
}

func TestNewRPInitiatedLogoutRequest_ParsesSimpleParameters(t *testing.T) {
	f := newLogoutProvider(t)

	requester, err := f.NewRPInitiatedLogoutRequest(t.Context(), newLogoutGet(url.Values{
		"state":       []string{"opaque-state"},
		"logout_hint": []string{"alice@example.com"},
		"ui_locales":  []string{"en-AU  en"},
	}))

	require.NoError(t, err)
	assert.Equal(t, "opaque-state", requester.GetState())
	assert.Equal(t, "alice@example.com", requester.GetLogoutHint())
	assert.Equal(t, oauth2.Arguments{"en-AU", "en"}, requester.GetUILocales())
}

func TestNewRPInitiatedLogoutRequest_ResolvesClientByClientID(t *testing.T) {
	client := &oauth2.DefaultClient{ID: "test-client"}
	f := newLogoutProvider(t, client)

	requester, err := f.NewRPInitiatedLogoutRequest(t.Context(), newLogoutGet(url.Values{
		"client_id": []string{"test-client"},
	}))

	require.NoError(t, err)
	assert.Equal(t, "test-client", requester.GetClient().GetID())
}

func TestNewRPInitiatedLogoutRequest_RejectsUnknownClientID(t *testing.T) {
	f := newLogoutProvider(t)

	_, err := f.NewRPInitiatedLogoutRequest(t.Context(), newLogoutGet(url.Values{
		"client_id": []string{"nope"},
	}))

	require.Error(t, err)
	assert.ErrorIs(t, err, oauth2.ErrInvalidClient)
}

func TestNewRPInitiatedLogoutRequest_NoClientIsNotAnError(t *testing.T) {
	f := newLogoutProvider(t)

	requester, err := f.NewRPInitiatedLogoutRequest(t.Context(), newLogoutGet(url.Values{}))

	require.NoError(t, err, "RP-Initiated Logout permits a request with neither client_id nor id_token_hint")
	assert.Nil(t, requester.GetClient())
}

func TestNewRPInitiatedLogoutRequest_AcceptsExpiredIDTokenHint(t *testing.T) {
	client := &oauth2.DefaultClient{ID: "test-client"}
	f, jwtStrategy, _ := newLogoutProviderWithJWT(t, client)

	hint := mintIDToken(t, jwtStrategy, baseHintClaims("test-client"))

	requester, err := f.NewRPInitiatedLogoutRequest(t.Context(), newLogoutGet(url.Values{
		"id_token_hint": []string{hint},
	}))

	require.NoError(t, err, "an expired id_token_hint must be accepted")
	assert.Equal(t, "test-client", requester.GetClient().GetID(), "client resolves from the hint's aud")
	assert.Equal(t, "alice", requester.GetSubject())
	assert.Equal(t, "session-1", requester.GetSessionID())
}

func TestNewRPInitiatedLogoutRequest_AcceptsAgreeingClientIDAndHint(t *testing.T) {
	client := &oauth2.DefaultClient{ID: "test-client"}
	f, jwtStrategy, _ := newLogoutProviderWithJWT(t, client)

	hint := mintIDToken(t, jwtStrategy, baseHintClaims("test-client"))

	requester, err := f.NewRPInitiatedLogoutRequest(t.Context(), newLogoutGet(url.Values{
		"client_id":     []string{"test-client"},
		"id_token_hint": []string{hint},
	}))

	require.NoError(t, err)
	assert.Equal(t, "test-client", requester.GetClient().GetID())
	assert.Equal(t, "alice", requester.GetSubject())
}

func TestNewRPInitiatedLogoutRequest_RejectsNotYetValidIDTokenHint(t *testing.T) {
	client := &oauth2.DefaultClient{ID: "test-client"}
	f, jwtStrategy, _ := newLogoutProviderWithJWT(t, client)

	claims := baseHintClaims("test-client")
	claims[jwt.ClaimNotBefore] = jwt.NewNumericDate(time.Now().Add(time.Hour))

	hint := mintIDToken(t, jwtStrategy, claims)

	_, err := f.NewRPInitiatedLogoutRequest(t.Context(), newLogoutGet(url.Values{
		"id_token_hint": []string{hint},
	}))

	require.Error(t, err)
	assert.ErrorIs(t, err, oauth2.ErrInvalidRequest)
}

func TestNewRPInitiatedLogoutRequest_ClaimPolicy(t *testing.T) {
	client := &oauth2.DefaultClient{ID: "test-client"}

	testCases := []struct {
		name   string
		mutate func(claims jwt.MapClaims)
	}{
		{"WrongIssuer", func(c jwt.MapClaims) { c[jwt.ClaimIssuer] = "https://evil.example/" }},
		{"AudienceMissingClient", func(c jwt.MapClaims) { c[jwt.ClaimAudience] = []string{"other-client"} }},
		{"AuthorizedPartyMismatch", func(c jwt.MapClaims) { c[jwt.ClaimAuthorizedParty] = "other-client" }},
		{"MissingSubject", func(c jwt.MapClaims) { delete(c, jwt.ClaimSubject) }},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			f, jwtStrategy, _ := newLogoutProviderWithJWT(t, client)

			claims := baseHintClaims("test-client")
			tc.mutate(claims)

			hint := mintIDToken(t, jwtStrategy, claims)

			_, err := f.NewRPInitiatedLogoutRequest(t.Context(), newLogoutGet(url.Values{
				"client_id":     []string{"test-client"},
				"id_token_hint": []string{hint},
			}))

			require.Error(t, err)
			assert.ErrorIs(t, err, oauth2.ErrInvalidRequest)
		})
	}
}

func TestNewRPInitiatedLogoutRequest_RejectsTamperedIDTokenHint(t *testing.T) {
	client := &oauth2.DefaultClient{ID: "test-client"}
	f, jwtStrategy, _ := newLogoutProviderWithJWT(t, client)

	hint := mintIDToken(t, jwtStrategy, baseHintClaims("test-client"))

	segments := strings.SplitN(hint, ".", 3)
	require.Len(t, segments, 3)

	signature := []byte(segments[2])
	if signature[0] == 'A' {
		signature[0] = 'B'
	} else {
		signature[0] = 'A'
	}

	tampered := strings.Join([]string{segments[0], segments[1], string(signature)}, ".")

	_, err := f.NewRPInitiatedLogoutRequest(t.Context(), newLogoutGet(url.Values{
		"id_token_hint": []string{tampered},
	}))

	require.Error(t, err)
	assert.ErrorIs(t, err, oauth2.ErrInvalidRequest)
}

func TestNewRPInitiatedLogoutRequest_RejectsHintSignedWithWrongKey(t *testing.T) {
	client := &oauth2.DefaultClient{ID: "test-client"}
	f, _, _ := newLogoutProviderWithJWT(t, client)

	wrongConfig := &oauth2.Config{IDTokenIssuer: logoutTestIssuer, MinParameterEntropy: 8}
	wrongStrategy := &jwt.DefaultStrategy{Config: wrongConfig, Issuer: jwt.NewDefaultIssuerRS256Unverified(gen.MustRSAKey())}

	hint := mintIDToken(t, wrongStrategy, baseHintClaims("test-client"))

	_, err := f.NewRPInitiatedLogoutRequest(t.Context(), newLogoutGet(url.Values{
		"id_token_hint": []string{hint},
	}))

	require.Error(t, err)
	assert.ErrorIs(t, err, oauth2.ErrInvalidRequest)
}

func TestNewRPInitiatedLogoutRequest_ClientIDMustMatchHint(t *testing.T) {
	clientA := &oauth2.DefaultClient{ID: "client-a"}
	clientB := &oauth2.DefaultClient{ID: "client-b"}
	f, jwtStrategy, _ := newLogoutProviderWithJWT(t, clientA, clientB)

	hint := mintIDToken(t, jwtStrategy, baseHintClaims("client-b"))

	_, err := f.NewRPInitiatedLogoutRequest(t.Context(), newLogoutGet(url.Values{
		"client_id":     []string{"client-a"},
		"id_token_hint": []string{hint},
	}))

	require.Error(t, err, "a client_id that disagrees with the hint's audience must be rejected")
	assert.ErrorIs(t, err, oauth2.ErrInvalidRequest)
}

func TestNewRPInitiatedLogoutRequest_HintWithoutDerivableClient(t *testing.T) {
	f, jwtStrategy, _ := newLogoutProviderWithJWT(t)

	claims := baseHintClaims("test-client")
	claims[jwt.ClaimAudience] = []string{"client-a", "client-b"}

	hint := mintIDToken(t, jwtStrategy, claims)

	_, err := f.NewRPInitiatedLogoutRequest(t.Context(), newLogoutGet(url.Values{
		"id_token_hint": []string{hint},
	}))

	require.Error(t, err, "a multi-valued aud with no azp gives no client to resolve")
	assert.ErrorIs(t, err, oauth2.ErrInvalidRequest)
}

func TestNewRPInitiatedLogoutRequest_ResolvesClientFromAuthorizedParty(t *testing.T) {
	clientA := &oauth2.DefaultClient{ID: "client-a"}
	clientB := &oauth2.DefaultClient{ID: "client-b"}
	f, jwtStrategy, _ := newLogoutProviderWithJWT(t, clientA, clientB)

	claims := baseHintClaims("client-b")
	claims[jwt.ClaimAudience] = []string{"client-a", "client-b"}
	claims[jwt.ClaimAuthorizedParty] = "client-b"

	hint := mintIDToken(t, jwtStrategy, claims)

	requester, err := f.NewRPInitiatedLogoutRequest(t.Context(), newLogoutGet(url.Values{
		"id_token_hint": []string{hint},
	}))

	require.NoError(t, err, "azp disambiguates a multi-valued aud and is preferred over the aud fallback")
	assert.Equal(t, "client-b", requester.GetClient().GetID())
}

func TestNewRPInitiatedLogoutRequest_AcceptsAuthorizedPartyMatchingClient(t *testing.T) {
	client := &oauth2.DefaultClient{ID: "test-client"}
	f, jwtStrategy, _ := newLogoutProviderWithJWT(t, client)

	claims := baseHintClaims("test-client")
	claims[jwt.ClaimAuthorizedParty] = "test-client"

	hint := mintIDToken(t, jwtStrategy, claims)

	requester, err := f.NewRPInitiatedLogoutRequest(t.Context(), newLogoutGet(url.Values{
		"id_token_hint": []string{hint},
	}))

	require.NoError(t, err, "azp equal to the resolved client must be accepted")
	assert.Equal(t, "test-client", requester.GetClient().GetID())
}

func TestNewRPInitiatedLogoutRequest_AcceptsRegisteredPostLogoutRedirectURI(t *testing.T) {
	client := newLogoutClient("test-client", "https://rp.example/logged-out")
	f, _, _ := newLogoutProviderWithJWT(t, client)

	requester, err := f.NewRPInitiatedLogoutRequest(t.Context(), newLogoutGet(url.Values{
		"client_id":                []string{"test-client"},
		"post_logout_redirect_uri": []string{"https://rp.example/logged-out"},
		"state":                    []string{"opaque"},
	}))

	require.NoError(t, err)
	require.NotNil(t, requester.GetPostLogoutRedirectURI())
	assert.Equal(t, "https://rp.example/logged-out", requester.GetPostLogoutRedirectURI().String())
	assert.Equal(t, "opaque", requester.GetState())
}

func TestNewRPInitiatedLogoutRequest_PostLogoutRedirectURIRejections(t *testing.T) {
	registered := newLogoutClient("test-client", "https://rp.example/logged-out")
	plain := &oauth2.DefaultClient{ID: "plain-client"}

	testCases := []struct {
		name  string
		query url.Values
	}{
		{
			name:  "Unregistered",
			query: url.Values{"client_id": {"test-client"}, "post_logout_redirect_uri": {"https://rp.example/logged-out-elsewhere"}},
		},
		{
			name:  "NoClient",
			query: url.Values{"post_logout_redirect_uri": {"https://rp.example/logged-out"}},
		},
		{
			name:  "ClientWithoutMetadata",
			query: url.Values{"client_id": {"plain-client"}, "post_logout_redirect_uri": {"https://rp.example/logged-out"}},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			f, _, _ := newLogoutProviderWithJWT(t, registered, plain)

			requester, err := f.NewRPInitiatedLogoutRequest(t.Context(), newLogoutGet(tc.query))

			require.Error(t, err)
			assert.ErrorIs(t, err, oauth2.ErrInvalidRequest)
			assert.Nil(t, requester.GetPostLogoutRedirectURI(), "an error path must never expose a redirect URI")
		})
	}
}

func TestNewRPInitiatedLogoutRequest_ErrorPathsNeverExposeRedirectURI(t *testing.T) {
	registered := newLogoutClient("test-client", "https://rp.example/logged-out")

	queries := []url.Values{
		{"client_id": {"unknown"}, "post_logout_redirect_uri": {"https://rp.example/logged-out"}},
		{"client_id": {"test-client"}, "id_token_hint": {"not-a-jwt"}, "post_logout_redirect_uri": {"https://rp.example/logged-out"}},
	}

	for i, query := range queries {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			f, _, _ := newLogoutProviderWithJWT(t, registered)

			requester, err := f.NewRPInitiatedLogoutRequest(t.Context(), newLogoutGet(query))

			require.Error(t, err)
			require.NotNil(t, requester, "a requester must always be returned so callers can read it unconditionally")
			assert.Nil(t, requester.GetPostLogoutRedirectURI())
		})
	}
}

func TestNewRPInitiatedLogoutRequest_RejectsHintWhenIssuerUnconfigured(t *testing.T) {
	client := &oauth2.DefaultClient{ID: "test-client"}
	f, jwtStrategy, config := newLogoutProviderWithJWT(t, client)

	hint := mintIDToken(t, jwtStrategy, baseHintClaims("test-client"))

	config.IDTokenIssuer = ""

	_, err := f.NewRPInitiatedLogoutRequest(t.Context(), newLogoutGet(url.Values{
		"id_token_hint": []string{hint},
	}))

	require.Error(t, err, "an unconfigured issuer must not silently skip the 'iss' check")
	assert.ErrorIs(t, err, oauth2.ErrServerError)
}

func newLogoutClient(id string, uris ...string) *oauth2.DefaultRPInitiatedLogoutClient {
	return &oauth2.DefaultRPInitiatedLogoutClient{
		DefaultClient:          &oauth2.DefaultClient{ID: id},
		PostLogoutRedirectURIs: uris,
	}
}

func newLogoutProviderWithJWT(t *testing.T, clients ...oauth2.Client) (*oauth2.Fosite, jwt.Strategy, *oauth2.Config) {
	t.Helper()

	config := &oauth2.Config{IDTokenIssuer: logoutTestIssuer, MinParameterEntropy: 8}
	jwtStrategy := &jwt.DefaultStrategy{Config: config, Issuer: jwt.NewDefaultIssuerRS256Unverified(logoutTestKey)}
	config.IDTokenValidationStrategy = &openid.DefaultIDTokenValidationStrategy{Strategy: jwtStrategy}

	store := storage.NewMemoryStore()

	for _, client := range clients {
		store.Clients[client.GetID()] = client
	}

	return &oauth2.Fosite{Store: store, Config: config}, jwtStrategy, config
}

func mintIDToken(t *testing.T, strategy jwt.Strategy, claims jwt.MapClaims) string {
	t.Helper()

	token, _, err := strategy.Encode(t.Context(), claims)
	require.NoError(t, err)

	return token
}

func baseHintClaims(clientID string) jwt.MapClaims {
	return jwt.MapClaims{
		jwt.ClaimIssuer:         logoutTestIssuer,
		jwt.ClaimSubject:        "alice",
		jwt.ClaimSessionID:      "session-1",
		jwt.ClaimAudience:       []string{clientID},
		jwt.ClaimIssuedAt:       jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
		jwt.ClaimExpirationTime: jwt.NewNumericDate(time.Now().Add(-time.Hour)),
	}
}

func newLogoutProvider(t *testing.T, clients ...oauth2.Client) *oauth2.Fosite {
	t.Helper()

	store := storage.NewMemoryStore()

	for _, client := range clients {
		store.Clients[client.GetID()] = client
	}

	return &oauth2.Fosite{Store: store, Config: &oauth2.Config{IDTokenIssuer: "https://issuer.example/"}}
}

func newLogoutGet(query url.Values) *http.Request {
	return httptest.NewRequest(http.MethodGet, "https://op.example/logout?"+query.Encode(), nil)
}

const logoutTestIssuer = "https://issuer.example/"

var logoutTestKey = gen.MustRSAKey()
