// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package integration_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	xoauth2 "golang.org/x/oauth2"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/compose"
	"authelia.com/provider/oauth2/handler/oidckb"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/gen"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/token/jose"
	josejwt "authelia.com/provider/oauth2/token/jose/jwt"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestOIDCKeyBindingAuthorizationCodeFlow(t *testing.T) {
	flow := runOIDCKeyBindingCodeFlow(t, true, []string{consts.ScopeOpenID, consts.ScopeBoundKey}, true)

	requireKeyBoundIDToken(t, flow.idTokenKey, flow.idToken, flow.pub)
}

func TestOIDCKeyBindingDeviceFlow(t *testing.T) {
	provider, _, idTokenKey, clientID := newOIDCKeyBindingProvider(t, true)
	session := newIDSession(&jwt.IDTokenClaims{Subject: "peter"})

	ts := oidckbServer(t, provider, session)
	defer ts.Close()

	key := newDPoPProofKey(t)
	pub := key.Public()

	jkt, err := jwt.ThumbprintJWK(&pub)
	require.NoError(t, err)

	daReq, err := http.NewRequest(http.MethodPost, ts.URL+"/device_authorization", strings.NewReader(url.Values{
		consts.FormParameterScope:   {consts.ScopeOpenID + " " + consts.ScopeBoundKey},
		consts.FormParameterDPoPJKT: {jkt},
	}.Encode()))
	require.NoError(t, err)
	daReq.Header.Set(consts.HeaderContentType, consts.ContentTypeApplicationURLEncodedForm)
	daReq.SetBasicAuth(clientID, oidckbClientSecret)

	daResp, err := http.DefaultClient.Do(daReq)
	require.NoError(t, err)
	defer daResp.Body.Close()

	daBody, err := io.ReadAll(daResp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, daResp.StatusCode, "device_authorization response: %s", daBody)

	var device struct {
		DeviceCode string `json:"device_code"`
		UserCode   string `json:"user_code"`
	}
	require.NoError(t, json.Unmarshal(daBody, &device))
	require.NotEmpty(t, device.DeviceCode)
	require.NotEmpty(t, device.UserCode)

	verifyResp, err := http.PostForm(ts.URL+"/device/verify", url.Values{
		consts.FormParameterUserCode: {device.UserCode},
	})
	require.NoError(t, err)
	defer verifyResp.Body.Close()

	verifyBody, err := io.ReadAll(verifyResp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, verifyResp.StatusCode, "device verify response: %s", verifyBody)

	proof := signDPoPProof(t, key, http.MethodPost, ts.URL+tokenRelativePath, map[string]any{
		jwt.ClaimDPoPCodeHash: oidckb.CodeHash(device.DeviceCode),
	})

	status, token, errBody := postOIDCKBToken(t, ts, clientID, oidckbClientSecret, url.Values{
		consts.FormParameterGrantType:  {consts.GrantTypeOAuthDeviceCode},
		consts.FormParameterDeviceCode: {device.DeviceCode},
	}, proof)

	require.Equal(t, http.StatusOK, status, "token error: %+v", errBody)
	require.NotEmpty(t, token.IDToken)

	requireKeyBoundIDToken(t, idTokenKey, token.IDToken, pub)
}

func TestOIDCKeyBindingRefreshPreservesConfirmation(t *testing.T) {
	flow := runOIDCKeyBindingCodeFlow(t, true, []string{consts.ScopeOpenID, consts.ScopeBoundKey, consts.ScopeOffline}, true)
	require.NotEmpty(t, flow.refreshToken)

	proof := signDPoPProof(t, flow.key, http.MethodPost, flow.ts.URL+tokenRelativePath, nil)

	status, refreshed, errBody := postOIDCKBToken(t, flow.ts, flow.clientID, oidckbClientSecret, url.Values{
		consts.FormParameterGrantType:    {consts.GrantTypeRefreshToken},
		consts.FormParameterRefreshToken: {flow.refreshToken},
	}, proof)

	require.Equal(t, http.StatusOK, status, "refresh error: %+v", errBody)
	require.NotEmpty(t, refreshed.IDToken)

	original := decodeOIDCKBIDToken(t, flow.idToken, &flow.idTokenKey.PublicKey)
	refreshedIDToken := decodeOIDCKBIDToken(t, refreshed.IDToken, &flow.idTokenKey.PublicKey)

	require.Contains(t, original.claims, consts.ClaimConfirmation, "the original id token carried no 'cnf' claim")
	require.Contains(t, refreshedIDToken.claims, consts.ClaimConfirmation, "the refreshed id token carried no 'cnf' claim")

	assert.Equal(t, string(original.claims[consts.ClaimConfirmation]), string(refreshedIDToken.claims[consts.ClaimConfirmation]),
		"the refreshed ID Token's 'cnf' claim must be byte-identical to the original's per Section 5")
}

func TestOIDCKeyBindingNarrowedRefreshPreservesConfirmation(t *testing.T) {
	flow := runOIDCKeyBindingCodeFlow(t, true, []string{consts.ScopeOpenID, consts.ScopeBoundKey, consts.ScopeOffline}, true)
	require.NotEmpty(t, flow.refreshToken)

	proof := signDPoPProof(t, flow.key, http.MethodPost, flow.ts.URL+tokenRelativePath, nil)

	status, body, _ := postOIDCKBToken(t, flow.ts, flow.clientID, oidckbClientSecret, url.Values{
		consts.FormParameterGrantType:    {consts.GrantTypeRefreshToken},
		consts.FormParameterRefreshToken: {flow.refreshToken},
		consts.FormParameterScope:        {consts.ScopeOpenID},
	}, proof)

	require.Equal(t, http.StatusOK, status)
	require.NotEmpty(t, body.IDToken, "the narrowed refresh returned no id token")

	original := decodeOIDCKBIDToken(t, flow.idToken, &flow.idTokenKey.PublicKey)
	refreshed := decodeOIDCKBIDToken(t, body.IDToken, &flow.idTokenKey.PublicKey)

	require.Contains(t, original.claims, consts.ClaimConfirmation, "the original id token carried no 'cnf' claim")
	require.Contains(t, refreshed.claims, consts.ClaimConfirmation, "the narrowed refresh dropped the 'cnf' claim")

	assert.Equal(t, string(original.claims[consts.ClaimConfirmation]), string(refreshed.claims[consts.ClaimConfirmation]),
		"the refreshed ID Token's 'cnf' claim must be byte-identical to the original's per Section 5")
}

func TestOIDCKeyBindingWithoutDPoPJKT(t *testing.T) {
	flow := runOIDCKeyBindingCodeFlow(t, true, []string{consts.ScopeOpenID}, false)

	requireNoConfirmation(t, flow.idTokenKey, flow.idToken)
}

func TestOIDCKeyBindingDisabled(t *testing.T) {
	flow := runOIDCKeyBindingCodeFlow(t, false, []string{consts.ScopeOpenID, consts.ScopeBoundKey}, true)

	requireNoConfirmation(t, flow.idTokenKey, flow.idToken)
}

func TestOIDCKeyBindingPlainDPoPClientCanStillRefresh(t *testing.T) {
	flow := runOIDCKeyBindingCodeFlow(t, true, []string{consts.ScopeOpenID, consts.ScopeOffline}, false)
	require.NotEmpty(t, flow.refreshToken)

	requireNoConfirmation(t, flow.idTokenKey, flow.idToken)

	proof := signDPoPProof(t, flow.key, http.MethodPost, flow.ts.URL+tokenRelativePath, nil)

	status, refreshed, errBody := postOIDCKBToken(t, flow.ts, flow.clientID, oidckbClientSecret, url.Values{
		consts.FormParameterGrantType:    {consts.GrantTypeRefreshToken},
		consts.FormParameterRefreshToken: {flow.refreshToken},
	}, proof)

	require.Equal(t, http.StatusOK, status, "refresh error: %+v", errBody)
	require.NotEmpty(t, refreshed.AccessToken)
}

const (
	oidckbClientID     = "oidckb-client"
	oidckbClientSecret = "foobar"
)

var oidckbProofSeq atomic.Uint64

type oidckbTokenResponse struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	Scope        string `json:"scope"`
}

type oidckbErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

type oidckbIDToken struct {
	typ    string
	claims map[string]json.RawMessage
}

type oidckbFlow struct {
	ts           *httptest.Server
	idTokenKey   *rsa.PrivateKey
	clientID     string
	key          *jose.JSONWebKey
	pub          jose.JSONWebKey
	idToken      string
	accessToken  string
	refreshToken string
}

func oidckbGrantScopes(r oauth2.Requester) {
	for _, scope := range []string{consts.ScopeOpenID, consts.ScopeOffline, consts.ScopeBoundKey} {
		if r.GetRequestedScopes().Has(scope) {
			r.GrantScope(scope)
		}
	}
}

func oidckbAuthEndpointHandler(provider oauth2.Provider, session oauth2.Session) http.HandlerFunc {
	return func(rw http.ResponseWriter, req *http.Request) {
		ctx := oauth2.NewContext()

		ar, err := provider.NewAuthorizeRequest(ctx, req)
		if err != nil {
			provider.WriteAuthorizeError(req.Context(), rw, ar, err)
			return
		}

		oidckbGrantScopes(ar)

		for _, a := range ar.GetRequestedAudience() {
			ar.GrantAudience(a)
		}

		response, err := provider.NewAuthorizeResponse(ctx, ar, session)
		if err != nil {
			provider.WriteAuthorizeError(req.Context(), rw, ar, err)
			return
		}

		provider.WriteAuthorizeResponse(req.Context(), rw, ar, response)
	}
}

func oidckbDeviceAuthorizeHandler(provider oauth2.Provider, session oauth2.Session) http.HandlerFunc {
	return func(rw http.ResponseWriter, req *http.Request) {
		ctx := oauth2.NewContext()

		ar, err := provider.NewRFC862DeviceAuthorizeRequest(ctx, req)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusBadRequest)
			return
		}

		response, err := provider.NewRFC862DeviceAuthorizeResponse(ctx, ar, session)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusBadRequest)
			return
		}

		provider.WriteRFC862DeviceAuthorizeResponse(ctx, rw, ar, response)
	}
}

func oidckbUserAuthorizeHandler(provider oauth2.Provider, session oauth2.Session) http.HandlerFunc {
	return func(rw http.ResponseWriter, req *http.Request) {
		ctx := oauth2.NewContext()

		ar, err := provider.NewRFC8628UserAuthorizeRequest(ctx, req)
		if err != nil {
			provider.WriteRFC8628UserAuthorizeError(ctx, rw, ar, err)
			return
		}

		oidckbGrantScopes(ar)
		ar.SetStatus(oauth2.DeviceAuthorizeStatusApproved)

		response, err := provider.NewRFC8628UserAuthorizeResponse(ctx, ar, session)
		if err != nil {
			provider.WriteRFC8628UserAuthorizeError(ctx, rw, ar, err)
			return
		}

		provider.WriteRFC8628UserAuthorizeResponse(ctx, rw, ar, response)
	}
}

func oidckbServer(t *testing.T, provider oauth2.Provider, session oauth2.Session) *httptest.Server {
	t.Helper()

	router := mux.NewRouter()
	router.HandleFunc("/auth", oidckbAuthEndpointHandler(provider, session))
	router.HandleFunc(tokenRelativePath, tokenEndpointHandler(t, provider))
	router.HandleFunc("/callback", authCallbackHandler(t))
	router.HandleFunc("/device_authorization", oidckbDeviceAuthorizeHandler(provider, session))
	router.HandleFunc("/device/verify", oidckbUserAuthorizeHandler(provider, session))

	return httptest.NewServer(router)
}

func newDPoPProofKey(t *testing.T) *jose.JSONWebKey {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	return &jose.JSONWebKey{Key: priv, Algorithm: string(jose.ES256)}
}

func signDPoPProof(t *testing.T, key *jose.JSONWebKey, method, url string, extra map[string]any) string {
	t.Helper()

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.SignatureAlgorithm(key.Algorithm), Key: key},
		(&jose.SignerOptions{EmbedJWK: true}).WithType(jose.ContentType(jwt.JSONWebTokenTypeDPoP)),
	)
	require.NoError(t, err)

	claims := map[string]any{
		jwt.ClaimJWTID:      fmt.Sprintf("oidckb-proof-%d", oidckbProofSeq.Add(1)),
		jwt.ClaimHTTPMethod: method,
		jwt.ClaimHTTPURI:    url,
		jwt.ClaimIssuedAt:   time.Now().Unix(),
	}

	for k, v := range extra {
		claims[k] = v
	}

	raw, err := josejwt.Signed(signer).Claims(claims).Serialize()
	require.NoError(t, err)

	return raw
}

func postOIDCKBToken(t *testing.T, ts *httptest.Server, clientID, clientSecret string, form url.Values, dpopProof string) (status int, token oidckbTokenResponse, errBody oidckbErrorResponse) {
	t.Helper()

	req, err := http.NewRequest(http.MethodPost, ts.URL+tokenRelativePath, strings.NewReader(form.Encode()))
	require.NoError(t, err)

	req.Header.Set(consts.HeaderContentType, consts.ContentTypeApplicationURLEncodedForm)
	req.SetBasicAuth(clientID, clientSecret)

	if dpopProof != "" {
		req.Header.Set(consts.HeaderDPoP, dpopProof)
	}

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	if resp.StatusCode >= http.StatusBadRequest {
		require.NoError(t, json.Unmarshal(body, &errBody), "error response: %s", body)
	} else {
		require.NoError(t, json.Unmarshal(body, &token), "token response: %s", body)
	}

	return resp.StatusCode, token, errBody
}

func decodeOIDCKBIDToken(t *testing.T, raw string, pub *rsa.PublicKey) oidckbIDToken {
	t.Helper()

	sig, err := jose.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256})
	require.NoError(t, err)
	require.Len(t, sig.Signatures, 1)

	payload, err := sig.Verify(pub)
	require.NoError(t, err, "id token signature verification")

	var claims map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(payload, &claims))

	var typ string
	if v, ok := sig.Signatures[0].Protected.ExtraHeaders[jose.HeaderKey(consts.JSONWebTokenHeaderType)]; ok {
		typ, _ = v.(string)
	}

	return oidckbIDToken{typ: typ, claims: claims}
}

func requireKeyBoundIDToken(t *testing.T, idTokenKey *rsa.PrivateKey, rawIDToken string, expectedPub jose.JSONWebKey) {
	t.Helper()

	result := decodeOIDCKBIDToken(t, rawIDToken, &idTokenKey.PublicKey)
	require.Equal(t, consts.JSONWebTokenTypeDPoPIDToken, result.typ, "id token 'typ' header")

	rawCNF, ok := result.claims[consts.ClaimConfirmation]
	require.True(t, ok, "id token carried no 'cnf' claim")

	var cnf map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(rawCNF, &cnf))

	rawJWK, ok := cnf[consts.ClaimConfirmationJWK]
	require.True(t, ok, "'cnf' claim carried no 'jwk' member")

	var actual map[string]any
	require.NoError(t, json.Unmarshal(rawJWK, &actual))

	expectedRaw, err := expectedPub.MarshalJSON()
	require.NoError(t, err)

	var expected map[string]any
	require.NoError(t, json.Unmarshal(expectedRaw, &expected))

	assert.Equal(t, expected, actual, "'cnf.jwk' does not match the DPoP proof key")
}

func requireNoConfirmation(t *testing.T, idTokenKey *rsa.PrivateKey, rawIDToken string) {
	t.Helper()

	result := decodeOIDCKBIDToken(t, rawIDToken, &idTokenKey.PublicKey)

	_, ok := result.claims[consts.ClaimConfirmation]
	assert.False(t, ok, "id token unexpectedly carried a 'cnf' claim")
}

func runOIDCKeyBindingCodeFlow(t *testing.T, oidcKeyBindingEnabled bool, scopes []string, withDPoPJKT bool) oidckbFlow {
	t.Helper()

	provider, memory, idTokenKey, clientID := newOIDCKeyBindingProvider(t, oidcKeyBindingEnabled)
	session := newIDSession(&jwt.IDTokenClaims{Subject: "peter"})

	ts := oidckbServer(t, provider, session)
	t.Cleanup(ts.Close)

	memory.Clients[clientID].(*oauth2.DefaultClient).RedirectURIs = []string{ts.URL + "/callback"}

	key := newDPoPProofKey(t)
	pub := key.Public()

	jkt, err := jwt.ThumbprintJWK(&pub)
	require.NoError(t, err)

	oauthClient := &xoauth2.Config{
		ClientID:     clientID,
		ClientSecret: oidckbClientSecret,
		RedirectURL:  ts.URL + "/callback",
		Scopes:       scopes,
		Endpoint: xoauth2.Endpoint{
			AuthURL:   ts.URL + "/auth",
			TokenURL:  ts.URL + tokenRelativePath,
			AuthStyle: xoauth2.AuthStyleInHeader,
		},
	}

	opts := []xoauth2.AuthCodeOption{xoauth2.SetAuthURLParam("nonce", "sufficiently-entropic-oidckb-nonce-value")}
	if withDPoPJKT {
		opts = append(opts, xoauth2.SetAuthURLParam(consts.FormParameterDPoPJKT, jkt))
	}

	resp, err := http.Get(oauthClient.AuthCodeURL(testState, opts...))
	require.NoError(t, err)
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	require.Equal(t, http.StatusOK, resp.StatusCode, "authorize response: %s", body)

	code := resp.Request.URL.Query().Get("code")
	require.NotEmpty(t, code)

	proof := signDPoPProof(t, key, http.MethodPost, ts.URL+tokenRelativePath, map[string]any{
		jwt.ClaimDPoPCodeHash: oidckb.CodeHash(code),
	})

	status, token, errBody := postOIDCKBToken(t, ts, clientID, oidckbClientSecret, url.Values{
		consts.FormParameterGrantType:         {consts.GrantTypeAuthorizationCode},
		consts.FormParameterAuthorizationCode: {code},
		consts.FormParameterRedirectURI:       {ts.URL + "/callback"},
	}, proof)

	require.Equal(t, http.StatusOK, status, "token error: %+v", errBody)
	require.NotEmpty(t, token.AccessToken)
	require.NotEmpty(t, token.IDToken)

	return oidckbFlow{
		ts:           ts,
		idTokenKey:   idTokenKey,
		clientID:     clientID,
		key:          key,
		pub:          pub,
		idToken:      token.IDToken,
		accessToken:  token.AccessToken,
		refreshToken: token.RefreshToken,
	}
}

func newOIDCKeyBindingProvider(t *testing.T, oidcKeyBindingEnabled bool) (provider oauth2.Provider, store *storage.MemoryStore, idTokenKey *rsa.PrivateKey, clientID string) {
	t.Helper()

	idTokenKey = gen.MustRSAKey()
	store = storage.NewMemoryStore()

	clientID = oidckbClientID
	store.Clients[clientID] = &oauth2.DefaultClient{
		ID:            clientID,
		ClientSecret:  oauth2.NewPlainTextClientSecret(oidckbClientSecret),
		RedirectURIs:  []string{"http://localhost/callback"},
		ResponseTypes: []string{consts.ResponseTypeAuthorizationCodeFlow},
		GrantTypes:    []string{consts.GrantTypeAuthorizationCode, consts.GrantTypeRefreshToken, consts.GrantTypeOAuthDeviceCode},
		Scopes:        []string{consts.ScopeOpenID, consts.ScopeOffline, consts.ScopeBoundKey},
	}

	config := &oauth2.Config{
		GlobalSecret:               []byte("oidckb-integration-test-secret-32-bytes"),
		DPoPEnabled:                true,
		OIDCKeyBindingEnabled:      oidcKeyBindingEnabled,
		RFC8628UserVerificationURL: "https://www.authelia.com/device",
	}

	keyGetter := func(context.Context) (any, error) { return idTokenKey, nil }
	strategy := &jwt.DefaultStrategy{Config: config, Issuer: jwt.NewDefaultIssuerRS256Unverified(idTokenKey)}

	provider = compose.Compose(
		config,
		store,
		&compose.CommonStrategy{
			CoreStrategy:               compose.NewOAuth2HMACStrategy(config),
			OpenIDConnectTokenStrategy: compose.NewOpenIDConnectStrategy(keyGetter, strategy, config),
			Strategy:                   strategy,
		},
		compose.OAuth2AuthorizeExplicitFactory,
		compose.OAuth2RefreshTokenGrantFactory,
		compose.RFC8628DeviceAuthorizeFactory,

		// MUST precede RFC8628UserAuthorizeFactory: see compose.OpenIDConnectKeyBindingUserAuthorizeFactory's doc comment.
		compose.OpenIDConnectKeyBindingUserAuthorizeFactory,
		compose.RFC8628UserAuthorizeFactory,
		compose.RFC8628DeviceAuthorizeTokenFactory,

		compose.OpenIDConnectExplicitFactory,
		compose.OpenIDConnectRefreshFactory,
		compose.OpenIDConnectDeviceAuthorizeFactory,

		compose.DPoPAuthorizeFactory,
		compose.DPoPDeviceAuthorizeFactory,

		compose.OpenIDConnectKeyBindingAuthorizeFactory,
		compose.OpenIDConnectKeyBindingDeviceAuthorizeFactory,

		compose.DPoPTokenFactory,
		compose.OpenIDConnectKeyBindingFactory,
	)

	return provider, store, idTokenKey, clientID
}
