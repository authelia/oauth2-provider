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
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"authelia.com/provider/jose"
	josejwt "authelia.com/provider/jose/jwt"

	. "authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/handler/rfc9449"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/testing/mock"
	"authelia.com/provider/oauth2/token/jwt"
)

// noSSFStore hides the SSFStreamStorage methods of the embedded Storage.
type noSSFStore struct {
	Storage
}

func TestAuthorizeSSFRequest(t *testing.T) {
	const (
		issuer      = "https://ssf.example.com"
		audience    = "https://ssf.example.com/ssf"
		requestURL  = "https://ssf.example.com/ssf/stream"
		bearerToken = "some-token"
	)

	const (
		clientDefault = iota
		clientNil
		clientEmptyID
	)

	testCases := []struct {
		name      string
		audience  string
		issuer    string
		noConfig  bool
		noToken   bool
		granted   []string
		aud       []string
		client    int
		use       TokenUse
		write     bool
		noStorage bool
		code      int
		errCode   string
	}{
		{name: "ShouldRejectMissingToken", issuer: issuer, audience: audience, noToken: true, code: http.StatusUnauthorized, errCode: "invalid_token"},
		{name: "ShouldRejectWrongAudience", issuer: issuer, audience: audience, granted: []string{consts.ScopeSSFManage}, aud: []string{"https://other.example.com"}, code: http.StatusUnauthorized, errCode: "invalid_token"},
		{name: "ShouldNotFallBackToRequestURL", issuer: issuer, audience: audience, granted: []string{consts.ScopeSSFManage}, aud: []string{requestURL}, code: http.StatusUnauthorized, errCode: "invalid_token"},
		{name: "ShouldNotFallBackToRequestURLWhenAudienceEmpty", issuer: "", audience: "", granted: []string{consts.ScopeSSFManage}, aud: []string{requestURL}, code: http.StatusInternalServerError, errCode: "server_error"},
		{name: "ShouldRejectNoConfig", noConfig: true, granted: []string{consts.ScopeSSFManage}, aud: []string{audience}, code: http.StatusInternalServerError, errCode: "server_error"},
		{name: "ShouldRejectReadScopeOnWrite", issuer: issuer, audience: audience, granted: []string{consts.ScopeSSFRead}, aud: []string{audience}, write: true, code: http.StatusForbidden, errCode: "insufficient_scope"},
		{name: "ShouldRejectUnrelatedScope", issuer: issuer, audience: audience, granted: []string{"openid"}, aud: []string{audience}, code: http.StatusForbidden, errCode: "insufficient_scope"},
		{name: "ShouldAcceptReadScopeOnRead", issuer: issuer, audience: audience, granted: []string{consts.ScopeSSFRead}, aud: []string{audience}},
		{name: "ShouldAcceptManageOnRead", issuer: issuer, audience: audience, granted: []string{consts.ScopeSSFManage}, aud: []string{audience}},
		{name: "ShouldAcceptManageOnWrite", issuer: issuer, audience: audience, granted: []string{consts.ScopeSSFManage}, aud: []string{audience}, write: true},
		{name: "ShouldAcceptIssuerWhenAudienceEmpty", issuer: issuer, audience: "", granted: []string{consts.ScopeSSFManage}, aud: []string{issuer}},
		{name: "ShouldRejectStoreWithoutSSF", issuer: issuer, audience: audience, granted: []string{consts.ScopeSSFManage}, aud: []string{audience}, noStorage: true, code: http.StatusInternalServerError, errCode: "server_error"},
		{name: "ShouldRejectNilClient", issuer: issuer, audience: audience, granted: []string{consts.ScopeSSFManage}, aud: []string{audience}, client: clientNil, code: http.StatusUnauthorized, errCode: "invalid_token"},
		{name: "ShouldRejectEmptyClientID", issuer: issuer, audience: audience, granted: []string{consts.ScopeSSFManage}, aud: []string{audience}, client: clientEmptyID, code: http.StatusUnauthorized, errCode: "invalid_token"},
		{name: "ShouldRejectRefreshToken", issuer: issuer, audience: audience, granted: []string{consts.ScopeSSFManage}, aud: []string{audience}, use: RefreshToken, code: http.StatusUnauthorized, errCode: "invalid_token"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			introspector := mock.NewMockTokenIntrospector(ctrl)
			store := storage.NewMemoryStore()

			config := &Config{
				TokenIntrospectionHandlers: TokenIntrospectionHandlers{introspector},
			}

			if !tc.noConfig {
				config.SSF = &SSFConfig{Issuer: tc.issuer, Audience: tc.audience}
			}

			var s Storage = store

			if tc.noStorage {
				s = noSSFStore{Storage: store}
			}

			provider := &Fosite{Store: s, Config: config}

			r := httptest.NewRequest(http.MethodPost, requestURL, nil)

			if !tc.noToken {
				r.Header.Set(consts.HeaderAuthorization, "Bearer "+bearerToken)

				introspector.EXPECT().IntrospectToken(gomock.Any(), bearerToken, gomock.Any(), gomock.Any(), gomock.Any()).
					Do(func(_ context.Context, _ string, _ TokenUse, requester AccessRequester, _ []string) {
						ar := requester.(*AccessRequest)
						ar.GrantedScope = tc.granted
						ar.GrantedAudience = tc.aud

						switch tc.client {
						case clientNil:
							ar.Client = nil
						case clientEmptyID:
							ar.Client = &DefaultClient{}
						default:
							ar.Client = &DefaultClient{ID: "client"}
						}
					}).Return(cmpUse(tc.use), nil).AnyTimes()
			}

			requester, ss, err := provider.AuthorizeSSFRequestForTest(context.Background(), r, &DefaultSession{}, tc.write)

			if tc.code == 0 {
				require.NoError(t, err)
				assert.NotNil(t, requester)
				assert.NotNil(t, ss)

				return
			}

			require.Error(t, err)
			assert.Nil(t, requester)
			assert.Nil(t, ss)

			rfc := ErrorToRFC6749Error(err)
			assert.Equal(t, tc.code, rfc.StatusCode())
			assert.Equal(t, tc.errCode, rfc.ErrorField)
		})
	}
}

func cmpUse(use TokenUse) TokenUse {
	if use == "" {
		return AccessToken
	}

	return use
}

func TestAuthorizeSSFRequestShouldNotRevealIntrospectionFailure(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	introspector := mock.NewMockTokenIntrospector(ctrl)
	introspector.EXPECT().IntrospectToken(gomock.Any(), "some-token", gomock.Any(), gomock.Any(), gomock.Any()).
		Return(TokenUse(""), ErrTokenExpired.WithHint("secret reason"))

	provider := &Fosite{
		Store:  storage.NewMemoryStore(),
		Config: &Config{SSF: &SSFConfig{Issuer: "https://ssf.example.com"}, TokenIntrospectionHandlers: TokenIntrospectionHandlers{introspector}},
	}

	r := httptest.NewRequest(http.MethodGet, "https://ssf.example.com/ssf/stream", nil)
	r.Header.Set(consts.HeaderAuthorization, "Bearer some-token")

	_, _, err := provider.AuthorizeSSFRequestForTest(context.Background(), r, &DefaultSession{}, false)

	require.Error(t, err)

	rfc := ErrorToRFC6749Error(err)
	assert.Equal(t, http.StatusUnauthorized, rfc.StatusCode())
	assert.Equal(t, "invalid_token", rfc.ErrorField)
	assert.NotContains(t, rfc.GetDescription(), "secret reason")
}

func TestAuthorizeSSFRequestShouldReportStorageFailure(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	introspector := mock.NewMockTokenIntrospector(ctrl)
	introspector.EXPECT().IntrospectToken(gomock.Any(), "some-token", gomock.Any(), gomock.Any(), gomock.Any()).
		Return(TokenUse(""), ErrServerError.WithDebug("storage unavailable"))

	provider := &Fosite{
		Store:  storage.NewMemoryStore(),
		Config: &Config{SSF: &SSFConfig{Issuer: "https://ssf.example.com"}, TokenIntrospectionHandlers: TokenIntrospectionHandlers{introspector}},
	}

	r := httptest.NewRequest(http.MethodGet, "https://ssf.example.com/ssf/stream", nil)
	r.Header.Set(consts.HeaderAuthorization, "Bearer some-token")

	_, _, err := provider.AuthorizeSSFRequestForTest(context.Background(), r, &DefaultSession{}, false)

	require.ErrorIs(t, err, ErrServerError)

	rw := httptest.NewRecorder()

	provider.WriteSSFError(context.Background(), rw, r, err)

	assert.Equal(t, http.StatusInternalServerError, rw.Code)
	assert.Empty(t, rw.Header().Get(consts.HeaderWWWAuthenticate))
}

func TestGetSSFConfigRetainsHooks(t *testing.T) {
	policy := &testSSFPolicy{}

	config := (&Config{SSF: &SSFConfig{Issuer: "https://ssf.example.com", Policy: policy, MinVerificationInterval: 5}}).GetSSFConfig(context.Background())

	require.NotNil(t, config)
	assert.Same(t, policy, config.Policy)
	assert.Equal(t, "https://ssf.example.com", config.Audience)
	assert.EqualValues(t, 5, config.MinVerificationInterval)
}

type testSSFPolicy struct{}

func (*testSSFPolicy) SSFStreamPolicy(ctx context.Context, client Client) (policy *SSFClientPolicy, err error) {
	return nil, nil
}

func TestAuthorizeSSFRequestDPoP(t *testing.T) {
	const (
		audience = "https://ssf.example.com/ssf"
		target   = "https://ssf.example.com/ssf/stream"
		token    = "some-token"
	)

	newKey := func(t *testing.T) *jose.JSONWebKey {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		return &jose.JSONWebKey{Key: priv, Algorithm: string(jose.ES256)}
	}

	sign := func(t *testing.T, key *jose.JSONWebKey, jti string) string {
		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, (&jose.SignerOptions{EmbedJWK: true}).WithType("dpop+jwt"))
		require.NoError(t, err)

		sum := sha256.Sum256([]byte(token))

		raw, err := josejwt.Signed(signer).Claims(map[string]any{
			jwt.ClaimJWTID: jti, jwt.ClaimHTTPMethod: http.MethodPost, jwt.ClaimHTTPURI: target, jwt.ClaimIssuedAt: time.Now().Unix(), "ath": base64.RawURLEncoding.EncodeToString(sum[:]),
		}).Serialize()
		require.NoError(t, err)

		return raw
	}

	testCases := []struct {
		name    string
		scheme  string
		proof   func(t *testing.T, bound, other *jose.JSONWebKey) string
		allowed bool
	}{
		{name: "ShouldAcceptValidProof", scheme: "DPoP", proof: func(t *testing.T, bound, _ *jose.JSONWebKey) string { return sign(t, bound, "p1") }, allowed: true},
		{name: "ShouldRejectNoProof", scheme: "DPoP", proof: func(*testing.T, *jose.JSONWebKey, *jose.JSONWebKey) string { return "" }},
		{name: "ShouldRejectWrongKey", scheme: "DPoP", proof: func(t *testing.T, _, other *jose.JSONWebKey) string { return sign(t, other, "p2") }},
		{name: "ShouldRejectBoundTokenUnderBearer", scheme: "Bearer", proof: func(t *testing.T, bound, _ *jose.JSONWebKey) string { return sign(t, bound, "p3") }},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			bound, other := newKey(t), newKey(t)

			jkt, err := jwt.ThumbprintJWK(bound)
			require.NoError(t, err)

			store := storage.NewMemoryStore()

			config := &Config{
				DPoPEnabled:              true,
				DPoPAllowedJWSAlgorithms: []string{"ES256"},
				SSF:                      &SSFConfig{Issuer: "https://ssf.example.com", Audience: audience},
			}

			config.DPoPStrategy = rfc9449.NewDefaultStrategy(config, store)

			introspector := mock.NewMockTokenIntrospector(ctrl)
			config.TokenIntrospectionHandlers = TokenIntrospectionHandlers{introspector}

			introspector.EXPECT().IntrospectToken(gomock.Any(), token, gomock.Any(), gomock.Any(), gomock.Any()).
				Do(func(_ context.Context, _ string, _ TokenUse, requester AccessRequester, _ []string) {
					ar := requester.(*AccessRequest)
					ar.GrantedScope = []string{consts.ScopeSSFManage}
					ar.GrantedAudience = []string{audience}
					ar.Client = &DefaultClient{ID: "client"}
					ar.Session = &DefaultSession{JWKThumbprint: jkt}
				}).Return(AccessToken, nil)

			provider := &Fosite{Store: store, Config: config}

			r := httptest.NewRequest(http.MethodPost, target, nil)
			r.Header.Set(consts.HeaderAuthorization, tc.scheme+" "+token)

			if proof := tc.proof(t, bound, other); proof != "" {
				r.Header.Set(consts.HeaderDPoP, proof)
			}

			requester, _, err := provider.AuthorizeSSFRequestForTest(context.Background(), r, &DefaultSession{}, false)

			if tc.allowed {
				require.NoError(t, err)
				assert.NotNil(t, requester)

				return
			}

			require.Error(t, err)
			assert.Nil(t, requester)
			assert.Contains(t, []int{http.StatusUnauthorized, http.StatusBadRequest}, ErrorToRFC6749Error(err).StatusCode())
		})
	}
}

func TestAuthorizeSSFRequestHeaderOnly(t *testing.T) {
	const target = "https://ssf.example.com/ssf/stream"

	form := "application/x-www-form-urlencoded"

	testCases := []struct {
		name        string
		method      string
		target      string
		contentType string
		body        string
		header      string
		code        int
		listed      string
	}{
		{name: "ShouldRejectQueryToken", method: http.MethodGet, target: target + "?access_token=tok-a", code: http.StatusUnauthorized},
		{name: "ShouldRejectFormToken", method: http.MethodPost, target: target, contentType: form, body: "access_token=tok-a", code: http.StatusUnauthorized},
		{name: "ShouldRejectQueryTokenWithBasicHeader", method: http.MethodGet, target: target + "?access_token=tok-a", header: "Basic abc", code: http.StatusUnauthorized},
		{name: "ShouldAcceptBearerHeaderWithSeveralSpaces", method: http.MethodGet, target: target, header: "bearer   tok-a", code: http.StatusOK, listed: "a"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			h := newSSFHandlerHarness(t, nil)
			id := h.createStream(t, "a", `{}`)

			r := httptest.NewRequest(tc.method, tc.target, strings.NewReader(tc.body))

			if tc.header != "" {
				r.Header.Set(consts.HeaderAuthorization, tc.header)
			}

			if tc.contentType != "" {
				r.Header.Set(consts.HeaderContentType, tc.contentType)
			}

			rw := httptest.NewRecorder()

			requester, err := h.provider.NewSSFStreamRequest(context.Background(), r, &DefaultSession{})

			if tc.code != http.StatusOK {
				require.Error(t, err)
				h.provider.WriteSSFError(context.Background(), rw, r, err)
				assert.Equal(t, tc.code, rw.Code)
				assert.Contains(t, rw.Body.String(), "invalid_token")
				assert.NotEmpty(t, rw.Header().Get(consts.HeaderWWWAuthenticate))
				assert.Nil(t, r.Form, "the request must not be parsed for a token")

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.listed, requester.GetClient().GetID())

			responder, err := h.provider.NewSSFStreamResponse(context.Background(), requester)
			require.NoError(t, err)

			streams, ok := responder.GetBody().([]*SSFStream)
			require.True(t, ok)
			require.Len(t, streams, 1)
			assert.Equal(t, id, streams[0].StreamID)
		})
	}

	t.Run("ShouldRejectHeaderAndParameterToken", func(t *testing.T) {
		for _, scheme := range []string{"Bearer", "DPoP"} {
			h := newSSFHandlerHarness(t, nil)

			r := httptest.NewRequest(http.MethodGet, target+"?access_token=tok-b", nil)
			r.Header.Set(consts.HeaderAuthorization, scheme+" tok-a")

			_, err := h.provider.NewSSFStreamRequest(context.Background(), r, &DefaultSession{})
			require.ErrorIs(t, err, ErrInvalidRequest, scheme)

			rw := httptest.NewRecorder()

			h.provider.WriteSSFError(context.Background(), rw, r, err)

			assert.Equal(t, http.StatusBadRequest, rw.Code, scheme)
			assert.Empty(t, rw.Header().Get(consts.HeaderWWWAuthenticate), scheme)
			assert.Nil(t, r.Form, scheme)
		}
	})

	t.Run("ShouldRejectHeaderAndParsedFormToken", func(t *testing.T) {
		h := newSSFHandlerHarness(t, nil)

		r := httptest.NewRequest(http.MethodGet, target, nil)
		r.Header.Set(consts.HeaderAuthorization, "Bearer tok-a")
		r.Form = url.Values{"access_token": {"tok-b"}}

		_, err := h.provider.NewSSFStreamRequest(context.Background(), r, &DefaultSession{})
		assert.ErrorIs(t, err, ErrInvalidRequest)
	})

	t.Run("ShouldRejectMultipleAuthorizationHeaders", func(t *testing.T) {
		h := newSSFHandlerHarness(t, nil)

		r := httptest.NewRequest(http.MethodGet, target, nil)
		r.Header.Add(consts.HeaderAuthorization, "Bearer tok-a")
		r.Header.Add(consts.HeaderAuthorization, "Bearer tok-b")

		_, err := h.provider.NewSSFStreamRequest(context.Background(), r, &DefaultSession{})
		assert.ErrorIs(t, err, ErrInvalidRequest)
	})
}

// ssfRawConfig is a provider returning its SSFConfig as is, without defaults.
type ssfRawConfig struct {
	*Config

	raw *SSFConfig
}

func (c *ssfRawConfig) GetSSFConfig(ctx context.Context) (config *SSFConfig) {
	return c.raw
}

func TestSSFConfigWithDefaults(t *testing.T) {
	config := SSFConfig{Issuer: "https://ssf.example.com"}.WithDefaults()

	assert.Equal(t, "https://ssf.example.com", config.Audience)
	assert.EqualValues(t, 1<<16, config.MaxRequestBytes)

	config = SSFConfig{Issuer: "https://ssf.example.com", Audience: "https://aud.example.com", MaxRequestBytes: 10}.WithDefaults()

	assert.Equal(t, "https://aud.example.com", config.Audience)
	assert.EqualValues(t, 10, config.MaxRequestBytes)

	config = SSFConfig{MaxRequestBytes: -1}.WithDefaults()

	assert.EqualValues(t, 1<<16, config.MaxRequestBytes)
}

func TestSSFRawConfigProvider(t *testing.T) {
	h := newSSFHandlerHarness(t, nil)

	base := h.provider.Config.(*Config)

	// The token audience of the harness is ssfHandlerAudience, reached here only through the Issuer default.
	raw := &SSFConfig{Issuer: ssfHandlerAudience, Policy: base.SSF.Policy, PollEndpointURL: base.SSF.PollEndpointURL}

	h.provider.Config = &ssfRawConfig{Config: base, raw: raw}

	rw := h.do(t, "a", http.MethodPost, ssfHandlerURL, "application/json", `{"description":"d"}`)
	require.Equal(t, http.StatusCreated, rw.Code, rw.Body.String())

	assert.Empty(t, raw.Audience)
	assert.Zero(t, raw.MaxRequestBytes)

	t.Run("ShouldBoundBodyByDefaultLimit", func(t *testing.T) {
		rw := h.do(t, "b", http.MethodPost, ssfHandlerURL, "application/json", `{"description":"`+strings.Repeat("x", 1<<16)+`"}`)
		assert.Equal(t, http.StatusBadRequest, rw.Code)
		assert.Contains(t, rw.Body.String(), "too large")
	})

	t.Run("ShouldStayNilWhenUnconfigured", func(t *testing.T) {
		h.provider.Config = &ssfRawConfig{Config: base}

		rw := h.do(t, "c", http.MethodGet, ssfHandlerURL, "", "")
		assert.Equal(t, http.StatusInternalServerError, rw.Code)
	})
}
