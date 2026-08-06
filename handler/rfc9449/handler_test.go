// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc9449

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestHandlerBindsProof(t *testing.T) {
	h, _, _ := newTestHandler(false)
	key := newTestProofKey(t)
	raw := signProof(t, key, jwt.JSONWebTokenTypeDPoP, map[string]any{
		jwt.ClaimJWTID: "h1", jwt.ClaimHTTPMethod: http.MethodPost, jwt.ClaimHTTPURI: "https://as.example.com/token", jwt.ClaimIssuedAt: time.Now().Unix(),
	})

	session := &oauth2.DefaultSession{}
	request := oauth2.NewAccessRequest(session)
	request.Client = &oauth2.DefaultClient{}

	ctx := ctxWithDPoP(http.MethodPost, "https://as.example.com/token", raw)

	assert.NoError(t, h.BindAccessRequest(ctx, request))
	assert.NotEmpty(t, session.GetDPoPJWKThumbprint())
}

func TestHandlerRejectsMultipleDPoPHeaders(t *testing.T) {
	h, _, _ := newTestHandler(false)
	key := newTestProofKey(t)
	raw := signProof(t, key, jwt.JSONWebTokenTypeDPoP, map[string]any{
		jwt.ClaimJWTID: "multi-1", jwt.ClaimHTTPMethod: http.MethodPost, jwt.ClaimHTTPURI: "https://as.example.com/token", jwt.ClaimIssuedAt: time.Now().Unix(),
	})

	u, _ := url.Parse("https://as.example.com/token")
	r := &http.Request{Method: http.MethodPost, Header: http.Header{}, URL: u, Host: u.Host}

	r.Header.Set(consts.HeaderXForwardedProto, consts.SchemeHTTPS)
	r.Header.Add(consts.HeaderDPoP, raw)
	r.Header.Add(consts.HeaderDPoP, raw)

	ctx := context.WithValue(context.Background(), oauth2.RequestContextKey, r)

	session := &oauth2.DefaultSession{}
	request := oauth2.NewAccessRequest(session)
	request.Client = &oauth2.DefaultClient{}

	err := h.BindAccessRequest(ctx, request)
	assert.ErrorIs(t, err, oauth2.ErrInvalidDPoPProof)
	assert.Empty(t, session.GetDPoPJWKThumbprint())
}

func TestHandlerRequiredButMissing(t *testing.T) {
	h, _, _ := newTestHandler(true)

	session := &oauth2.DefaultSession{}
	request := oauth2.NewAccessRequest(session)
	request.Client = &oauth2.DefaultClient{}

	ctx := ctxWithDPoP(http.MethodPost, "https://as.example.com/token", "")
	err := h.BindAccessRequest(ctx, request)
	assert.ErrorIs(t, err, oauth2.ErrInvalidDPoPProof)
}

func TestHandlerAuthorize(t *testing.T) {
	testCases := []struct {
		name          string
		enabled       bool
		session       oauth2.Session
		jkt           string
		responseTypes oauth2.Arguments
		wantErr       error
		wantJKT       string
	}{
		{
			name:          "RecordsDPoPJKT",
			enabled:       true,
			session:       &oauth2.DefaultSession{},
			jkt:           testAuthorizeJKT,
			responseTypes: oauth2.Arguments{consts.ResponseTypeAuthorizationCodeFlow},
			wantJKT:       testAuthorizeJKT,
		},
		{
			name:    "DisabledLeavesSessionUnchanged",
			enabled: false,
			session: &oauth2.DefaultSession{},
			jkt:     testAuthorizeJKT,
		},
		{
			name:    "NoDPoPJKTLeavesSessionUnchanged",
			enabled: true,
			session: &oauth2.DefaultSession{},
		},
		{
			name:          "RecordsDPoPJKTOnlyForCodeFlow",
			enabled:       true,
			session:       &oauth2.DefaultSession{},
			jkt:           testAuthorizeJKT,
			responseTypes: oauth2.Arguments{consts.ResponseTypeImplicitFlowToken},
		},
		{
			name:          "RecordsDPoPJKTForCodeIDTokenHybridFlow",
			enabled:       true,
			session:       &oauth2.DefaultSession{},
			jkt:           testAuthorizeJKT,
			responseTypes: oauth2.Arguments{consts.ResponseTypeAuthorizationCodeFlow, consts.ResponseTypeImplicitFlowIDToken},
			wantJKT:       testAuthorizeJKT,
		},
		{
			name:          "SkipsHybridFlowIssuingAnAccessTokenDirectly",
			enabled:       true,
			session:       &oauth2.DefaultSession{},
			jkt:           testAuthorizeJKT,
			responseTypes: oauth2.Arguments{consts.ResponseTypeAuthorizationCodeFlow, consts.ResponseTypeImplicitFlowToken},
		},
		{
			name:          "NonDPoPSessionReturnsServerError",
			enabled:       true,
			session:       nonDPoPSession{},
			jkt:           testAuthorizeJKT,
			responseTypes: oauth2.Arguments{consts.ResponseTypeAuthorizationCodeFlow},
			wantErr:       oauth2.ErrServerError,
		},
		{
			name:          "RejectsMalformedDPoPJKT",
			enabled:       true,
			session:       &oauth2.DefaultSession{},
			jkt:           "not-a-thumbprint",
			responseTypes: oauth2.Arguments{consts.ResponseTypeAuthorizationCodeFlow},
			wantErr:       oauth2.ErrInvalidRequest,
		},
		{
			name:          "RejectsOverlongDPoPJKT",
			enabled:       true,
			session:       &oauth2.DefaultSession{},
			jkt:           strings.Repeat("A", 4096),
			responseTypes: oauth2.Arguments{consts.ResponseTypeAuthorizationCodeFlow},
			wantErr:       oauth2.ErrInvalidRequest,
		},
		{
			name:          "RejectsDPoPJKTOutsideTheBase64URLAlphabet",
			enabled:       true,
			session:       &oauth2.DefaultSession{},
			jkt:           "kM1FTfCFVzO9tGKBVBEAWCVoWZ2WcOK1EbSPxNjQfS+",
			responseTypes: oauth2.Arguments{consts.ResponseTypeAuthorizationCodeFlow},
			wantErr:       oauth2.ErrInvalidRequest,
		},
		{
			name:          "RejectsMalformedDPoPJKTForSkippedFlow",
			enabled:       true,
			session:       &oauth2.DefaultSession{},
			jkt:           "not-a-thumbprint",
			responseTypes: oauth2.Arguments{consts.ResponseTypeImplicitFlowToken},
			wantErr:       oauth2.ErrInvalidRequest,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, cfg := newTestHandler(false)
			cfg.enabled = tc.enabled

			h := &AuthorizeHandler{Config: cfg}

			ar := oauth2.NewAuthorizeRequest()
			ar.Client = &oauth2.DefaultClient{}
			ar.Session = tc.session

			if tc.jkt != "" {
				ar.Form.Set(consts.FormParameterDPoPJKT, tc.jkt)
			}

			if tc.responseTypes != nil {
				ar.ResponseTypes = tc.responseTypes
			}

			err := h.BindAuthorizeRequest(context.Background(), ar)
			if tc.wantErr != nil {
				assert.ErrorIs(t, err, tc.wantErr)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.wantJKT, tc.session.(*oauth2.DefaultSession).GetDPoPJWKThumbprint())
		})
	}
}

func TestHandlerRefreshThumbprintMismatch(t *testing.T) {
	h, _, _ := newTestHandler(false)
	key := newTestProofKey(t)
	raw := signProof(t, key, jwt.JSONWebTokenTypeDPoP, map[string]any{
		jwt.ClaimJWTID: "h2", jwt.ClaimHTTPMethod: http.MethodPost, jwt.ClaimHTTPURI: "https://as.example.com/token", jwt.ClaimIssuedAt: time.Now().Unix(),
	})

	session := &oauth2.DefaultSession{}
	session.SetDPoPJWKThumbprint("some-other-thumbprint")
	request := oauth2.NewAccessRequest(session)
	request.Client = &oauth2.DefaultClient{}

	ctx := ctxWithDPoP(http.MethodPost, "https://as.example.com/token", raw)
	err := h.BindAccessRequest(ctx, request)
	assert.ErrorIs(t, err, oauth2.ErrInvalidDPoPProof)
}

func TestHandlerIsANoOpWhenUnbound(t *testing.T) {
	h, _, _ := newTestHandler(false)

	session := &oauth2.DefaultSession{}
	request := oauth2.NewAccessRequest(session)
	request.Client = &oauth2.DefaultClient{}

	ctx := ctxWithDPoP(http.MethodPost, "https://as.example.com/token", "")

	require.NoError(t, h.BindAccessRequest(ctx, request))
	assert.Empty(t, session.GetDPoPJWKThumbprint())
}

func TestHandlerPopulateBoundTokenEndpointResponseSetsDPoPTokenType(t *testing.T) {
	h, _, _ := newTestHandler(false)

	session := &oauth2.DefaultSession{}
	session.SetDPoPJWKThumbprint("some-thumbprint")
	request := oauth2.NewAccessRequest(session)
	request.Client = &oauth2.DefaultClient{}

	response := oauth2.NewAccessResponse()

	require.NoError(t, h.PopulateBoundTokenEndpointResponse(context.Background(), request, response))
	assert.Equal(t, oauth2.DPoPAccessToken, response.GetTokenType())
}

func TestDPoPEndToEndBindingAndRefresh(t *testing.T) {
	h, _, _ := newTestHandler(false)
	key := newTestProofKey(t)

	session := &oauth2.DefaultSession{}
	request := oauth2.NewAccessRequest(session)
	request.Client = &oauth2.DefaultClient{DPoPBoundAccessTokens: true}

	raw1 := signProof(t, key, jwt.JSONWebTokenTypeDPoP, map[string]any{
		jwt.ClaimJWTID: "e2e-1", jwt.ClaimHTTPMethod: http.MethodPost, jwt.ClaimHTTPURI: "https://as.example.com/token", jwt.ClaimIssuedAt: time.Now().Unix(),
	})
	ctx1 := ctxWithDPoP(http.MethodPost, "https://as.example.com/token", raw1)

	require.NoError(t, h.BindAccessRequest(ctx1, request))
	jkt := session.GetDPoPJWKThumbprint()
	require.NotEmpty(t, jkt)

	refreshSession := &oauth2.DefaultSession{}
	refreshSession.SetDPoPJWKThumbprint(jkt)
	refreshRequest := oauth2.NewAccessRequest(refreshSession)
	refreshRequest.Client = &oauth2.DefaultClient{DPoPBoundAccessTokens: true}

	raw2 := signProof(t, key, jwt.JSONWebTokenTypeDPoP, map[string]any{
		jwt.ClaimJWTID: "e2e-2", jwt.ClaimHTTPMethod: http.MethodPost, jwt.ClaimHTTPURI: "https://as.example.com/token", jwt.ClaimIssuedAt: time.Now().Unix(),
	})
	ctx2 := ctxWithDPoP(http.MethodPost, "https://as.example.com/token", raw2)

	require.NoError(t, h.BindAccessRequest(ctx2, refreshRequest))
	assert.Equal(t, jkt, refreshSession.GetDPoPJWKThumbprint())

	otherKey := newTestProofKey(t)
	otherSession := &oauth2.DefaultSession{}
	otherSession.SetDPoPJWKThumbprint(jkt)
	otherRequest := oauth2.NewAccessRequest(otherSession)
	otherRequest.Client = &oauth2.DefaultClient{DPoPBoundAccessTokens: true}

	raw3 := signProof(t, otherKey, jwt.JSONWebTokenTypeDPoP, map[string]any{
		jwt.ClaimJWTID: "e2e-3", jwt.ClaimHTTPMethod: http.MethodPost, jwt.ClaimHTTPURI: "https://as.example.com/token", jwt.ClaimIssuedAt: time.Now().Unix(),
	})
	ctx3 := ctxWithDPoP(http.MethodPost, "https://as.example.com/token", raw3)

	err := h.BindAccessRequest(ctx3, otherRequest)
	assert.ErrorIs(t, err, oauth2.ErrInvalidDPoPProof)
}

func TestHandlerBindAccessRequestWithoutAnHTTPRequest(t *testing.T) {
	t.Run("ShouldNoOpWhenNothingRequiresABinding", func(t *testing.T) {
		h, _, _ := newTestHandler(false)

		session := &oauth2.DefaultSession{}
		request := oauth2.NewAccessRequest(session)
		request.Client = &oauth2.DefaultClient{}

		require.NoError(t, h.BindAccessRequest(context.Background(), request))
		assert.Empty(t, session.GetDPoPJWKThumbprint())
	})

	t.Run("ShouldErrorWhenTheSessionIsAlreadyBound", func(t *testing.T) {
		h, _, _ := newTestHandler(false)

		session := &oauth2.DefaultSession{}
		session.SetDPoPJWKThumbprint("an-existing-thumbprint")

		request := oauth2.NewAccessRequest(session)
		request.Client = &oauth2.DefaultClient{}

		assert.ErrorIs(t, h.BindAccessRequest(context.Background(), request), oauth2.ErrServerError)
	})

	t.Run("ShouldErrorWhenEnforced", func(t *testing.T) {
		h, _, _ := newTestHandler(true)

		request := oauth2.NewAccessRequest(&oauth2.DefaultSession{})
		request.Client = &oauth2.DefaultClient{}

		assert.ErrorIs(t, h.BindAccessRequest(context.Background(), request), oauth2.ErrServerError)
	})
}

const testAuthorizeJKT = "kM1FTfCFVzO9tGKBVBEAWCVoWZ2WcOK1EbSPxNjQfSw"

type testHandlerConfig struct {
	testStrategyConfig
	enabled, enforce, nonceRequired bool
	strategy                        oauth2.DPoPStrategy
}

func (c *testHandlerConfig) GetDPoPEnabled(context.Context) bool { return c.enabled }

func (c *testHandlerConfig) GetDPoPEnforce(context.Context) bool { return c.enforce }

func (c *testHandlerConfig) GetDPoPNonceRequired(context.Context) bool { return c.nonceRequired }

func (c *testHandlerConfig) GetDPoPStrategy(context.Context) oauth2.DPoPStrategy { return c.strategy }

func newTestHandler(enforce bool) (*Handler, *storage.MemoryStore, *testHandlerConfig) {
	store := storage.NewMemoryStore()
	cfg := &testHandlerConfig{
		testStrategyConfig: testStrategyConfig{algs: []string{"ES256"}, skew: time.Minute, lifespan: time.Minute, nonceExp: time.Minute},
		enabled:            true,
		enforce:            enforce,
	}
	strategy := NewDefaultStrategy(cfg, store)
	cfg.strategy = strategy

	return &Handler{Config: cfg, Strategy: strategy}, store, cfg
}

func ctxWithDPoP(method, rawURL, proof string) context.Context {
	u, _ := url.Parse(rawURL)

	r := &http.Request{Method: method, Header: http.Header{}, URL: u, Host: u.Host}

	if u.Scheme == consts.SchemeHTTPS {
		r.Header.Set(consts.HeaderXForwardedProto, consts.SchemeHTTPS)
	}

	if proof != "" {
		r.Header.Set(consts.HeaderDPoP, proof)
	}

	return context.WithValue(context.Background(), oauth2.RequestContextKey, r)
}

type nonDPoPSession struct{}

func (nonDPoPSession) SetExpiresAt(oauth2.TokenType, time.Time) {}

func (nonDPoPSession) GetExpiresAt(oauth2.TokenType) time.Time { return time.Time{} }

func (nonDPoPSession) GetUsername() string { return "" }

func (nonDPoPSession) GetSubject() string { return "" }

func (nonDPoPSession) Clone() oauth2.Session { return nonDPoPSession{} }
