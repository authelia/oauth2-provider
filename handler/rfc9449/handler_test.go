// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc9449

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/token/jwt"
)

type testHandlerConfig struct {
	testStrategyConfig
	enabled, enforce, nonceRequired bool
	strategy                        oauth2.DPoPStrategy
}

func (c *testHandlerConfig) GetDPoPEnabled(context.Context) bool                 { return c.enabled }
func (c *testHandlerConfig) GetDPoPEnforce(context.Context) bool                 { return c.enforce }
func (c *testHandlerConfig) GetDPoPNonceRequired(context.Context) bool           { return c.nonceRequired }
func (c *testHandlerConfig) GetDPoPStrategy(context.Context) oauth2.DPoPStrategy { return c.strategy }

func newTestHandler(enforce bool) (*Handler, *storage.MemoryStore, *testHandlerConfig) {
	store := storage.NewMemoryStore()
	cfg := &testHandlerConfig{
		testStrategyConfig: testStrategyConfig{algs: []string{"ES256"}, skew: time.Minute, nonceExp: time.Minute},
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
	require.NoError(t, h.HandleTokenEndpointRequest(ctx, request))
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

	err := h.HandleTokenEndpointRequest(ctx, request)
	assert.ErrorIs(t, err, oauth2.ErrInvalidDPoPProof)
	assert.Empty(t, session.GetDPoPJWKThumbprint())
}

func TestHandlerRequiredButMissing(t *testing.T) {
	h, _, _ := newTestHandler(true)

	session := &oauth2.DefaultSession{}
	request := oauth2.NewAccessRequest(session)
	request.Client = &oauth2.DefaultClient{}

	ctx := ctxWithDPoP(http.MethodPost, "https://as.example.com/token", "")
	err := h.HandleTokenEndpointRequest(ctx, request)
	assert.ErrorIs(t, err, oauth2.ErrInvalidDPoPProof)
}

func TestHandlerAuthorizeRecordsDPoPJKT(t *testing.T) {
	h, _, _ := newTestHandler(false)

	session := &oauth2.DefaultSession{}
	ar := oauth2.NewAuthorizeRequest()
	ar.Client = &oauth2.DefaultClient{}
	ar.Session = session
	ar.Form.Set(consts.FormParameterDPoPJKT, "authz-jkt")
	ar.ResponseTypes = oauth2.Arguments{consts.ResponseTypeAuthorizationCodeFlow}

	require.NoError(t, h.HandleAuthorizeEndpointRequest(context.Background(), ar, oauth2.NewAuthorizeResponse()))
	assert.Equal(t, "authz-jkt", session.GetDPoPJWKThumbprint())
}

func TestHandlerAuthorizeDisabledLeavesSessionUnchanged(t *testing.T) {
	h, _, cfg := newTestHandler(false)
	cfg.enabled = false

	session := &oauth2.DefaultSession{}
	ar := oauth2.NewAuthorizeRequest()
	ar.Client = &oauth2.DefaultClient{}
	ar.Session = session
	ar.Form.Set(consts.FormParameterDPoPJKT, "authz-jkt")

	require.NoError(t, h.HandleAuthorizeEndpointRequest(context.Background(), ar, oauth2.NewAuthorizeResponse()))
	assert.Empty(t, session.GetDPoPJWKThumbprint())
}

func TestHandlerAuthorizeNoDPoPJKTLeavesSessionUnchanged(t *testing.T) {
	h, _, _ := newTestHandler(false)

	session := &oauth2.DefaultSession{}
	ar := oauth2.NewAuthorizeRequest()
	ar.Client = &oauth2.DefaultClient{}
	ar.Session = session

	require.NoError(t, h.HandleAuthorizeEndpointRequest(context.Background(), ar, oauth2.NewAuthorizeResponse()))
	assert.Empty(t, session.GetDPoPJWKThumbprint())
}

func TestHandlerRefreshThumbprintMismatch(t *testing.T) {
	h, _, _ := newTestHandler(false)
	key := newTestProofKey(t)
	raw := signProof(t, key, jwt.JSONWebTokenTypeDPoP, map[string]any{
		jwt.ClaimJWTID: "h2", jwt.ClaimHTTPMethod: http.MethodPost, jwt.ClaimHTTPURI: "https://as.example.com/token", jwt.ClaimIssuedAt: time.Now().Unix(),
	})

	// Session already bound to a different thumbprint (as if restored from a refresh token).
	session := &oauth2.DefaultSession{}
	session.SetDPoPJWKThumbprint("some-other-thumbprint")
	request := oauth2.NewAccessRequest(session)
	request.Client = &oauth2.DefaultClient{}

	ctx := ctxWithDPoP(http.MethodPost, "https://as.example.com/token", raw)
	err := h.HandleTokenEndpointRequest(ctx, request)
	assert.ErrorIs(t, err, oauth2.ErrInvalidDPoPProof)
}

func TestHandlerCanSkipClientAuth(t *testing.T) {
	h, _, _ := newTestHandler(false)

	assert.True(t, h.CanSkipClientAuth(context.Background(), oauth2.NewAccessRequest(&oauth2.DefaultSession{})))
}

func TestHandlerCanHandleTokenEndpointRequestGatedByEnabled(t *testing.T) {
	h, _, cfg := newTestHandler(false)
	request := oauth2.NewAccessRequest(&oauth2.DefaultSession{})

	assert.True(t, h.CanHandleTokenEndpointRequest(context.Background(), request))

	cfg.enabled = false
	assert.False(t, h.CanHandleTokenEndpointRequest(context.Background(), request))
}

func TestHandlerReturnsUnknownRequestWhenUnbound(t *testing.T) {
	h, _, _ := newTestHandler(false)

	session := &oauth2.DefaultSession{}
	request := oauth2.NewAccessRequest(session)
	request.Client = &oauth2.DefaultClient{}

	ctx := ctxWithDPoP(http.MethodPost, "https://as.example.com/token", "")
	err := h.HandleTokenEndpointRequest(ctx, request)
	assert.True(t, errors.Is(err, oauth2.ErrUnknownRequest))
}

// nonDPoPSession implements only oauth2.Session, not oauth2.DPoPBoundSession.
type nonDPoPSession struct{}

func (nonDPoPSession) SetExpiresAt(oauth2.TokenType, time.Time) {}
func (nonDPoPSession) GetExpiresAt(oauth2.TokenType) time.Time  { return time.Time{} }
func (nonDPoPSession) GetUsername() string                      { return "" }
func (nonDPoPSession) GetSubject() string                       { return "" }
func (nonDPoPSession) Clone() oauth2.Session                    { return nonDPoPSession{} }

func TestHandlerAuthorizeNonDPoPSessionReturnsServerError(t *testing.T) {
	h, _, _ := newTestHandler(false)

	ar := oauth2.NewAuthorizeRequest()
	ar.Client = &oauth2.DefaultClient{}
	ar.Session = nonDPoPSession{}
	ar.Form.Set(consts.FormParameterDPoPJKT, "authz-jkt")
	ar.ResponseTypes = oauth2.Arguments{consts.ResponseTypeAuthorizationCodeFlow}

	err := h.HandleAuthorizeEndpointRequest(context.Background(), ar, oauth2.NewAuthorizeResponse())
	assert.ErrorIs(t, err, oauth2.ErrServerError)
}

func TestHandlerPopulateTokenEndpointResponseSetsDPoPTokenType(t *testing.T) {
	h, _, _ := newTestHandler(false)

	session := &oauth2.DefaultSession{}
	session.SetDPoPJWKThumbprint("some-thumbprint")
	request := oauth2.NewAccessRequest(session)
	request.Client = &oauth2.DefaultClient{}

	response := oauth2.NewAccessResponse()

	require.NoError(t, h.PopulateTokenEndpointResponse(context.Background(), request, response))
	assert.Equal(t, oauth2.DPoPAccessToken, response.GetTokenType())
}

func TestHandlerAuthorizeRecordsDPoPJKTOnlyForCodeFlow(t *testing.T) {
	h, _, _ := newTestHandler(false)

	session := &oauth2.DefaultSession{}
	ar := oauth2.NewAuthorizeRequest()
	ar.Client = &oauth2.DefaultClient{}
	ar.Session = session
	ar.Form.Set(consts.FormParameterDPoPJKT, "authz-jkt")
	ar.ResponseTypes = oauth2.Arguments{consts.ResponseTypeImplicitFlowToken}

	require.NoError(t, h.HandleAuthorizeEndpointRequest(context.Background(), ar, oauth2.NewAuthorizeResponse()))
	assert.Empty(t, session.GetDPoPJWKThumbprint())
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

	require.NoError(t, h.HandleTokenEndpointRequest(ctx1, request))
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

	require.NoError(t, h.HandleTokenEndpointRequest(ctx2, refreshRequest))
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

	err := h.HandleTokenEndpointRequest(ctx3, otherRequest)
	assert.ErrorIs(t, err, oauth2.ErrInvalidDPoPProof)
}
