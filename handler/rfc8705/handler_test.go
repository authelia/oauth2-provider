// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc8705

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/handler/openid"
	"authelia.com/provider/oauth2/internal/gen"
)

func TestHandlerBindsCertificate(t *testing.T) {
	cert := gen.MustCertificate(gen.CertificateOptions{})

	session := &oauth2.DefaultSession{}
	request := oauth2.NewAccessRequest(session)
	request.Client = &oauth2.DefaultClient{TLSClientCertificateBoundAccessTokens: true}

	err := newTestHandler(true, false).HandleTokenEndpointRequest(ctxWithCertificate(cert), request)

	assert.ErrorIs(t, err, oauth2.ErrUnknownRequest)
	assert.Equal(t, oauth2.X509CertificateSHA256Thumbprint(cert), session.GetClientCertificateSHA256Thumbprint())
}

func TestHandlerBindsCertificateWhenEnforced(t *testing.T) {
	cert := gen.MustCertificate(gen.CertificateOptions{})

	session := &oauth2.DefaultSession{}
	request := oauth2.NewAccessRequest(session)
	request.Client = &oauth2.DefaultClient{}

	err := newTestHandler(true, true).HandleTokenEndpointRequest(ctxWithCertificate(cert), request)

	assert.ErrorIs(t, err, oauth2.ErrUnknownRequest)
	assert.Equal(t, oauth2.X509CertificateSHA256Thumbprint(cert), session.GetClientCertificateSHA256Thumbprint())
}

func TestHandlerBindsCertificateForAPublicClient(t *testing.T) {
	cert := gen.MustCertificate(gen.CertificateOptions{})

	session := &oauth2.DefaultSession{}
	request := oauth2.NewAccessRequest(session)
	request.Client = &oauth2.DefaultClient{Public: true, TLSClientCertificateBoundAccessTokens: true}

	err := newTestHandler(true, false).HandleTokenEndpointRequest(ctxWithCertificate(cert), request)

	assert.ErrorIs(t, err, oauth2.ErrUnknownRequest)
	assert.Equal(t, oauth2.X509CertificateSHA256Thumbprint(cert), session.GetClientCertificateSHA256Thumbprint())
}

func TestHandlerRequiredButMissing(t *testing.T) {
	session := &oauth2.DefaultSession{}
	request := oauth2.NewAccessRequest(session)
	request.Client = &oauth2.DefaultClient{TLSClientCertificateBoundAccessTokens: true}

	err := newTestHandler(true, false).HandleTokenEndpointRequest(ctxWithCertificate(nil), request)

	assert.ErrorIs(t, err, oauth2.ErrInvalidRequest)
	assert.Empty(t, session.GetClientCertificateSHA256Thumbprint())
}

func TestHandlerRefreshThumbprintMismatch(t *testing.T) {
	bound := gen.MustCertificate(gen.CertificateOptions{})
	presented := gen.MustCertificate(gen.CertificateOptions{SerialNumber: 2})

	session := &oauth2.DefaultSession{}
	session.SetClientCertificateSHA256Thumbprint(oauth2.X509CertificateSHA256Thumbprint(bound))

	request := oauth2.NewAccessRequest(session)
	request.Client = &oauth2.DefaultClient{}

	err := newTestHandler(true, false).HandleTokenEndpointRequest(ctxWithCertificate(presented), request)

	assert.ErrorIs(t, err, oauth2.ErrInvalidGrant)
	assert.Equal(t, oauth2.X509CertificateSHA256Thumbprint(bound), session.GetClientCertificateSHA256Thumbprint())
}

func TestHandlerRefreshRequiresTheBoundCertificate(t *testing.T) {
	bound := gen.MustCertificate(gen.CertificateOptions{})

	session := &oauth2.DefaultSession{}
	session.SetClientCertificateSHA256Thumbprint(oauth2.X509CertificateSHA256Thumbprint(bound))

	request := oauth2.NewAccessRequest(session)
	request.Client = &oauth2.DefaultClient{}

	err := newTestHandler(true, false).HandleTokenEndpointRequest(ctxWithCertificate(nil), request)

	assert.ErrorIs(t, err, oauth2.ErrInvalidRequest)
}

func TestHandlerIgnoresUnboundRequests(t *testing.T) {
	session := &oauth2.DefaultSession{}
	request := oauth2.NewAccessRequest(session)
	request.Client = &oauth2.DefaultClient{}

	err := newTestHandler(true, false).HandleTokenEndpointRequest(ctxWithCertificate(nil), request)

	assert.ErrorIs(t, err, oauth2.ErrUnknownRequest)
	assert.Empty(t, session.GetClientCertificateSHA256Thumbprint())
}

func TestHandlerDisabled(t *testing.T) {
	cert := gen.MustCertificate(gen.CertificateOptions{})

	session := &oauth2.DefaultSession{}
	request := oauth2.NewAccessRequest(session)
	request.Client = &oauth2.DefaultClient{TLSClientCertificateBoundAccessTokens: true}

	err := newTestHandler(false, false).HandleTokenEndpointRequest(ctxWithCertificate(cert), request)

	assert.ErrorIs(t, err, oauth2.ErrUnknownRequest)
	assert.Empty(t, session.GetClientCertificateSHA256Thumbprint())
}

func TestHandlerSessionDoesNotSupportBinding(t *testing.T) {
	cert := gen.MustCertificate(gen.CertificateOptions{})

	request := oauth2.NewAccessRequest(&unboundSession{})
	request.Client = &oauth2.DefaultClient{TLSClientCertificateBoundAccessTokens: true}

	err := newTestHandler(true, false).HandleTokenEndpointRequest(ctxWithCertificate(cert), request)

	assert.ErrorIs(t, err, oauth2.ErrServerError)
}

func TestHandlerIgnoresIncidentalCertificateOnUnbindableSession(t *testing.T) {
	cert := gen.MustCertificate(gen.CertificateOptions{})

	request := oauth2.NewAccessRequest(&unboundSession{})
	request.Client = &oauth2.DefaultClient{}

	err := newTestHandler(true, false).HandleTokenEndpointRequest(ctxWithCertificate(cert), request)

	assert.ErrorIs(t, err, oauth2.ErrUnknownRequest)
	assert.NotErrorIs(t, err, oauth2.ErrServerError)
}

func TestHandlerSessionDoesNotSupportBindingWhenEnforced(t *testing.T) {
	cert := gen.MustCertificate(gen.CertificateOptions{})

	request := oauth2.NewAccessRequest(&unboundSession{})
	request.Client = &oauth2.DefaultClient{}

	err := newTestHandler(true, true).HandleTokenEndpointRequest(ctxWithCertificate(cert), request)

	assert.ErrorIs(t, err, oauth2.ErrServerError)
}

func TestHandlerBindsOpenIDSession(t *testing.T) {
	cert := gen.MustCertificate(gen.CertificateOptions{})

	session := openid.NewDefaultSession()
	request := oauth2.NewAccessRequest(session)
	request.Client = &oauth2.DefaultClient{TLSClientCertificateBoundAccessTokens: true}

	err := newTestHandler(true, false).HandleTokenEndpointRequest(ctxWithCertificate(cert), request)

	assert.ErrorIs(t, err, oauth2.ErrUnknownRequest)
	assert.Equal(t, oauth2.X509CertificateSHA256Thumbprint(cert), session.GetClientCertificateSHA256Thumbprint())
}

func TestHandlerPopulateTokenEndpointResponseLeavesTokenTypeAlone(t *testing.T) {
	session := &oauth2.DefaultSession{}
	session.SetClientCertificateSHA256Thumbprint("test-x5t")

	request := oauth2.NewAccessRequest(session)
	request.Client = &oauth2.DefaultClient{}

	response := oauth2.NewAccessResponse()
	response.SetTokenType(oauth2.BearerAccessToken)

	require.NoError(t, newTestHandler(true, false).PopulateTokenEndpointResponse(context.Background(), request, response))

	assert.Equal(t, oauth2.BearerAccessToken, response.GetTokenType())
}

func TestHandlerCanHandleTokenEndpointRequest(t *testing.T) {
	request := oauth2.NewAccessRequest(&oauth2.DefaultSession{})

	t.Run("ShouldNotHandleWhenNoOtherHandlerWill", func(t *testing.T) {
		h := &Handler{Config: &oauth2.Config{MTLSEnabled: true}}

		assert.False(t, h.CanHandleTokenEndpointRequest(context.Background(), request))
	})

	t.Run("ShouldHandleWhenAnotherHandlerWill", func(t *testing.T) {
		config := &oauth2.Config{MTLSEnabled: true}
		h := &Handler{Config: config}

		config.TokenEndpointHandlers = oauth2.TokenEndpointHandlers{h, &willHandle{}}

		assert.True(t, h.CanHandleTokenEndpointRequest(context.Background(), request))
	})

	t.Run("ShouldNotRecurseOnADuplicateRegistration", func(t *testing.T) {
		config := &oauth2.Config{MTLSEnabled: true}
		h := &Handler{Config: config}

		config.TokenEndpointHandlers = oauth2.TokenEndpointHandlers{h, &Handler{Config: config}}

		assert.False(t, h.CanHandleTokenEndpointRequest(context.Background(), request))
	})

	assert.True(t, (&Handler{Config: &oauth2.Config{MTLSEnabled: true}}).CanSkipClientAuth(context.Background(), request))
}

type unboundSession struct {
	oauth2.Session
}

type willHandle struct{}

func (h *willHandle) HandleTokenEndpointRequest(context.Context, oauth2.AccessRequester) error {
	return nil
}

func (h *willHandle) PopulateTokenEndpointResponse(context.Context, oauth2.AccessRequester, oauth2.AccessResponder) error {
	return nil
}

func (h *willHandle) CanSkipClientAuth(context.Context, oauth2.AccessRequester) bool { return false }

func (h *willHandle) CanHandleTokenEndpointRequest(context.Context, oauth2.AccessRequester) bool {
	return true
}

func newTestHandler(enabled, enforce bool) *Handler {
	return &Handler{Config: &oauth2.Config{MTLSEnabled: enabled, MTLSEnforce: enforce}}
}

func ctxWithCertificate(cert *x509.Certificate) context.Context {
	r := &http.Request{Method: http.MethodPost, Header: http.Header{}}

	if cert != nil {
		r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	}

	return context.WithValue(context.Background(), oauth2.RequestContextKey, r)
}
