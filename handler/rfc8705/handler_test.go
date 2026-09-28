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
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/gen"
)

func TestHandlerBindsCertificate(t *testing.T) {
	cert := gen.MustCertificate(gen.CertificateOptions{})

	session := &oauth2.DefaultSession{}
	request := oauth2.NewAccessRequest(session)
	request.Client = &oauth2.DefaultClient{TLSClientCertificateBoundAccessTokens: true}

	err := newTestHandler(true, false).BindAccessRequest(ctxWithCertificate(cert), request)

	require.NoError(t, err)
	assert.Equal(t, oauth2.X509CertificateSHA256Thumbprint(cert), session.GetClientCertificateSHA256Thumbprint())
}

func TestHandlerBindsCertificateWhenEnforced(t *testing.T) {
	cert := gen.MustCertificate(gen.CertificateOptions{})

	session := &oauth2.DefaultSession{}
	request := oauth2.NewAccessRequest(session)
	request.Client = &oauth2.DefaultClient{}

	err := newTestHandler(true, true).BindAccessRequest(ctxWithCertificate(cert), request)

	require.NoError(t, err)
	assert.Equal(t, oauth2.X509CertificateSHA256Thumbprint(cert), session.GetClientCertificateSHA256Thumbprint())
}

func TestHandlerBindsCertificateForAPublicClient(t *testing.T) {
	cert := gen.MustCertificate(gen.CertificateOptions{})

	session := &oauth2.DefaultSession{}
	request := oauth2.NewAccessRequest(session)
	request.Client = &oauth2.DefaultClient{Public: true, TLSClientCertificateBoundAccessTokens: true}

	err := newTestHandler(true, false).BindAccessRequest(ctxWithCertificate(cert), request)

	require.NoError(t, err)
	assert.Equal(t, oauth2.X509CertificateSHA256Thumbprint(cert), session.GetClientCertificateSHA256Thumbprint())
}

func TestHandlerRequiredButMissing(t *testing.T) {
	session := &oauth2.DefaultSession{}
	request := oauth2.NewAccessRequest(session)
	request.Client = &oauth2.DefaultClient{TLSClientCertificateBoundAccessTokens: true}

	err := newTestHandler(true, false).BindAccessRequest(ctxWithCertificate(nil), request)

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

	err := newTestHandler(true, false).BindAccessRequest(ctxWithCertificate(presented), request)

	assert.ErrorIs(t, err, oauth2.ErrInvalidGrant)
	assert.Equal(t, oauth2.X509CertificateSHA256Thumbprint(bound), session.GetClientCertificateSHA256Thumbprint())
}

func TestHandlerRefreshRequiresTheBoundCertificate(t *testing.T) {
	bound := gen.MustCertificate(gen.CertificateOptions{})

	session := &oauth2.DefaultSession{}
	session.SetClientCertificateSHA256Thumbprint(oauth2.X509CertificateSHA256Thumbprint(bound))

	request := oauth2.NewAccessRequest(session)
	request.Client = &oauth2.DefaultClient{}

	err := newTestHandler(true, false).BindAccessRequest(ctxWithCertificate(nil), request)

	assert.ErrorIs(t, err, oauth2.ErrInvalidRequest)
}

func TestHandlerIgnoresUnboundRequests(t *testing.T) {
	session := &oauth2.DefaultSession{}
	request := oauth2.NewAccessRequest(session)
	request.Client = &oauth2.DefaultClient{}

	err := newTestHandler(true, false).BindAccessRequest(ctxWithCertificate(nil), request)

	require.NoError(t, err)
	assert.Empty(t, session.GetClientCertificateSHA256Thumbprint())
}

func TestHandlerIgnoresAnIncidentalCertificate(t *testing.T) {
	cert := gen.MustCertificate(gen.CertificateOptions{})

	session := &oauth2.DefaultSession{}
	request := oauth2.NewAccessRequest(session)
	request.Client = &oauth2.DefaultClient{}

	err := newTestHandler(true, false).BindAccessRequest(ctxWithCertificate(cert), request)

	require.NoError(t, err)
	assert.Empty(t, session.GetClientCertificateSHA256Thumbprint())
}

func TestHandlerDisabled(t *testing.T) {
	cert := gen.MustCertificate(gen.CertificateOptions{})

	session := &oauth2.DefaultSession{}
	request := oauth2.NewAccessRequest(session)
	request.Client = &oauth2.DefaultClient{TLSClientCertificateBoundAccessTokens: true}

	err := newTestHandler(false, false).BindAccessRequest(ctxWithCertificate(cert), request)

	require.NoError(t, err)
	assert.Empty(t, session.GetClientCertificateSHA256Thumbprint())
}

func TestHandlerSessionDoesNotSupportBinding(t *testing.T) {
	cert := gen.MustCertificate(gen.CertificateOptions{})

	request := oauth2.NewAccessRequest(&unboundSession{})
	request.Client = &oauth2.DefaultClient{TLSClientCertificateBoundAccessTokens: true}

	err := newTestHandler(true, false).BindAccessRequest(ctxWithCertificate(cert), request)

	assert.ErrorIs(t, err, oauth2.ErrServerError)
}

func TestHandlerIgnoresIncidentalCertificateOnUnbindableSession(t *testing.T) {
	cert := gen.MustCertificate(gen.CertificateOptions{})

	request := oauth2.NewAccessRequest(&unboundSession{})
	request.Client = &oauth2.DefaultClient{}

	err := newTestHandler(true, false).BindAccessRequest(ctxWithCertificate(cert), request)

	require.NoError(t, err)
}

func TestHandlerSessionDoesNotSupportBindingWhenEnforced(t *testing.T) {
	cert := gen.MustCertificate(gen.CertificateOptions{})

	request := oauth2.NewAccessRequest(&unboundSession{})
	request.Client = &oauth2.DefaultClient{}

	err := newTestHandler(true, true).BindAccessRequest(ctxWithCertificate(cert), request)

	assert.ErrorIs(t, err, oauth2.ErrServerError)
}

func TestHandlerBindsOpenIDSession(t *testing.T) {
	cert := gen.MustCertificate(gen.CertificateOptions{})

	session := openid.NewDefaultSession()
	request := oauth2.NewAccessRequest(session)
	request.Client = &oauth2.DefaultClient{TLSClientCertificateBoundAccessTokens: true}

	err := newTestHandler(true, false).BindAccessRequest(ctxWithCertificate(cert), request)

	require.NoError(t, err)
	assert.Equal(t, oauth2.X509CertificateSHA256Thumbprint(cert), session.GetClientCertificateSHA256Thumbprint())
}

func TestHandlerPopulateBoundTokenEndpointResponseLeavesTokenTypeAlone(t *testing.T) {
	session := &oauth2.DefaultSession{}
	session.SetClientCertificateSHA256Thumbprint("test-x5t")

	request := oauth2.NewAccessRequest(session)
	request.Client = &oauth2.DefaultClient{}

	response := oauth2.NewAccessResponse()
	response.SetTokenType(oauth2.BearerAccessToken)

	require.NoError(t, newTestHandler(true, false).PopulateBoundTokenEndpointResponse(context.Background(), request, response))

	assert.Equal(t, oauth2.BearerAccessToken, response.GetTokenType())
}

func TestHandlerBindAccessRequestWithoutAnHTTPRequest(t *testing.T) {
	t.Run("ShouldNoOpWhenNothingRequiresABinding", func(t *testing.T) {
		session := &oauth2.DefaultSession{}
		request := oauth2.NewAccessRequest(session)
		request.Client = &oauth2.DefaultClient{}

		require.NoError(t, newTestHandler(true, false).BindAccessRequest(context.Background(), request))
		assert.Empty(t, session.GetClientCertificateSHA256Thumbprint())
	})

	t.Run("ShouldErrorWhenTheSessionIsAlreadyBound", func(t *testing.T) {
		session := &oauth2.DefaultSession{}
		session.SetClientCertificateSHA256Thumbprint("an-existing-x5t")

		request := oauth2.NewAccessRequest(session)
		request.Client = &oauth2.DefaultClient{}

		err := newTestHandler(true, false).BindAccessRequest(context.Background(), request)

		assert.ErrorIs(t, err, oauth2.ErrServerError)
	})

	t.Run("ShouldErrorWhenEnforced", func(t *testing.T) {
		request := oauth2.NewAccessRequest(&oauth2.DefaultSession{})
		request.Client = &oauth2.DefaultClient{}

		err := newTestHandler(true, true).BindAccessRequest(context.Background(), request)

		assert.ErrorIs(t, err, oauth2.ErrServerError)
	})
}

func TestHandlerRefreshBinding(t *testing.T) {
	testCases := []struct {
		name         string
		public       bool
		strict       bool
		clientStrict bool
		noRotation   bool
		grantType    string
		certificate  bool
		err          error
	}{
		{name: "ShouldRebindConfidentialClientRefreshToThePresentedCertificate", grantType: consts.GrantTypeRefreshToken, certificate: true},
		{name: "ShouldRejectConfidentialClientRefreshWithoutACertificate", grantType: consts.GrantTypeRefreshToken, err: oauth2.ErrInvalidRequest},
		{name: "ShouldRejectPublicClientRefreshWithAnotherCertificate", public: true, grantType: consts.GrantTypeRefreshToken, certificate: true, err: oauth2.ErrInvalidGrant},
		{name: "ShouldRejectConfidentialClientTokenExchangeWithAnotherCertificate", grantType: consts.GrantTypeOAuthTokenExchange, certificate: true, err: oauth2.ErrInvalidGrant},
		{name: "ShouldRejectConfidentialClientRefreshWithAnotherCertificateWhenStrict", strict: true, grantType: consts.GrantTypeRefreshToken, certificate: true, err: oauth2.ErrInvalidGrant},
		{name: "ShouldRejectConfidentialClientRefreshWithAnotherCertificateWhenTheClientIsStrict", clientStrict: true, grantType: consts.GrantTypeRefreshToken, certificate: true, err: oauth2.ErrInvalidGrant},
		{name: "ShouldRebindConfidentialClientRefreshToThePresentedCertificateWithoutRotation", noRotation: true, grantType: consts.GrantTypeRefreshToken, certificate: true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			bound := oauth2.X509CertificateSHA256Thumbprint(gen.MustCertificate(gen.CertificateOptions{}))

			session := &oauth2.DefaultSession{}
			session.SetClientCertificateSHA256Thumbprint(bound)

			request := oauth2.NewAccessRequest(session)
			request.Client = &strictRefreshTokenBindingClient{DefaultClient: &oauth2.DefaultClient{Public: tc.public}, strict: tc.clientStrict}
			request.GrantTypes = oauth2.Arguments{tc.grantType}

			var presented *x509.Certificate

			if tc.certificate {
				presented = gen.MustCertificate(gen.CertificateOptions{SerialNumber: 2})
			}

			h := &Handler{Config: &oauth2.Config{MTLSEnabled: true, MTLSStrictRefreshTokenBinding: tc.strict, DisableRefreshTokenRotation: tc.noRotation}}

			err := h.BindAccessRequest(ctxWithCertificate(presented), request)

			if tc.err != nil {
				assert.ErrorIs(t, err, tc.err)
				assert.Equal(t, bound, session.GetClientCertificateSHA256Thumbprint())

				return
			}

			require.NoError(t, err)
			assert.Equal(t, oauth2.X509CertificateSHA256Thumbprint(presented), session.GetClientCertificateSHA256Thumbprint())
		})
	}
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

type strictRefreshTokenBindingClient struct {
	*oauth2.DefaultClient

	strict bool
}

func (c *strictRefreshTokenBindingClient) GetMTLSStrictRefreshTokenBinding() bool {
	return c.strict
}

type unboundSession struct {
	oauth2.Session
}
