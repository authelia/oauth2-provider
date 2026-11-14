// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc8705

import (
	"context"
	"crypto/x509"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/gen"
)

func TestBackChannelMTLS(t *testing.T) {
	cert := gen.MustCertificate(gen.CertificateOptions{})

	x5t := oauth2.X509CertificateSHA256Thumbprint(cert)

	mtlsAuthenticated := &oauth2.DefaultJARClient{TokenEndpointAuthMethod: consts.ClientAuthMethodTLSClientAuth, DefaultClient: &oauth2.DefaultClient{}}

	testCases := []struct {
		name     string
		config   *oauth2.Config
		mode     string
		client   oauth2.Client
		cert     *x509.Certificate
		noHTTP   bool
		dpop     bool
		jkt      bool
		session  oauth2.Session
		expected string
		err      error
	}{
		{name: "ShouldNotRecordForABoundPollClient", mode: consts.CIBAModePoll, client: &oauth2.DefaultClient{TLSClientCertificateBoundAccessTokens: true}, cert: cert},
		{name: "ShouldNotRecordForABoundPingClient", mode: consts.CIBAModePing, client: &oauth2.DefaultClient{TLSClientCertificateBoundAccessTokens: true}, cert: cert},
		{name: "ShouldNotRecordForAPollClientWhenEnforced", config: &oauth2.Config{MTLSEnabled: true, MTLSEnforce: true}, mode: consts.CIBAModePoll, client: &oauth2.DefaultClient{}, cert: cert},
		{name: "ShouldNotRecordForAnMTLSAuthenticatedPollClient", mode: consts.CIBAModePoll, client: mtlsAuthenticated, cert: cert},
		{name: "ShouldRecordForABoundPushClient", mode: consts.CIBAModePush, client: &oauth2.DefaultClient{TLSClientCertificateBoundAccessTokens: true}, cert: cert, expected: x5t},
		{name: "ShouldRecordForAPushClientWhenEnforced", config: &oauth2.Config{MTLSEnabled: true, MTLSEnforce: true}, mode: consts.CIBAModePush, client: &oauth2.DefaultClient{}, cert: cert, expected: x5t},
		{name: "ShouldRecordForAnMTLSAuthenticatedPushClient", mode: consts.CIBAModePush, client: mtlsAuthenticated, cert: cert, expected: x5t},
		{name: "ShouldRecordForAPushClientWhenSenderConstraintIsEnforced", config: &oauth2.Config{MTLSEnabled: true, EnforceSenderConstrainedAccessTokens: true}, mode: consts.CIBAModePush, client: &oauth2.DefaultClient{}, cert: cert, expected: x5t},
		{name: "ShouldNotRecordForAPushClientPresentingADPoPProof", config: &oauth2.Config{MTLSEnabled: true, DPoPEnabled: true, EnforceSenderConstrainedAccessTokens: true}, mode: consts.CIBAModePush, client: mtlsAuthenticated, cert: cert, dpop: true},
		{name: "ShouldNotRecordForAPushClientPresentingADPoPJKT", config: &oauth2.Config{MTLSEnabled: true, DPoPEnabled: true}, mode: consts.CIBAModePush, client: mtlsAuthenticated, cert: cert, jkt: true},
		{name: "ShouldNotRecordWhenTheSessionHoldsADPoPThumbprint", config: &oauth2.Config{MTLSEnabled: true, DPoPEnabled: true}, mode: consts.CIBAModePush, client: mtlsAuthenticated, cert: cert, session: &oauth2.DefaultSession{JWKThumbprint: "jkt"}},
		{name: "ShouldRecordDespiteADPoPJKTWhenDPoPIsDisabled", mode: consts.CIBAModePush, client: mtlsAuthenticated, cert: cert, jkt: true, expected: x5t},
		{name: "ShouldRejectDPoPKeyMaterialForABoundPushClient", config: &oauth2.Config{MTLSEnabled: true, DPoPEnabled: true}, mode: consts.CIBAModePush, client: &oauth2.DefaultClient{TLSClientCertificateBoundAccessTokens: true}, cert: cert, jkt: true, err: oauth2.ErrInvalidRequest},
		{name: "ShouldIgnoreAnIncidentalCertificate", mode: consts.CIBAModePush, client: &oauth2.DefaultClient{}, cert: cert},
		{name: "ShouldSkipWhenDisabled", config: &oauth2.Config{}, mode: consts.CIBAModePush, client: &oauth2.DefaultClient{TLSClientCertificateBoundAccessTokens: true}, cert: cert},
		{name: "ShouldPassWithoutACertificateForAPollClient", mode: consts.CIBAModePoll, client: &oauth2.DefaultClient{TLSClientCertificateBoundAccessTokens: true}},
		{name: "ShouldRequireACertificateForABoundPushClient", mode: consts.CIBAModePush, client: &oauth2.DefaultClient{TLSClientCertificateBoundAccessTokens: true}, err: oauth2.ErrInvalidRequest},
		{name: "ShouldFailClosedWithoutAnHTTPRequestForABoundPushClient", mode: consts.CIBAModePush, client: &oauth2.DefaultClient{TLSClientCertificateBoundAccessTokens: true}, noHTTP: true, err: oauth2.ErrServerError},
		{name: "ShouldPassWithoutAnHTTPRequestForAPollClient", mode: consts.CIBAModePoll, client: &oauth2.DefaultClient{TLSClientCertificateBoundAccessTokens: true}, noHTTP: true},
		{name: "ShouldRejectASessionWithoutMTLSSupport", mode: consts.CIBAModePush, client: &oauth2.DefaultClient{TLSClientCertificateBoundAccessTokens: true}, cert: cert, session: unboundSession{Session: &oauth2.DefaultSession{}}, err: oauth2.ErrServerError},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := tc.config
			if config == nil {
				config = &oauth2.Config{MTLSEnabled: true}
			}

			session := tc.session
			if session == nil {
				session = &oauth2.DefaultSession{}
			}

			request := oauth2.NewBackChannelAuthenticationRequest()
			request.Form = url.Values{}
			request.DeliveryMode = tc.mode
			request.Client = tc.client
			request.SetSession(session)

			if tc.jkt {
				request.Form.Set(consts.FormParameterDPoPJKT, "dnfb1T9jil_gOhti60baHs_WD_a4D8JN9VDJXbmBmGw")
			}

			ctx := ctxWithCertificate(tc.cert)

			if tc.dpop {
				ctx.Value(oauth2.RequestContextKey).(*http.Request).Header.Set(consts.HeaderDPoP, "proof")
			}

			if tc.noHTTP {
				ctx = context.Background()
			}

			err := (&Handler{Config: config}).BindBackChannelAuthenticationRequest(ctx, request)

			if tc.err != nil {
				assert.ErrorIs(t, err, tc.err)

				return
			}

			require.NoError(t, err)

			if s, ok := session.(oauth2.MTLSBoundSession); ok {
				assert.Equal(t, tc.expected, s.GetClientCertificateSHA256Thumbprint())
			}
		})
	}
}
