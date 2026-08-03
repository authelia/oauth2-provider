// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc8705

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/gen"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestValidateResourceAccess(t *testing.T) {
	cert := gen.MustCertificate(gen.CertificateOptions{})
	other := gen.MustCertificate(gen.CertificateOptions{SerialNumber: 2})

	newRequest := func(peer *x509.Certificate) *http.Request {
		r := &http.Request{Header: http.Header{}}

		if peer != nil {
			r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{peer}}
		}

		return r
	}

	t.Run("ShouldAcceptTheBoundCertificate", func(t *testing.T) {
		actual, err := ValidateResourceAccess(newRequest(cert), "", oauth2.X509CertificateSHA256Thumbprint(cert))

		require.NoError(t, err)
		require.NotNil(t, actual)
		assert.Equal(t, cert.Raw, actual.Raw)
	})

	t.Run("ShouldRejectADifferentCertificate", func(t *testing.T) {
		actual, err := ValidateResourceAccess(newRequest(other), "", oauth2.X509CertificateSHA256Thumbprint(cert))

		assert.Nil(t, actual)
		assert.ErrorIs(t, err, oauth2.ErrInvalidToken)
	})

	t.Run("ShouldRejectNoCertificate", func(t *testing.T) {
		actual, err := ValidateResourceAccess(newRequest(nil), "", oauth2.X509CertificateSHA256Thumbprint(cert))

		assert.Nil(t, actual)
		assert.ErrorIs(t, err, oauth2.ErrInvalidToken)
	})

	t.Run("ShouldRejectAnEmptyBinding", func(t *testing.T) {
		actual, err := ValidateResourceAccess(newRequest(cert), "", "")

		assert.Nil(t, actual)
		assert.ErrorIs(t, err, oauth2.ErrInvalidToken)
	})

	t.Run("ShouldReadTheConfiguredHeader", func(t *testing.T) {
		r := &http.Request{Header: http.Header{}}
		r.Header.Set("X-Forwarded-Tls-Client-Cert", encodeDER(cert))

		actual, err := ValidateResourceAccess(r, "X-Forwarded-Tls-Client-Cert", oauth2.X509CertificateSHA256Thumbprint(cert))

		require.NoError(t, err)
		require.NotNil(t, actual)
		assert.Equal(t, cert.Raw, actual.Raw)
	})

	t.Run("ShouldPairWithTheIntrospectionAccessor", func(t *testing.T) {
		claims := map[string]any{jwt.ClaimConfirmation: map[string]any{jwt.ClaimConfirmationX509SHA256Thumbprint: oauth2.X509CertificateSHA256Thumbprint(cert)}}

		actual, err := ValidateResourceAccess(newRequest(cert), "", oauth2.GetMTLSConfirmationX509SHA256Thumbprint(claims))

		require.NoError(t, err)
		assert.Equal(t, cert.Raw, actual.Raw)
	})
}

func encodeDER(cert *x509.Certificate) string {
	return base64.StdEncoding.EncodeToString(cert.Raw)
}
