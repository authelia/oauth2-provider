// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2/internal/gen"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestX509CertificateSHA256Thumbprint(t *testing.T) {
	cert := gen.MustCertificate(gen.CertificateOptions{})

	sum := sha256.Sum256(cert.Raw)

	assert.Equal(t, base64.RawURLEncoding.EncodeToString(sum[:]), X509CertificateSHA256Thumbprint(cert))
	assert.Len(t, X509CertificateSHA256Thumbprint(cert), 43)
	assert.Empty(t, X509CertificateSHA256Thumbprint(nil))
}

func TestParseClientCertificateHeader(t *testing.T) {
	cert := gen.MustCertificate(gen.CertificateOptions{Subject: pkix.Name{CommonName: "leaf"}})
	issuer := gen.MustCertificate(gen.CertificateOptions{Subject: pkix.Name{CommonName: "issuer"}, SerialNumber: 2})

	testCases := []struct {
		name  string
		value string
		err   string
	}{
		{name: "ShouldParseTraefikV3BareBase64DER", value: encodeTraefikV3(cert)},
		{name: "ShouldParseTraefikV2EscapedPEM", value: encodeEscapedPEM(cert)},
		{name: "ShouldParseNginxEscapedPEM", value: encodeEscapedPEM(cert)},
		{name: "ShouldParsePlainPEM", value: encodePEM(cert)},
		{name: "ShouldParsePEMWithoutLineBreaks", value: "-----BEGIN CERTIFICATE-----" + encodeTraefikV3(cert) + "-----END CERTIFICATE-----"},
		{name: "ShouldParseBase64URLAlphabet", value: base64.RawURLEncoding.EncodeToString(cert.Raw)},
		{name: "ShouldTakeTheLeafOfACommaSeparatedChain", value: encodeTraefikV3(cert) + "," + encodeTraefikV3(issuer)},
		{name: "ShouldTakeTheLeafOfAConcatenatedPEMChain", value: encodePEM(cert) + encodePEM(issuer)},
		{name: "ShouldErrorOnEmptyValue", value: "", err: "the client certificate header was empty"},
		{name: "ShouldErrorOnUndecodableValue", value: "!!!not base64!!!", err: "the client certificate header could not be decoded"},
		{name: "ShouldErrorOnNonCertificateDER", value: base64.StdEncoding.EncodeToString([]byte("definitely not a certificate")), err: "the client certificate header did not contain a valid X.509 certificate"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual, err := ParseClientCertificateHeader(tc.value)

			if tc.err != "" {
				assert.Nil(t, actual)
				assert.ErrorContains(t, err, tc.err)

				return
			}

			require.NoError(t, err)
			require.NotNil(t, actual)
			assert.Equal(t, cert.Raw, actual.Raw)
		})
	}
}

func TestClientCertificateFromRequest(t *testing.T) {
	cert := gen.MustCertificate(gen.CertificateOptions{Subject: pkix.Name{CommonName: "leaf"}})
	other := gen.MustCertificate(gen.CertificateOptions{Subject: pkix.Name{CommonName: "other"}, SerialNumber: 2})

	const header = "X-Forwarded-Tls-Client-Cert"

	newRequest := func(peer *x509.Certificate, headerName, headerValue string) *http.Request {
		r := &http.Request{Header: http.Header{}}

		if peer != nil {
			r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{peer}}
		}

		if headerName != "" {
			r.Header.Set(headerName, headerValue)
		}

		return r
	}

	t.Run("ShouldReturnThePeerCertificateWhenNoHeaderIsConfigured", func(t *testing.T) {
		actual, err := ClientCertificateFromRequest(newRequest(cert, "", ""), "")

		require.NoError(t, err)
		require.NotNil(t, actual)
		assert.Equal(t, cert.Raw, actual.Raw)
	})

	t.Run("ShouldPreferTheHeaderOverThePeerCertificate", func(t *testing.T) {
		actual, err := ClientCertificateFromRequest(newRequest(other, header, encodeTraefikV3(cert)), header)

		require.NoError(t, err)
		require.NotNil(t, actual)
		assert.Equal(t, cert.Raw, actual.Raw)
	})

	t.Run("ShouldIgnoreThePeerCertificateWhenAHeaderIsConfiguredButAbsent", func(t *testing.T) {
		actual, err := ClientCertificateFromRequest(newRequest(other, "", ""), header)

		require.NoError(t, err)
		assert.Nil(t, actual)
	})

	t.Run("ShouldReadTheHeaderWhenThereIsNoPeerCertificate", func(t *testing.T) {
		actual, err := ClientCertificateFromRequest(newRequest(nil, header, encodeTraefikV3(cert)), header)

		require.NoError(t, err)
		require.NotNil(t, actual)
		assert.Equal(t, cert.Raw, actual.Raw)
	})

	t.Run("ShouldIgnoreTheHeaderWhenNoHeaderIsConfigured", func(t *testing.T) {
		actual, err := ClientCertificateFromRequest(newRequest(nil, header, encodeTraefikV3(cert)), "")

		require.NoError(t, err)
		assert.Nil(t, actual)
	})

	t.Run("ShouldReturnNothingWhenNoCertificateIsPresented", func(t *testing.T) {
		actual, err := ClientCertificateFromRequest(newRequest(nil, "", ""), header)

		require.NoError(t, err)
		assert.Nil(t, actual)
	})

	t.Run("ShouldReturnNothingForANilRequest", func(t *testing.T) {
		actual, err := ClientCertificateFromRequest(nil, header)

		require.NoError(t, err)
		assert.Nil(t, actual)
	})

	t.Run("ShouldErrorOnAMalformedHeader", func(t *testing.T) {
		actual, err := ClientCertificateFromRequest(newRequest(nil, header, "!!!"), header)

		assert.Nil(t, actual)
		assert.ErrorContains(t, err, "the client certificate header could not be decoded")
	})

	t.Run("ShouldIgnoreAnEmptyPeerCertificateSlice", func(t *testing.T) {
		r := &http.Request{Header: http.Header{}, TLS: &tls.ConnectionState{}}
		r.Header.Set(header, encodeTraefikV3(cert))

		actual, err := ClientCertificateFromRequest(r, header)

		require.NoError(t, err)
		require.NotNil(t, actual)
		assert.Equal(t, cert.Raw, actual.Raw)
	})
}

func TestValidateClientCertificateBinding(t *testing.T) {
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
		actual, err := ValidateClientCertificateBinding(newRequest(cert), "", X509CertificateSHA256Thumbprint(cert))

		require.NoError(t, err)
		require.NotNil(t, actual)
		assert.Equal(t, cert.Raw, actual.Raw)
	})

	t.Run("ShouldRejectADifferentCertificate", func(t *testing.T) {
		actual, err := ValidateClientCertificateBinding(newRequest(other), "", X509CertificateSHA256Thumbprint(cert))

		assert.Nil(t, actual)
		assert.ErrorIs(t, err, ErrInvalidToken)
	})

	t.Run("ShouldRejectNoCertificate", func(t *testing.T) {
		actual, err := ValidateClientCertificateBinding(newRequest(nil), "", X509CertificateSHA256Thumbprint(cert))

		assert.Nil(t, actual)
		assert.ErrorIs(t, err, ErrInvalidToken)
	})

	t.Run("ShouldRejectAnEmptyBinding", func(t *testing.T) {
		actual, err := ValidateClientCertificateBinding(newRequest(cert), "", "")

		assert.Nil(t, actual)
		assert.ErrorIs(t, err, ErrInvalidToken)
	})

	t.Run("ShouldReadTheConfiguredHeader", func(t *testing.T) {
		r := &http.Request{Header: http.Header{}}
		r.Header.Set("X-Forwarded-Tls-Client-Cert", encodeTraefikV3(cert))

		actual, err := ValidateClientCertificateBinding(r, "X-Forwarded-Tls-Client-Cert", X509CertificateSHA256Thumbprint(cert))

		require.NoError(t, err)
		require.NotNil(t, actual)
		assert.Equal(t, cert.Raw, actual.Raw)
	})

	t.Run("ShouldRejectAMalformedConfiguredHeader", func(t *testing.T) {
		r := &http.Request{Header: http.Header{}}
		r.Header.Set("X-Forwarded-Tls-Client-Cert", "not-a-certificate")

		actual, err := ValidateClientCertificateBinding(r, "X-Forwarded-Tls-Client-Cert", X509CertificateSHA256Thumbprint(cert))

		assert.Nil(t, actual)
		assert.ErrorIs(t, err, ErrInvalidToken)
	})

	t.Run("ShouldPairWithTheIntrospectionAccessor", func(t *testing.T) {
		claims := map[string]any{jwt.ClaimConfirmation: map[string]any{jwt.ClaimConfirmationX509SHA256Thumbprint: X509CertificateSHA256Thumbprint(cert)}}

		actual, err := ValidateClientCertificateBinding(newRequest(cert), "", GetMTLSConfirmationX509SHA256Thumbprint(claims))

		require.NoError(t, err)
		assert.Equal(t, cert.Raw, actual.Raw)
	})
}

func TestParseClientCertificateHeaderPreservesPlus(t *testing.T) {
	for i := int64(1); i < 40; i++ {
		cert := gen.MustCertificate(gen.CertificateOptions{SerialNumber: i})

		encoded := encodeTraefikV3(cert)
		if !containsPlus(encoded) {
			continue
		}

		actual, err := ParseClientCertificateHeader("%20" + encoded)

		require.NoError(t, err)
		require.NotNil(t, actual)
		assert.Equal(t, cert.Raw, actual.Raw)

		return
	}

	t.Skip("no certificate in the sample encoded with a '+'")
}

func containsPlus(v string) bool {
	for _, r := range v {
		if r == '+' {
			return true
		}
	}

	return false
}

func encodeTraefikV3(cert *x509.Certificate) string {
	return base64.StdEncoding.EncodeToString(cert.Raw)
}

func encodePEM(cert *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
}

func encodeEscapedPEM(cert *x509.Certificate) string {
	return url.PathEscape(encodePEM(cert))
}
