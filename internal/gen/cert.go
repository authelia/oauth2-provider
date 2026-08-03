// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package gen

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/url"
	"time"
)

// CertificateOptions describes the certificate MustCertificate mints. The zero value produces a certificate with the
// subject 'CN=test' and no subject alternative names.
type CertificateOptions struct {
	// Subject is the certificate subject. When the zero value it defaults to 'CN=test'.
	Subject pkix.Name

	// DNSNames are the dNSName subject alternative name entries.
	DNSNames []string

	// EmailAddresses are the rfc822Name subject alternative name entries.
	EmailAddresses []string

	// IPAddresses are the iPAddress subject alternative name entries.
	IPAddresses []net.IP

	// URIs are the uniformResourceIdentifier subject alternative name entries.
	URIs []*url.URL

	// SerialNumber distinguishes two certificates minted with otherwise identical options, which matters whenever a
	// test needs two certificates with different thumbprints. When zero it defaults to 1.
	SerialNumber int64
}

// MustCertificate mints a self-signed certificate from opts and panics on failure. It is intended for tests.
func MustCertificate(opts CertificateOptions) *x509.Certificate {
	subject := opts.Subject

	if subject.String() == "" {
		subject = pkix.Name{CommonName: "test"}
	}

	serial := opts.SerialNumber

	if serial == 0 {
		serial = 1
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               subject,
		DNSNames:              opts.DNSNames,
		EmailAddresses:        opts.EmailAddresses,
		IPAddresses:           opts.IPAddresses,
		URIs:                  opts.URIs,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	key := MustRSAKey()

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		panic(err)
	}

	return cert
}
