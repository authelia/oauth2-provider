// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

const (
	pemArmourBegin = "-----BEGIN"
	pemArmourEnd   = "-----END"
	pemArmourDelim = "-----"
)

// X509CertificateSHA256Thumbprint returns the RFC 8705 Section 3.1 'x5t#S256' confirmation value for cert, being the
// base64url encoding without padding of the SHA-256 digest over the DER encoding of the certificate. It returns an
// empty string when cert is nil, so callers can treat 'no certificate' and 'no binding' identically.
func X509CertificateSHA256Thumbprint(cert *x509.Certificate) (x5t string) {
	if cert == nil {
		return ""
	}

	sum := sha256.Sum256(cert.Raw)

	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// ClientCertificateFromRequest returns the X.509 certificate the client authenticated with, or nil when it presented
// none. It is the single point at which RFC 8705 obtains a certificate.
//
// The two sources are mutually exclusive, selected by whether header names one. Configuring a header name declares
// that clients reach this server through a TLS terminating reverse proxy which forwards their certificate in that
// header (see RFC 8705 Section 6.5); the peer certificate on such a connection belongs to the proxy, not to the
// client, so r.TLS is not consulted at all. Preferring r.TLS there would bind a token to the proxy's certificate,
// which every client behind that proxy would then satisfy. A request arriving without the header carries no client
// certificate, even when the connection has a peer certificate of its own.
//
// With no header configured, which is the default, the certificate comes from r.TLS alone, where Go has already
// validated it against the listener's ClientCAs before the handler ran.
//
// The header is fully spoofable by anyone able to reach the server without transiting that proxy, and a forged value
// authenticates the sender as any client registered with an mTLS authentication method. The caller must therefore opt
// in by configuring a name, and a deployment that does MUST ensure the proxy overwrites the header on every inbound
// request and that the server is unreachable except through it.
func ClientCertificateFromRequest(r *http.Request, header string) (cert *x509.Certificate, err error) {
	if r == nil {
		return nil, nil
	}

	if header != "" {
		var value string

		if value = r.Header.Get(header); value == "" {
			return nil, nil
		}

		return ParseClientCertificateHeader(value)
	}

	if r.TLS != nil && len(r.TLS.PeerCertificates) != 0 {
		return r.TLS.PeerCertificates[0], nil
	}

	return nil, nil
}

// ParseClientCertificateHeader decodes a client certificate forwarded by a TLS terminating proxy.
//
// No encoding is prescribed for this header, and the proxies that emit one disagree: Traefik v2 and nginx
// (ssl_client_escaped_cert) URL-escape a PEM document, Traefik v3 sends the bare base64 DER with the armour and line
// breaks stripped, and HAProxy sends base64 DER. The parser therefore accepts all of them rather than requiring a
// deployment to declare which one it has, since a mismatch would present as mutual TLS silently failing.
//
// When a chain is present only the leaf is returned, as that is the certificate whose private key the client proved
// possession of. A chain arrives either comma separated or as concatenated PEM documents, and the leaf is first in
// both.
func ParseClientCertificateHeader(value string) (cert *x509.Certificate, err error) {
	if value = strings.TrimSpace(value); value == "" {
		return nil, errors.New("the client certificate header was empty")
	}

	// PathUnescape rather than QueryUnescape: the standard base64 alphabet contains '+', and QueryUnescape would
	// rewrite an unescaped one to a space and corrupt the DER. Neither proxy encodes a space as '+' here. A value
	// that does not decode is passed through unchanged, as it was most likely never escaped to begin with.
	if strings.ContainsRune(value, '%') {
		if unescaped, e := url.PathUnescape(value); e == nil {
			value = unescaped
		}
	}

	if index := strings.IndexByte(value, ','); index >= 0 {
		value = value[:index]
	}

	value = stripPEMArmour(value)

	var der []byte

	if der, err = decodeCertificateBase64(value); err != nil {
		return nil, err
	}

	if cert, err = x509.ParseCertificate(der); err != nil {
		return nil, fmt.Errorf("the client certificate header did not contain a valid X.509 certificate: %w", err)
	}

	return cert, nil
}

// stripPEMArmour returns the body of the first PEM document in value, or value unchanged when it carries no armour.
// It is used in preference to pem.Decode because pem.Decode requires the line breaks that several proxies strip.
func stripPEMArmour(value string) string {
	begin := strings.Index(value, pemArmourBegin)
	if begin < 0 {
		return value
	}

	body := value[begin+len(pemArmourBegin):]

	// Skip the remainder of the BEGIN armour, which carries the label and the closing delimiter.
	if index := strings.Index(body, pemArmourDelim); index >= 0 {
		body = body[index+len(pemArmourDelim):]
	}

	if index := strings.Index(body, pemArmourEnd); index >= 0 {
		body = body[:index]
	}

	return body
}

// decodeCertificateBase64 decodes value as base64, accepting the standard and URL alphabets with or without padding.
// Proxies vary and the distinction carries no meaning here, so all four are normalised to one form rather than
// attempted in turn.
func decodeCertificateBase64(value string) (der []byte, err error) {
	compact := strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\t', '\r', '\n', '=':
			return -1
		case '-':
			return '+'
		case '_':
			return '/'
		default:
			return r
		}
	}, value)

	if compact == "" {
		return nil, errors.New("the client certificate header was empty")
	}

	if der, err = base64.RawStdEncoding.DecodeString(compact); err != nil {
		return nil, fmt.Errorf("the client certificate header could not be decoded: %w", err)
	}

	return der, nil
}

// MTLSBoundSession is implemented by sessions that can be bound to a mutual-TLS client certificate per RFC 8705
// Section 3. The binding is the base64url SHA-256 thumbprint of the certificate's DER encoding, the same value used
// for 'x5t#S256' in the 'cnf' claim.
//
// Both accessors are required. The setter is what RestoreConfirmation uses to recover the binding from a stateless
// token, whose own claims are the only record of what it is bound to; a session implementing only the getter reports
// such a token as unbound.
type MTLSBoundSession interface {
	// SetClientCertificateSHA256Thumbprint records the certificate thumbprint (x5t#S256) the token is bound to.
	SetClientCertificateSHA256Thumbprint(x5t string)

	// GetClientCertificateSHA256Thumbprint returns the bound certificate thumbprint, or an empty string when the
	// session is not certificate bound.
	GetClientCertificateSHA256Thumbprint() (x5t string)
}
