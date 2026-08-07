// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"crypto/subtle"
	"crypto/x509"
	"net"
	"net/url"
	"slices"
	"strings"

	"github.com/go-jose/go-jose/v4"

	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/token/jwt"
	"authelia.com/provider/oauth2/x/errorsx"
)

// EqualDistinguishedNames reports whether two RFC 4514 string representations of a distinguished name denote the same
// name.
//
// RFC 8705 Section 2.1 notes that a predictable treatment of DN values, such as the distinguishedNameMatch rule from
// RFC 4517, is needed when comparing a certificate's subject DN to a client's registered one. Full RFC 4517 matching
// is not implemented; this normalises the two spellings that differ in practice without changing what a DN denotes.
// Insignificant whitespace around each relative distinguished name is ignored, attribute types are compared without
// regard to case, and the sequence is compared in both directions because Go's pkix.Name.String and OpenSSL emit
// relative distinguished names in opposite orders.
//
// Attribute values are compared with case significance. Most attribute types in a subject DN use caseIgnoreMatch, so
// this is stricter than RFC 4517 requires; the registered value is ordinarily copied from the certificate, and for a
// value serving as an authentication credential a visible mismatch is preferable to a silent widening.
func EqualDistinguishedNames(a, b string) (equal bool) {
	x, y := normalizeDistinguishedName(a), normalizeDistinguishedName(b)

	if len(x) != len(y) {
		return false
	}

	if slices.Equal(x, y) {
		return true
	}

	slices.Reverse(y)

	return slices.Equal(x, y)
}

// normalizeDistinguishedName splits an RFC 4514 distinguished name into its relative distinguished names, trims
// insignificant whitespace, and uppercases each attribute type.
func normalizeDistinguishedName(dn string) (rdns []string) {
	raw := splitDistinguishedName(dn)

	rdns = make([]string, 0, len(raw))

	for _, rdn := range raw {
		if rdn = trimUnescapedSpace(rdn); rdn == "" {
			continue
		}

		if attribute, value, ok := strings.Cut(rdn, "="); ok {
			rdn = strings.ToUpper(trimUnescapedSpace(attribute)) + "=" + trimUnescapedSpace(value)
		}

		rdns = append(rdns, rdn)
	}

	return rdns
}

// trimUnescapedSpace trims leading and trailing ASCII space (U+0020) characters from s. It is narrower
// than strings.TrimSpace, which strips the full unicode.IsSpace set (tab, newline, U+00A0, ...).
//
// Go's pkix.RDNSequence.String, which produces one side of every comparison EqualDistinguishedNames performs, escapes
// only a leading or trailing space, the characters `,+"\<>;`, and a leading '#'; every other whitespace character,
// including a tab or newline in any position, is emitted into the value literally. Trimming the full Unicode space set
// would therefore delete characters that are part of the value, letting a certificate whose subject differs only by a
// trailing tab, newline, or non-breaking space collide with an unrelated registered value. Only the plain space
// adjacent to an RDN or attribute/value boundary is insignificant formatting; every other whitespace character is left
// untouched.
//
// A trailing space escaped with a backslash per RFC 4514 is part of the value and is not trimmed: the number of
// consecutive backslashes immediately preceding it is counted, and trimming stops as soon as that count is odd. A
// leading space can never be escaped from this position: RFC 4514 escapes a leading space as "\ ", so an escaped
// leading space is preceded by its backslash and is not the first character; a space that is the first character is
// therefore always insignificant and is trimmed unconditionally.
func trimUnescapedSpace(s string) (trimmed string) {
	for len(s) > 0 && s[len(s)-1] == ' ' {
		i := len(s) - 1
		j := i

		for j > 0 && s[j-1] == '\\' {
			j--
		}

		if (i-j)%2 == 1 {
			break
		}

		s = s[:i]
	}

	for len(s) > 0 && s[0] == ' ' {
		s = s[1:]
	}

	return s
}

// splitDistinguishedName splits an RFC 4514 distinguished name on its unescaped commas. A comma appearing within an
// attribute value is escaped with a backslash and does not separate relative distinguished names.
func splitDistinguishedName(dn string) (rdns []string) {
	var (
		start   int
		escaped bool
	)

	for i, r := range dn {
		switch {
		case escaped:
			escaped = false
		case r == '\\':
			escaped = true
		case r == ',':
			rdns = append(rdns, dn[start:i])
			start = i + 1
		}
	}

	return append(rdns, dn[start:])
}

// matchTLSClientAuthSubject performs the RFC 8705 Section 2.1 PKI method check, verifying that the subject information
// in cert matches the single subject value registered for client.
//
// The certificate chain is not validated here; see the documentation on Config.MTLSClientCertificateHeader
// for where that responsibility sits.
func matchTLSClientAuthSubject(client TLSClientAuthClient, cert *x509.Certificate, endpoint string) (err error) {
	if cert == nil {
		return errorsx.WithStack(ErrInvalidClient.
			WithHint(hintClientCredentialsInvalid).
			WithDebugf("The registered client with id '%s' is configured with the '%s_endpoint_auth_method' method '%s' but the request did not include a client certificate.", client.GetID(), endpoint, consts.ClientAuthMethodTLSClientAuth))
	}

	var (
		count     int
		parameter string
		match     func() bool
	)

	var subjectDNEmpty bool

	if dn := client.GetTLSClientAuthSubjectDN(); dn != "" {
		count, parameter = count+1, "tls_client_auth_subject_dn"
		// A registered value made only of separators and space, such as "  ", " , " or ",", is non-empty as a string
		// but names no relative distinguished name at all. It would otherwise satisfy the exactly-one check below and
		// then normalise to a zero length sequence, which compares equal to the empty subject of any SAN-only
		// certificate and would authenticate its holder as this client.
		subjectDNEmpty = len(normalizeDistinguishedName(dn)) == 0
		match = func() bool { return EqualDistinguishedNames(dn, cert.Subject.String()) }
	}

	if dns := client.GetTLSClientAuthSANDNS(); dns != "" {
		count, parameter = count+1, "tls_client_auth_san_dns"
		match = func() bool {
			return slices.ContainsFunc(cert.DNSNames, func(name string) bool { return strings.EqualFold(name, dns) })
		}
	}

	if uri := client.GetTLSClientAuthSANURI(); uri != "" {
		count, parameter = count+1, "tls_client_auth_san_uri"
		match = func() bool {
			return slices.ContainsFunc(cert.URIs, func(u *url.URL) bool { return u != nil && u.String() == uri })
		}
	}

	if ip := client.GetTLSClientAuthSANIP(); ip != "" {
		count, parameter = count+1, "tls_client_auth_san_ip"
		match = func() bool { return matchCertificateIPAddress(cert, ip) }
	}

	if email := client.GetTLSClientAuthSANEmail(); email != "" {
		count, parameter = count+1, "tls_client_auth_san_email"
		match = func() bool { return slices.Contains(cert.EmailAddresses, email) }
	}

	if count != 1 {
		return errorsx.WithStack(ErrInvalidClient.
			WithHint(hintClientCredentialsInvalid).
			WithDebugf("The registered client with id '%s' is configured with the '%s_endpoint_auth_method' method '%s' which requires that it must register exactly one of the 'tls_client_auth_subject_dn', 'tls_client_auth_san_dns', 'tls_client_auth_san_uri', 'tls_client_auth_san_ip', or 'tls_client_auth_san_email' client registration values, but it has registered %d of them.", client.GetID(), endpoint, consts.ClientAuthMethodTLSClientAuth, count))
	}

	// Checked ahead of the match, for the same reason as the IP address below: a registered value that names no
	// relative distinguished name is a registration error, and reporting it as a failed match would leave a bypass
	// looking like an ordinary mismatch.
	if subjectDNEmpty {
		return errorsx.WithStack(ErrInvalidClient.
			WithHint(hintClientCredentialsInvalid).
			WithDebugf("The registered client with id '%s' has a 'tls_client_auth_subject_dn' value of '%s' which contains no relative distinguished names.", client.GetID(), client.GetTLSClientAuthSubjectDN()))
	}

	// Checked ahead of the match so an unparseable registered value is reported as the registration error it is,
	// rather than as a certificate that failed to match.
	if parameter == "tls_client_auth_san_ip" && net.ParseIP(client.GetTLSClientAuthSANIP()) == nil {
		return errorsx.WithStack(ErrInvalidClient.
			WithHint(hintClientCredentialsInvalid).
			WithDebugf("The registered client with id '%s' has a 'tls_client_auth_san_ip' value of '%s' which is not a valid IP address.", client.GetID(), client.GetTLSClientAuthSANIP()))
	}

	if !match() {
		return errorsx.WithStack(ErrInvalidClient.
			WithHint(hintClientCredentialsInvalid).
			WithDebugf("The client certificate presented by the client with id '%s' does not match the registered '%s' value.", client.GetID(), parameter))
	}

	return nil
}

// matchCertificateIPAddress reports whether cert carries an iPAddress subject alternative name entry equal to ip. The
// comparison is performed on the parsed binary form as RFC 8705 Section 2.1.2 requires, so that the two notations for
// an IPv6 address compare equal.
func matchCertificateIPAddress(cert *x509.Certificate, ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}

	return slices.ContainsFunc(cert.IPAddresses, func(entry net.IP) bool { return entry.Equal(parsed) })
}

// matchSelfSignedCertificate performs the RFC 8705 Section 2.2 Self-Signed Certificate method check, verifying that
// cert is one of the certificates conveyed by the client's registered 'jwks' or 'jwks_uri' via the 'x5c' member of a
// JSON Web Key.
//
// Per Section 2.2 the certificate chain is not validated for this method; possession of the private key
// was proven by the TLS handshake and the registration is what confers trust.
func matchSelfSignedCertificate(ctx context.Context, client AuthenticationMethodClient, cert *x509.Certificate, fetcher jwt.JWKSFetcherStrategy, endpoint string) (err error) {
	if cert == nil {
		return errorsx.WithStack(ErrInvalidClient.
			WithHint(hintClientCredentialsInvalid).
			WithDebugf("The registered client with id '%s' is configured with the '%s_endpoint_auth_method' method '%s' but the request did not include a client certificate.", client.GetID(), endpoint, consts.ClientAuthMethodSelfSignedTLSClientAuth))
	}

	var jwks *jose.JSONWebKeySet

	if jwks = client.GetJSONWebKeys(); jwks == nil || len(jwks.Keys) == 0 {
		uri := client.GetJSONWebKeysURI()

		switch {
		case uri == "":
			return errorsx.WithStack(ErrInvalidClient.
				WithHint(hintClientCredentialsInvalid).
				WithDebugf("The registered client with id '%s' is configured with the '%s_endpoint_auth_method' method '%s' but has no 'jwks' or 'jwks_uri' from which to determine the certificates it authenticates with.", client.GetID(), endpoint, consts.ClientAuthMethodSelfSignedTLSClientAuth))
		case fetcher == nil:
			return errorsx.WithStack(ErrInvalidClient.
				WithHint(hintClientCredentialsInvalid).
				WithDebugf("The registered client with id '%s' has a 'jwks_uri' but the authorization server has no JWKS fetcher strategy configured to resolve it.", client.GetID()))
		}

		if jwks, err = fetcher.Resolve(ctx, uri, false); err != nil {
			return errorsx.WithStack(ErrInvalidClient.
				WithHint(hintClientCredentialsInvalid).
				WithWrap(err).
				WithDebugf("The registered client with id '%s' has a 'jwks_uri' which could not be resolved. %s.", client.GetID(), ErrorToDebugRFC6749Error(err).Error()))
		}
	}

	if jwks == nil || len(jwks.Keys) == 0 {
		return errorsx.WithStack(ErrInvalidClient.
			WithHint(hintClientCredentialsInvalid).
			WithDebugf("The registered client with id '%s' has no 'jwks' or 'jwks_uri' keys from which to determine the certificates it authenticates with.", client.GetID()))
	}

	presented := []byte(X509CertificateSHA256Thumbprint(cert))

	for _, key := range jwks.Keys {
		for _, registered := range key.Certificates {
			// X509CertificateSHA256Thumbprint returns "" for a nil certificate. Skipping an empty thumbprint here,
			// on top of the cert == nil guard above, keeps a malformed or absent registered entry from ever being
			// treated as a match rather than relying on presented always being non-empty.
			thumbprint := X509CertificateSHA256Thumbprint(registered)
			if thumbprint == "" {
				continue
			}

			if subtle.ConstantTimeCompare(presented, []byte(thumbprint)) == 1 {
				return nil
			}
		}
	}

	return errorsx.WithStack(ErrInvalidClient.
		WithHint(hintClientCredentialsInvalid).
		WithDebugf("The client certificate presented by the client with id '%s' does not match any certificate in the 'x5c' of its registered JSON Web Key Set.", client.GetID()))
}

// isMTLSAuthMethod reports whether client is registered to authenticate at the endpoint strategy represents using one
// of the two RFC 8705 mutual-TLS methods.
func isMTLSAuthMethod(client Client, strategy EndpointClientAuthStrategy) bool {
	c, ok := client.(AuthenticationMethodClient)
	if !ok {
		return false
	}

	switch strategy.GetAuthMethod(c) {
	case consts.ClientAuthMethodTLSClientAuth, consts.ClientAuthMethodSelfSignedTLSClientAuth:
		return true
	default:
		return false
	}
}

// doAuthenticateMTLS authenticates a client using the RFC 8705 Section 2 mutual-TLS methods. It is reached only when
// isMTLSAuthMethod reported that the client is registered to use one and a certificate was presented.
func (s *DefaultClientAuthenticationStrategy) doAuthenticateMTLS(ctx context.Context, client Client, cert *x509.Certificate, strategy EndpointClientAuthStrategy) (method string, err error) {
	c, ok := client.(AuthenticationMethodClient)
	if !ok {
		return "", errorsx.WithStack(ErrInvalidClient.WithHint(hintClientCredentialsInvalid).WithDebug("The registered client does not support RFC 8705 Mutual-TLS client authentication methods."))
	}

	switch method = strategy.GetAuthMethod(c); method {
	case consts.ClientAuthMethodTLSClientAuth:
		tc, ok := client.(TLSClientAuthClient)
		if !ok {
			return "", errorsx.WithStack(ErrInvalidClient.
				WithHint(hintClientCredentialsInvalid).
				WithDebugf("The registered client with id '%s' is configured to use the '%s_endpoint_auth_method' method '%s' but does not implement the client registration values that method requires.", client.GetID(), strategy.Name(), method))
		}

		if err = matchTLSClientAuthSubject(tc, cert, strategy.Name()); err != nil {
			return "", err
		}
	case consts.ClientAuthMethodSelfSignedTLSClientAuth:
		if err = matchSelfSignedCertificate(ctx, c, cert, s.Config.GetJWKSFetcherStrategy(ctx), strategy.Name()); err != nil {
			return "", err
		}
	default:
		return "", errorsx.WithStack(ErrInvalidClient.
			WithHint(hintClientCredentialsInvalid).
			WithDebugf("The registered client with id '%s' is not configured to use an RFC 8705 Mutual-TLS '%s_endpoint_auth_method' method.", client.GetID(), strategy.Name()))
	}

	return method, nil
}
