// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"bytes"
	"context"
	"crypto/subtle"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"net"
	"net/url"
	"slices"
	"strings"
	"unicode/utf8"

	"authelia.com/provider/jose"

	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/token/jwt"
	"authelia.com/provider/oauth2/x/errorsx"
)

// EqualDistinguishedNames reports whether two RFC 4514 string representations of a distinguished name denote the same
// name.
//
// Each value is parsed into its sequence of relative distinguished names. Attribute types are the RFC 4514 Section 3
// short names (CN, L, ST, O, OU, C, STREET, DC, UID), SERIALNUMBER, POSTALCODE, emailAddress, or a dotted OID, compared
// without regard to case, and a short name equals its dotted OID. The attributes of a multi-valued relative
// distinguished name are compared without regard to order. Insignificant space around a separator is ignored. A
// value that is not well formed per RFC 4514 Section 3, or that uses any other attribute type name, equals nothing.
//
// Full RFC 4517 distinguishedNameMatch is not implemented: attribute values are compared exactly, which is stricter
// than RFC 4517 requires.
//
// See: https://www.rfc-editor.org/rfc/rfc8705#section-2.1.2
func EqualDistinguishedNames(a, b string) (equal bool) {
	x, ok := parseDistinguishedName(a)
	if !ok {
		return false
	}

	y, ok := parseDistinguishedName(b)
	if !ok {
		return false
	}

	return equalRelativeDistinguishedNames(x, y)
}

type distinguishedNameAttribute struct {
	kind   string
	value  string
	binary bool
}

type distinguishedNameAttributeASN1 struct {
	Type  asn1.ObjectIdentifier
	Value asn1.RawValue
}

type distinguishedNameRelativeSET []distinguishedNameAttributeASN1

var distinguishedNameAttributeTypes = map[string]string{
	"CN":           "2.5.4.3",
	"SERIALNUMBER": "2.5.4.5",
	"C":            "2.5.4.6",
	"L":            "2.5.4.7",
	"ST":           "2.5.4.8",
	"STREET":       "2.5.4.9",
	"O":            "2.5.4.10",
	"OU":           "2.5.4.11",
	"POSTALCODE":   "2.5.4.17",
	"UID":          "0.9.2342.19200300.100.1.1",
	"DC":           "0.9.2342.19200300.100.1.25",
	"EMAILADDRESS": "1.2.840.113549.1.9.1",
}

func equalRelativeDistinguishedNames(x, y [][]distinguishedNameAttribute) (equal bool) {
	return slices.EqualFunc(x, y, slices.Equal[[]distinguishedNameAttribute])
}

func equalCertificateSubjectDistinguishedName(dn string, cert *x509.Certificate) (equal bool) {
	x, ok := parseDistinguishedName(dn)
	if !ok {
		return false
	}

	y, ok := parseCertificateSubject(cert)
	if !ok {
		return false
	}

	slices.Reverse(x)

	return equalRelativeDistinguishedNames(x, y)
}

func parseCertificateSubject(cert *x509.Certificate) (rdns [][]distinguishedNameAttribute, ok bool) {
	var sequence []distinguishedNameRelativeSET

	if rest, err := asn1.Unmarshal(cert.RawSubject, &sequence); err != nil || len(rest) != 0 {
		return nil, false
	}

	rdns = make([][]distinguishedNameAttribute, 0, len(sequence))

	for _, set := range sequence {
		if len(set) == 0 {
			return nil, false
		}

		rdn := make([]distinguishedNameAttribute, 0, len(set))

		for _, attribute := range set {
			value, valid := newDistinguishedNameAttribute(attribute.Type.String(), attribute.Value.FullBytes)
			if !valid {
				return nil, false
			}

			rdn = append(rdn, value)
		}

		slices.SortFunc(rdn, compareDistinguishedNameAttributes)

		rdns = append(rdns, rdn)
	}

	return rdns, true
}

func parseDistinguishedName(dn string) (rdns [][]distinguishedNameAttribute, ok bool) {
	if trimUnescapedSpace(dn) == "" {
		return nil, true
	}

	for _, raw := range splitDistinguishedName(dn, ',') {
		if trimUnescapedSpace(raw) == "" {
			return nil, false
		}

		var rdn []distinguishedNameAttribute

		for _, part := range splitDistinguishedName(raw, '+') {
			kind, value, found := strings.Cut(part, "=")
			if !found {
				return nil, false
			}

			var attribute distinguishedNameAttribute

			if attribute, ok = parseDistinguishedNameAttribute(trimUnescapedSpace(kind), trimUnescapedSpace(value)); !ok {
				return nil, false
			}

			rdn = append(rdn, attribute)
		}

		slices.SortFunc(rdn, compareDistinguishedNameAttributes)

		rdns = append(rdns, rdn)
	}

	return rdns, true
}

func parseDistinguishedNameAttribute(kind, value string) (attribute distinguishedNameAttribute, ok bool) {
	if oid, known := distinguishedNameAttributeTypes[strings.ToUpper(kind)]; known {
		kind = oid
	} else if !isDottedObjectIdentifier(kind) {
		return attribute, false
	}

	if strings.HasPrefix(value, "#") {
		ber, err := hex.DecodeString(value[1:])
		if err != nil || len(ber) == 0 {
			return attribute, false
		}

		der, rest, valid := normalizeBER(ber, 0)
		if !valid || len(rest) != 0 {
			return attribute, false
		}

		return newDistinguishedNameAttribute(kind, der)
	}

	if value, ok = unescapeDistinguishedNameValue(value); !ok {
		return attribute, false
	}

	return distinguishedNameAttribute{kind: kind, value: value}, true
}

func newDistinguishedNameAttribute(kind string, der []byte) (attribute distinguishedNameAttribute, ok bool) {
	var raw asn1.RawValue

	if rest, err := asn1.Unmarshal(der, &raw); err != nil || len(rest) != 0 {
		return attribute, false
	}

	if raw.Class != asn1.ClassUniversal || raw.IsCompound || !slices.Contains(distinguishedNameStringTags, raw.Tag) {
		return distinguishedNameAttribute{kind: kind, value: string(der), binary: true}, true
	}

	var value string

	if rest, err := asn1.Unmarshal(der, &value); err != nil || len(rest) != 0 {
		return attribute, false
	}

	return distinguishedNameAttribute{kind: kind, value: value}, true
}

var distinguishedNameStringTags = []int{
	asn1.TagUTF8String,
	asn1.TagNumericString,
	asn1.TagPrintableString,
	asn1.TagT61String,
	asn1.TagIA5String,
	asn1.TagGeneralString,
	asn1.TagBMPString,
}

//nolint:gocyclo
func normalizeBER(ber []byte, depth int) (der, rest []byte, ok bool) {
	if depth > 16 || len(ber) < 2 {
		return nil, nil, false
	}

	i := 1

	if ber[0]&0x1f == 0x1f {
		for {
			if i >= len(ber) || i > 5 {
				return nil, nil, false
			}

			i++

			if ber[i-1]&0x80 == 0 {
				break
			}
		}
	}

	if i >= len(ber) {
		return nil, nil, false
	}

	identifier, constructed, length := ber[:i], ber[0]&0x20 != 0, int(ber[i])
	i++

	var (
		children [][]byte
		content  []byte
	)

	switch length {
	case 0x80:
		if !constructed {
			return nil, nil, false
		}

		rest = ber[i:]

		for {
			if len(rest) >= 2 && rest[0] == 0 && rest[1] == 0 {
				rest = rest[2:]

				break
			}

			var child []byte

			if child, rest, ok = normalizeBER(rest, depth+1); !ok {
				return nil, nil, false
			}

			children = append(children, child)
		}
	default:
		if length&0x80 != 0 {
			n := length & 0x7f

			if n == 0x7f || i+n > len(ber) {
				return nil, nil, false
			}

			length = 0

			for _, b := range ber[i : i+n] {
				if length = length<<8 | int(b); length > len(ber) {
					return nil, nil, false
				}
			}

			i += n
		}

		if length < 0 || i+length > len(ber) {
			return nil, nil, false
		}

		content, rest = ber[i:i+length], ber[i+length:]

		if constructed {
			for remaining := content; len(remaining) != 0; {
				var child []byte

				if child, remaining, ok = normalizeBER(remaining, depth+1); !ok {
					return nil, nil, false
				}

				children = append(children, child)
			}
		}
	}

	if !constructed {
		if identifier[0] == asn1.TagBoolean && len(content) == 1 && content[0] != 0 {
			content = []byte{0xff}
		}

		return encodeDER(identifier, content), rest, true
	}

	if len(identifier) == 1 && identifier[0]&0xc0 == 0 && slices.Contains(berStringTags, identifier[0]&0x1f) {
		if content, ok = joinBERStringSegments(identifier[0]&0x1f, children); !ok {
			return nil, nil, false
		}

		return encodeDER([]byte{identifier[0] &^ 0x20}, content), rest, true
	}

	if identifier[0]&0xc0 == 0 && identifier[0]&0x1f == asn1.TagSet {
		slices.SortFunc(children, bytes.Compare)
	}

	return encodeDER(identifier, bytes.Join(children, nil)), rest, true
}

var berStringTags = []byte{
	asn1.TagBitString,
	asn1.TagOctetString,
	asn1.TagUTF8String,
	asn1.TagNumericString,
	asn1.TagPrintableString,
	asn1.TagT61String,
	21,
	asn1.TagIA5String,
	25,
	26,
	asn1.TagGeneralString,
	28,
	asn1.TagBMPString,
}

func joinBERStringSegments(tag byte, segments [][]byte) (content []byte, ok bool) {
	var unused byte

	for i, segment := range segments {
		var raw asn1.RawValue

		if _, err := asn1.Unmarshal(segment, &raw); err != nil || raw.Class != asn1.ClassUniversal || raw.Tag != int(tag) {
			return nil, false
		}

		if tag != asn1.TagBitString {
			content = append(content, raw.Bytes...)

			continue
		}

		if len(raw.Bytes) == 0 || (raw.Bytes[0] != 0 && i != len(segments)-1) {
			return nil, false
		}

		unused = raw.Bytes[0]
		content = append(content, raw.Bytes[1:]...)
	}

	if tag == asn1.TagBitString {
		content = append([]byte{unused}, content...)
	}

	return content, true
}

func encodeDER(identifier, content []byte) (der []byte) {
	der = append(der, identifier...)

	switch n := len(content); {
	case n < 0x80:
		der = append(der, byte(n))
	default:
		var (
			length []byte
			count  byte
		)

		for ; n > 0; n >>= 8 {
			length = append([]byte{byte(n)}, length...)
			count++
		}

		der = append(der, 0x80|count)
		der = append(der, length...)
	}

	return append(der, content...)
}

func compareDistinguishedNameAttributes(a, b distinguishedNameAttribute) (n int) {
	if n = strings.Compare(a.kind, b.kind); n != 0 {
		return n
	}

	if n = strings.Compare(a.value, b.value); n != 0 {
		return n
	}

	switch {
	case a.binary == b.binary:
		return 0
	case b.binary:
		return -1
	default:
		return 1
	}
}

func isDottedObjectIdentifier(s string) (ok bool) {
	if !strings.Contains(s, ".") {
		return false
	}

	for _, arc := range strings.Split(s, ".") {
		if arc == "" || (len(arc) > 1 && arc[0] == '0') {
			return false
		}

		for i := 0; i < len(arc); i++ {
			if arc[i] < '0' || arc[i] > '9' {
				return false
			}
		}
	}

	return true
}

func unescapeDistinguishedNameValue(value string) (unescaped string, ok bool) {
	var builder strings.Builder

	for i := 0; i < len(value); i++ {
		if value[i] != '\\' {
			if strings.IndexByte("\"+,;<>\x00", value[i]) >= 0 {
				return "", false
			}

			builder.WriteByte(value[i])

			continue
		}

		switch {
		case i+1 < len(value) && strings.IndexByte(` "#+,;<=>\`, value[i+1]) >= 0:
			builder.WriteByte(value[i+1])

			i++
		case i+2 < len(value):
			decoded, err := hex.DecodeString(value[i+1 : i+3])
			if err != nil {
				return "", false
			}

			builder.WriteByte(decoded[0])

			i += 2
		default:
			return "", false
		}
	}

	if unescaped = builder.String(); !utf8.ValidString(unescaped) {
		return "", false
	}

	return unescaped, true
}

// trimUnescapedSpace trims leading and trailing ASCII space (U+0020) characters from s. It is deliberately narrower
// than [strings.TrimSpace], which strips the full [unicode.IsSpace] set (tab, newline, U+00A0, ...): every other
// whitespace character is part of the value. A trailing space escaped with a backslash is also part of the value and
// is not trimmed.
//
// See: https://www.rfc-editor.org/rfc/rfc4514#section-2.4
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

func splitDistinguishedName(dn string, separator rune) (rdns []string) {
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
		case r == separator:
			rdns = append(rdns, dn[start:i])
			start = i + 1
		}
	}

	return append(rdns, dn[start:])
}

func validateTLSClientAuthSubjectDN(dn string) (problem string) {
	rdns, valid := parseDistinguishedName(dn)

	switch {
	case !valid:
		return "is not a valid RFC 4514 distinguished name"
	case len(rdns) == 0:
		return "contains no relative distinguished names"
	default:
		return ""
	}
}

// matchTLSClientAuthSubject performs the RFC 8705 Section 2.1 PKI method check, verifying that the subject information
// in cert matches the single subject value registered for client.
//
// The chain is not validated here. verified reports whether it was already validated, by Go against the listener's
// ClientCAs or by the TLS terminating proxy that forwarded the certificate; see ClientCertificateChainVerified. The
// method relies on that having happened, since a subject is not a secret and this check would otherwise be satisfied
// by a self signed certificate bearing a registered one.
func matchTLSClientAuthSubject(client TLSClientAuthClient, cert *x509.Certificate, verified bool, endpoint string) (err error) {
	if cert == nil {
		return errorsx.WithStack(ErrInvalidClient.
			WithHint(hintClientCredentialsInvalid).
			WithDebugf("The registered client with id '%s' is configured with the '%s_endpoint_auth_method' method '%s' but the request did not include a client certificate.", client.GetID(), endpoint, consts.ClientAuthMethodTLSClientAuth))
	}

	if !verified {
		return errorsx.WithStack(ErrInvalidClient.
			WithHint(hintClientCredentialsInvalid).
			WithDebugf("The registered client with id '%s' is configured with the '%s_endpoint_auth_method' method '%s' but the client certificate was not presented with a validated certificate chain.", client.GetID(), endpoint, consts.ClientAuthMethodTLSClientAuth))
	}

	var (
		count     int
		parameter string
		match     func() bool
	)

	var subjectDNProblem string

	if dn := client.GetTLSClientAuthSubjectDN(); dn != "" {
		count, parameter = count+1, "tls_client_auth_subject_dn"
		subjectDNProblem = validateTLSClientAuthSubjectDN(dn)
		match = func() bool { return equalCertificateSubjectDistinguishedName(dn, cert) }
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
		count, parameter = count+1, consts.ClientMetadataTLSClientAuthSANIP
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
	if subjectDNProblem != "" {
		return errorsx.WithStack(ErrInvalidClient.
			WithHint(hintClientCredentialsInvalid).
			WithDebugf("The registered client with id '%s' has a 'tls_client_auth_subject_dn' value of '%s' which %s.", client.GetID(), client.GetTLSClientAuthSubjectDN(), subjectDNProblem))
	}

	// Checked ahead of the match so an unparsable registered value is reported as the registration error it is,
	// rather than as a certificate that failed to match.
	if parameter == consts.ClientMetadataTLSClientAuthSANIP && net.ParseIP(client.GetTLSClientAuthSANIP()) == nil {
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
// Per Section 2.2 the certificate chain is deliberately not validated for this method; possession of the private key
// was proven by the TLS handshake and the registration is what confers trust.
func matchSelfSignedCertificate(ctx context.Context, client AuthenticationMethodClient, cert *x509.Certificate, fetcher jwt.JWKSFetcherStrategy, endpoint string) (err error) {
	if cert == nil {
		return errorsx.WithStack(ErrInvalidClient.
			WithHint(hintClientCredentialsInvalid).
			WithDebugf("The registered client with id '%s' is configured with the '%s_endpoint_auth_method' method '%s' but the request did not include a client certificate.", client.GetID(), endpoint, consts.ClientAuthMethodSelfSignedTLSClientAuth))
	}

	var (
		jwks *jose.JSONWebKeySet
		uri  string
	)

	if jwks = client.GetJSONWebKeys(); jwks == nil || len(jwks.Keys) == 0 {
		uri = client.GetJSONWebKeysURI()

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

		if jwks, err = resolveSelfSignedCertificateJWKS(ctx, client, fetcher, uri, false); err != nil {
			return err
		}
	}

	if matchSelfSignedCertificateJWKS(jwks, cert) {
		return nil
	}

	// A certificate absent from the cached 'jwks_uri' may have been added since it was fetched.
	//
	// See: https://www.rfc-editor.org/rfc/rfc8705#section-2.2
	if uri != "" {
		if jwks, err = resolveSelfSignedCertificateJWKS(ctx, client, fetcher, uri, true); err != nil {
			return err
		}

		if matchSelfSignedCertificateJWKS(jwks, cert) {
			return nil
		}
	}

	if jwks == nil || len(jwks.Keys) == 0 {
		return errorsx.WithStack(ErrInvalidClient.
			WithHint(hintClientCredentialsInvalid).
			WithDebugf("The registered client with id '%s' has no 'jwks' or 'jwks_uri' keys from which to determine the certificates it authenticates with.", client.GetID()))
	}

	return errorsx.WithStack(ErrInvalidClient.
		WithHint(hintClientCredentialsInvalid).
		WithDebugf("The client certificate presented by the client with id '%s' does not match any certificate in the 'x5c' of its registered JSON Web Key Set.", client.GetID()))
}

func resolveSelfSignedCertificateJWKS(ctx context.Context, client AuthenticationMethodClient, fetcher jwt.JWKSFetcherStrategy, uri string, refresh bool) (jwks *jose.JSONWebKeySet, err error) {
	if jwks, err = fetcher.Resolve(ctx, uri, refresh); err != nil {
		return nil, errorsx.WithStack(ErrInvalidClient.
			WithHint(hintClientCredentialsInvalid).
			WithWrap(err).
			WithDebugf("The registered client with id '%s' has a 'jwks_uri' which could not be resolved. %s.", client.GetID(), ErrorToDebugRFC6749Error(err).Error()))
	}

	return jwks, nil
}

func matchSelfSignedCertificateJWKS(jwks *jose.JSONWebKeySet, cert *x509.Certificate) (match bool) {
	if jwks == nil {
		return false
	}

	presented := []byte(X509CertificateSHA256Thumbprint(cert))

	for _, key := range jwks.Keys {
		for _, registered := range key.Certificates {
			// An empty thumbprint is skipped so a malformed or absent registered entry is never treated as a match.
			thumbprint := X509CertificateSHA256Thumbprint(registered)
			if thumbprint == "" {
				continue
			}

			if subtle.ConstantTimeCompare(presented, []byte(thumbprint)) == 1 {
				return true
			}
		}
	}

	return false
}

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
func (s *DefaultClientAuthenticationStrategy) doAuthenticateMTLS(ctx context.Context, client Client, cert *x509.Certificate, verified bool, strategy EndpointClientAuthStrategy) (method string, err error) {
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
				WithDebugf("The registered client with id '%s' is configured to use the '%s_endpoint_auth_method' method '%s' but does not implement the client registration values that method requires.", client.GetID(), endpointClientAuthMetadataName(strategy), method))
		}

		if err = matchTLSClientAuthSubject(tc, cert, verified, endpointClientAuthMetadataName(strategy)); err != nil {
			return "", err
		}
	case consts.ClientAuthMethodSelfSignedTLSClientAuth:
		if err = matchSelfSignedCertificate(ctx, c, cert, jwt.ClientJWKSFetcherStrategy(ctx, s.Config, c), endpointClientAuthMetadataName(strategy)); err != nil {
			return "", err
		}
	default:
		return "", errorsx.WithStack(ErrInvalidClient.
			WithHint(hintClientCredentialsInvalid).
			WithDebugf("The registered client with id '%s' is not configured to use an RFC 8705 Mutual-TLS '%s_endpoint_auth_method' method.", client.GetID(), endpointClientAuthMetadataName(strategy)))
	}

	return method, nil
}
