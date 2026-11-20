// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/jose"

	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/gen"
)

func TestEqualDistinguishedNames(t *testing.T) {
	testCases := []struct {
		name     string
		a, b     string
		expected bool
	}{
		{name: "ShouldMatchIdentical", a: "CN=test,O=Example", b: "CN=test,O=Example", expected: true},
		{name: "ShouldIgnoreWhitespace", a: "CN=test, O=Example", b: "CN=test,O=Example", expected: true},
		{name: "ShouldIgnoreAttributeTypeCase", a: "cn=test,o=Example", b: "CN=test,O=Example", expected: true},
		{name: "ShouldNotMatchReversedOrder", a: "O=Example,CN=test", b: "CN=test,O=Example", expected: false},
		{name: "ShouldNotMatchDifferentValues", a: "CN=other,O=Example", b: "CN=test,O=Example", expected: false},
		{name: "ShouldNotMatchDifferentValueCase", a: "CN=TEST,O=Example", b: "CN=test,O=Example", expected: false},
		{name: "ShouldNotMatchDifferentLength", a: "CN=test", b: "CN=test,O=Example", expected: false},
		{name: "ShouldNotMatchArbitraryReordering", a: "CN=test,O=Example,C=AU", b: "O=Example,CN=test,C=AU", expected: false},
		{name: "ShouldHandleEscapedComma", a: "CN=test\\, inc,O=Example", b: "CN=test\\, inc,O=Example", expected: true},
		{name: "ShouldTreatEscapedCommaAsPartOfTheValue", a: "CN=test\\, inc", b: "CN=test\\,inc", expected: false},
		{name: "ShouldNotMatchEmptyAgainstValue", a: "", b: "CN=test", expected: false},
		{name: "ShouldMatchEmptyAgainstEmpty", a: "", b: "", expected: true},
		{name: "ShouldNotMatchTrailingTabInValue", a: "CN=test\t,O=Example", b: "CN=test,O=Example", expected: false},
		{name: "ShouldNotMatchLeadingTabInValue", a: "CN=\ttest,O=Example", b: "CN=test,O=Example", expected: false},
		{name: "ShouldNotMatchTrailingNewlineInValue", a: "CN=test\n,O=Example", b: "CN=test,O=Example", expected: false},
		{name: "ShouldNotMatchTrailingVerticalTabInValue", a: "CN=test\v,O=Example", b: "CN=test,O=Example", expected: false},
		{name: "ShouldNotMatchTrailingNonBreakingSpaceInValue", a: "CN=test ,O=Example", b: "CN=test,O=Example", expected: false},
		{name: "ShouldNotMatchWhenTrailingSpaceIsEscaped", a: "CN=test\\ ,O=Example", b: "CN=test,O=Example", expected: false},
		{name: "ShouldStillMatchInsignificantSpaceAfterComma", a: "CN=test, O=Example", b: "CN=test,O=Example", expected: true},
		{name: "ShouldMatchShortNameAgainstDottedOID", a: "2.5.4.3=test,0.9.2342.19200300.100.1.25=example", b: "CN=test,DC=example", expected: true},
		{name: "ShouldMatchEmailAddressAndUIDNames", a: "emailAddress=a@example.com,UID=a", b: "1.2.840.113549.1.9.1=a@example.com,0.9.2342.19200300.100.1.1=a", expected: true},
		{name: "ShouldMatchMultiValuedRDNInAnyOrder", a: "OU=A+CN=test,O=Example", b: "CN=test+OU=A,O=Example", expected: true},
		{name: "ShouldNotMatchMultiValuedRDNAgainstSeparateRDNs", a: "CN=test+OU=A,O=Example", b: "CN=test,OU=A,O=Example", expected: false},
		{name: "ShouldTreatEscapedPlusAsPartOfTheValue", a: "CN=a\\+OU=b", b: "CN=a+OU=b", expected: false},
		{name: "ShouldMatchHexPairEscape", a: "CN=test\\2C inc", b: "CN=test\\, inc", expected: true},
		{name: "ShouldMatchEscapedLeadingHash", a: "CN=\\#test", b: "CN=\\23test", expected: true},
		{name: "ShouldMatchHexStringValueAgainstStringValue", a: "CN=#0C0474657374", b: "CN=test", expected: true},
		{name: "ShouldMatchHexNonStringValueExactly", a: "2.5.4.45=#03020001", b: "2.5.4.45=#03020001", expected: true},
		{name: "ShouldNotMatchDifferentHexNonStringValue", a: "2.5.4.45=#03020001", b: "2.5.4.45=#03020002", expected: false},
		{name: "ShouldNotMatchMalformedHexValue", a: "CN=#0C04746573", b: "CN=#0C04746573", expected: false},
		{name: "ShouldNotMatchOddHexValue", a: "CN=#0C0", b: "CN=#0C0", expected: false},
		{name: "ShouldNotMatchUnknownAttributeTypeName", a: "FOO=test", b: "FOO=test", expected: false},
		{name: "ShouldNotMatchRDNWithoutAttributeType", a: "test", b: "test", expected: false},
		{name: "ShouldNotMatchInvalidEscape", a: "CN=te\\st", b: "CN=te\\st", expected: false},
		{name: "ShouldNotMatchTrailingEscape", a: "CN=test\\", b: "CN=test\\", expected: false},
		{name: "ShouldNotMatchEmptyAttributeInMultiValuedRDN", a: "CN=test+", b: "CN=test+", expected: false},
		{name: "ShouldNotMatchEmptyRDN", a: "CN=test,,O=Example", b: "CN=test,,O=Example", expected: false},
		{name: "ShouldNotMatchTrailingSeparator", a: "CN=test,", b: "CN=test,", expected: false},
		{name: "ShouldNotMatchOnlySeparators", a: ",", b: ",", expected: false},
		{name: "ShouldNotMatchUnescapedSemicolon", a: "CN=test;demo", b: "CN=test;demo", expected: false},
		{name: "ShouldNotMatchUnescapedSemicolonBesideAnEscape", a: "CN=a\\,b;c", b: "CN=a\\,b;c", expected: false},
		{name: "ShouldNotMatchUnescapedQuote", a: "CN=\"test\"", b: "CN=\"test\"", expected: false},
		{name: "ShouldNotMatchUnescapedAngleBracket", a: "CN=<test>", b: "CN=<test>", expected: false},
		{name: "ShouldMatchEscapedSemicolon", a: "CN=test\\;demo", b: "CN=test\\3Bdemo", expected: true},
		{name: "ShouldNotMatchInvalidUTF8Escape", a: "CN=\\FF", b: "CN=\\FF", expected: false},
		{name: "ShouldNotMatchInvalidUTF8StringHexValue", a: "CN=#0C01FF", b: "CN=#0C01FF", expected: false},
		{name: "ShouldMatchBERLongFormLength", a: "CN=#0C810474657374", b: "CN=test", expected: true},
		{name: "ShouldMatchBERLengthWithLeadingZeroOctets", a: "CN=#0C85000000000474657374", b: "CN=test", expected: true},
		{name: "ShouldNotMatchBERReservedLengthOctet", a: "CN=#0CFF74657374", b: "CN=#0CFF74657374", expected: false},
		{name: "ShouldNotMatchBERLengthBeyondTheValue", a: "CN=#0C840000FFFF74657374", b: "CN=#0C840000FFFF74657374", expected: false},
		{name: "ShouldNotMatchBERLengthOverflow", a: "CN=#0C89FFFFFFFFFFFFFFFFFF74657374", b: "CN=#0C89FFFFFFFFFFFFFFFFFF74657374", expected: false},
		{name: "ShouldMatchBERConstructedIndefiniteString", a: "CN=#2C800C0274650C0273740000", b: "CN=test", expected: true},
		{name: "ShouldMatchBERConstructedBitString", a: "2.5.4.45=#238003020001030201000000", b: "2.5.4.45=#0303010100", expected: true},
		{name: "ShouldMatchBERBooleanAsDER", a: "2.5.4.45=#010101", b: "2.5.4.45=#0101FF", expected: true},
		{name: "ShouldNotMatchIndefiniteLengthPrimitive", a: "CN=#0C8074650000", b: "CN=#0C8074650000", expected: false},
		{name: "ShouldNotMatchConstructedStringOfMixedTypes", a: "CN=#2C800C027465130273740000", b: "CN=test", expected: false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, EqualDistinguishedNames(tc.a, tc.b))
		})
	}
}

func TestMatchTLSClientAuthSubject(t *testing.T) {
	uri, err := url.Parse("https://client.example.com/id")
	require.NoError(t, err)

	cert := gen.MustCertificate(gen.CertificateOptions{
		Subject:        pkix.Name{CommonName: "test", Organization: []string{"Example"}},
		DNSNames:       []string{"client.example.com"},
		EmailAddresses: []string{"client@example.com"},
		IPAddresses:    []net.IP{net.ParseIP("203.0.113.1"), net.ParseIP("2001:db8::1")},
		URIs:           []*url.URL{uri},
	})

	testCases := []struct {
		name   string
		client *DefaultMTLSClient
		err    string
	}{
		{
			name:   "ShouldMatchSubjectDN",
			client: &DefaultMTLSClient{DefaultJARClient: &DefaultJARClient{DefaultClient: &DefaultClient{ID: "test"}}, TLSClientAuthSubjectDN: cert.Subject.String()},
		},
		{
			name:   "ShouldMatchSANDNS",
			client: &DefaultMTLSClient{DefaultJARClient: &DefaultJARClient{DefaultClient: &DefaultClient{ID: "test"}}, TLSClientAuthSANDNS: "client.example.com"},
		},
		{
			name:   "ShouldMatchSANDNSCaseInsensitively",
			client: &DefaultMTLSClient{DefaultJARClient: &DefaultJARClient{DefaultClient: &DefaultClient{ID: "test"}}, TLSClientAuthSANDNS: "CLIENT.EXAMPLE.COM"},
		},
		{
			name:   "ShouldMatchSANURI",
			client: &DefaultMTLSClient{DefaultJARClient: &DefaultJARClient{DefaultClient: &DefaultClient{ID: "test"}}, TLSClientAuthSANURI: "https://client.example.com/id"},
		},
		{
			name:   "ShouldMatchSANIP",
			client: &DefaultMTLSClient{DefaultJARClient: &DefaultJARClient{DefaultClient: &DefaultClient{ID: "test"}}, TLSClientAuthSANIP: "203.0.113.1"},
		},
		{
			name:   "ShouldMatchSANIPInAnyNotation",
			client: &DefaultMTLSClient{DefaultJARClient: &DefaultJARClient{DefaultClient: &DefaultClient{ID: "test"}}, TLSClientAuthSANIP: "2001:0db8:0000:0000:0000:0000:0000:0001"},
		},
		{
			name:   "ShouldMatchSANEmail",
			client: &DefaultMTLSClient{DefaultJARClient: &DefaultJARClient{DefaultClient: &DefaultClient{ID: "test"}}, TLSClientAuthSANEmail: "client@example.com"},
		},
		{
			name:   "ShouldNotMatchWrongSubjectDN",
			client: &DefaultMTLSClient{DefaultJARClient: &DefaultJARClient{DefaultClient: &DefaultClient{ID: "test"}}, TLSClientAuthSubjectDN: "CN=other"},
			err:    "does not match the registered 'tls_client_auth_subject_dn'",
		},
		{
			name:   "ShouldNotMatchWrongSANDNS",
			client: &DefaultMTLSClient{DefaultJARClient: &DefaultJARClient{DefaultClient: &DefaultClient{ID: "test"}}, TLSClientAuthSANDNS: "other.example.com"},
			err:    "does not match the registered 'tls_client_auth_san_dns'",
		},
		{
			name:   "ShouldNotMatchWrongSANIP",
			client: &DefaultMTLSClient{DefaultJARClient: &DefaultJARClient{DefaultClient: &DefaultClient{ID: "test"}}, TLSClientAuthSANIP: "203.0.113.9"},
			err:    "does not match the registered 'tls_client_auth_san_ip'",
		},
		{
			name:   "ShouldRejectAnUnparsableSANIP",
			client: &DefaultMTLSClient{DefaultJARClient: &DefaultJARClient{DefaultClient: &DefaultClient{ID: "test"}}, TLSClientAuthSANIP: "not-an-ip"},
			err:    "is not a valid IP address",
		},
		{
			name:   "ShouldRejectNoSubjectRegistered",
			client: &DefaultMTLSClient{DefaultJARClient: &DefaultJARClient{DefaultClient: &DefaultClient{ID: "test"}}},
			err:    "must register exactly one",
		},
		{
			name:   "ShouldRejectMultipleSubjectsRegistered",
			client: &DefaultMTLSClient{DefaultJARClient: &DefaultJARClient{DefaultClient: &DefaultClient{ID: "test"}}, TLSClientAuthSANDNS: "client.example.com", TLSClientAuthSANEmail: "client@example.com"},
			err:    "must register exactly one",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := matchTLSClientAuthSubject(tc.client, cert, true, "token")

			if tc.err == "" {
				assert.NoError(t, err)

				return
			}

			require.Error(t, err)
			assert.Contains(t, ErrorToDebugRFC6749Error(err).Error(), tc.err)
		})
	}

	t.Run("ShouldRejectANilCertificate", func(t *testing.T) {
		client := &DefaultMTLSClient{DefaultJARClient: &DefaultJARClient{DefaultClient: &DefaultClient{ID: "test"}}, TLSClientAuthSubjectDN: "CN=test,O=Example"}

		err := matchTLSClientAuthSubject(client, nil, true, "token")

		require.Error(t, err)
		assert.Contains(t, ErrorToDebugRFC6749Error(err).Error(), "did not include a client certificate")
	})
}

func TestMatchTLSClientAuthSubjectDNSequence(t *testing.T) {
	var (
		oidCN     = asn1.ObjectIdentifier{2, 5, 4, 3}
		oidO      = asn1.ObjectIdentifier{2, 5, 4, 10}
		oidOU     = asn1.ObjectIdentifier{2, 5, 4, 11}
		oidDC     = asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 25}
		oidUID    = asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 1}
		oidEmail  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}
		oidUnique = asn1.ObjectIdentifier{2, 5, 4, 45}
	)

	single := func(oid asn1.ObjectIdentifier, value any) pkix.RelativeDistinguishedNameSET {
		return pkix.RelativeDistinguishedNameSET{{Type: oid, Value: value}}
	}

	directory := pkix.RDNSequence{single(oidDC, "example"), single(oidDC, "corp"), single(oidCN, "Users"), single(oidCN, "app")}

	var lossy pkix.Name

	lossy.FillFromRDNSequence(&directory)

	testCases := []struct {
		name     string
		subject  pkix.RDNSequence
		dn       string
		expected bool
		err      string
	}{
		{name: "ShouldMatchRFC4514Order", subject: pkix.RDNSequence{single(oidO, "Bank"), single(oidOU, "Clients"), single(oidCN, "app")}, dn: "CN=app,OU=Clients,O=Bank", expected: true},
		{name: "ShouldNotMatchEncodingOrder", subject: pkix.RDNSequence{single(oidO, "Bank"), single(oidOU, "Clients"), single(oidCN, "app")}, dn: "O=Bank, OU=Clients, CN=app", expected: false},
		{name: "ShouldNotMatchReversedSubject", subject: pkix.RDNSequence{single(oidCN, "app"), single(oidOU, "Clients"), single(oidO, "Bank")}, dn: "CN=app,OU=Clients,O=Bank", expected: false},
		{name: "ShouldNotMatchReorderedRDNs", subject: pkix.RDNSequence{single(oidOU, "Clients"), single(oidO, "Bank"), single(oidCN, "app")}, dn: "CN=app,OU=Clients,O=Bank", expected: false},
		{name: "ShouldMatchSubjectNotInGoFieldOrder", subject: pkix.RDNSequence{single(oidCN, "app"), single(oidOU, "Clients"), single(oidO, "Bank")}, dn: "O=Bank,OU=Clients,CN=app", expected: true},
		{name: "ShouldMatchRepeatedCNAndDC", subject: directory, dn: "CN=app,CN=Users,DC=corp,DC=example", expected: true},
		{name: "ShouldNotMatchDifferentInnerCN", subject: directory, dn: "CN=app,CN=Computers,DC=corp,DC=example", expected: false},
		{name: "ShouldNotMatchWhenAnRDNIsMissing", subject: directory, dn: "CN=app,DC=corp,DC=example", expected: false},
		{name: "ShouldNotMatchGoRenderingOfRepeatedCN", subject: directory, dn: lossy.String(), expected: false},
		{name: "ShouldMatchRepeatedOUAsSeparateRDNs", subject: pkix.RDNSequence{single(oidO, "Bank"), single(oidOU, "A"), single(oidOU, "B"), single(oidCN, "app")}, dn: "CN=app,OU=B,OU=A,O=Bank", expected: true},
		{name: "ShouldNotMatchRepeatedOUAsMultiValuedRDN", subject: pkix.RDNSequence{single(oidO, "Bank"), single(oidOU, "A"), single(oidOU, "B"), single(oidCN, "app")}, dn: "CN=app,OU=A+OU=B,O=Bank", expected: false},
		{name: "ShouldMatchMultiValuedRDN", subject: pkix.RDNSequence{single(oidO, "Bank"), {{Type: oidOU, Value: "Clients"}, {Type: oidCN, Value: "app"}}}, dn: "CN=app+OU=Clients,O=Bank", expected: true},
		{name: "ShouldNotMatchMultiValuedRDNAgainstSeparateRDNs", subject: pkix.RDNSequence{single(oidO, "Bank"), {{Type: oidOU, Value: "Clients"}, {Type: oidCN, Value: "app"}}}, dn: "CN=app,OU=Clients,O=Bank", expected: false},
		{name: "ShouldMatchUIDAndEmailAddress", subject: pkix.RDNSequence{single(oidO, "Bank"), single(oidUID, "app"), single(oidEmail, asn1.RawValue{Tag: asn1.TagIA5String, Bytes: []byte("app@example.com")})}, dn: "emailAddress=app@example.com,UID=app,O=Bank", expected: true},
		{name: "ShouldMatchDottedOID", subject: directory, dn: "2.5.4.3=app,2.5.4.3=Users,0.9.2342.19200300.100.1.25=corp,0.9.2342.19200300.100.1.25=example", expected: true},
		{name: "ShouldMatchHexValue", subject: directory, dn: "CN=app,CN=Users,DC=#0c04636f7270,DC=example", expected: true},
		{name: "ShouldMatchBERHexValue", subject: directory, dn: "CN=app,CN=Users,DC=#0c8104636f7270,DC=example", expected: true},
		{name: "ShouldMatchEscapedCharacters", subject: pkix.RDNSequence{single(oidO, "Bank, Inc."), single(oidCN, "#app+1 ")}, dn: "CN=\\#app\\+1\\ ,O=Bank\\2C Inc.", expected: true},
		{name: "ShouldMatchNonStringValueByHex", subject: pkix.RDNSequence{single(oidUnique, asn1.BitString{Bytes: []byte{1}, BitLength: 8}), single(oidCN, "app")}, dn: "CN=app,2.5.4.45=#03020001", expected: true},
		{name: "ShouldNotMatchNonStringValueByString", subject: pkix.RDNSequence{single(oidUnique, asn1.BitString{Bytes: []byte{1}, BitLength: 8}), single(oidCN, "app")}, dn: "CN=app,2.5.4.45=\\03\\02\\00\\01", expected: false},
		{name: "ShouldNotMatchDifferentValueCase", subject: pkix.RDNSequence{single(oidCN, "app")}, dn: "CN=APP", expected: false},
		{name: "ShouldNotMatchUnparsableRegisteredValue", subject: pkix.RDNSequence{single(oidCN, "app")}, dn: "CN=app,FOO=bar", expected: false, err: "is not a valid RFC 4514 distinguished name"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			client := &DefaultMTLSClient{DefaultJARClient: &DefaultJARClient{DefaultClient: &DefaultClient{ID: "test"}}, TLSClientAuthSubjectDN: tc.dn}

			err := matchTLSClientAuthSubject(client, mustCertificateWithSubject(t, tc.subject), true, "token")

			if tc.expected {
				assert.NoError(t, err)

				return
			}

			if tc.err == "" {
				tc.err = "does not match the registered 'tls_client_auth_subject_dn'"
			}

			require.Error(t, err)
			assert.Contains(t, ErrorToDebugRFC6749Error(err).Error(), tc.err)
		})
	}
}

func TestMatchTLSClientAuthSubjectDNDegenerate(t *testing.T) {
	sanOnly := &x509.Certificate{DNSNames: []string{"client.example.com"}}

	require.Empty(t, sanOnly.Subject.String(), "the fixture must have an empty subject for this test to mean anything")

	testCases := []struct {
		name string
		dn   string
		err  string
	}{
		{name: "ShouldRejectASubjectDNOfOnlySpace", dn: "  ", err: "contains no relative distinguished names"},
		{name: "ShouldRejectASubjectDNOfOnlyASeparatorAndSpace", dn: " , ", err: "is not a valid RFC 4514 distinguished name"},
		{name: "ShouldRejectASubjectDNOfOnlyASeparator", dn: ",", err: "is not a valid RFC 4514 distinguished name"},
		{name: "ShouldStillReportALegitimateSubjectDNAsAMismatch", dn: "CN=test,O=Example", err: "does not match the registered 'tls_client_auth_subject_dn'"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			client := &DefaultMTLSClient{DefaultJARClient: &DefaultJARClient{DefaultClient: &DefaultClient{ID: "test"}}, TLSClientAuthSubjectDN: tc.dn}

			err := matchTLSClientAuthSubject(client, sanOnly, true, "token")

			require.Error(t, err)
			assert.Contains(t, ErrorToDebugRFC6749Error(err).Error(), tc.err)
		})
	}

	t.Run("ShouldLeaveTheComparisonItselfUnchanged", func(t *testing.T) {
		assert.True(t, EqualDistinguishedNames("  ", sanOnly.Subject.String()))
	})
}

func TestMatchSelfSignedCertificate(t *testing.T) {
	registered := gen.MustCertificate(gen.CertificateOptions{Subject: pkix.Name{CommonName: "registered"}})
	other := gen.MustCertificate(gen.CertificateOptions{Subject: pkix.Name{CommonName: "other"}, SerialNumber: 2})

	t.Run("ShouldMatchARegisteredCertificate", func(t *testing.T) {
		assert.NoError(t, matchSelfSignedCertificate(context.TODO(), newMTLSJWKSClient([]*x509.Certificate{other, registered}, ""), registered, nil, "token"))
	})

	t.Run("ShouldNotMatchAnUnregisteredCertificate", func(t *testing.T) {
		err := matchSelfSignedCertificate(context.TODO(), newMTLSJWKSClient([]*x509.Certificate{other}, ""), registered, nil, "token")

		require.Error(t, err)
		assert.Contains(t, ErrorToDebugRFC6749Error(err).Error(), "does not match any certificate")
	})

	t.Run("ShouldErrorWhenNoKeysAreRegistered", func(t *testing.T) {
		err := matchSelfSignedCertificate(context.TODO(), newMTLSJWKSClient(nil, ""), registered, nil, "token")

		require.Error(t, err)
		assert.Contains(t, ErrorToDebugRFC6749Error(err).Error(), "has no 'jwks' or 'jwks_uri'")
	})

	t.Run("ShouldResolveFromTheJWKSURI", func(t *testing.T) {
		client := newMTLSJWKSClient(nil, "https://client.example.com/jwks.json")
		fetcher := &staticJWKSFetcher{jwks: &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: registered.PublicKey, Certificates: []*x509.Certificate{registered}}}}}

		assert.NoError(t, matchSelfSignedCertificate(context.TODO(), client, registered, fetcher, "token"))
		assert.Equal(t, "https://client.example.com/jwks.json", fetcher.location)
	})

	t.Run("ShouldRefreshTheJWKSURIForACertificateAbsentFromTheCachedSet", func(t *testing.T) {
		client := newMTLSJWKSClient(nil, "https://client.example.com/jwks.json")
		fetcher := &staticJWKSFetcher{
			jwks:      &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: other.PublicKey, Certificates: []*x509.Certificate{other}}}},
			refreshed: &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: registered.PublicKey, Certificates: []*x509.Certificate{registered}}}},
		}

		assert.NoError(t, matchSelfSignedCertificate(context.TODO(), client, registered, fetcher, "token"))
		assert.Equal(t, 1, fetcher.refreshes)
	})

	t.Run("ShouldNotRefreshTheJWKSURIForACertificateInTheCachedSet", func(t *testing.T) {
		client := newMTLSJWKSClient(nil, "https://client.example.com/jwks.json")
		fetcher := &staticJWKSFetcher{jwks: &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: registered.PublicKey, Certificates: []*x509.Certificate{registered}}}}}

		assert.NoError(t, matchSelfSignedCertificate(context.TODO(), client, registered, fetcher, "token"))
		assert.Equal(t, 0, fetcher.refreshes)
	})

	t.Run("ShouldNotMatchACertificateAbsentFromTheRefreshedSet", func(t *testing.T) {
		client := newMTLSJWKSClient(nil, "https://client.example.com/jwks.json")
		fetcher := &staticJWKSFetcher{jwks: &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: other.PublicKey, Certificates: []*x509.Certificate{other}}}}}

		err := matchSelfSignedCertificate(context.TODO(), client, registered, fetcher, "token")

		require.Error(t, err)
		assert.Contains(t, ErrorToDebugRFC6749Error(err).Error(), "does not match any certificate")
		assert.Equal(t, 1, fetcher.refreshes)
	})

	t.Run("ShouldRejectANilCertificate", func(t *testing.T) {
		err := matchSelfSignedCertificate(context.TODO(), newMTLSJWKSClient([]*x509.Certificate{registered}, ""), nil, nil, "token")

		require.Error(t, err)
		assert.Contains(t, ErrorToDebugRFC6749Error(err).Error(), "did not include a client certificate")
	})

	t.Run("ShouldNotMatchWhenARegisteredCertificateIsNil", func(t *testing.T) {
		client := &mtlsJWKSClient{DefaultJARClient: &DefaultJARClient{
			DefaultClient: &DefaultClient{ID: "test"},
			JSONWebKeys:   &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Certificates: []*x509.Certificate{nil}}}},
		}}

		err := matchSelfSignedCertificate(context.TODO(), client, registered, nil, "token")

		require.Error(t, err)
		assert.Contains(t, ErrorToDebugRFC6749Error(err).Error(), "does not match any certificate")
	})

	t.Run("ShouldRejectWhenBothThePresentedAndARegisteredCertificateAreNil", func(t *testing.T) {
		client := &mtlsJWKSClient{DefaultJARClient: &DefaultJARClient{
			DefaultClient: &DefaultClient{ID: "test"},
			JSONWebKeys:   &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Certificates: []*x509.Certificate{nil}}}},
		}}

		err := matchSelfSignedCertificate(context.TODO(), client, nil, nil, "token")

		require.Error(t, err)
		assert.Contains(t, ErrorToDebugRFC6749Error(err).Error(), "did not include a client certificate")
	})

	t.Run("ShouldRejectWhenNoFetcherIsConfigured", func(t *testing.T) {
		client := newMTLSJWKSClient(nil, "https://client.example.com/jwks.json")

		err := matchSelfSignedCertificate(context.TODO(), client, registered, nil, "token")

		require.Error(t, err)
		assert.Contains(t, ErrorToDebugRFC6749Error(err).Error(), "no JWKS fetcher strategy")
	})

	t.Run("ShouldPropagateAJWKSResolutionError", func(t *testing.T) {
		client := newMTLSJWKSClient(nil, "https://client.example.com/jwks.json")
		fetcher := &staticJWKSFetcher{err: errors.New("network unreachable")}

		err := matchSelfSignedCertificate(context.TODO(), client, registered, fetcher, "token")

		require.Error(t, err)
		assert.Contains(t, ErrorToDebugRFC6749Error(err).Error(), "could not be resolved")
	})

	t.Run("ShouldRejectWhenTheResolvedJWKSHasNoKeys", func(t *testing.T) {
		client := newMTLSJWKSClient(nil, "https://client.example.com/jwks.json")
		fetcher := &staticJWKSFetcher{jwks: &jose.JSONWebKeySet{}}

		err := matchSelfSignedCertificate(context.TODO(), client, registered, fetcher, "token")

		require.Error(t, err)
		assert.Contains(t, ErrorToDebugRFC6749Error(err).Error(), "has no 'jwks' or 'jwks_uri' keys")
	})
}

func TestAuthenticateClientMTLS(t *testing.T) {
	cert := gen.MustCertificate(gen.CertificateOptions{Subject: pkix.Name{CommonName: "test"}, DNSNames: []string{"client.example.com"}})
	other := gen.MustCertificate(gen.CertificateOptions{Subject: pkix.Name{CommonName: "other"}, DNSNames: []string{"other.example.com"}, SerialNumber: 2})

	pkiClient := func() Client {
		return &DefaultMTLSClient{
			DefaultJARClient: &DefaultJARClient{
				DefaultClient:           &DefaultClient{ID: "test"},
				TokenEndpointAuthMethod: consts.ClientAuthMethodTLSClientAuth,
			},
			TLSClientAuthSANDNS: "client.example.com",
		}
	}

	secretClient := func() Client {
		return &DefaultMTLSClient{
			DefaultJARClient: &DefaultJARClient{
				DefaultClient:           &DefaultClient{ID: "test", ClientSecret: NewPlainTextClientSecret("secret")},
				TokenEndpointAuthMethod: consts.ClientAuthMethodClientSecretPost,
			},
		}
	}

	testCases := []struct {
		name   string
		client Client
		cert   *x509.Certificate
		form   url.Values
		method string
		err    string
	}{
		{
			name:   "ShouldAuthenticateWithTLSClientAuth",
			client: pkiClient(),
			cert:   cert,
			form:   url.Values{consts.FormParameterClientID: []string{"test"}},
			method: consts.ClientAuthMethodTLSClientAuth,
		},
		{
			name:   "ShouldRejectAMismatchedCertificate",
			client: pkiClient(),
			cert:   other,
			form:   url.Values{consts.FormParameterClientID: []string{"test"}},
			err:    "does not match the registered 'tls_client_auth_san_dns'",
		},
		{
			name:   "ShouldRejectAMissingCertificate",
			client: pkiClient(),
			form:   url.Values{consts.FormParameterClientID: []string{"test"}},
			err:    "no known authentication method",
		},
		{
			name:   "ShouldRejectMTLSCombinedWithClientSecretPost",
			client: pkiClient(),
			cert:   cert,
			form:   url.Values{consts.FormParameterClientID: []string{"test"}, consts.FormParameterClientSecret: []string{"secret"}},
			err:    "more than one known authentication method",
		},
		{
			name:   "ShouldIgnoreAnIncidentalCertificateForANonMTLSClient",
			client: secretClient(),
			cert:   cert,
			form:   url.Values{consts.FormParameterClientID: []string{"test"}, consts.FormParameterClientSecret: []string{"secret"}},
			method: consts.ClientAuthMethodClientSecretPost,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			store := newMTLSClientStore()
			store.clients["test"] = tc.client

			config := &Config{MTLSEnabled: true}
			strategy := &DefaultClientAuthenticationStrategy{Store: store, Config: config}

			r := &http.Request{Header: http.Header{}, PostForm: tc.form, Form: tc.form}

			if tc.cert != nil {
				r.TLS = &tls.ConnectionState{
					PeerCertificates: []*x509.Certificate{tc.cert},
					VerifiedChains:   [][]*x509.Certificate{{tc.cert}},
				}
			}

			client, method, err := strategy.AuthenticateClient(context.TODO(), r, tc.form, &TokenEndpointClientAuthStrategy{})

			if tc.err != "" {
				assert.Nil(t, client)
				require.Error(t, err)
				assert.Contains(t, ErrorToDebugRFC6749Error(err).Error(), tc.err)

				return
			}

			require.NoError(t, err)
			require.NotNil(t, client)
			assert.Equal(t, tc.method, method)
		})
	}
}

func TestAuthenticateClientMTLSViaForwardedHeader(t *testing.T) {
	cert := gen.MustCertificate(gen.CertificateOptions{Subject: pkix.Name{CommonName: "test"}, DNSNames: []string{"client.example.com"}})
	proxy := gen.MustCertificate(gen.CertificateOptions{Subject: pkix.Name{CommonName: "proxy"}, DNSNames: []string{"proxy.example.com"}, SerialNumber: 3})

	const header = "X-Forwarded-Tls-Client-Cert"

	form := url.Values{consts.FormParameterClientID: []string{"test"}}

	newStrategy := func() *DefaultClientAuthenticationStrategy {
		store := newMTLSClientStore()
		store.clients["test"] = &DefaultMTLSClient{
			DefaultJARClient: &DefaultJARClient{
				DefaultClient:           &DefaultClient{ID: "test"},
				TokenEndpointAuthMethod: consts.ClientAuthMethodTLSClientAuth,
			},
			TLSClientAuthSANDNS: "client.example.com",
		}

		return &DefaultClientAuthenticationStrategy{
			Store:  store,
			Config: &Config{MTLSEnabled: true, MTLSClientCertificateHeader: header},
		}
	}

	newRequest := func(peer *x509.Certificate, headerValue string) *http.Request {
		r := &http.Request{Header: http.Header{}, PostForm: form, Form: form}

		if peer != nil {
			r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{peer}}
		}

		if headerValue != "" {
			r.Header.Set(header, headerValue)
		}

		return r
	}

	t.Run("ShouldAuthenticateTheForwardedClientRatherThanTheProxy", func(t *testing.T) {
		client, method, err := newStrategy().AuthenticateClient(context.TODO(), newRequest(proxy, encodeTraefikV3(cert)), form, &TokenEndpointClientAuthStrategy{})

		require.NoError(t, err)
		require.NotNil(t, client)
		assert.Equal(t, consts.ClientAuthMethodTLSClientAuth, method)
	})

	t.Run("ShouldRejectWhenOnlyTheProxyCertificateIsPresent", func(t *testing.T) {
		client, _, err := newStrategy().AuthenticateClient(context.TODO(), newRequest(proxy, ""), form, &TokenEndpointClientAuthStrategy{})

		assert.Nil(t, client)
		require.Error(t, err)
		assert.Contains(t, ErrorToDebugRFC6749Error(err).Error(), "no known authentication method")
	})
}

func TestAuthenticateClientSelfSignedMTLS(t *testing.T) {
	cert := gen.MustCertificate(gen.CertificateOptions{Subject: pkix.Name{CommonName: "registered"}})
	other := gen.MustCertificate(gen.CertificateOptions{Subject: pkix.Name{CommonName: "other"}, SerialNumber: 2})

	client := &DefaultMTLSClient{
		DefaultJARClient: &DefaultJARClient{
			DefaultClient:           &DefaultClient{ID: "test"},
			TokenEndpointAuthMethod: consts.ClientAuthMethodSelfSignedTLSClientAuth,
			JSONWebKeys:             &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: cert.PublicKey, Certificates: []*x509.Certificate{cert}, KeyID: cert.Subject.CommonName}}},
		},
	}

	store := newMTLSClientStore()
	store.clients["test"] = client

	strategy := &DefaultClientAuthenticationStrategy{Store: store, Config: &Config{MTLSEnabled: true}}

	form := url.Values{consts.FormParameterClientID: []string{"test"}}

	t.Run("ShouldAuthenticateWithARegisteredCertificate", func(t *testing.T) {
		r := &http.Request{Header: http.Header{}, PostForm: form, Form: form, TLS: &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}}

		actual, method, err := strategy.AuthenticateClient(context.TODO(), r, form, &TokenEndpointClientAuthStrategy{})

		require.NoError(t, err)
		require.NotNil(t, actual)
		assert.Equal(t, consts.ClientAuthMethodSelfSignedTLSClientAuth, method)
	})

	t.Run("ShouldRejectAnUnregisteredCertificate", func(t *testing.T) {
		r := &http.Request{Header: http.Header{}, PostForm: form, Form: form, TLS: &tls.ConnectionState{PeerCertificates: []*x509.Certificate{other}}}

		_, _, err := strategy.AuthenticateClient(context.TODO(), r, form, &TokenEndpointClientAuthStrategy{})

		require.Error(t, err)
		assert.Contains(t, ErrorToDebugRFC6749Error(err).Error(), "does not match any certificate")
	})
}

func TestAuthenticateClientMTLSRequiresVerifiedChain(t *testing.T) {
	cert := gen.MustCertificate(gen.CertificateOptions{Subject: pkix.Name{CommonName: "test"}, DNSNames: []string{"client.example.com"}})

	form := url.Values{consts.FormParameterClientID: []string{"test"}}

	newStrategy := func(client Client) *DefaultClientAuthenticationStrategy {
		store := newMTLSClientStore()
		store.clients["test"] = client

		return &DefaultClientAuthenticationStrategy{Store: store, Config: &Config{MTLSEnabled: true}}
	}

	pkiClient := &DefaultMTLSClient{
		DefaultJARClient: &DefaultJARClient{
			DefaultClient:           &DefaultClient{ID: "test"},
			TokenEndpointAuthMethod: consts.ClientAuthMethodTLSClientAuth,
		},
		TLSClientAuthSANDNS: "client.example.com",
	}

	selfSignedClient := &DefaultMTLSClient{
		DefaultJARClient: &DefaultJARClient{
			DefaultClient:           &DefaultClient{ID: "test"},
			TokenEndpointAuthMethod: consts.ClientAuthMethodSelfSignedTLSClientAuth,
			JSONWebKeys:             &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: cert.PublicKey, Certificates: []*x509.Certificate{cert}, KeyID: cert.Subject.CommonName}}},
		},
	}

	newRequest := func(verified bool) *http.Request {
		state := &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}

		if verified {
			state.VerifiedChains = [][]*x509.Certificate{{cert}}
		}

		return &http.Request{Header: http.Header{}, PostForm: form, Form: form, TLS: state}
	}

	t.Run("ShouldRejectPKIMethodWhenTheChainWasNotValidated", func(t *testing.T) {
		_, _, err := newStrategy(pkiClient).
			AuthenticateClient(context.TODO(), newRequest(false), form, &TokenEndpointClientAuthStrategy{})

		require.Error(t, err)
		assert.Contains(t, ErrorToDebugRFC6749Error(err).Error(), "validated certificate chain")
	})

	t.Run("ShouldAuthenticatePKIMethodWhenTheChainWasValidated", func(t *testing.T) {
		client, method, err := newStrategy(pkiClient).
			AuthenticateClient(context.TODO(), newRequest(true), form, &TokenEndpointClientAuthStrategy{})

		require.NoError(t, err)
		require.NotNil(t, client)
		assert.Equal(t, consts.ClientAuthMethodTLSClientAuth, method)
	})

	t.Run("ShouldAuthenticateSelfSignedMethodWithoutAValidatedChain", func(t *testing.T) {
		client, method, err := newStrategy(selfSignedClient).
			AuthenticateClient(context.TODO(), newRequest(false), form, &TokenEndpointClientAuthStrategy{})

		require.NoError(t, err)
		require.NotNil(t, client)
		assert.Equal(t, consts.ClientAuthMethodSelfSignedTLSClientAuth, method)
	})
}

func newMTLSClientStore() *mtlsClientStore {
	return &mtlsClientStore{clients: make(map[string]Client)}
}

func newMTLSJWKSClient(certs []*x509.Certificate, uri string) *mtlsJWKSClient {
	keys := make([]jose.JSONWebKey, 0, len(certs))

	for _, cert := range certs {
		keys = append(keys, jose.JSONWebKey{Key: cert.PublicKey, Certificates: []*x509.Certificate{cert}, KeyID: cert.Subject.CommonName})
	}

	client := &mtlsJWKSClient{DefaultJARClient: &DefaultJARClient{DefaultClient: &DefaultClient{ID: "test"}, JSONWebKeysURI: uri}}

	if len(keys) != 0 {
		client.JSONWebKeys = &jose.JSONWebKeySet{Keys: keys}
	}

	return client
}

type mtlsClientStore struct {
	clients map[string]Client
}

func (s *mtlsClientStore) GetClient(_ context.Context, id string) (Client, error) {
	client, ok := s.clients[id]
	if !ok {
		return nil, ErrNotFound
	}

	return client, nil
}

func (s *mtlsClientStore) ClientAssertionJWTValid(_ context.Context, _, _ string) error {
	return nil
}

func (s *mtlsClientStore) SetClientAssertionJWT(_ context.Context, _, _ string, _ time.Time) error {
	return nil
}

func (s *mtlsClientStore) CreateClient(_ context.Context, _ Client) error {
	return ErrNotFound
}

func (s *mtlsClientStore) UpdateClient(_ context.Context, _ string, _ Client) error {
	return ErrNotFound
}

func (s *mtlsClientStore) DeleteClient(_ context.Context, _ string) error {
	return ErrNotFound
}

type mtlsJWKSClient struct {
	*DefaultJARClient
}

type staticJWKSFetcher struct {
	jwks      *jose.JSONWebKeySet
	refreshed *jose.JSONWebKeySet
	err       error
	location  string
	refreshes int
}

func (f *staticJWKSFetcher) Resolve(_ context.Context, location string, ignoreCache bool) (*jose.JSONWebKeySet, error) {
	f.location = location

	if f.err != nil {
		return nil, f.err
	}

	if ignoreCache {
		f.refreshes++

		if f.refreshed != nil {
			return f.refreshed, nil
		}
	}

	return f.jwks, nil
}

func mustCertificateWithSubject(t *testing.T, subject pkix.RDNSequence) *x509.Certificate {
	t.Helper()

	raw, err := asn1.Marshal(subject)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		RawSubject:   raw,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	key := gen.MustRSAKey()

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	return cert
}
