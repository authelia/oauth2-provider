// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
		{name: "ShouldMatchReversedOrder", a: "O=Example,CN=test", b: "CN=test,O=Example", expected: true},
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
			name:   "ShouldRejectAnUnparseableSANIP",
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
			err := matchTLSClientAuthSubject(tc.client, cert, "token")

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

		err := matchTLSClientAuthSubject(client, nil, "token")

		require.Error(t, err)
		assert.Contains(t, ErrorToDebugRFC6749Error(err).Error(), "did not include a client certificate")
	})
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
		{name: "ShouldRejectASubjectDNOfOnlyASeparatorAndSpace", dn: " , ", err: "contains no relative distinguished names"},
		{name: "ShouldRejectASubjectDNOfOnlyASeparator", dn: ",", err: "contains no relative distinguished names"},
		{name: "ShouldStillReportALegitimateSubjectDNAsAMismatch", dn: "CN=test,O=Example", err: "does not match the registered 'tls_client_auth_subject_dn'"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			client := &DefaultMTLSClient{DefaultJARClient: &DefaultJARClient{DefaultClient: &DefaultClient{ID: "test"}}, TLSClientAuthSubjectDN: tc.dn}

			err := matchTLSClientAuthSubject(client, sanOnly, "token")

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
				r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{tc.cert}}
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

// TestAuthenticateClientMTLSViaForwardedHeader covers the deployment MTLSClientCertificateHeader exists for: a TLS
// terminating reverse proxy that forwards the client's certificate in a header while authenticating its own
// connection to this server with mutual TLS. The peer certificate on such a connection is the proxy's, so the header
// is the only source of the client's certificate.
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
		// No header means no client certificate. Were the connection's peer certificate consulted instead, this would
		// fail on the SAN mismatch rather than on there being no credential at all.
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

type mtlsClientStore struct {
	clients map[string]Client
}

func newMTLSClientStore() *mtlsClientStore {
	return &mtlsClientStore{clients: make(map[string]Client)}
}

func (s *mtlsClientStore) GetClient(_ context.Context, id string) (Client, error) {
	client, ok := s.clients[id]
	if !ok {
		return nil, ErrNotFound
	}

	return client, nil
}

func (s *mtlsClientStore) ClientAssertionJWTValid(_ context.Context, _ string) error {
	return nil
}

func (s *mtlsClientStore) SetClientAssertionJWT(_ context.Context, _ string, _ time.Time) error {
	return nil
}

// The mutual-TLS tests exercise authentication, not dynamic registration, so this store implements the
// ClientRegistrationManager half of ClientManager as unsupported.

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

func newMTLSJWKSClient(certs []*x509.Certificate, uri string) *mtlsJWKSClient {
	var keys []jose.JSONWebKey

	for _, cert := range certs {
		keys = append(keys, jose.JSONWebKey{Key: cert.PublicKey, Certificates: []*x509.Certificate{cert}, KeyID: cert.Subject.CommonName})
	}

	client := &mtlsJWKSClient{DefaultJARClient: &DefaultJARClient{DefaultClient: &DefaultClient{ID: "test"}, JSONWebKeysURI: uri}}

	if len(keys) != 0 {
		client.JSONWebKeys = &jose.JSONWebKeySet{Keys: keys}
	}

	return client
}

type staticJWKSFetcher struct {
	jwks     *jose.JSONWebKeySet
	err      error
	location string
}

func (f *staticJWKSFetcher) Resolve(_ context.Context, location string, _ bool) (*jose.JSONWebKeySet, error) {
	f.location = location

	if f.err != nil {
		return nil, f.err
	}

	return f.jwks, nil
}
