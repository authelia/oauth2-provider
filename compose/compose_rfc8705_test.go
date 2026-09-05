// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package compose

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/gen"
	"authelia.com/provider/oauth2/storage"
)

func TestMTLSBindsAndEnforcesOnRefreshTokenRequests(t *testing.T) {
	provider, _ := newMTLSProvider(t)

	cert := gen.MustCertificate(gen.CertificateOptions{})
	other := gen.MustCertificate(gen.CertificateOptions{SerialNumber: 2})

	code := mtlsAuthorizeForCode(t, provider)

	response, err := mtlsTokenRequest(t, provider, url.Values{
		consts.FormParameterGrantType:         []string{consts.GrantTypeAuthorizationCode},
		consts.FormParameterAuthorizationCode: []string{code},
		consts.FormParameterRedirectURI:       []string{mtRedirectURI},
	}, cert)
	require.NoError(t, err)

	assert.Equal(t, oauth2.BearerAccessToken, response.GetTokenType())

	refreshToken, _ := response.ToMap()[consts.AccessResponseRefreshToken].(string)
	require.NotEmpty(t, refreshToken)

	t.Run("ShouldRejectRefreshWithoutACertificate", func(t *testing.T) {
		_, err := mtlsTokenRequest(t, provider, url.Values{
			consts.FormParameterGrantType:    []string{consts.GrantTypeRefreshToken},
			consts.FormParameterRefreshToken: []string{refreshToken},
		}, nil)

		require.Error(t, err)
		assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The request requires a mutual-TLS client certificate but none was presented.")
	})

	t.Run("ShouldRejectRefreshWithAnotherCertificate", func(t *testing.T) {
		_, err := mtlsTokenRequest(t, provider, url.Values{
			consts.FormParameterGrantType:    []string{consts.GrantTypeRefreshToken},
			consts.FormParameterRefreshToken: []string{refreshToken},
		}, other)

		require.Error(t, err)
		assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), "The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client. The mutual-TLS client certificate does not match the certificate the grant is bound to.")
	})

	t.Run("ShouldAcceptRefreshWithTheBoundCertificateAndStayBound", func(t *testing.T) {
		response, err := mtlsTokenRequest(t, provider, url.Values{
			consts.FormParameterGrantType:    []string{consts.GrantTypeRefreshToken},
			consts.FormParameterRefreshToken: []string{refreshToken},
		}, cert)

		require.NoError(t, err)
		assert.Equal(t, oauth2.BearerAccessToken, response.GetTokenType())

		rotated, _ := response.ToMap()[consts.AccessResponseRefreshToken].(string)
		require.NotEmpty(t, rotated)

		_, err = mtlsTokenRequest(t, provider, url.Values{
			consts.FormParameterGrantType:    []string{consts.GrantTypeRefreshToken},
			consts.FormParameterRefreshToken: []string{rotated},
		}, nil)

		require.Error(t, err)
		assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The request requires a mutual-TLS client certificate but none was presented.")
	})
}

func newMTLSProvider(t *testing.T) (oauth2.Provider, *storage.MemoryStore) {
	t.Helper()

	store := storage.NewMemoryStore()
	config := &oauth2.Config{MTLSEnabled: true, GlobalSecret: []byte("some-cool-secret-that-is-32bytes"), RFC7591ClientRegistrationGlobalSecret: []byte("a-completely-different-secret-at-least-32b")}

	provider := ComposeAllEnabled(config, store, gen.MustRSAKey())

	store.Clients[mtClientID] = &oauth2.DefaultClient{
		ID:                                    mtClientID,
		ClientSecret:                          oauth2.NewPlainTextClientSecret(mtSecret),
		RedirectURIs:                          []string{mtRedirectURI},
		ResponseTypes:                         []string{consts.ResponseTypeAuthorizationCodeFlow},
		GrantTypes:                            []string{consts.GrantTypeAuthorizationCode, consts.GrantTypeRefreshToken},
		Scopes:                                []string{consts.ScopeOffline},
		TLSClientCertificateBoundAccessTokens: true,
	}

	return provider, store
}

func mtlsTokenRequest(t *testing.T, provider oauth2.Provider, form url.Values, cert *x509.Certificate) (oauth2.AccessResponder, error) {
	t.Helper()

	form.Set(consts.FormParameterClientID, mtClientID)
	form.Set(consts.FormParameterClientSecret, mtSecret)

	r := httptest.NewRequest(http.MethodPost, mtTokenEndpoint, strings.NewReader(form.Encode()))
	r.Header.Set(consts.HeaderContentType, consts.ContentTypeApplicationURLEncodedForm)

	if cert != nil {
		r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	} else {
		r.TLS = nil
	}

	requester, err := provider.NewAccessRequest(context.Background(), r, &oauth2.DefaultSession{})
	if err != nil {
		return nil, err
	}

	return provider.NewAccessResponse(context.Background(), requester)
}

func mtlsAuthorizeForCode(t *testing.T, provider oauth2.Provider) string {
	t.Helper()

	form := url.Values{
		consts.FormParameterClientID:     []string{mtClientID},
		consts.FormParameterResponseType: []string{consts.ResponseTypeAuthorizationCodeFlow},
		consts.FormParameterRedirectURI:  []string{mtRedirectURI},
		consts.FormParameterScope:        []string{consts.ScopeOffline},
		consts.FormParameterState:        []string{"abcdefghijklmnop"},
	}

	r := httptest.NewRequest(http.MethodGet, "https://as.example.com/authorize?"+form.Encode(), nil)

	requester, err := provider.NewAuthorizeRequest(context.Background(), r)
	require.NoError(t, err)

	requester.GrantScope(consts.ScopeOffline)

	responder, err := provider.NewAuthorizeResponse(context.Background(), requester, &oauth2.DefaultSession{Subject: "peter"})
	require.NoError(t, err)

	code := responder.GetParameters().Get(consts.FormParameterAuthorizationCode)
	require.NotEmpty(t, code)

	return code
}

const (
	mtTokenEndpoint = "https://as.example.com/token"
	mtClientID      = "mtls-client"
	mtSecret        = "mtls-client-secret"
	mtRedirectURI   = "https://rp.example.com/cb"
)
