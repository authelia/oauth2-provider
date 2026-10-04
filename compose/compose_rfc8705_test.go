// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package compose

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
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

func TestMTLSRefreshRebindsAConfidentialClientToThePresentedCertificate(t *testing.T) {
	stores := []func() (store any, clients map[string]oauth2.Client){
		func() (any, map[string]oauth2.Client) {
			store := storage.NewMemoryStore()

			return store, store.Clients
		},
		func() (any, map[string]oauth2.Client) {
			store := storage.NewHydratingMemoryStore()

			return store, store.Clients
		},
	}

	for _, newStore := range stores {
		store, clients := newStore()

		t.Run(fmt.Sprintf("%T", store), func(t *testing.T) {
			provider := ComposeAllEnabled(&oauth2.Config{MTLSEnabled: true, GlobalSecret: []byte("some-cool-secret-that-is-32bytes"), RFC7591ClientRegistrationGlobalSecret: []byte("a-completely-different-secret-at-least-32b")}, store, gen.MustRSAKey())

			clients[mtClientID] = &oauth2.DefaultClient{
				ID:                                    mtClientID,
				ClientSecret:                          oauth2.NewPlainTextClientSecret(mtSecret),
				RedirectURIs:                          []string{mtRedirectURI},
				ResponseTypes:                         []string{consts.ResponseTypeAuthorizationCodeFlow},
				GrantTypes:                            []string{consts.GrantTypeAuthorizationCode, consts.GrantTypeRefreshToken},
				Scopes:                                []string{consts.ScopeOffline},
				TLSClientCertificateBoundAccessTokens: true,
			}

			response, err := mtlsTokenRequest(t, provider, url.Values{
				consts.FormParameterGrantType:         []string{consts.GrantTypeAuthorizationCode},
				consts.FormParameterAuthorizationCode: []string{mtlsAuthorizeForCode(t, provider)},
				consts.FormParameterRedirectURI:       []string{mtRedirectURI},
			}, gen.MustCertificate(gen.CertificateOptions{}))
			require.NoError(t, err)

			refreshToken, _ := response.ToMap()[consts.AccessResponseRefreshToken].(string)
			require.NotEmpty(t, refreshToken)

			renewed := gen.MustCertificate(gen.CertificateOptions{SerialNumber: 2})

			response, err = mtlsTokenRequest(t, provider, url.Values{
				consts.FormParameterGrantType:    []string{consts.GrantTypeRefreshToken},
				consts.FormParameterRefreshToken: []string{refreshToken},
			}, renewed)
			require.NoError(t, err)

			_, requester, err := provider.IntrospectToken(context.Background(), response.GetAccessToken(), oauth2.AccessToken, &oauth2.DefaultSession{})
			require.NoError(t, err)

			session, ok := requester.GetSession().(oauth2.MTLSBoundSession)
			require.True(t, ok)

			assert.Equal(t, oauth2.X509CertificateSHA256Thumbprint(renewed), session.GetClientCertificateSHA256Thumbprint())

			refreshToken, _ = response.ToMap()[consts.AccessResponseRefreshToken].(string)
			require.NotEmpty(t, refreshToken)

			_, err = mtlsTokenRequest(t, provider, url.Values{
				consts.FormParameterGrantType:    []string{consts.GrantTypeRefreshToken},
				consts.FormParameterRefreshToken: []string{refreshToken},
			}, nil)

			require.Error(t, err)
			assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The request requires a mutual-TLS client certificate but none was presented.")
		})
	}
}

func TestMTLSRefreshWithoutRotationRebindsTheRefreshToken(t *testing.T) {
	stores := []func() (store any, clients map[string]oauth2.Client){
		func() (any, map[string]oauth2.Client) {
			store := storage.NewMemoryStore()

			return store, store.Clients
		},
		func() (any, map[string]oauth2.Client) {
			store := storage.NewHydratingMemoryStore()

			return store, store.Clients
		},
	}

	for _, newStore := range stores {
		store, clients := newStore()

		t.Run(fmt.Sprintf("%T", store), func(t *testing.T) {
			provider := ComposeAllEnabled(&oauth2.Config{MTLSEnabled: true, DisableRefreshTokenRotation: true, GlobalSecret: []byte("some-cool-secret-that-is-32bytes"), RFC7591ClientRegistrationGlobalSecret: []byte("a-completely-different-secret-at-least-32b")}, store, gen.MustRSAKey())

			clients[mtClientID] = &oauth2.DefaultClient{
				ID:                                    mtClientID,
				ClientSecret:                          oauth2.NewPlainTextClientSecret(mtSecret),
				RedirectURIs:                          []string{mtRedirectURI},
				ResponseTypes:                         []string{consts.ResponseTypeAuthorizationCodeFlow},
				GrantTypes:                            []string{consts.GrantTypeAuthorizationCode, consts.GrantTypeRefreshToken},
				Scopes:                                []string{consts.ScopeOffline},
				TLSClientCertificateBoundAccessTokens: true,
			}

			original := gen.MustCertificate(gen.CertificateOptions{})

			response, err := mtlsTokenRequest(t, provider, url.Values{
				consts.FormParameterGrantType:         []string{consts.GrantTypeAuthorizationCode},
				consts.FormParameterAuthorizationCode: []string{mtlsAuthorizeForCode(t, provider)},
				consts.FormParameterRedirectURI:       []string{mtRedirectURI},
			}, original)
			require.NoError(t, err)

			refreshToken, _ := response.ToMap()[consts.AccessResponseRefreshToken].(string)
			require.NotEmpty(t, refreshToken)

			renewed := gen.MustCertificate(gen.CertificateOptions{SerialNumber: 2})
			x5t := oauth2.X509CertificateSHA256Thumbprint(renewed)

			for i := range 2 {
				response, err = mtlsTokenRequest(t, provider, url.Values{
					consts.FormParameterGrantType:    []string{consts.GrantTypeRefreshToken},
					consts.FormParameterRefreshToken: []string{refreshToken},
				}, renewed)
				require.NoError(t, err, "refresh %d", i)

				assert.NotContains(t, response.ToMap(), consts.AccessResponseRefreshToken)

				for tokenType, token := range map[oauth2.TokenType]string{oauth2.AccessToken: response.GetAccessToken(), oauth2.RefreshToken: refreshToken} {
					_, requester, err := provider.IntrospectToken(context.Background(), token, tokenType, &oauth2.DefaultSession{})
					require.NoError(t, err)

					session, ok := requester.GetSession().(oauth2.MTLSBoundSession)
					require.True(t, ok)

					assert.Equal(t, x5t, session.GetClientCertificateSHA256Thumbprint(), "refresh %d %s", i, tokenType)
				}
			}

			_, err = mtlsTokenRequest(t, provider, url.Values{
				consts.FormParameterGrantType:    []string{consts.GrantTypeRefreshToken},
				consts.FormParameterRefreshToken: []string{refreshToken},
			}, nil)

			require.Error(t, err)
			assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The request requires a mutual-TLS client certificate but none was presented.")
		})
	}
}

func TestMTLSStrictRefreshTokenBindingRejectsAConfidentialClientWithAnotherCertificate(t *testing.T) {
	stores := []func() (store any, clients map[string]oauth2.Client){
		func() (any, map[string]oauth2.Client) {
			store := storage.NewMemoryStore()

			return store, store.Clients
		},
		func() (any, map[string]oauth2.Client) {
			store := storage.NewHydratingMemoryStore()

			return store, store.Clients
		},
	}

	for _, newStore := range stores {
		store, clients := newStore()

		t.Run(fmt.Sprintf("%T", store), func(t *testing.T) {
			provider := ComposeAllEnabled(&oauth2.Config{MTLSEnabled: true, MTLSStrictRefreshTokenBinding: true, GlobalSecret: []byte("some-cool-secret-that-is-32bytes"), RFC7591ClientRegistrationGlobalSecret: []byte("a-completely-different-secret-at-least-32b")}, store, gen.MustRSAKey())

			clients[mtClientID] = &oauth2.DefaultClient{
				ID:                                    mtClientID,
				ClientSecret:                          oauth2.NewPlainTextClientSecret(mtSecret),
				RedirectURIs:                          []string{mtRedirectURI},
				ResponseTypes:                         []string{consts.ResponseTypeAuthorizationCodeFlow},
				GrantTypes:                            []string{consts.GrantTypeAuthorizationCode, consts.GrantTypeRefreshToken},
				Scopes:                                []string{consts.ScopeOffline},
				TLSClientCertificateBoundAccessTokens: true,
			}

			cert := gen.MustCertificate(gen.CertificateOptions{})

			response, err := mtlsTokenRequest(t, provider, url.Values{
				consts.FormParameterGrantType:         []string{consts.GrantTypeAuthorizationCode},
				consts.FormParameterAuthorizationCode: []string{mtlsAuthorizeForCode(t, provider)},
				consts.FormParameterRedirectURI:       []string{mtRedirectURI},
			}, cert)
			require.NoError(t, err)

			refreshToken, _ := response.ToMap()[consts.AccessResponseRefreshToken].(string)
			require.NotEmpty(t, refreshToken)

			_, err = mtlsTokenRequest(t, provider, url.Values{
				consts.FormParameterGrantType:    []string{consts.GrantTypeRefreshToken},
				consts.FormParameterRefreshToken: []string{refreshToken},
			}, gen.MustCertificate(gen.CertificateOptions{SerialNumber: 2}))

			require.Error(t, err)
			assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), "The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client. The mutual-TLS client certificate does not match the certificate the grant is bound to.")

			_, err = mtlsTokenRequest(t, provider, url.Values{
				consts.FormParameterGrantType:    []string{consts.GrantTypeRefreshToken},
				consts.FormParameterRefreshToken: []string{refreshToken},
			}, cert)
			require.NoError(t, err)
		})
	}
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
