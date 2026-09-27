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

// RFC 9700 Section 4.14.2: a public client's refresh token that was issued unbound is rotated even when the refresh
// request binds the new tokens, as the presented refresh token itself is not sender-constrained.
func TestRefreshRotatesAnUnboundPublicClientTokenThatTheRequestBinds(t *testing.T) {
	stores := []struct {
		name string
		new  func() (store any, clients map[string]oauth2.Client)
	}{
		{"MemoryStore", func() (any, map[string]oauth2.Client) {
			store := storage.NewMemoryStore()

			return store, store.Clients
		}},
		{"HydratingMemoryStore", func() (any, map[string]oauth2.Client) {
			store := storage.NewHydratingMemoryStore()

			return store, store.Clients
		}},
	}

	for _, s := range stores {
		t.Run(s.name, func(t *testing.T) {
			t.Run("ShouldRotateWhenADPoPProofIsPresented", func(t *testing.T) {
				store, clients := s.new()

				provider := ComposeAllEnabled(&oauth2.Config{
					DPoPEnabled:                           true,
					DisableRefreshTokenRotation:           true,
					GlobalSecret:                          []byte("some-cool-secret-that-is-32bytes"),
					RFC7591ClientRegistrationGlobalSecret: []byte("a-completely-different-secret-at-least-32b"),
				}, store, gen.MustRSAKey())

				clients[rrbClientID] = newRRBPublicClient()

				unbound := rrbExchange(t, provider)

				key := newPARProofKey(t)

				response, err := rrbTokenRequest(t, provider, unbound, signPARProof(t, key, "rrb-1", rrbTokenEndpoint, nil), nil)
				require.NoError(t, err)

				assert.Equal(t, oauth2.DPoPAccessToken, response.GetTokenType())

				bound, _ := response.ToMap()[consts.AccessResponseRefreshToken].(string)
				require.NotEmpty(t, bound)

				response, err = rrbTokenRequest(t, provider, bound, signPARProof(t, key, "rrb-2", rrbTokenEndpoint, nil), nil)
				require.NoError(t, err)

				assert.NotContains(t, response.ToMap(), consts.AccessResponseRefreshToken)

				_, err = rrbTokenRequest(t, provider, unbound, signPARProof(t, key, "rrb-3", rrbTokenEndpoint, nil), nil)
				require.Error(t, err)
			})

			t.Run("ShouldRotateWhenACertificateIsPresented", func(t *testing.T) {
				store, clients := s.new()

				provider := ComposeAllEnabled(&oauth2.Config{
					MTLSEnabled:                           true,
					DisableRefreshTokenRotation:           true,
					GlobalSecret:                          []byte("some-cool-secret-that-is-32bytes"),
					RFC7591ClientRegistrationGlobalSecret: []byte("a-completely-different-secret-at-least-32b"),
				}, store, gen.MustRSAKey())

				client := newRRBPublicClient()
				clients[rrbClientID] = client

				unbound := rrbExchange(t, provider)

				client.TLSClientCertificateBoundAccessTokens = true

				cert := gen.MustCertificate(gen.CertificateOptions{})

				response, err := rrbTokenRequest(t, provider, unbound, "", cert)
				require.NoError(t, err)

				bound, _ := response.ToMap()[consts.AccessResponseRefreshToken].(string)
				require.NotEmpty(t, bound)

				response, err = rrbTokenRequest(t, provider, bound, "", cert)
				require.NoError(t, err)

				assert.NotContains(t, response.ToMap(), consts.AccessResponseRefreshToken)

				_, err = rrbTokenRequest(t, provider, unbound, "", cert)
				require.Error(t, err)
			})
		})
	}
}

func newRRBPublicClient() *oauth2.DefaultClient {
	return &oauth2.DefaultClient{
		ID:            rrbClientID,
		Public:        true,
		RedirectURIs:  []string{rrbRedirectURI},
		ResponseTypes: []string{consts.ResponseTypeAuthorizationCodeFlow},
		GrantTypes:    []string{consts.GrantTypeAuthorizationCode, consts.GrantTypeRefreshToken},
		Scopes:        []string{consts.ScopeOffline},
	}
}

// rrbExchange runs the authorization code flow without any binding and returns the refresh token it issues.
func rrbExchange(t *testing.T, provider oauth2.Provider) string {
	t.Helper()

	form := url.Values{
		consts.FormParameterClientID:     []string{rrbClientID},
		consts.FormParameterResponseType: []string{consts.ResponseTypeAuthorizationCodeFlow},
		consts.FormParameterRedirectURI:  []string{rrbRedirectURI},
		consts.FormParameterScope:        []string{consts.ScopeOffline},
		consts.FormParameterState:        []string{"abcdefghijklmnop"},
	}

	requester, err := provider.NewAuthorizeRequest(context.Background(), httptest.NewRequest(http.MethodGet, "https://as.example.com/authorize?"+form.Encode(), nil))
	require.NoError(t, err)

	requester.GrantScope(consts.ScopeOffline)

	responder, err := provider.NewAuthorizeResponse(context.Background(), requester, &oauth2.DefaultSession{Subject: "peter"})
	require.NoError(t, err)

	code := responder.GetParameters().Get(consts.FormParameterAuthorizationCode)
	require.NotEmpty(t, code)

	r := rrbHTTPRequest(url.Values{
		consts.FormParameterGrantType:         []string{consts.GrantTypeAuthorizationCode},
		consts.FormParameterAuthorizationCode: []string{code},
		consts.FormParameterRedirectURI:       []string{rrbRedirectURI},
	}, "", nil)

	ar, err := provider.NewAccessRequest(context.Background(), r, &oauth2.DefaultSession{})
	require.NoError(t, err)

	response, err := provider.NewAccessResponse(context.Background(), ar)
	require.NoError(t, err)

	assert.Equal(t, oauth2.BearerAccessToken, response.GetTokenType())

	refreshToken, _ := response.ToMap()[consts.AccessResponseRefreshToken].(string)
	require.NotEmpty(t, refreshToken)

	return refreshToken
}

func rrbTokenRequest(t *testing.T, provider oauth2.Provider, refreshToken, proof string, cert *x509.Certificate) (oauth2.AccessResponder, error) {
	t.Helper()

	r := rrbHTTPRequest(url.Values{
		consts.FormParameterGrantType:    []string{consts.GrantTypeRefreshToken},
		consts.FormParameterRefreshToken: []string{refreshToken},
	}, proof, cert)

	requester, err := provider.NewAccessRequest(context.Background(), r, &oauth2.DefaultSession{})
	if err != nil {
		return nil, err
	}

	return provider.NewAccessResponse(context.Background(), requester)
}

func rrbHTTPRequest(form url.Values, proof string, cert *x509.Certificate) *http.Request {
	form.Set(consts.FormParameterClientID, rrbClientID)

	r := httptest.NewRequest(http.MethodPost, rrbTokenEndpoint, strings.NewReader(form.Encode()))
	r.Header.Set(consts.HeaderContentType, consts.ContentTypeApplicationURLEncodedForm)

	if proof != "" {
		r.Header.Set(consts.HeaderDPoP, proof)
	}

	if cert != nil {
		r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	}

	return r
}

const (
	rrbTokenEndpoint = "https://as.example.com/token"
	rrbClientID      = "rotation-binding-client"
	rrbRedirectURI   = "https://rp.example.com/cb"
)
