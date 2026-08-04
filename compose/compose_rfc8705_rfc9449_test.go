// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package compose

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/gen"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestNoBindingWorkForAGrantTypeNoHandlerOwns(t *testing.T) {
	provider, store := newBothProvider(t)

	proofKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	form := url.Values{
		consts.FormParameterGrantType:    []string{"urn:example:not-a-real-grant"},
		consts.FormParameterClientID:     []string{bothClientID},
		consts.FormParameterClientSecret: []string{"an-incorrect-secret"},
	}

	r := httptest.NewRequest(http.MethodPost, bothTokenURI, strings.NewReader(form.Encode()))
	r.Header.Set(consts.HeaderContentType, consts.ContentTypeApplicationURLEncodedForm)
	r.Header.Set(consts.HeaderDPoP, bothDPoPProof(t, proofKey, "recursion-poc"))
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{gen.MustCertificate(gen.CertificateOptions{})}}

	_, err = provider.NewAccessRequest(context.Background(), r, &oauth2.DefaultSession{})
	require.Error(t, err)

	rfc := oauth2.ErrorToRFC6749Error(err)

	assert.Equal(t, http.StatusBadRequest, rfc.CodeField)
	assert.Equal(t, "invalid_request", rfc.ErrorField)

	assert.Empty(t, store.DPoPProofJTIs, "an unauthenticated caller wrote a replay marker to the store")
}

func TestBothBindingsAreRecordedWhenAClientPresentsBoth(t *testing.T) {
	provider, _ := newBothProvider(t)

	proofKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	cert := gen.MustCertificate(gen.CertificateOptions{})
	other := gen.MustCertificate(gen.CertificateOptions{SerialNumber: 2})

	code := bothAuthorizeForCode(t, provider)

	response, granted, err := bothTokenRequest(t, provider, url.Values{
		consts.FormParameterGrantType:         []string{consts.GrantTypeAuthorizationCode},
		consts.FormParameterAuthorizationCode: []string{code},
		consts.FormParameterRedirectURI:       []string{bothRedirectURI},
	}, cert, bothDPoPProof(t, proofKey, "initial"))
	require.NoError(t, err)

	assert.Equal(t, oauth2.DPoPAccessToken, response.GetTokenType())

	assertBoundToBoth(t, granted, cert)

	refreshToken, _ := response.ToMap()[consts.AccessResponseRefreshToken].(string)
	require.NotEmpty(t, refreshToken, "no refresh token was issued")

	form := func() url.Values {
		return url.Values{
			consts.FormParameterGrantType:    []string{consts.GrantTypeRefreshToken},
			consts.FormParameterRefreshToken: []string{refreshToken},
		}
	}

	t.Run("ShouldRejectARefreshMissingTheCertificate", func(t *testing.T) {
		_, _, err := bothTokenRequest(t, provider, form(), nil, bothDPoPProof(t, proofKey, "no-cert"))

		require.Error(t, err)
		assert.Equal(t, "invalid_request", oauth2.ErrorToRFC6749Error(err).ErrorField)
	})

	t.Run("ShouldRejectARefreshMissingTheProof", func(t *testing.T) {
		_, _, err := bothTokenRequest(t, provider, form(), cert, "")

		require.Error(t, err)
		assert.Equal(t, "invalid_dpop_proof", oauth2.ErrorToRFC6749Error(err).ErrorField)
	})

	t.Run("ShouldRejectARefreshWithAnotherCertificate", func(t *testing.T) {
		_, _, err := bothTokenRequest(t, provider, form(), other, bothDPoPProof(t, proofKey, "wrong-cert"))

		require.Error(t, err)
		assert.Equal(t, "invalid_grant", oauth2.ErrorToRFC6749Error(err).ErrorField)
	})

	t.Run("ShouldRejectARefreshWithAnotherProofKey", func(t *testing.T) {
		rogue, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		_, _, err = bothTokenRequest(t, provider, form(), cert, bothDPoPProof(t, rogue, "wrong-key"))

		require.Error(t, err)
		assert.Equal(t, "invalid_dpop_proof", oauth2.ErrorToRFC6749Error(err).ErrorField)
	})

	t.Run("ShouldAcceptARefreshSatisfyingBothAndStayBoundToBoth", func(t *testing.T) {
		response, granted, err := bothTokenRequest(t, provider, form(), cert, bothDPoPProof(t, proofKey, "both"))
		require.NoError(t, err)

		assert.Equal(t, oauth2.DPoPAccessToken, response.GetTokenType())

		assertBoundToBoth(t, granted, cert)
	})
}

func TestBindingIsIndependentOfFactoryOrder(t *testing.T) {
	provider, _ := newBothProviderBindingFirst(t)

	proofKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	cert := gen.MustCertificate(gen.CertificateOptions{})

	code := bothAuthorizeForCode(t, provider)

	response, granted, err := bothTokenRequest(t, provider, url.Values{
		consts.FormParameterGrantType:         []string{consts.GrantTypeAuthorizationCode},
		consts.FormParameterAuthorizationCode: []string{code},
		consts.FormParameterRedirectURI:       []string{bothRedirectURI},
	}, cert, bothDPoPProof(t, proofKey, "order-initial"))
	require.NoError(t, err)

	assert.Equal(t, oauth2.DPoPAccessToken, response.GetTokenType())

	assertBoundToBoth(t, granted, cert)

	refreshToken, _ := response.ToMap()[consts.AccessResponseRefreshToken].(string)
	require.NotEmpty(t, refreshToken, "no refresh token was issued")

	form := url.Values{
		consts.FormParameterGrantType:    []string{consts.GrantTypeRefreshToken},
		consts.FormParameterRefreshToken: []string{refreshToken},
	}

	_, _, err = bothTokenRequest(t, provider, form, nil, bothDPoPProof(t, proofKey, "order-no-cert"))

	require.Error(t, err)
	assert.Equal(t, "invalid_request", oauth2.ErrorToRFC6749Error(err).ErrorField)

	_, _, err = bothTokenRequest(t, provider, form, cert, "")

	require.Error(t, err)
	assert.Equal(t, "invalid_dpop_proof", oauth2.ErrorToRFC6749Error(err).ErrorField)
}

const (
	bothClientID    = "both-client"
	bothSecret      = "both-client-secret"
	bothRedirectURI = "https://rp.example.com/cb"
	bothTokenURI    = "https://as.example.com/token"
)

func newBothProviderBindingFirst(t *testing.T) (oauth2.Provider, *storage.MemoryStore) {
	t.Helper()

	store := storage.NewMemoryStore()
	config := &oauth2.Config{
		MTLSEnabled:  true,
		DPoPEnabled:  true,
		GlobalSecret: []byte("some-cool-secret-that-is-32bytes"),
	}

	key := gen.MustRSAKey()

	keyGetter := func(context.Context) (any, error) {
		return key, nil
	}

	strategy := &jwt.DefaultStrategy{
		Config: config,
		Issuer: jwt.NewDefaultIssuerRS256Unverified(key),
	}

	provider := Compose(
		config,
		store,
		&CommonStrategy{
			CoreStrategy:               NewOAuth2HMACStrategy(config),
			OpenIDConnectTokenStrategy: NewOpenIDConnectStrategy(keyGetter, strategy, config),
			Strategy:                   strategy,
		},
		DPoPAuthorizeFactory,
		DPoPTokenFactory,
		RFC8705Factory,

		OAuth2AuthorizeExplicitFactory,
		OAuth2RefreshTokenGrantFactory,
		OpenIDConnectExplicitFactory,
		OpenIDConnectRefreshFactory,
		OAuth2PKCEFactory,
	)

	store.Clients[bothClientID] = &oauth2.DefaultClient{
		ID:                                    bothClientID,
		ClientSecret:                          oauth2.NewPlainTextClientSecret(bothSecret),
		RedirectURIs:                          []string{bothRedirectURI},
		ResponseTypes:                         []string{consts.ResponseTypeAuthorizationCodeFlow},
		GrantTypes:                            []string{consts.GrantTypeAuthorizationCode, consts.GrantTypeRefreshToken},
		Scopes:                                []string{consts.ScopeOffline},
		DPoPBoundAccessTokens:                 false,
		TLSClientCertificateBoundAccessTokens: false,
	}

	return provider, store
}

func assertBoundToBoth(t *testing.T, session oauth2.Session, cert *x509.Certificate) {
	t.Helper()

	mtls, ok := session.(oauth2.MTLSBoundSession)
	require.True(t, ok, "the granted session does not carry a certificate binding")

	dpop, ok := session.(oauth2.DPoPBoundSession)
	require.True(t, ok, "the granted session does not carry a DPoP binding")

	assert.Equal(t, oauth2.X509CertificateSHA256Thumbprint(cert), mtls.GetClientCertificateSHA256Thumbprint())
	assert.NotEmpty(t, dpop.GetDPoPJWKThumbprint())
}

func newBothProvider(t *testing.T) (oauth2.Provider, *storage.MemoryStore) {
	t.Helper()

	store := storage.NewMemoryStore()
	config := &oauth2.Config{
		MTLSEnabled:  true,
		DPoPEnabled:  true,
		GlobalSecret: []byte("some-cool-secret-that-is-32bytes"),
	}

	provider := ComposeAllEnabled(config, store, gen.MustRSAKey())

	store.Clients[bothClientID] = &oauth2.DefaultClient{
		ID:                                    bothClientID,
		ClientSecret:                          oauth2.NewPlainTextClientSecret(bothSecret),
		RedirectURIs:                          []string{bothRedirectURI},
		ResponseTypes:                         []string{consts.ResponseTypeAuthorizationCodeFlow},
		GrantTypes:                            []string{consts.GrantTypeAuthorizationCode, consts.GrantTypeRefreshToken},
		Scopes:                                []string{consts.ScopeOffline},
		TLSClientCertificateBoundAccessTokens: true,
		DPoPBoundAccessTokens:                 true,
	}

	return provider, store
}

func bothDPoPProof(t *testing.T, key *ecdsa.PrivateKey, jti string) string {
	t.Helper()

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: &jose.JSONWebKey{Key: key, Algorithm: string(jose.ES256)}},
		(&jose.SignerOptions{EmbedJWK: true}).WithType(jose.ContentType(consts.JSONWebTokenTypeDPoP)),
	)
	require.NoError(t, err)

	proof, err := josejwt.Signed(signer).Claims(map[string]any{
		consts.ClaimJWTID:      jti,
		consts.ClaimHTTPMethod: http.MethodPost,
		consts.ClaimHTTPURI:    bothTokenURI,
		consts.ClaimIssuedAt:   time.Now().Unix(),
	}).Serialize()
	require.NoError(t, err)

	return proof
}

func bothTokenRequest(t *testing.T, provider oauth2.Provider, form url.Values, cert *x509.Certificate, proof string) (response oauth2.AccessResponder, granted oauth2.Session, err error) {
	t.Helper()

	form.Set(consts.FormParameterClientID, bothClientID)
	form.Set(consts.FormParameterClientSecret, bothSecret)

	r := httptest.NewRequest(http.MethodPost, bothTokenURI, strings.NewReader(form.Encode()))
	r.Header.Set(consts.HeaderContentType, consts.ContentTypeApplicationURLEncodedForm)

	if proof != "" {
		r.Header.Set(consts.HeaderDPoP, proof)
	}

	if cert != nil {
		r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	}

	requester, err := provider.NewAccessRequest(context.Background(), r, &oauth2.DefaultSession{})
	if err != nil {
		return nil, nil, err
	}

	response, err = provider.NewAccessResponse(context.Background(), requester)

	return response, requester.GetSession(), err
}

func bothAuthorizeForCode(t *testing.T, provider oauth2.Provider) string {
	t.Helper()

	form := url.Values{
		consts.FormParameterClientID:     []string{bothClientID},
		consts.FormParameterResponseType: []string{consts.ResponseTypeAuthorizationCodeFlow},
		consts.FormParameterRedirectURI:  []string{bothRedirectURI},
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
