// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package compose

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/jose"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/gen"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestEnforceSenderConstrainedAccessTokens(t *testing.T) {
	const (
		errMissingCertificate = "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The request requires a mutual-TLS client certificate but none was presented."
		errNotConstrained     = "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The request requires a sender-constrained access token, but neither a DPoP proof nor a mutual-TLS client certificate was presented to bind it to."
	)

	testCases := []struct {
		name      string
		enforce   bool
		client    bool
		mtls      bool
		cert      bool
		proof     bool
		err       string
		dpop      bool
		certBound bool
	}{
		{name: "ShouldBindTheDPoPProof", enforce: true, mtls: true, proof: true, dpop: true},
		{name: "ShouldBindTheCertificate", enforce: true, mtls: true, cert: true, certBound: true},
		{name: "ShouldPreferTheDPoPProofOverAnIncidentalCertificate", enforce: true, mtls: true, cert: true, proof: true, dpop: true},
		{name: "ShouldRejectARequestPresentingNeither", enforce: true, mtls: true, err: errMissingCertificate},
		{name: "ShouldRejectARequestPresentingNeitherForTheClient", client: true, mtls: true, err: errMissingCertificate},
		{name: "ShouldBindTheCertificateForTheClient", client: true, mtls: true, cert: true, certBound: true},
		{name: "ShouldRejectARequestPresentingNeitherWithoutMTLS", enforce: true, err: errNotConstrained},
		{name: "ShouldRejectACertificateWithoutMTLS", enforce: true, cert: true, err: errNotConstrained},
		{name: "ShouldNotBindAnIncidentalCertificateWhenNotEnforced", mtls: true, cert: true},
		{name: "ShouldIssueABearerTokenWhenNotEnforced", mtls: true},
	}

	for _, order := range []struct {
		name         string
		bindingFirst bool
		mtlsFirst    bool
	}{
		{"BindingFactoriesFirstDPoPFirst", true, false},
		{"BindingFactoriesFirstMTLSFirst", true, true},
		{"BindingFactoriesLastDPoPFirst", false, false},
		{"BindingFactoriesLastMTLSFirst", false, true},
	} {
		for _, tc := range testCases {
			t.Run(order.name+"/"+tc.name, func(t *testing.T) {
				provider := newSenderConstrainedProvider(t, order.bindingFirst, order.mtlsFirst, tc.enforce, tc.client, tc.mtls)

				var (
					proof string
					jkt   string
				)

				if tc.proof {
					key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
					require.NoError(t, err)

					proof = bothDPoPProof(t, key, "sender-constrained-"+tc.name)

					thumbprint, err := (&jose.JSONWebKey{Key: key.Public()}).Thumbprint(crypto.SHA256)
					require.NoError(t, err)

					jkt = base64.RawURLEncoding.EncodeToString(thumbprint)
				}

				var cert = gen.MustCertificate(gen.CertificateOptions{})
				if !tc.cert {
					cert = nil
				}

				response, granted, err := bothTokenRequest(t, provider, url.Values{
					consts.FormParameterGrantType:         []string{consts.GrantTypeAuthorizationCode},
					consts.FormParameterAuthorizationCode: []string{bothAuthorizeForCode(t, provider)},
					consts.FormParameterRedirectURI:       []string{bothRedirectURI},
				}, cert, proof)

				if tc.err != "" {
					require.Error(t, err)
					assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), tc.err)

					return
				}

				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

				dpop, ok := granted.(oauth2.DPoPBoundSession)
				require.True(t, ok)

				mtls, ok := granted.(oauth2.MTLSBoundSession)
				require.True(t, ok)

				if tc.dpop {
					assert.Equal(t, jkt, dpop.GetDPoPJWKThumbprint())
				} else {
					assert.Empty(t, dpop.GetDPoPJWKThumbprint())
				}

				if tc.certBound {
					assert.Equal(t, oauth2.X509CertificateSHA256Thumbprint(cert), mtls.GetClientCertificateSHA256Thumbprint())
				} else {
					assert.Empty(t, mtls.GetClientCertificateSHA256Thumbprint())
				}

				if tc.dpop {
					assert.Equal(t, oauth2.DPoPAccessToken, response.GetTokenType())
				} else {
					assert.Equal(t, oauth2.BearerAccessToken, response.GetTokenType())
				}
			})
		}
	}
}

func TestEnforceSenderConstrainedAccessTokensRequiresPossessionOfTheBinding(t *testing.T) {
	const errNotConstrained = "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The request requires a sender-constrained access token, but neither a DPoP proof nor a mutual-TLS client certificate was presented to bind it to."

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	thumbprint, err := (&jose.JSONWebKey{Key: key.Public()}).Thumbprint(crypto.SHA256)
	require.NoError(t, err)

	bound := gen.MustCertificate(gen.CertificateOptions{})
	other := gen.MustCertificate(gen.CertificateOptions{SerialNumber: 2})

	testCases := []struct {
		name    string
		config  *oauth2.Config
		session *oauth2.DefaultSession
		cert    *x509.Certificate
		proof   string
		err     string
	}{
		{
			name:    "ShouldRejectADPoPBindingNoHandlerVerified",
			config:  &oauth2.Config{DPoPEnabled: true},
			session: &oauth2.DefaultSession{JWKThumbprint: base64.RawURLEncoding.EncodeToString(thumbprint)},
			proof:   bothDPoPProof(t, key, "unverified"),
			err:     errNotConstrained,
		},
		{
			name:    "ShouldRejectACertificateBindingWithoutTheCertificate",
			config:  &oauth2.Config{MTLSEnabled: true},
			session: &oauth2.DefaultSession{ClientCertificateThumbprint: oauth2.X509CertificateSHA256Thumbprint(bound)},
			err:     errNotConstrained,
		},
		{
			name:    "ShouldRejectACertificateBindingWithAnotherCertificate",
			config:  &oauth2.Config{MTLSEnabled: true},
			session: &oauth2.DefaultSession{ClientCertificateThumbprint: oauth2.X509CertificateSHA256Thumbprint(bound)},
			cert:    other,
			err:     errNotConstrained,
		},
		{
			name:    "ShouldAcceptACertificateBindingWithTheCertificate",
			config:  &oauth2.Config{MTLSEnabled: true},
			session: &oauth2.DefaultSession{ClientCertificateThumbprint: oauth2.X509CertificateSHA256Thumbprint(bound)},
			cert:    bound,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := tc.config
			config.EnforceSenderConstrainedAccessTokens = true
			config.GlobalSecret = []byte("some-cool-secret-that-is-32bytes")

			store := storage.NewMemoryStore()
			strategy := NewOAuth2HMACStrategy(config)

			provider := Compose(config, store, strategy, OAuth2RefreshTokenGrantFactory)

			client := &oauth2.DefaultRegisteredClient{
				DefaultClient: &oauth2.DefaultClient{
					ID:           bothClientID,
					ClientSecret: oauth2.NewPlainTextClientSecret(bothSecret),
					GrantTypes:   []string{consts.GrantTypeRefreshToken},
					Scopes:       []string{consts.ScopeOffline},
				},
				TokenEndpointAuthMethod: consts.ClientAuthMethodClientSecretPost,
			}

			store.Clients[bothClientID] = client

			tc.session.Subject = testSenderConstrainedSubject
			tc.session.ExpiresAt = map[oauth2.TokenType]time.Time{oauth2.RefreshToken: time.Now().UTC().Add(time.Hour)}

			original := &oauth2.Request{
				ID:             "req-id",
				Client:         client,
				RequestedAt:    time.Now().UTC(),
				GrantedScope:   oauth2.Arguments{consts.ScopeOffline},
				RequestedScope: oauth2.Arguments{consts.ScopeOffline},
				Session:        tc.session,
				Form:           url.Values{},
			}

			refreshToken, refreshSignature, err := strategy.GenerateRefreshToken(t.Context(), nil)
			require.NoError(t, err)

			_, accessSignature, err := strategy.GenerateAccessToken(t.Context(), nil)
			require.NoError(t, err)

			require.NoError(t, store.CreateAccessTokenSession(t.Context(), accessSignature, original))
			require.NoError(t, store.CreateRefreshTokenSession(t.Context(), refreshSignature, accessSignature, original))

			_, _, err = bothTokenRequest(t, provider, url.Values{
				consts.FormParameterGrantType:    []string{consts.GrantTypeRefreshToken},
				consts.FormParameterRefreshToken: []string{refreshToken},
			}, tc.cert, tc.proof)

			if tc.err != "" {
				require.Error(t, err)
				assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), tc.err)
			} else {
				assert.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
			}
		})
	}
}

const testSenderConstrainedSubject = "sender-constrained-subject"

func newSenderConstrainedProvider(t *testing.T, bindingFirst, mtlsFirst, enforce, client, mtls bool) oauth2.Provider {
	t.Helper()

	store := storage.NewMemoryStore()
	config := &oauth2.Config{
		MTLSEnabled:                          mtls,
		DPoPEnabled:                          true,
		EnforceSenderConstrainedAccessTokens: enforce,
		GlobalSecret:                         []byte("some-cool-secret-that-is-32bytes"),
	}

	key := gen.MustRSAKey()

	keyGetter := func(context.Context) (any, error) {
		return key, nil
	}

	strategy := &jwt.DefaultStrategy{
		Config: config,
		Issuer: jwt.NewDefaultIssuerRS256Unverified(key),
	}

	bindings := []Factory{DPoPAuthorizeFactory, DPoPTokenFactory, RFC8705Factory}
	if mtlsFirst {
		bindings = []Factory{RFC8705Factory, DPoPAuthorizeFactory, DPoPTokenFactory}
	}
	grants := []Factory{OAuth2AuthorizeExplicitFactory, OAuth2RefreshTokenGrantFactory, OAuth2PKCEFactory}

	factories := append(append([]Factory{}, grants...), bindings...)
	if bindingFirst {
		factories = append(append([]Factory{}, bindings...), grants...)
	}

	provider := Compose(
		config,
		store,
		&CommonStrategy{
			CoreStrategy:               NewOAuth2HMACStrategy(config),
			OpenIDConnectTokenStrategy: NewOpenIDConnectStrategy(keyGetter, strategy, config),
			Strategy:                   strategy,
		},
		factories...,
	)

	store.Clients[bothClientID] = &oauth2.DefaultRegisteredClient{
		DefaultClient: &oauth2.DefaultClient{
			ID:            bothClientID,
			ClientSecret:  oauth2.NewPlainTextClientSecret(bothSecret),
			RedirectURIs:  []string{bothRedirectURI},
			ResponseTypes: []string{consts.ResponseTypeAuthorizationCodeFlow},
			GrantTypes:    []string{consts.GrantTypeAuthorizationCode, consts.GrantTypeRefreshToken},
			Scopes:        []string{consts.ScopeOffline},
		},
		TokenEndpointAuthMethod:              consts.ClientAuthMethodClientSecretPost,
		EnforceSenderConstrainedAccessTokens: client,
	}

	return provider
}
