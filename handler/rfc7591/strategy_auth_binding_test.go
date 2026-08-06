// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc7591

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/handler/rfc9449"
	"authelia.com/provider/oauth2/internal/gen"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestAuthEnforcesDPoPBindingAtTheRegistrationEndpoint(t *testing.T) {
	ctx := context.Background()

	t.Run("ShouldAcceptABoundTokenPresentedWithAValidProof", func(t *testing.T) {
		auth, _, store, access := newBindingFixtures(t)

		key := newProofKey(t)
		token := mintBoundAccessToken(t, ctx, store, access, proofThumbprint(t, key), "")

		proof := signDPoPProof(t, key, "reg-1", http.MethodPost, testEndpoint, token)

		requester, err := auth.AuthenticateClientRegistrationRequest(ctx, bindingRequest("DPoP", token, proof, nil), "")

		require.NoError(t, err)
		assert.Equal(t, "onboarding", requester.GetClient().GetID())
	})

	t.Run("ShouldRejectABoundTokenPresentedAsABearerToken", func(t *testing.T) {
		auth, _, store, access := newBindingFixtures(t)

		key := newProofKey(t)
		token := mintBoundAccessToken(t, ctx, store, access, proofThumbprint(t, key), "")

		_, err := auth.AuthenticateClientRegistrationRequest(ctx, bindingRequest("Bearer", token, "", nil), "")

		require.Error(t, err)
		assert.ErrorIs(t, err, oauth2.ErrRequestUnauthorized)
	})

	t.Run("ShouldRejectABoundTokenPresentedWithoutAProof", func(t *testing.T) {
		auth, _, store, access := newBindingFixtures(t)

		key := newProofKey(t)
		token := mintBoundAccessToken(t, ctx, store, access, proofThumbprint(t, key), "")

		_, err := auth.AuthenticateClientRegistrationRequest(ctx, bindingRequest("DPoP", token, "", nil), "")

		require.Error(t, err)
		assert.ErrorIs(t, err, oauth2.ErrRequestUnauthorized)
	})

	t.Run("ShouldRejectAProofSignedByAnotherKey", func(t *testing.T) {
		auth, _, store, access := newBindingFixtures(t)

		key, attacker := newProofKey(t), newProofKey(t)
		token := mintBoundAccessToken(t, ctx, store, access, proofThumbprint(t, key), "")

		proof := signDPoPProof(t, attacker, "reg-2", http.MethodPost, testEndpoint, token)

		_, err := auth.AuthenticateClientRegistrationRequest(ctx, bindingRequest("DPoP", token, proof, nil), "")

		require.Error(t, err)
		assert.ErrorIs(t, err, oauth2.ErrRequestUnauthorized)
	})

	t.Run("ShouldSkipWhenDPoPIsDisabled", func(t *testing.T) {
		auth, config, store, access := newBindingFixtures(t)
		config.DPoPEnabled = false

		key := newProofKey(t)
		token := mintBoundAccessToken(t, ctx, store, access, proofThumbprint(t, key), "")

		_, err := auth.AuthenticateClientRegistrationRequest(ctx, bindingRequest("Bearer", token, "", nil), "")

		require.NoError(t, err)
	})

	t.Run("ShouldRejectWhenTheConfiguredStrategyCannotValidateResourceAccess", func(t *testing.T) {
		auth, config, store, access := newBindingFixtures(t)
		config.DPoPStrategy = &proofOnlyDPoPStrategy{}

		key := newProofKey(t)
		token := mintBoundAccessToken(t, ctx, store, access, proofThumbprint(t, key), "")

		proof := signDPoPProof(t, key, "reg-3", http.MethodPost, testEndpoint, token)

		_, err := auth.AuthenticateClientRegistrationRequest(ctx, bindingRequest("DPoP", token, proof, nil), "")

		require.Error(t, err)
		assert.ErrorIs(t, err, oauth2.ErrRequestUnauthorized)
	})
}

func TestAuthEnforcesMTLSBindingAtTheRegistrationEndpoint(t *testing.T) {
	ctx := context.Background()

	cert := gen.MustCertificate(gen.CertificateOptions{})
	other := gen.MustCertificate(gen.CertificateOptions{SerialNumber: 2})

	t.Run("ShouldAcceptTheBoundCertificate", func(t *testing.T) {
		auth, _, store, access := newBindingFixtures(t)

		token := mintBoundAccessToken(t, ctx, store, access, "", oauth2.X509CertificateSHA256Thumbprint(cert))

		requester, err := auth.AuthenticateClientRegistrationRequest(ctx, bindingRequest("Bearer", token, "", cert), "")

		require.NoError(t, err)
		assert.Equal(t, "onboarding", requester.GetClient().GetID())
	})

	t.Run("ShouldRejectADifferentCertificate", func(t *testing.T) {
		auth, _, store, access := newBindingFixtures(t)

		token := mintBoundAccessToken(t, ctx, store, access, "", oauth2.X509CertificateSHA256Thumbprint(cert))

		_, err := auth.AuthenticateClientRegistrationRequest(ctx, bindingRequest("Bearer", token, "", other), "")

		require.Error(t, err)
		assert.ErrorIs(t, err, oauth2.ErrRequestUnauthorized)
	})

	t.Run("ShouldRejectNoCertificate", func(t *testing.T) {
		auth, _, store, access := newBindingFixtures(t)

		token := mintBoundAccessToken(t, ctx, store, access, "", oauth2.X509CertificateSHA256Thumbprint(cert))

		_, err := auth.AuthenticateClientRegistrationRequest(ctx, bindingRequest("Bearer", token, "", nil), "")

		require.Error(t, err)
		assert.ErrorIs(t, err, oauth2.ErrRequestUnauthorized)
	})

	t.Run("ShouldReadTheConfiguredProxyHeader", func(t *testing.T) {
		auth, config, store, access := newBindingFixtures(t)
		config.MTLSClientCertificateHeader = "X-Forwarded-Tls-Client-Cert"

		token := mintBoundAccessToken(t, ctx, store, access, "", oauth2.X509CertificateSHA256Thumbprint(cert))

		r := bindingRequest("Bearer", token, "", nil)
		r.Header.Set("X-Forwarded-Tls-Client-Cert", base64.StdEncoding.EncodeToString(cert.Raw))

		_, err := auth.AuthenticateClientRegistrationRequest(ctx, r, "")

		require.NoError(t, err)
	})

	t.Run("ShouldSkipWhenMTLSIsDisabled", func(t *testing.T) {
		auth, config, store, access := newBindingFixtures(t)
		config.MTLSEnabled = false

		token := mintBoundAccessToken(t, ctx, store, access, "", oauth2.X509CertificateSHA256Thumbprint(cert))

		_, err := auth.AuthenticateClientRegistrationRequest(ctx, bindingRequest("Bearer", token, "", nil), "")

		require.NoError(t, err)
	})
}

func TestAuthAcceptsAnUnboundTokenWithBindingEnabled(t *testing.T) {
	ctx := context.Background()

	auth, _, store, access := newBindingFixtures(t)

	token := mintBoundAccessToken(t, ctx, store, access, "", "")

	requester, err := auth.AuthenticateClientRegistrationRequest(ctx, bindingRequest("Bearer", token, "", nil), "")

	require.NoError(t, err)
	assert.Equal(t, "onboarding", requester.GetClient().GetID())
}

func TestAuthRejectsTheDPoPSchemeAtTheConfigurationEndpoint(t *testing.T) {
	ctx := context.Background()

	auth, config, store, _ := newAuthFixtures(t)

	token, err := NewClientManagementToken(ctx, hoauth2.NewHMACCoreStrategy(config, "authelia_%s_"), store, config, &oauth2.DefaultClient{ID: "client-a"}, oauth2.Arguments{"openid"}, nil)
	require.NoError(t, err)

	r := httptest.NewRequest(http.MethodGet, ClientConfigurationURL("https://auth.example.com/register", "client-a"), nil)
	r.Header.Set("Authorization", "DPoP "+token)

	_, err = auth.AuthenticateClientRegistrationRequest(ctx, r, "client-a")

	require.Error(t, err)
	assert.ErrorIs(t, err, oauth2.ErrRequestUnauthorized)
	assert.Contains(t, oauth2.ErrorToRFC6749Error(err).HintField, "must use the Bearer scheme")
}

type proofOnlyDPoPStrategy struct{}

func (proofOnlyDPoPStrategy) ValidateDPoPProof(_ context.Context, _, _, _ string, _ bool) (parsed *oauth2.DPoPProof, err error) {
	return &oauth2.DPoPProof{}, nil
}

func (proofOnlyDPoPStrategy) NewDPoPNonce(_ context.Context) (nonce string, err error) {
	return "", nil
}

func (proofOnlyDPoPStrategy) ValidateDPoPNonce(_ context.Context, _ string) (err error) {
	return nil
}

func newBindingFixtures(t *testing.T) (auth *DefaultEndpointAuthStrategy, config *oauth2.Config, store *storage.MemoryStore, access *hoauth2.HMACCoreStrategy) {
	t.Helper()

	config = &oauth2.Config{
		GlobalSecret:                          []byte("super-duper-secret-that-is-at-least-32-bytes"),
		RFC7591ClientRegistrationGlobalSecret: []byte("a-completely-different-secret-at-least-32b"),
		RFC7591ClientRegistrationEndpointURL:  testEndpoint,
		TokenEntropy:                          32,
		DPoPEnabled:                           true,
		MTLSEnabled:                           true,
	}

	store = storage.NewMemoryStore()
	config.DPoPStrategy = rfc9449.NewDefaultStrategy(config, store)

	access = hoauth2.NewHMACCoreStrategy(config, "authelia_%s_")

	return NewDefaultEndpointAuthStrategy(config, store, access, access), config, store, access
}

func mintBoundAccessToken(t *testing.T, ctx context.Context, store *storage.MemoryStore, strategy hoauth2.AccessTokenStrategy, jkt, x5t string) string {
	t.Helper()

	request := oauth2.NewRequest()
	request.Client = &oauth2.DefaultClient{ID: "onboarding"}
	request.Session = &oauth2.DefaultSession{
		ExpiresAt:                   map[oauth2.TokenType]time.Time{oauth2.AccessToken: time.Now().UTC().Add(time.Hour)},
		JWKThumbprint:               jkt,
		ClientCertificateThumbprint: x5t,
	}
	request.GrantScope("client_registration")
	request.GrantAudience(testEndpoint)

	token, signature, err := strategy.GenerateAccessToken(ctx, request)
	require.NoError(t, err)
	require.NoError(t, store.CreateAccessTokenSession(ctx, signature, request))

	return token
}

func newProofKey(t *testing.T) *jose.JSONWebKey {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	return &jose.JSONWebKey{Key: priv, Algorithm: string(jose.ES256)}
}

func proofThumbprint(t *testing.T, key *jose.JSONWebKey) string {
	t.Helper()

	jkt, err := jwt.ThumbprintJWK(key)
	require.NoError(t, err)

	return jkt
}

func signDPoPProof(t *testing.T, key *jose.JSONWebKey, id, method, url, token string) string {
	t.Helper()

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.SignatureAlgorithm(key.Algorithm), Key: key},
		(&jose.SignerOptions{EmbedJWK: true}).WithType(jose.ContentType(jwt.JSONWebTokenTypeDPoP)),
	)
	require.NoError(t, err)

	sum := sha256.Sum256([]byte(token))

	raw, err := josejwt.Signed(signer).Claims(map[string]any{
		jwt.ClaimJWTID:               id,
		jwt.ClaimHTTPMethod:          method,
		jwt.ClaimHTTPURI:             url,
		jwt.ClaimIssuedAt:            time.Now().Unix(),
		jwt.ClaimDPoPAccessTokenHash: base64.RawURLEncoding.EncodeToString(sum[:]),
	}).Serialize()
	require.NoError(t, err)

	return raw
}

func bindingRequest(scheme, token, proof string, peer *x509.Certificate) *http.Request {
	r := httptest.NewRequest(http.MethodPost, testEndpoint, nil)
	r.Header.Set("Authorization", scheme+" "+token)

	if proof != "" {
		r.Header.Set("DPoP", proof)
	}

	if peer != nil {
		r.TLS.PeerCertificates = []*x509.Certificate{peer}
	}

	return r
}
