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
	"maps"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/handler/rfc9449"
	"authelia.com/provider/oauth2/internal/gen"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/token/jose"
	josejwt "authelia.com/provider/oauth2/token/jose/jwt"
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
		assert.ErrorIs(t, err, oauth2.ErrInvalidToken)
	})

	t.Run("ShouldRejectABoundTokenPresentedWithoutAProof", func(t *testing.T) {
		auth, _, store, access := newBindingFixtures(t)

		key := newProofKey(t)
		token := mintBoundAccessToken(t, ctx, store, access, proofThumbprint(t, key), "")

		_, err := auth.AuthenticateClientRegistrationRequest(ctx, bindingRequest("DPoP", token, "", nil), "")

		require.Error(t, err)
		assert.ErrorIs(t, err, oauth2.ErrInvalidDPoPProof)
	})

	t.Run("ShouldRejectAProofSignedByAnotherKey", func(t *testing.T) {
		auth, _, store, access := newBindingFixtures(t)

		key, attacker := newProofKey(t), newProofKey(t)
		token := mintBoundAccessToken(t, ctx, store, access, proofThumbprint(t, key), "")

		proof := signDPoPProof(t, attacker, "reg-2", http.MethodPost, testEndpoint, token)

		_, err := auth.AuthenticateClientRegistrationRequest(ctx, bindingRequest("DPoP", token, proof, nil), "")

		require.Error(t, err)
		assert.ErrorIs(t, err, oauth2.ErrInvalidDPoPProof)
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
		assert.ErrorIs(t, err, oauth2.ErrInvalidToken)
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
		assert.ErrorIs(t, err, oauth2.ErrInvalidToken)
	})

	t.Run("ShouldRejectNoCertificate", func(t *testing.T) {
		auth, _, store, access := newBindingFixtures(t)

		token := mintBoundAccessToken(t, ctx, store, access, "", oauth2.X509CertificateSHA256Thumbprint(cert))

		_, err := auth.AuthenticateClientRegistrationRequest(ctx, bindingRequest("Bearer", token, "", nil), "")

		require.Error(t, err)
		assert.ErrorIs(t, err, oauth2.ErrInvalidToken)
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

func TestAuthRequiresABoundTokenWhenBindingIsEnforced(t *testing.T) {
	ctx := context.Background()

	cert := gen.MustCertificate(gen.CertificateOptions{})

	t.Run("ShouldRejectAnUnboundTokenWhenDPoPIsEnforced", func(t *testing.T) {
		auth, config, store, access := newBindingFixtures(t)
		config.DPoPEnforce = true

		token := mintBoundAccessToken(t, ctx, store, access, "", "")

		_, err := auth.AuthenticateClientRegistrationRequest(ctx, bindingRequest("Bearer", token, "", nil), "")

		require.Error(t, err)
		assert.ErrorIs(t, err, oauth2.ErrInvalidToken)
		assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), "The access token provided is expired, revoked, malformed, or invalid for other reasons. The credential used to authenticate the request is not bound to a DPoP key. DPoP is enforced, so every credential presented to authenticate a request must be bound to a DPoP key, but this credential records no binding.")
	})

	t.Run("ShouldRejectAnUnboundTokenWhenMTLSIsEnforced", func(t *testing.T) {
		auth, config, store, access := newBindingFixtures(t)
		config.MTLSEnforce = true

		token := mintBoundAccessToken(t, ctx, store, access, "", "")

		_, err := auth.AuthenticateClientRegistrationRequest(ctx, bindingRequest("Bearer", token, "", nil), "")

		require.Error(t, err)
		assert.ErrorIs(t, err, oauth2.ErrInvalidToken)
		assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), "The access token provided is expired, revoked, malformed, or invalid for other reasons. The credential used to authenticate the request is not bound to a client certificate. Mutual-TLS client certificate bound access tokens are enforced, so every credential presented to authenticate a request must be bound to a client certificate, but this credential records no binding.")
	})

	t.Run("ShouldRejectATokenSatisfyingOnlyOneOfTwoEnforcedBindings", func(t *testing.T) {
		auth, config, store, access := newBindingFixtures(t)
		config.DPoPEnforce, config.MTLSEnforce = true, true

		key := newProofKey(t)
		token := mintBoundAccessToken(t, ctx, store, access, proofThumbprint(t, key), "")

		proof := signDPoPProof(t, key, "enforce-1", http.MethodPost, testEndpoint, token)

		_, err := auth.AuthenticateClientRegistrationRequest(ctx, bindingRequest("DPoP", token, proof, cert), "")

		require.Error(t, err)
		assert.ErrorIs(t, err, oauth2.ErrInvalidToken)
		assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), "The access token provided is expired, revoked, malformed, or invalid for other reasons. The credential used to authenticate the request is not bound to a client certificate. Mutual-TLS client certificate bound access tokens are enforced, so every credential presented to authenticate a request must be bound to a client certificate, but this credential records no binding.")
	})

	t.Run("ShouldAcceptATokenSatisfyingBothEnforcedBindings", func(t *testing.T) {
		auth, config, store, access := newBindingFixtures(t)
		config.DPoPEnforce, config.MTLSEnforce = true, true

		key := newProofKey(t)
		token := mintBoundAccessToken(t, ctx, store, access, proofThumbprint(t, key), oauth2.X509CertificateSHA256Thumbprint(cert))

		proof := signDPoPProof(t, key, "enforce-2", http.MethodPost, testEndpoint, token)

		requester, err := auth.AuthenticateClientRegistrationRequest(ctx, bindingRequest("DPoP", token, proof, cert), "")

		require.NoError(t, err)
		assert.Equal(t, "onboarding", requester.GetClient().GetID())
	})
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
	assert.ErrorIs(t, err, oauth2.ErrInvalidToken)
	assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), "The access token provided is expired, revoked, malformed, or invalid for other reasons. The Authorization header must use the Bearer scheme.")
}

func TestAuthEnforcesBothBindingsIndependentlyAtTheRegistrationEndpoint(t *testing.T) {
	ctx := context.Background()

	cert := gen.MustCertificate(gen.CertificateOptions{})
	other := gen.MustCertificate(gen.CertificateOptions{SerialNumber: 2})

	t.Run("ShouldAcceptWhenBothAreSatisfied", func(t *testing.T) {
		auth, _, store, access := newBindingFixtures(t)

		key := newProofKey(t)
		token := mintBoundAccessToken(t, ctx, store, access, proofThumbprint(t, key), oauth2.X509CertificateSHA256Thumbprint(cert))

		proof := signDPoPProof(t, key, "both-1", http.MethodPost, testEndpoint, token)

		requester, err := auth.AuthenticateClientRegistrationRequest(ctx, bindingRequest("DPoP", token, proof, cert), "")

		require.NoError(t, err)
		assert.Equal(t, "onboarding", requester.GetClient().GetID())
	})

	t.Run("ShouldRejectAValidProofWithTheWrongCertificate", func(t *testing.T) {
		auth, _, store, access := newBindingFixtures(t)

		key := newProofKey(t)
		token := mintBoundAccessToken(t, ctx, store, access, proofThumbprint(t, key), oauth2.X509CertificateSHA256Thumbprint(cert))

		proof := signDPoPProof(t, key, "both-2", http.MethodPost, testEndpoint, token)

		_, err := auth.AuthenticateClientRegistrationRequest(ctx, bindingRequest("DPoP", token, proof, other), "")

		require.Error(t, err)
		assert.ErrorIs(t, err, oauth2.ErrInvalidToken)
	})

	t.Run("ShouldRejectTheCorrectCertificateWithAProofFromAnotherKey", func(t *testing.T) {
		auth, _, store, access := newBindingFixtures(t)

		key, attacker := newProofKey(t), newProofKey(t)
		token := mintBoundAccessToken(t, ctx, store, access, proofThumbprint(t, key), oauth2.X509CertificateSHA256Thumbprint(cert))

		proof := signDPoPProof(t, attacker, "both-3", http.MethodPost, testEndpoint, token)

		_, err := auth.AuthenticateClientRegistrationRequest(ctx, bindingRequest("DPoP", token, proof, cert), "")

		require.Error(t, err)
		assert.ErrorIs(t, err, oauth2.ErrInvalidDPoPProof)
	})
}

func TestAuthRejectsAMisdirectedOrSubstitutedDPoPProof(t *testing.T) {
	ctx := context.Background()

	t.Run("ShouldRejectAProofWhoseATHNamesAnotherToken", func(t *testing.T) {
		auth, _, store, access := newBindingFixtures(t)

		key := newProofKey(t)
		token := mintBoundAccessToken(t, ctx, store, access, proofThumbprint(t, key), "")
		elsewhere := mintBoundAccessToken(t, ctx, store, access, proofThumbprint(t, key), "")

		proof := signDPoPProof(t, key, "sub-1", http.MethodPost, testEndpoint, elsewhere)

		_, err := auth.AuthenticateClientRegistrationRequest(ctx, bindingRequest("DPoP", token, proof, nil), "")

		require.Error(t, err)
		assert.ErrorIs(t, err, oauth2.ErrInvalidDPoPProof)
	})

	t.Run("ShouldRejectAProofMintedForAnotherURI", func(t *testing.T) {
		auth, _, store, access := newBindingFixtures(t)

		key := newProofKey(t)
		token := mintBoundAccessToken(t, ctx, store, access, proofThumbprint(t, key), "")

		proof := signDPoPProof(t, key, "sub-2", http.MethodPost, "https://auth.example.com/token", token)

		_, err := auth.AuthenticateClientRegistrationRequest(ctx, bindingRequest("DPoP", token, proof, nil), "")

		require.Error(t, err)
		assert.ErrorIs(t, err, oauth2.ErrInvalidDPoPProof)
	})

	t.Run("ShouldRejectAProofMintedForAnotherMethod", func(t *testing.T) {
		auth, _, store, access := newBindingFixtures(t)

		key := newProofKey(t)
		token := mintBoundAccessToken(t, ctx, store, access, proofThumbprint(t, key), "")

		proof := signDPoPProof(t, key, "sub-3", http.MethodGet, testEndpoint, token)

		_, err := auth.AuthenticateClientRegistrationRequest(ctx, bindingRequest("DPoP", token, proof, nil), "")

		require.Error(t, err)
		assert.ErrorIs(t, err, oauth2.ErrInvalidDPoPProof)
	})

	t.Run("ShouldRejectAReplayedProof", func(t *testing.T) {
		auth, _, store, access := newBindingFixtures(t)

		key := newProofKey(t)
		token := mintBoundAccessToken(t, ctx, store, access, proofThumbprint(t, key), "")

		proof := signDPoPProof(t, key, "sub-4", http.MethodPost, testEndpoint, token)

		_, err := auth.AuthenticateClientRegistrationRequest(ctx, bindingRequest("DPoP", token, proof, nil), "")
		require.NoError(t, err)

		_, err = auth.AuthenticateClientRegistrationRequest(ctx, bindingRequest("DPoP", token, proof, nil), "")

		require.Error(t, err)
		assert.ErrorIs(t, err, oauth2.ErrInvalidDPoPProof)
	})
}

func TestAuthRejectsAnUnreadableClientCertificateHeader(t *testing.T) {
	ctx := context.Background()

	cert := gen.MustCertificate(gen.CertificateOptions{})

	auth, config, store, access := newBindingFixtures(t)
	config.MTLSClientCertificateHeader = "X-Forwarded-Tls-Client-Cert"

	token := mintBoundAccessToken(t, ctx, store, access, "", oauth2.X509CertificateSHA256Thumbprint(cert))

	r := bindingRequest("Bearer", token, "", nil)
	r.Header.Set("X-Forwarded-Tls-Client-Cert", "not-a-certificate")

	_, err := auth.AuthenticateClientRegistrationRequest(ctx, r, "")

	require.Error(t, err)
	assert.ErrorIs(t, err, oauth2.ErrInvalidToken)
}

func TestAuthRequiresANonceWhenConfigured(t *testing.T) {
	ctx := context.Background()

	auth, config, store, access := newBindingFixtures(t)
	config.DPoPNonceRequired = true

	key := newProofKey(t)
	token := mintBoundAccessToken(t, ctx, store, access, proofThumbprint(t, key), "")

	proof := signDPoPProof(t, key, "nonce-1", http.MethodPost, testEndpoint, token)

	_, err := auth.AuthenticateClientRegistrationRequest(ctx, bindingRequest("DPoP", token, proof, nil), "")

	require.Error(t, err)
	assert.ErrorIs(t, err, oauth2.ErrUseDPoPNonce)

	proof = signDPoPProofWithClaims(t, key, "nonce-2", http.MethodPost, testEndpoint, token, map[string]any{jwt.ClaimNonce: "guessed-nonce"})

	_, err = auth.AuthenticateClientRegistrationRequest(ctx, bindingRequest("DPoP", token, proof, nil), "")

	require.Error(t, err)
	assert.ErrorIs(t, err, oauth2.ErrUseDPoPNonce)
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
	request.GrantScope("authelia:oauth2:client_registration")
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

	return signDPoPProofWithClaims(t, key, id, method, url, token, nil)
}

func signDPoPProofWithClaims(t *testing.T, key *jose.JSONWebKey, id, method, url, token string, extra map[string]any) string {
	t.Helper()

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.SignatureAlgorithm(key.Algorithm), Key: key},
		(&jose.SignerOptions{EmbedJWK: true}).WithType(jwt.JSONWebTokenTypeDPoP),
	)
	require.NoError(t, err)

	sum := sha256.Sum256([]byte(token))

	claims := map[string]any{
		jwt.ClaimJWTID:               id,
		jwt.ClaimHTTPMethod:          method,
		jwt.ClaimHTTPURI:             url,
		jwt.ClaimIssuedAt:            time.Now().Unix(),
		jwt.ClaimDPoPAccessTokenHash: base64.RawURLEncoding.EncodeToString(sum[:]),
	}

	maps.Copy(claims, extra)

	raw, err := josejwt.Signed(signer).Claims(claims).Serialize()
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
