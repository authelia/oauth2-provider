// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package openid

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/jose"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/token/jwt"
)

const (
	hintClientSecret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	hintOtherSecret  = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
)

func TestIDTokenHintSignedWithClientSecret(t *testing.T) {
	testCases := []struct {
		name     string
		signer   *oauth2.DefaultRegisteredClient
		verifier *oauth2.DefaultRegisteredClient
		expected string
	}{
		{
			name:     "ShouldAcceptTheRegisteredAlgorithm",
			signer:   newHintClient(hintClientSecret, "HS256", ""),
			verifier: newHintClient(hintClientSecret, "HS256", ""),
		},
		{
			name:     "ShouldRejectADifferentSecret",
			signer:   newHintClient(hintOtherSecret, "HS256", ""),
			verifier: newHintClient(hintClientSecret, "HS256", ""),
			expected: "go-jose/go-jose: error in cryptographic primitive",
		},
		{
			name:     "ShouldRejectAnAlgorithmTheClientIsNotRegisteredFor",
			signer:   newHintClient(hintClientSecret, "HS512", ""),
			verifier: newHintClient(hintClientSecret, "HS256", ""),
			expected: "Error occurred retrieving the JSON Web Key. Unable to find JSON web key with kid '', use 'sig', and alg 'HS512' in JSON Web Key Set",
		},
		{
			name:     "ShouldRejectAClientRegisteredForAnAsymmetricAlgorithm",
			signer:   newHintClient(hintClientSecret, "HS256", ""),
			verifier: newHintClient(hintClientSecret, "RS256", ""),
			expected: "Error occurred retrieving the JSON Web Key. Unable to find JSON web key with kid '', use 'sig', and alg 'HS256' in JSON Web Key Set",
		},
		{
			name:     "ShouldRejectAClientWithASigningKeyIdentifier",
			signer:   newHintClient(hintClientSecret, "HS256", ""),
			verifier: newHintClient(hintClientSecret, "HS256", "issuer-key"),
			expected: "Error occurred retrieving the JSON Web Key. Unable to find JSON web key with kid '', use 'sig', and alg 'HS256' in JSON Web Key Set",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			strategy := newHintStrategy()

			hint := newClientSignedHint(t, strategy, tc.signer)

			claims, err := (&DefaultIDTokenValidationStrategy{Strategy: strategy}).ValidateIDToken(t.Context(), &oauth2.Request{Client: tc.verifier}, hint, oauth2.WithIDTokenHint())

			if tc.expected != "" {
				assert.EqualError(t, err, tc.expected)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, "peter", claims[jwt.ClaimSubject])
		})
	}
}

func TestIDTokenSignedWithClientSecretIsOnlyAcceptedAsAHint(t *testing.T) {
	const expected = "Error occurred retrieving the JSON Web Key. Unable to find JSON web key with kid '', use 'sig', and alg 'HS256' in JSON Web Key Set"

	strategy := newHintStrategy()
	client := newHintClient(hintClientSecret, "HS256", "")
	hint := newClientSignedHint(t, strategy, client)

	_, err := (&DefaultIDTokenValidationStrategy{Strategy: strategy}).ValidateIDToken(t.Context(), &oauth2.Request{Client: client}, hint)
	assert.EqualError(t, err, expected)

	_, err = strategy.Decode(t.Context(), hint, jwt.WithIDTokenClient(client))
	assert.EqualError(t, err, expected)
}

func TestIDTokenHintSignedWithTheIssuerKeyStillVerifies(t *testing.T) {
	strategy := newHintStrategy()

	hint, _, err := strategy.Encode(t.Context(), newHintClaims())
	require.NoError(t, err)

	claims, err := (&DefaultIDTokenValidationStrategy{Strategy: strategy}).ValidateIDToken(t.Context(), &oauth2.Request{Client: newHintClient(hintClientSecret, "HS256", "")}, hint, oauth2.WithIDTokenHint())
	require.NoError(t, err)
	assert.Equal(t, "peter", claims[jwt.ClaimSubject])
}

func TestIDTokenHintSignedWithClientSecretRejectsAKeyIdentifier(t *testing.T) {
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: []byte(hintClientSecret)}, (&jose.SignerOptions{}).WithHeader(jose.HeaderKey(jwt.JSONWebTokenHeaderKeyIdentifier), "secret"))
	require.NoError(t, err)

	payload, err := json.Marshal(newHintClaims())
	require.NoError(t, err)

	signed, err := signer.Sign(payload)
	require.NoError(t, err)

	hint, err := signed.CompactSerialize()
	require.NoError(t, err)

	_, err = (&DefaultIDTokenValidationStrategy{Strategy: newHintStrategy()}).ValidateIDToken(t.Context(), &oauth2.Request{Client: newHintClient(hintClientSecret, "HS256", "")}, hint, oauth2.WithIDTokenHint())
	assert.EqualError(t, err, "Error occurred retrieving the JSON Web Key. The JSON Web Token uses signing key with kid 'secret' which was not found")
}

func TestGenerateIDTokenAcceptsAHintSignedWithClientSecret(t *testing.T) {
	cfg := &oauth2.Config{IDTokenIssuer: "https://issuer.example/", IDTokenLifespan: 5 * time.Minute, MinParameterEntropy: 8}
	strategy := &jwt.DefaultStrategy{Config: cfg, Issuer: jwt.NewDefaultIssuerRS256Unverified(key)}
	client := newHintClient(hintClientSecret, "HS256", "")

	session := &DefaultSession{Claims: &jwt.IDTokenClaims{Subject: "peter", AuthTime: jwt.Now()}, Headers: &jwt.Headers{}, Subject: "peter"}

	request := oauth2.NewAccessRequest(session)
	request.Client = client
	request.Form.Set("id_token_hint", newClientSignedHint(t, strategy, client))

	token, err := (&DefaultStrategy{Strategy: strategy, Config: cfg}).GenerateIDToken(t.Context(), cfg.IDTokenLifespan, request)
	require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
	assert.NotEmpty(t, token)
}

func newHintStrategy() *jwt.DefaultStrategy {
	return &jwt.DefaultStrategy{Config: &oauth2.Config{}, Issuer: jwt.NewDefaultIssuerRS256Unverified(key)}
}

func newHintClient(secret, alg, kid string) *oauth2.DefaultRegisteredClient {
	return &oauth2.DefaultRegisteredClient{
		DefaultClient:              &oauth2.DefaultClient{ID: "hint-client", ClientSecret: oauth2.NewPlainTextClientSecret(secret)},
		IDTokenSignedResponseAlg:   alg,
		IDTokenSignedResponseKeyID: kid,
	}
}

func newHintClaims() jwt.MapClaims {
	return jwt.MapClaims{
		jwt.ClaimIssuer:         "https://issuer.example/",
		jwt.ClaimSubject:        "peter",
		jwt.ClaimAudience:       []string{"hint-client"},
		jwt.ClaimIssuedAt:       jwt.NewNumericDate(time.Now().Add(-time.Minute)),
		jwt.ClaimExpirationTime: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}
}

func newClientSignedHint(t *testing.T, strategy jwt.Strategy, client *oauth2.DefaultRegisteredClient) string {
	t.Helper()

	token, _, err := strategy.Encode(t.Context(), newHintClaims(), jwt.WithIDTokenClient(client))
	require.NoError(t, err)

	return token
}
