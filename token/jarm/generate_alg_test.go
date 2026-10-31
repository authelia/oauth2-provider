// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package jarm

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/jose"

	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestGenerateSigningAlgorithm(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	rs256 := jose.JSONWebKey{Key: rsaKey, KeyID: "rsa", Algorithm: string(jose.RS256), Use: consts.JSONWebTokenUseSignature}
	es256 := jose.JSONWebKey{Key: ecKey, KeyID: "ec", Algorithm: string(jose.ES256), Use: consts.JSONWebTokenUseSignature}

	testCases := []struct {
		name     string
		keys     []jose.JSONWebKey
		alg      string
		kid      string
		expected string
		keyID    string
		err      string
	}{
		{name: "ShouldDefaultToRS256", keys: []jose.JSONWebKey{es256, rs256}, expected: "RS256", keyID: "rsa"},
		{name: "ShouldDefaultToRS256WithAKeyIdentifier", keys: []jose.JSONWebKey{es256, rs256}, kid: "rsa", expected: "RS256", keyID: "rsa"},
		{name: "ShouldUseTheRegisteredAlgorithm", keys: []jose.JSONWebKey{rs256, es256}, alg: "ES256", expected: "ES256", keyID: "ec"},
		{name: "ShouldFailWithoutARS256Key", keys: []jose.JSONWebKey{es256}, err: "Unable to find JSON web key"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := &realStrategyConfigurator{
				stubConfigurator: stubConfigurator{issuer: "https://issuer.example.com", lifespan: time.Hour},
				signer:           &jwt.DefaultStrategy{Issuer: jwt.NewDefaultIssuerUnverifiedFromJWKS(&jose.JSONWebKeySet{Keys: tc.keys})},
			}

			token, _, err := Generate(context.Background(), config, &registeredJARMClient{alg: tc.alg, kid: tc.kid}, nil, url.Values{"code": {"abc"}})

			if tc.err != "" {
				assert.ErrorContains(t, err, tc.err)

				return
			}

			require.NoError(t, err)

			signed, err := jose.ParseSigned(token, []jose.SignatureAlgorithm{jose.RS256, jose.ES256})
			require.NoError(t, err)
			require.Len(t, signed.Signatures, 1)

			assert.Equal(t, tc.expected, signed.Signatures[0].Header.Algorithm)
			assert.Equal(t, tc.keyID, signed.Signatures[0].Header.KeyID)
		})
	}
}

type realStrategyConfigurator struct {
	stubConfigurator

	signer jwt.Strategy
}

func (c *realStrategyConfigurator) GetJWTSecuredAuthorizeResponseModeStrategy(_ context.Context) jwt.Strategy {
	return c.signer
}

var _ jwt.JARMClient = (*registeredJARMClient)(nil)

type registeredJARMClient struct {
	jwt.BaseClient

	alg, kid string
}

func (c *registeredJARMClient) GetID() string { return "client-id" }

func (c *registeredJARMClient) IsPublic() bool { return true }

func (c *registeredJARMClient) GetAuthorizationSignedResponseKeyID() string { return c.kid }

func (c *registeredJARMClient) GetAuthorizationSignedResponseAlg() string { return c.alg }

func (c *registeredJARMClient) GetAuthorizationEncryptedResponseKeyID() string { return "" }

func (c *registeredJARMClient) GetAuthorizationEncryptedResponseAlg() string { return "" }

func (c *registeredJARMClient) GetAuthorizationEncryptedResponseEnc() string { return "" }
