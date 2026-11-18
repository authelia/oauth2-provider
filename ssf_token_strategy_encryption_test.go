// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/jose"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestDefaultSecurityEventTokenStrategyEncryption(t *testing.T) {
	const secret = "a-client-secret-of-sufficient-length"

	keyIssuer, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	keyIssuerEC, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	keyRSA, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	keyRSAOther, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	keyEC, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	issuer := &jwt.DefaultStrategy{
		Config: &oauth2.Config{},
		Issuer: jwt.NewDefaultIssuerUnverifiedFromJWKS(&jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
			{Key: keyIssuer, KeyID: "k1", Algorithm: string(jose.RS256), Use: jwt.JSONWebTokenUseSignature},
			{Key: keyIssuerEC, KeyID: "k2", Algorithm: string(jose.ES256), Use: jwt.JSONWebTokenUseSignature},
		}}),
	}

	keys := &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
		{Key: keyRSA.Public(), KeyID: "rsa-1", Algorithm: string(jose.RSA_OAEP_256), Use: jwt.JSONWebTokenUseEncryption},
		{Key: keyRSAOther.Public(), KeyID: "rsa-2", Algorithm: string(jose.RSA_OAEP_256), Use: jwt.JSONWebTokenUseEncryption},
		{Key: keyEC.Public(), KeyID: "ec-1", Algorithm: string(jose.ECDH_ES), Use: jwt.JSONWebTokenUseEncryption},
	}}

	keysSigning := &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
		{Key: keyRSA.Public(), KeyID: "rsa-1", Algorithm: string(jose.RS256), Use: jwt.JSONWebTokenUseSignature},
	}}

	keysRSA15 := &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
		{Key: keyRSA.Public(), KeyID: "rsa-1", Algorithm: string(jose.RSA1_5), Use: jwt.JSONWebTokenUseEncryption},
	}}

	keySecret, err := jwt.NewClientSecretJWK(t.Context(), []byte(secret), "", string(jose.A128KW), "", jwt.JSONWebTokenUseEncryption)
	require.NoError(t, err)

	subject, err := jwt.NewSubjectIdentifierOpaque("abc")
	require.NoError(t, err)

	client := func(jwks *jose.JSONWebKeySet, kid, alg, enc string) *oauth2.DefaultRegisteredClient {
		return &oauth2.DefaultRegisteredClient{
			DefaultClient: &oauth2.DefaultClient{ID: "rx", ClientSecret: oauth2.NewPlainTextClientSecret(secret)},
			JSONWebKeys:   jwks,

			SecurityEventTokenEncryptedResponseKeyID: kid,
			SecurityEventTokenEncryptedResponseAlg:   alg,
			SecurityEventTokenEncryptedResponseEnc:   enc,
		}
	}

	public := func(c *oauth2.DefaultRegisteredClient) *oauth2.DefaultRegisteredClient {
		c.Public = true

		return c
	}

	expired := func(c *oauth2.DefaultRegisteredClient) *oauth2.DefaultRegisteredClient {
		c.ClientSecretExpiresAt = time.Now().Add(-time.Hour)

		return c
	}

	testCases := []struct {
		name    string
		signing string
		client  oauth2.Client
		alg     jose.KeyAlgorithm
		enc     jose.ContentEncryption
		kid     string
		decrypt any
		fail    bool
		err     error
	}{
		{name: "ShouldSignWithNilClient"},
		{name: "ShouldSignWithClientWithoutMetadata", client: &oauth2.DefaultClient{ID: "rx"}},
		{name: "ShouldSignWithoutEncryptionAlg", client: client(keys, "", "", "")},
		{name: "ShouldSignWithSigningAlg", signing: string(jose.ES256)},
		{name: "ShouldSignWhenOnlyEncSet", client: client(keys, "", "", string(jose.A256GCM))},
		{name: "ShouldEncryptRSAOAEP256A256GCM", client: client(keys, "", string(jose.RSA_OAEP_256), string(jose.A256GCM)), alg: jose.RSA_OAEP_256, enc: jose.A256GCM, kid: "rsa-1", decrypt: keyRSA},
		{name: "ShouldEncryptECDHESDefaultEnc", client: client(keys, "", string(jose.ECDH_ES), ""), alg: jose.ECDH_ES, enc: jose.A128CBC_HS256, kid: "ec-1", decrypt: keyEC},
		{name: "ShouldEncryptClientSecretSymmetric", client: client(nil, "", string(jose.A128KW), ""), alg: jose.A128KW, enc: jose.A128CBC_HS256, decrypt: keySecret.Key},
		{name: "ShouldEncryptWithKeyID", client: client(keys, "rsa-2", string(jose.RSA_OAEP_256), ""), alg: jose.RSA_OAEP_256, enc: jose.A128CBC_HS256, kid: "rsa-2", decrypt: keyRSAOther},
		{name: "ShouldEncryptWithSigningAlg", signing: string(jose.ES256), client: client(keys, "", string(jose.RSA_OAEP_256), ""), alg: jose.RSA_OAEP_256, enc: jose.A128CBC_HS256, kid: "rsa-1", decrypt: keyRSA},
		{name: "ShouldFailSymmetricSigningAlg", signing: string(jose.HS256), client: client(keys, "", string(jose.RSA_OAEP_256), ""), fail: true, err: oauth2.ErrServerError},
		{name: "ShouldFailNoneAlg", client: client(keys, "", jwt.JSONWebTokenAlgNone, ""), fail: true, err: oauth2.ErrServerError},
		{name: "ShouldFailNoneAlgWithKeyID", client: client(keys, "rsa-1", jwt.JSONWebTokenAlgNone, ""), fail: true, err: oauth2.ErrServerError},
		{name: "ShouldFailPublicClientSymmetric", client: public(client(nil, "", string(jose.A128KW), "")), fail: true},
		{name: "ShouldFailExpiredClientSecretSymmetric", client: expired(client(nil, "", string(jose.A128KW), "")), fail: true},
		{name: "ShouldFailNoEncryptionKey", client: client(nil, "", string(jose.RSA_OAEP_256), ""), fail: true},
		{name: "ShouldFailUnknownKeyID", client: client(keys, "rsa-3", string(jose.RSA_OAEP_256), ""), fail: true},
		{name: "ShouldFailSigningOnlyKey", client: client(keysSigning, "", string(jose.RSA_OAEP_256), ""), fail: true},
		{name: "ShouldFailTypedNilClient", client: (*oauth2.DefaultRegisteredClient)(nil), fail: true, err: oauth2.ErrServerError},
		{name: "ShouldFailNotPermittedAlg", client: client(keysRSA15, "", string(jose.RSA1_5), ""), fail: true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			claims, err := jwt.NewSecurityEventTokenClaims("https://tx.example.com", []string{"rx"}, subject, jwt.CAEPSessionRevoked{}, "")
			require.NoError(t, err)

			strategy := &oauth2.DefaultSecurityEventTokenStrategy{Strategy: issuer, SigningAlg: tc.signing}

			token, err := strategy.GenerateSecurityEventToken(t.Context(), tc.client, claims)

			if tc.fail {
				require.Error(t, err)

				if tc.err != nil {
					require.ErrorIs(t, err, tc.err)
				}

				assert.Empty(t, token)

				return
			}

			require.NoError(t, err)

			nested := token

			if tc.alg == "" {
				require.Len(t, strings.Split(token, "."), 3)
			} else {
				require.Len(t, strings.Split(token, "."), 5)

				jwe, err := jose.ParseEncryptedCompact(token, []jose.KeyAlgorithm{tc.alg}, []jose.ContentEncryption{tc.enc})
				require.NoError(t, err)

				assert.Equal(t, string(tc.alg), jwe.Header.Algorithm)
				assert.Equal(t, tc.kid, jwe.Header.KeyID)
				assert.Equal(t, string(tc.enc), jwe.Header.ExtraHeaders[jose.HeaderKey(jwt.JSONWebTokenHeaderEncryptionAlgorithm)])
				assert.Equal(t, jwt.JSONWebTokenTypeJWT, jwe.Header.ExtraHeaders[jose.HeaderKey(jwt.JSONWebTokenHeaderContentType)])
				assert.Equal(t, jwt.JSONWebTokenTypeJWT, jwe.Header.ExtraHeaders[jose.HeaderKey(jwt.JSONWebTokenHeaderType)])

				plaintext, err := jwe.Decrypt(tc.decrypt)
				require.NoError(t, err)

				nested = string(plaintext)
			}

			var (
				key      any = keyIssuer.Public()
				kid, alg     = "k1", string(jose.RS256)
			)

			if tc.signing == string(jose.ES256) {
				key, kid, alg = keyIssuerEC.Public(), "k2", tc.signing
			}

			decoded, err := jwt.Parse(nested, func(*jwt.Token) (any, error) { return key, nil })
			require.NoError(t, err)

			assert.Equal(t, jwt.JSONWebTokenTypeSecurityEventToken, decoded.Header[jwt.JSONWebTokenHeaderType])
			assert.Equal(t, alg, decoded.Header[jwt.JSONWebTokenHeaderAlgorithm])
			assert.Equal(t, kid, decoded.Header[jwt.JSONWebTokenHeaderKeyIdentifier])

			actual := decoded.Claims.ToMapClaims()

			assert.Equal(t, claims.JTI, actual[jwt.ClaimJWTID])
			assert.Equal(t, claims.Issuer, actual[jwt.ClaimIssuer])
			assert.Equal(t, []any{"rx"}, actual[jwt.ClaimAudience])
			assert.Equal(t, map[string]any{jwt.SecurityEventTypeCAEPSessionRevoked: map[string]any{}}, actual[jwt.ClaimEvents])
		})
	}
}
