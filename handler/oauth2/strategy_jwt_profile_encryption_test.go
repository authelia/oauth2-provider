// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/jose"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/gen"
	"authelia.com/provider/oauth2/token/jwt"
)

// RFC 9068 Sections 2.1 and 4, RFC 7516 Section 4.1, and RFC 7519 Section 5.2.
func TestGenerateJWTEncryptedForTheClient(t *testing.T) {
	issuer := gen.MustRSAKey()
	rsaKey, otherRSAKey := gen.MustRSAKey(), gen.MustRSAKey()
	ecKey := gen.MustES256Key()

	const secret = "a-client-secret-that-is-long-enough-to-derive-keys"

	testCases := []struct {
		name    string
		keys    []jose.JSONWebKey
		kid     string
		alg     jose.KeyAlgorithm
		enc     jose.ContentEncryption
		decrypt func(t *testing.T, client oauth2.Client) any
		eKid    string
		eEnc    jose.ContentEncryption
	}{
		{
			name:    "ShouldEncryptWithRSAOAEP256",
			keys:    []jose.JSONWebKey{{Key: rsaKey.Public(), KeyID: "rsa", Use: consts.JSONWebTokenUseEncryption, Algorithm: string(jose.RSA_OAEP_256)}},
			alg:     jose.RSA_OAEP_256,
			enc:     jose.A256GCM,
			decrypt: func(*testing.T, oauth2.Client) any { return rsaKey },
			eKid:    "rsa",
			eEnc:    jose.A256GCM,
		},
		{
			name:    "ShouldEncryptWithECDHESA128KW",
			keys:    []jose.JSONWebKey{{Key: ecKey.Public(), KeyID: "ec", Use: consts.JSONWebTokenUseEncryption, Algorithm: string(jose.ECDH_ES_A128KW)}},
			alg:     jose.ECDH_ES_A128KW,
			enc:     jose.A128GCM,
			decrypt: func(*testing.T, oauth2.Client) any { return ecKey },
			eKid:    "ec",
			eEnc:    jose.A128GCM,
		},
		{
			name: "ShouldEncryptToTheRegisteredKeyID",
			keys: []jose.JSONWebKey{
				{Key: otherRSAKey.Public(), KeyID: "first", Use: consts.JSONWebTokenUseEncryption, Algorithm: string(jose.RSA_OAEP_256)},
				{Key: rsaKey.Public(), KeyID: "second", Use: consts.JSONWebTokenUseEncryption, Algorithm: string(jose.RSA_OAEP_256)},
			},
			kid:     "second",
			alg:     jose.RSA_OAEP_256,
			enc:     jose.A128GCM,
			decrypt: func(*testing.T, oauth2.Client) any { return rsaKey },
			eKid:    "second",
			eEnc:    jose.A128GCM,
		},
		{
			name:    "ShouldDefaultTheContentEncryption",
			keys:    []jose.JSONWebKey{{Key: rsaKey.Public(), KeyID: "rsa", Use: consts.JSONWebTokenUseEncryption, Algorithm: string(jose.RSA_OAEP_256)}},
			alg:     jose.RSA_OAEP_256,
			decrypt: func(*testing.T, oauth2.Client) any { return rsaKey },
			eKid:    "rsa",
			eEnc:    jose.A128CBC_HS256,
		},
		{
			name: "ShouldEncryptWithAKeyDerivedFromTheClientSecret",
			alg:  jose.A128KW,
			enc:  jose.A128GCM,
			decrypt: func(t *testing.T, client oauth2.Client) any {
				key, err := jwt.NewClientSecretJWKFromClient(context.Background(), jwt.NewJWTProfileAccessTokenClient(client), "", string(jose.A128KW), string(jose.A128GCM), consts.JSONWebTokenUseEncryption)
				require.NoError(t, err)

				return key
			},
			eEnc: jose.A128GCM,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()

			config := &oauth2.Config{
				EnforceJWTProfileAccessTokens: true,
				GlobalSecret:                  []byte("foofoofoofoofoofoofoofoofoofoofoo"),
			}

			strategy := NewCoreStrategy(config, "authelia_%s_", &jwt.DefaultStrategy{Config: config, Issuer: jwt.NewDefaultIssuerUnverifiedFromJWKS(&jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
				{Key: issuer, KeyID: "issuer", Algorithm: string(jose.RS256), Use: consts.JSONWebTokenUseSignature},
			}})})

			client := &oauth2.DefaultRegisteredClient{
				DefaultClient:                     &oauth2.DefaultClient{ID: "client-abc", ClientSecret: oauth2.NewPlainTextClientSecret(secret)},
				AccessTokenEncryptedResponseKeyID: tc.kid,
				AccessTokenEncryptedResponseAlg:   string(tc.alg),
				AccessTokenEncryptedResponseEnc:   string(tc.enc),
			}

			if tc.keys != nil {
				client.JSONWebKeys = &jose.JSONWebKeySet{Keys: tc.keys}
			}

			request := jwtValidCase(oauth2.AccessToken)
			request.Client = client

			token, _, err := strategy.GenerateAccessToken(ctx, request)
			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

			jwe, err := jose.ParseEncryptedCompact(token, []jose.KeyAlgorithm{tc.alg}, []jose.ContentEncryption{tc.eEnc})
			require.NoError(t, err)

			assert.Equal(t, string(tc.alg), jwe.Header.Algorithm)
			assert.Equal(t, tc.eKid, jwe.Header.KeyID)
			assert.Equal(t, tc.eEnc, jose.ContentEncryption(jwe.Header.ExtraHeaders[jose.HeaderKey("enc")].(string)))
			assert.Equal(t, consts.JSONWebTokenTypeJWT, jwe.Header.ExtraHeaders[jose.HeaderContentType])

			plaintext, err := jwe.Decrypt(tc.decrypt(t, client))
			require.NoError(t, err)

			jws, err := jose.ParseSignedCompact(string(plaintext), []jose.SignatureAlgorithm{jose.RS256})
			require.NoError(t, err)
			require.Len(t, jws.Signatures, 1)

			assert.Equal(t, "issuer", jws.Signatures[0].Header.KeyID)
			assert.Equal(t, consts.JSONWebTokenTypeAccessToken, jws.Signatures[0].Header.ExtraHeaders[jose.HeaderType])

			payload, err := jws.Verify(issuer.Public())
			require.NoError(t, err)
			assert.Contains(t, string(payload), `"client_id":"client-abc"`)
		})
	}
}

// RFC 9068 Section 4.
func TestGenerateJWTEncryptedNeverFallsBackToSigned(t *testing.T) {
	config := &oauth2.Config{EnforceJWTProfileAccessTokens: true, GlobalSecret: []byte("foofoofoofoofoofoofoofoofoofoofoo")}

	strategy := NewCoreStrategy(config, "authelia_%s_", &jwt.DefaultStrategy{Config: config, Issuer: jwt.NewDefaultIssuerRS256Unverified(gen.MustRSAKey())})

	request := jwtValidCase(oauth2.AccessToken)
	request.Client = &oauth2.DefaultRegisteredClient{
		DefaultClient:                   &oauth2.DefaultClient{ID: "client-abc"},
		JSONWebKeys:                     &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: gen.MustES256Key().Public(), KeyID: "ec", Use: consts.JSONWebTokenUseEncryption, Algorithm: string(jose.ECDH_ES_A128KW)}}},
		AccessTokenEncryptedResponseAlg: string(jose.RSA_OAEP_256),
	}

	token, _, err := strategy.GenerateAccessToken(t.Context(), request)

	require.Error(t, err)
	assert.Empty(t, token)
}

// RFC 9068 Section 4.
func TestValidateJWTSignedForAClientRegisteredForEncryption(t *testing.T) {
	config := &oauth2.Config{EnforceJWTProfileAccessTokens: true, GlobalSecret: []byte("foofoofoofoofoofoofoofoofoofoofoo")}

	strategy := NewCoreStrategy(config, "authelia_%s_", &jwt.DefaultStrategy{Config: config, Issuer: jwt.NewDefaultIssuerRS256Unverified(gen.MustRSAKey())})

	request := jwtValidCase(oauth2.AccessToken)
	request.Client = &oauth2.DefaultRegisteredClient{DefaultClient: &oauth2.DefaultClient{ID: "client-abc"}}

	token, _, err := strategy.GenerateAccessToken(t.Context(), request)
	require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

	request.Client = &oauth2.DefaultRegisteredClient{
		DefaultClient:                   &oauth2.DefaultClient{ID: "client-abc"},
		JSONWebKeys:                     &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: gen.MustRSAKey().Public(), KeyID: "rsa", Use: consts.JSONWebTokenUseEncryption, Algorithm: string(jose.RSA_OAEP_256)}}},
		AccessTokenEncryptedResponseAlg: string(jose.RSA_OAEP_256),
	}

	assert.Error(t, strategy.ValidateAccessToken(t.Context(), request, token))
}

// RFC 9068 Section 4.
func TestStatelessJWTValidatorSignedForAClientRegisteredForEncryption(t *testing.T) {
	config := &oauth2.Config{EnforceJWTProfileAccessTokens: true, GlobalSecret: []byte("foofoofoofoofoofoofoofoofoofoofoo")}

	strategy := NewCoreStrategy(config, "authelia_%s_", &jwt.DefaultStrategy{Config: config, Issuer: jwt.NewDefaultIssuerRS256Unverified(gen.MustRSAKey())}).(*JWTProfileCoreStrategy)

	request := jwtValidCase(oauth2.AccessToken)
	request.Client = &oauth2.DefaultRegisteredClient{DefaultClient: &oauth2.DefaultClient{ID: "client-abc"}}

	token, _, err := strategy.GenerateAccessToken(t.Context(), request)
	require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

	encrypting := &oauth2.DefaultRegisteredClient{
		DefaultClient:                   &oauth2.DefaultClient{ID: "client-abc"},
		JSONWebKeys:                     &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: gen.MustRSAKey().Public(), KeyID: "rsa", Use: consts.JSONWebTokenUseEncryption, Algorithm: string(jose.RSA_OAEP_256)}}},
		AccessTokenEncryptedResponseAlg: string(jose.RSA_OAEP_256),
	}

	testCases := []struct {
		name    string
		clients oauth2.ClientGetter
		err     bool
	}{
		{name: "ShouldValidateWithoutClients"},
		{name: "ShouldValidateForAClientNotRegisteredForEncryption", clients: statelessClients{"client-abc": request.Client}},
		{name: "ShouldRejectForAClientRegisteredForEncryption", clients: statelessClients{"client-abc": encrypting}, err: true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			validator := &StatelessJWTValidator{StatelessJWTStrategy: strategy, Config: &oauth2.Config{ScopeStrategy: oauth2.HierarchicScopeStrategy}, Clients: tc.clients}

			_, err := validator.IntrospectToken(t.Context(), token, oauth2.AccessToken, oauth2.NewAccessRequest(&JWTSession{}), nil)

			if tc.err {
				require.ErrorIs(t, err, oauth2.ErrRequestUnauthorized)

				return
			}

			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
		})
	}
}
