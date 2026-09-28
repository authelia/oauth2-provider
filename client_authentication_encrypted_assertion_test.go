// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/jose"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestClientAssertionEncryptedWithClientSecret(t *testing.T) {
	const (
		id       = "encrypted-assertion"
		other    = "encrypted-assertion-other"
		secret   = "foobarfoobarfoobarfoobarfoobarfoobar"
		audience = "https://auth.example.com/token"
		derived  = "derives the key from the client secret"
	)

	testCases := []struct {
		name     string
		alg      jose.KeyAlgorithm
		enc      jose.ContentEncryption
		clientID string
		disabled bool
		err      string
	}{
		{name: "ShouldAuthenticateA256KW", alg: jose.A256KW, enc: jose.A256GCM, clientID: id},
		{name: "ShouldAuthenticateA128GCMKW", alg: jose.A128GCMKW, enc: jose.A128GCM, clientID: id},
		{name: "ShouldAuthenticateDirect", alg: jose.DIRECT, enc: jose.A256GCM, clientID: id},
		{name: "ShouldAuthenticateDirectCBC", alg: jose.DIRECT, enc: jose.A128CBC_HS256, clientID: id},
		{name: "ShouldRejectUnregisteredPBES2", alg: jose.PBES2_HS256_A128KW, enc: jose.A128GCM, clientID: id, err: "password based algorithm the client has not registered"},
		{name: "ShouldRejectWithoutClientID", alg: jose.A256KW, enc: jose.A256GCM, err: derived},
		{name: "ShouldRejectUnknownClientID", alg: jose.A256KW, enc: jose.A256GCM, clientID: id + "-unknown", err: "could not be found"},
		{name: "ShouldRejectMismatchedClientID", alg: jose.A256KW, enc: jose.A256GCM, clientID: other, err: "MUST identify the same client as the client assertion"},
		{name: "ShouldRejectWhenDisabled", alg: jose.A256KW, enc: jose.A256GCM, clientID: id, disabled: true, err: derived},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			store := storage.NewMemoryStore()

			for _, cid := range []string{id, other} {
				store.Clients[cid] = &oauth2.DefaultRegisteredClient{
					DefaultClient: &oauth2.DefaultClient{
						ID:           cid,
						ClientSecret: oauth2.NewPlainTextClientSecret(secret),
					},
					TokenEndpointAuthMethod: consts.ClientAuthMethodClientSecretJWT,
				}
			}

			config := &oauth2.Config{
				AllowedJWTAssertionAudiences:                  []string{audience},
				ClientAssertionClientSecretEncryptionDisabled: tc.disabled,
			}
			config.JWTStrategy = &jwt.DefaultStrategy{Config: config, Issuer: jwt.NewDefaultIssuerUnverifiedFromJWKS(&jose.JSONWebKeySet{})}

			provider := &oauth2.Fosite{Store: store, Config: config}

			keySig, err := jwt.NewClientSecretJWK(t.Context(), []byte(secret), "", string(jose.HS256), "", consts.JSONWebTokenUseSignature)
			require.NoError(t, err)

			keyEnc, err := jwt.NewClientSecretJWK(t.Context(), []byte(secret), "", string(tc.alg), string(tc.enc), consts.JSONWebTokenUseEncryption)
			require.NoError(t, err)

			claims := jwt.MapClaims{
				consts.ClaimIssuer:         id,
				consts.ClaimSubject:        id,
				consts.ClaimAudience:       audience,
				consts.ClaimJWTID:          uuid.NewString(),
				consts.ClaimIssuedAt:       time.Now().Unix(),
				consts.ClaimExpirationTime: time.Now().Add(time.Minute).Unix(),
			}

			assertion, _, err := jwt.EncodeNestedCompactEncrypted(t.Context(), claims, nil, nil, keySig, keyEnc, tc.enc)
			require.NoError(t, err)

			form := url.Values{
				consts.FormParameterClientAssertionType: {consts.ClientAssertionTypeJWTBearer},
				consts.FormParameterClientAssertion:     {assertion},
			}

			if tc.clientID != "" {
				form.Set(consts.FormParameterClientID, tc.clientID)
			}

			client, method, err := provider.AuthenticateClient(t.Context(), &http.Request{Header: http.Header{}}, form)

			if tc.err == "" {
				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
				assert.Equal(t, id, client.GetID())
				assert.Equal(t, consts.ClientAuthMethodClientSecretJWT, method)

				return
			}

			require.ErrorIs(t, err, oauth2.ErrInvalidClient)
			assert.Contains(t, oauth2.ErrorToDebugRFC6749Error(err).Error(), tc.err)
		})
	}
}

func TestNewClientAssertionEncryptedWithClientSecret(t *testing.T) {
	const secret = "foobarfoobarfoobarfoobarfoobarfoobar"

	config := &oauth2.Config{}
	config.JWTStrategy = &jwt.DefaultStrategy{Config: config, Issuer: jwt.NewDefaultIssuerUnverifiedFromJWKS(&jose.JSONWebKeySet{})}

	keySig, err := jwt.NewClientSecretJWK(t.Context(), []byte(secret), "", string(jose.HS256), "", consts.JSONWebTokenUseSignature)
	require.NoError(t, err)

	keyEnc, err := jwt.NewClientSecretJWK(t.Context(), []byte(secret), "", string(jose.A256KW), string(jose.A256GCM), consts.JSONWebTokenUseEncryption)
	require.NoError(t, err)

	assertion, _, err := jwt.EncodeNestedCompactEncrypted(t.Context(), jwt.MapClaims{consts.ClaimSubject: "encrypted-assertion"}, nil, nil, keySig, keyEnc, jose.A256GCM)
	require.NoError(t, err)

	_, err = oauth2.NewClientAssertion(t.Context(), config.GetJWTStrategy(t.Context()), storage.NewMemoryStore(), assertion, consts.ClientAssertionTypeJWTBearer, &oauth2.TokenEndpointClientAuthStrategy{})

	require.ErrorIs(t, err, oauth2.ErrInvalidClient)
	assert.Contains(t, oauth2.ErrorToDebugRFC6749Error(err).Error(), "derives the key from the client secret")
}
