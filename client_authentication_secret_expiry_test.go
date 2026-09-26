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

func TestCompareClientSecretHonoursTheSecretExpiry(t *testing.T) {
	const secret = "foobarfoobarfoobarfoobar"

	newClient := func(expires time.Time) *oauth2.DefaultRegisteredClient {
		return &oauth2.DefaultRegisteredClient{
			DefaultClient: &oauth2.DefaultClient{
				ID:           "test",
				ClientSecret: oauth2.NewPlainTextClientSecret(secret),
			},
			ClientSecretExpiresAt: expires,
		}
	}

	testCases := []struct {
		name    string
		expires time.Time
		err     bool
	}{
		{name: "ShouldAcceptWhenTheSecretDoesNotExpire", expires: time.Time{}},
		{name: "ShouldAcceptWhenTheSecretHasNotExpired", expires: time.Now().Add(time.Hour)},
		{name: "ShouldRejectWhenTheSecretHasExpired", expires: time.Now().Add(-time.Hour), err: true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := oauth2.CompareClientSecret(t.Context(), newClient(tc.expires), []byte(secret))

			if !tc.err {
				assert.NoError(t, err)

				return
			}

			require.Error(t, err)
			assert.Contains(t, err.Error(), "expired")
		})
	}
}

func TestClientSecretJWTHonoursTheSecretExpiry(t *testing.T) {
	const secret = "foobarfoobarfoobarfoobarfoobarfoobar"

	testCases := []struct {
		name    string
		expires time.Time
		err     bool
	}{
		{name: "ShouldAcceptWhenTheSecretDoesNotExpire", expires: time.Time{}},
		{name: "ShouldAcceptWhenTheSecretHasNotExpired", expires: time.Now().Add(time.Hour)},
		{name: "ShouldRejectWhenTheSecretHasExpired", expires: time.Now().Add(-time.Hour), err: true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			store := storage.NewMemoryStore()
			store.Clients["test"] = &oauth2.DefaultRegisteredClient{
				DefaultClient: &oauth2.DefaultClient{
					ID:           "test",
					ClientSecret: oauth2.NewPlainTextClientSecret(secret),
				},
				TokenEndpointAuthMethod: consts.ClientAuthMethodClientSecretJWT,
				ClientSecretExpiresAt:   tc.expires,
			}

			config := &oauth2.Config{AllowedJWTAssertionAudiences: []string{"token-url"}}
			config.JWTStrategy = &jwt.DefaultStrategy{Config: config, Issuer: jwt.NewDefaultIssuerUnverifiedFromJWKS(&jose.JSONWebKeySet{})}

			provider := &oauth2.Fosite{Store: store, Config: config}

			key, err := jwt.NewClientSecretJWK(t.Context(), []byte(secret), "", string(jose.HS256), "", consts.JSONWebTokenUseSignature)
			require.NoError(t, err)

			assertion, err := jwt.NewWithClaims(jose.HS256, jwt.MapClaims{
				consts.ClaimIssuer:         "test",
				consts.ClaimSubject:        "test",
				consts.ClaimAudience:       "token-url",
				consts.ClaimJWTID:          uuid.NewString(),
				consts.ClaimIssuedAt:       time.Now().Unix(),
				consts.ClaimExpirationTime: time.Now().Add(time.Minute).Unix(),
			}).CompactSignedString(key)
			require.NoError(t, err)

			form := url.Values{
				consts.FormParameterClientAssertionType: {consts.ClientAssertionTypeJWTBearer},
				consts.FormParameterClientAssertion:     {assertion},
			}

			client, method, err := provider.AuthenticateClient(t.Context(), &http.Request{Header: http.Header{}}, form)

			if !tc.err {
				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
				assert.Equal(t, "test", client.GetID())
				assert.Equal(t, consts.ClientAuthMethodClientSecretJWT, method)

				return
			}

			require.ErrorIs(t, err, oauth2.ErrInvalidClient)
			assert.Contains(t, oauth2.ErrorToDebugRFC6749Error(err).Error(), "The client secret has expired")
		})
	}
}
