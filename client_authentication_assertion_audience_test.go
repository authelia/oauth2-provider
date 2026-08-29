// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"context"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	. "authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/gen"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/token/jose"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestClientAssertionAudienceIssuerEnforcement(t *testing.T) {
	const (
		issuer      = "https://as.example.com"
		tokenURL    = "https://as.example.com/token"
		otherIssuer = "https://other.example.com"
	)

	key := gen.MustRSAKey()

	set := &jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{{KeyID: "kid-foo", Use: "sig", Algorithm: "RS256", Key: &key.PublicKey}},
	}

	testCases := []struct {
		name    string
		enforce bool
		aud     any
		err     string
	}{
		{name: "ShouldAcceptTheTokenEndpointURLWhenNotEnforced", aud: []string{tokenURL}},
		{name: "ShouldAcceptTheIssuerWhenNotEnforced", aud: []string{issuer}},
		{name: "ShouldAcceptMultipleAudiencesWhenNotEnforced", aud: []string{issuer, tokenURL}},
		{name: "ShouldAcceptTheIssuerWhenEnforced", enforce: true, aud: []string{issuer}},
		{name: "ShouldRejectTheTokenEndpointURLWhenEnforced", enforce: true, aud: []string{tokenURL}, err: "audience"},
		{name: "ShouldRejectAnotherIssuerWhenEnforced", enforce: true, aud: []string{otherIssuer}, err: "audience"},
		{name: "ShouldRejectMultipleAudiencesWhenEnforced", enforce: true, aud: []string{issuer, tokenURL}, err: "sole"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := &Config{
				JWKSFetcherStrategy:                  NewDefaultJWKSFetcherStrategy(),
				AllowedJWTAssertionAudiences:         []string{issuer, tokenURL, otherIssuer},
				IDTokenIssuer:                        issuer,
				EnforceClientAssertionIssuerAudience: tc.enforce,
			}

			config.JWTStrategy = &jwt.DefaultStrategy{Config: config, Issuer: jwt.NewDefaultIssuerRS256Unverified(key)}

			store := storage.NewMemoryStore()
			store.Clients["bar"] = &DefaultJARClient{
				DefaultClient:           &DefaultClient{ID: "bar", ClientSecret: testClientSecretBar},
				JSONWebKeys:             set,
				TokenEndpointAuthMethod: consts.ClientAuthMethodPrivateKeyJWT,
			}

			provider := &Fosite{Store: store, Config: config}

			form := url.Values{
				consts.FormParameterClientAssertion: {
					mustGenerateClientAssertion(t, jwt.MapClaims{
						consts.ClaimSubject:        "bar",
						consts.ClaimIssuer:         "bar",
						consts.ClaimJWTID:          "12345",
						consts.ClaimExpirationTime: time.Now().Add(time.Hour).Unix(),
						consts.ClaimAudience:       tc.aud,
					}, jose.RS256, jwt.JSONWebTokenTypeClientAuthentication, "kid-foo", key),
				},
				consts.FormParameterClientAssertionType: {consts.ClientAssertionTypeJWTBearer},
			}

			client, _, err := provider.AuthenticateClientWithAuthHandler(context.Background(), new(http.Request), form,
				config.GetTokenEndpointClientAuthStrategy(context.Background()))

			if tc.err == "" {
				require.NoError(t, ErrorToDebugRFC6749Error(err))
				assert.NotNil(t, client)

				return
			}

			require.Error(t, err)
			assert.Contains(t, ErrorToDebugRFC6749Error(err).Error(), tc.err)
		})
	}
}
