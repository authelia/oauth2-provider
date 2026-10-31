// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/gen"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestJWTProfileAccessTokenRequiresIssuerAndExpiry(t *testing.T) {
	testCases := []struct {
		name     string
		config   string
		session  string
		noExpiry bool
		issuer   string
		err      string
	}{
		{name: "ShouldUseTheConfiguredIssuer", config: "https://as.example.com", issuer: "https://as.example.com"},
		{name: "ShouldPreferTheSessionIssuer", config: "https://as.example.com", session: "https://session.example.com", issuer: "https://session.example.com"},
		{name: "ShouldUseTheSessionIssuerWithoutAConfiguredOne", session: "https://session.example.com", issuer: "https://session.example.com"},
		{name: "ShouldRefuseWithoutAnIssuer", err: "requires an 'iss' claim"},
		{name: "ShouldRefuseWithoutAnExpiry", config: "https://as.example.com", noExpiry: true, err: "requires an 'exp' claim"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := &oauth2.Config{
				EnforceJWTProfileAccessTokens: true,
				AccessTokenIssuer:             tc.config,
				GlobalSecret:                  []byte("foofoofoofoofoofoofoofoofoofoofoo"),
			}

			strategy := &JWTProfileCoreStrategy{
				HMACCoreStrategy: NewHMACCoreStrategy(config, "authelia_%s_"),
				Strategy:         &jwt.DefaultStrategy{Config: config, Issuer: jwt.NewDefaultIssuerRS256Unverified(gen.MustRSAKey())},
				Config:           config,
			}

			session := &JWTSession{JWTClaims: &jwt.JWTClaims{Issuer: tc.session, Subject: "alice"}}

			if !tc.noExpiry {
				session.SetExpiresAt(oauth2.AccessToken, time.Now().UTC().Add(time.Hour))
			}

			request := oauth2.NewAccessRequest(session)
			request.Client = &oauth2.DefaultClient{ID: "jwt-client"}
			request.GrantAudience("https://api.example.com")

			token, _, err := strategy.GenerateAccessToken(context.Background(), request)

			if tc.err != "" {
				assert.ErrorIs(t, err, oauth2.ErrServerError)
				assert.ErrorContains(t, oauth2.ErrorToDebugRFC6749Error(err), tc.err)

				return
			}

			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

			payload, err := base64.RawURLEncoding.DecodeString(strings.Split(token, ".")[1])
			require.NoError(t, err)

			var claims map[string]any

			require.NoError(t, json.Unmarshal(payload, &claims))

			assert.Equal(t, tc.issuer, claims[consts.ClaimIssuer])
			assert.NotEmpty(t, claims[consts.ClaimExpirationTime])
		})
	}
}
