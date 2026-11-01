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

	"authelia.com/provider/jose"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/handler/openid"
	"authelia.com/provider/oauth2/handler/rfc8693"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/gen"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestIsTxnTokenType(t *testing.T) {
	testCases := []struct {
		name     string
		typ      string
		expected bool
	}{
		{"ShouldMatchExact", "txntoken+jwt", true},
		{"ShouldMatchCaseInsensitive", "TXNTOKEN+JWT", true},
		{"ShouldMatchMediaType", "application/txntoken+jwt", true},
		{"ShouldNotMatchJWT", "JWT", false},
		{"ShouldNotMatchAccessToken", "at+jwt", false},
		{"ShouldNotMatchEmpty", "", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, oauth2.IsTxnTokenType(tc.typ))
		})
	}
}

// §13.12: a Txn-Token is not a client assertion.
func TestTxnTokenIsNotAcceptedAsClientAssertion(t *testing.T) {
	const (
		clientID = "workload"
		tokenURL = "https://as.example.com/token"
		keyID    = "issuer-key"
	)

	key := gen.MustRSAKey()

	config := &oauth2.Config{
		JWKSFetcherStrategy:          oauth2.NewDefaultJWKSFetcherStrategy(),
		AllowedJWTAssertionAudiences: []string{tokenURL},
		IDTokenIssuer:                "https://op.example.com",
	}

	issuer, err := jwt.NewDefaultIssuer(jose.JSONWebKey{Key: key, KeyID: keyID, Algorithm: "RS256", Use: "sig"})
	require.NoError(t, err)

	config.JWTStrategy = &jwt.DefaultStrategy{Config: config, Issuer: issuer}

	store := storage.NewMemoryStore()
	client := &oauth2.DefaultJARClient{
		DefaultClient:           &oauth2.DefaultClient{ID: clientID, ClientSecret: oauth2.NewPlainTextClientSecret("secret")},
		JSONWebKeys:             &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{KeyID: keyID, Use: "sig", Algorithm: "RS256", Key: &key.PublicKey}}},
		TokenEndpointAuthMethod: consts.ClientAuthMethodPrivateKeyJWT,
	}
	store.Clients[clientID] = client

	provider := &oauth2.Fosite{Store: store, Config: config}

	authenticate := func(t *testing.T, assertion string) (oauth2.Client, error) {
		t.Helper()

		form := url.Values{
			consts.FormParameterClientAssertion:     {assertion},
			consts.FormParameterClientAssertionType: {consts.ClientAssertionTypeJWTBearer},
		}

		authenticated, _, err := provider.AuthenticateClientWithAuthHandler(context.Background(), new(http.Request), form, config.GetTokenEndpointClientAuthStrategy(context.Background()))

		return authenticated, err
	}

	t.Run("ShouldAcceptTheSameClaimsAsAClientAssertion", func(t *testing.T) {
		authenticated, err := authenticate(t, mustGenerateClientAssertion(t, jwt.MapClaims{
			consts.ClaimIssuer:         clientID,
			consts.ClaimSubject:        clientID,
			consts.ClaimAudience:       tokenURL,
			consts.ClaimJWTID:          "control",
			consts.ClaimExpirationTime: time.Now().Add(time.Minute).Unix(),
		}, jose.RS256, jwt.JSONWebTokenTypeClientAuthentication, keyID, key))

		require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
		assert.Equal(t, clientID, authenticated.GetID())
	})

	t.Run("ShouldRefuseAnIssuedTxnToken", func(t *testing.T) {
		tokenTypes := map[string]oauth2.RFC8693TokenType{
			consts.TokenTypeRFC8693TxnToken: &rfc8693.TxnTokenType{Name: consts.TokenTypeRFC8693TxnToken, TrustDomain: tokenURL, Issuer: clientID},
		}

		config.RFC8693TokenTypes = tokenTypes

		session := &rfc8693.DefaultSession{DefaultSession: &openid.DefaultSession{Subject: clientID}}
		session.SetSubjectToken(map[string]any{consts.ClaimSubject: clientID})

		request := &oauth2.AccessRequest{
			GrantTypes: oauth2.Arguments{consts.GrantTypeOAuthTokenExchange},
			Request: oauth2.Request{
				Client:         client,
				Session:        session,
				RequestedScope: oauth2.Arguments{"trade.stocks"},
				GrantedScope:   oauth2.Arguments{"trade.stocks"},
				Form:           url.Values{consts.FormParameterRequestedTokenType: {consts.TokenTypeRFC8693TxnToken}},
			},
		}

		response := oauth2.NewAccessResponse()

		handler := &rfc8693.TxnTokenTypeHandler{Config: config, Strategy: config.JWTStrategy}

		require.NoError(t, oauth2.ErrorToDebugRFC6749Error(handler.PopulateTokenEndpointResponse(t.Context(), request, response)))

		_, err := authenticate(t, response.GetAccessToken())

		require.ErrorIs(t, err, oauth2.ErrInvalidClient)
		assert.Contains(t, oauth2.ErrorToDebugRFC6749Error(err).Error(), "'typ' header")
	})
}
