// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc8693_test

import (
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/handler/openid"
	. "authelia.com/provider/oauth2/handler/rfc8693"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestIDTokenSubjectTokenIsBoundToTheRequestingClient(t *testing.T) {
	store := storage.NewExampleStore()
	cfg := newSpecConfig(t)

	jwtStrategy := &jwt.DefaultStrategy{Config: cfg, Issuer: jwt.NewDefaultIssuerRS256Unverified(key)}

	requesting := store.Clients["my-client"]
	other := store.Clients["custom-lifespan-client"]

	handler := &IDTokenTypeHandler{
		Config:             cfg,
		Strategy:           jwtStrategy,
		IssueStrategy:      &openid.DefaultStrategy{Strategy: jwtStrategy, Config: cfg},
		ValidationStrategy: &openid.DefaultIDTokenValidationStrategy{Strategy: jwtStrategy},
		Storage:            store,
	}

	newRequest := func(audience, azp string) *oauth2.AccessRequest {
		claims := jwt.MapClaims{
			consts.ClaimSubject:        "peter",
			consts.ClaimAudience:       []string{audience},
			consts.ClaimExpirationTime: time.Now().Add(10 * time.Minute).Unix(),
			consts.ClaimIssuedAt:       time.Now().Unix(),
		}

		if azp != "" {
			claims[consts.ClaimAuthorizedParty] = azp
		}

		return &oauth2.AccessRequest{
			GrantTypes: oauth2.Arguments{consts.GrantTypeOAuthTokenExchange},
			Request: oauth2.Request{
				ID:     uuid.New().String(),
				Client: requesting,
				Form: url.Values{
					consts.FormParameterGrantType:        {consts.GrantTypeOAuthTokenExchange},
					consts.FormParameterSubjectTokenType: {consts.TokenTypeRFC8693IDToken},
					consts.FormParameterSubjectToken:     {createJWT(t.Context(), requesting, jwtStrategy, claims)},
				},
				Session: newSpecSession("peter"),
			},
		}
	}

	t.Run("ShouldRejectAnIDTokenIssuedToAnotherClient", func(t *testing.T) {
		err := handler.HandleTokenEndpointRequest(t.Context(), newRequest(other.GetID(), ""))

		require.Error(t, err)
		assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Claim 'aud' from the id_token must include the OAuth 2.0 Client 'my-client'.")
	})

	t.Run("ShouldRejectAnIDTokenWhoseAuthorizedPartyIsAnotherClient", func(t *testing.T) {
		err := handler.HandleTokenEndpointRequest(t.Context(), newRequest(requesting.GetID(), other.GetID()))

		require.Error(t, err)
		assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Claim 'azp' from the id_token must be the OAuth 2.0 Client 'my-client' when it is present.")
	})

	t.Run("ShouldAcceptAnIDTokenIssuedToTheRequestingClient", func(t *testing.T) {
		require.NoError(t, handler.HandleTokenEndpointRequest(t.Context(), newRequest(requesting.GetID(), "")))
	})

	t.Run("ShouldAcceptAMatchingAuthorizedParty", func(t *testing.T) {
		require.NoError(t, handler.HandleTokenEndpointRequest(t.Context(), newRequest(requesting.GetID(), requesting.GetID())))
	})
}
