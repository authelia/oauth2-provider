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

func TestIDTokenSubjectTokenRequiresExpiration(t *testing.T) {
	store := storage.NewExampleStore()
	cfg := newSpecConfig(t)

	jwtStrategy := &jwt.DefaultStrategy{Config: cfg, Issuer: jwt.NewDefaultIssuerRS256Unverified(key)}

	client := store.Clients["my-client"]

	handler := &IDTokenTypeHandler{
		Config:             cfg,
		Strategy:           jwtStrategy,
		IssueStrategy:      &openid.DefaultStrategy{Strategy: jwtStrategy, Config: cfg},
		ValidationStrategy: &openid.DefaultIDTokenValidationStrategy{Strategy: jwtStrategy},
		Storage:            store,
	}

	testCases := []struct {
		name string
		omit string
		err  string
	}{
		{"ShouldAcceptAnIDToken", "", ""},
		{"ShouldRejectAnIDTokenWithoutExpiration", consts.ClaimExpirationTime, "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Unable to parse the id_token Token is expired"},
		{"ShouldRejectAnIDTokenWithoutIssuedAt", consts.ClaimIssuedAt, "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Unable to parse the id_token Token used before issued"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			claims := jwt.MapClaims{
				consts.ClaimSubject:        "peter",
				consts.ClaimAudience:       []string{client.GetID()},
				consts.ClaimExpirationTime: time.Now().Add(10 * time.Minute).Unix(),
				consts.ClaimIssuedAt:       time.Now().Unix(),
			}

			delete(claims, tc.omit)

			request := &oauth2.AccessRequest{
				GrantTypes: oauth2.Arguments{consts.GrantTypeOAuthTokenExchange},
				Request: oauth2.Request{
					ID:     uuid.New().String(),
					Client: client,
					Form: url.Values{
						consts.FormParameterGrantType:        {consts.GrantTypeOAuthTokenExchange},
						consts.FormParameterSubjectTokenType: {consts.TokenTypeRFC8693IDToken},
						consts.FormParameterSubjectToken:     {createJWT(t.Context(), client, jwtStrategy, claims)},
					},
					Session: newSpecSession("peter"),
				},
			}

			err := handler.HandleTokenEndpointRequest(t.Context(), request)

			if tc.err == "" {
				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

				return
			}

			require.ErrorIs(t, err, oauth2.ErrInvalidRequest)
			assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), tc.err)
		})
	}
}
