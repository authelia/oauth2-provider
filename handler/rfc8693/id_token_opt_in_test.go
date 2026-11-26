// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc8693_test

import (
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/handler/openid"
	. "authelia.com/provider/oauth2/handler/rfc8693"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestIDTokenSubjectExchangeOptIn(t *testing.T) {
	const hint = "Clients are not allowed to perform a token exchange on their own ID Tokens."

	testCases := []struct {
		name      string
		optedIn   bool
		actor     bool
		requested string
		refused   bool
	}{
		{name: "ShouldRejectAnAccessTokenByDefault", requested: consts.TokenTypeRFC8693AccessToken, refused: true},
		{name: "ShouldRejectTheDefaultTokenTypeByDefault", refused: true},
		{name: "ShouldRejectAnIDTokenByDefault", requested: consts.TokenTypeRFC8693IDToken, refused: true},
		{name: "ShouldRejectAJWTByDefault", requested: grantPartnerType, refused: true},
		{name: "ShouldRejectATxnTokenByDefault", requested: consts.TokenTypeRFC8693TxnToken, refused: true},
		{name: "ShouldAcceptAnAccessTokenWhenOptedIn", optedIn: true, requested: consts.TokenTypeRFC8693AccessToken},
		{name: "ShouldAcceptTheDefaultTokenTypeWhenOptedIn", optedIn: true},
		{name: "ShouldAcceptAnIDTokenWhenOptedIn", optedIn: true, requested: consts.TokenTypeRFC8693IDToken},
		{name: "ShouldAcceptAJWTWhenOptedIn", optedIn: true, requested: grantPartnerType},
		{name: "ShouldAcceptATxnTokenWhenOptedIn", optedIn: true, requested: consts.TokenTypeRFC8693TxnToken},
		{name: "ShouldAcceptAJWTAuthorizationGrantByDefault", requested: consts.TokenTypeRFC8693JWT},
		{name: "ShouldAcceptAnIDJAGByDefault", requested: consts.TokenTypeRFC8693IDJAG},
		{name: "ShouldAcceptAnActorTokenByDefault", actor: true, requested: consts.TokenTypeRFC8693AccessToken},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := newSpecConfig(t)
			config.RFC8693TokenTypes[consts.TokenTypeRFC8693IDJAG] = &DefaultTokenType{Name: consts.TokenTypeRFC8693IDJAG}
			config.RFC8693TokenTypes[consts.TokenTypeRFC8693TxnToken] = &TxnTokenType{Name: consts.TokenTypeRFC8693TxnToken}
			config.RFC8693TokenTypes[grantPartnerType] = &JWTType{Name: grantPartnerType, Issue: &JWTIssueConfig{Issuer: grantIssuer}}
			config.RFC8693TokenTypes[consts.TokenTypeRFC8693JWT] = &JWTType{Name: consts.TokenTypeRFC8693JWT, Issue: &JWTIssueConfig{Issuer: grantIssuer, AuthorizationGrant: true}}

			strategy := &jwt.DefaultStrategy{Config: config, Issuer: jwt.NewDefaultIssuerRS256Unverified(key)}

			client := &oauth2.DefaultRegisteredClient{
				DefaultClient: &oauth2.DefaultClient{
					ID:         "requester",
					GrantTypes: []string{consts.GrantTypeOAuthTokenExchange},
				},
				TokenExchangeOwnIDToken: tc.optedIn,
			}

			handler := &IDTokenTypeHandler{
				Config:             config,
				Strategy:           strategy,
				IssueStrategy:      &openid.DefaultStrategy{Strategy: strategy, Config: config},
				ValidationStrategy: &openid.DefaultIDTokenValidationStrategy{Strategy: strategy},
				Storage:            storage.NewExampleStore(),
			}

			token := createJWT(t.Context(), client, strategy, jwt.MapClaims{
				consts.ClaimSubject:        "peter",
				consts.ClaimAudience:       []string{client.GetID()},
				consts.ClaimExpirationTime: time.Now().Add(10 * time.Minute).Unix(),
				consts.ClaimIssuedAt:       time.Now().Unix(),
			})

			form := url.Values{
				consts.FormParameterSubjectTokenType: {consts.TokenTypeRFC8693IDToken},
				consts.FormParameterSubjectToken:     {token},
			}

			if tc.actor {
				form = url.Values{
					consts.FormParameterSubjectTokenType: {consts.TokenTypeRFC8693AccessToken},
					consts.FormParameterSubjectToken:     {"opaque-subject-token"},
					consts.FormParameterActorTokenType:   {consts.TokenTypeRFC8693IDToken},
					consts.FormParameterActorToken:       {token},
				}
			}

			if tc.requested != "" {
				form.Set(consts.FormParameterRequestedTokenType, tc.requested)
			}

			request := newExchangeRequest(t, client, newSpecSession("other"), form)

			err := handler.HandleTokenEndpointRequest(t.Context(), request)

			session := request.GetSession().(*DefaultSession)

			if !tc.refused {
				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

				if tc.actor {
					assert.Equal(t, "peter", session.GetActorToken()[consts.ClaimSubject])
					assert.Equal(t, "other", session.GetSubject())
					assert.Nil(t, session.GetSubjectToken())

					return
				}

				assert.Equal(t, "peter", session.GetSubject())
				assert.Equal(t, "peter", session.GetSubjectToken()[consts.ClaimSubject])
				assert.Nil(t, session.GetActorToken())

				return
			}

			// See: https://datatracker.ietf.org/doc/html/rfc8693#section-2.2.2
			assert.ErrorIs(t, err, oauth2.ErrInvalidRequest)
			assert.ErrorContains(t, oauth2.ErrorToDebugRFC6749Error(err), hint)
			assert.Nil(t, session.GetSubjectToken())
			assert.Equal(t, "other", session.GetSubject())
		})
	}
}
