// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc8693_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	. "authelia.com/provider/oauth2/handler/rfc8693"
	"authelia.com/provider/oauth2/internal/consts"
)

func TestCustomJWTIssuedTokenTypeIsTheRegisteredIdentifier(t *testing.T) {
	testCases := []struct {
		name      string
		grant     bool
		byDefault bool
	}{
		{name: "ShouldIdentifyAJWT"},
		{name: "ShouldIdentifyAJWTRequestedByDefault", byDefault: true},
		{name: "ShouldIdentifyAJWTAuthorizationGrant", grant: true},
		{name: "ShouldIdentifyAJWTAuthorizationGrantRequestedByDefault", grant: true, byDefault: true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			f := newGrantFixture(t, func(jwtType *JWTType) {
				jwtType.Name = "Partner JWT"
				jwtType.Issue.AuthorizationGrant = tc.grant
			})

			f.requester.(*oauth2.DefaultRegisteredClient).TokenExchangeOwnAccessToken = true

			if tc.byDefault {
				f.cfg.DefaultRequestedTokenType = consts.TokenTypeRFC8693JWT
			}

			response, err := f.exchange(t, grantExchange{audience: []string{grantTarget}, omitRequestedType: tc.byDefault})
			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

			// See: https://datatracker.ietf.org/doc/html/rfc8693#section-2.2.1
			assert.Equal(t, consts.TokenTypeRFC8693JWT, response.GetExtra(consts.FormParameterIssuedTokenType))
		})
	}
}
