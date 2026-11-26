// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc8693

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"authelia.com/provider/oauth2"
)

func TestSanitizeRefreshTokenRequester(t *testing.T) {
	details := oauth2.AuthorizationDetails{{Type: "payment", Actions: []string{"initiate", "status"}}}

	grant := oauth2.NewAccessRequest(&DefaultSession{})
	grant.SetID("grant")
	grant.SetRequestedScopes(oauth2.Arguments{"openid", "offline_access", "read"})
	grant.SetRequestedAudience(oauth2.Arguments{"api", "other"})
	grant.SetRequestedResource(oauth2.Arguments{"https://rs.example.com"})
	grant.SetRequestedAuthorizationDetails(details)
	grant.SetGrantedAuthorizationDetails(details)

	for _, scope := range grant.GetRequestedScopes() {
		grant.GrantScope(scope)
	}

	for _, audience := range grant.GetRequestedAudience() {
		grant.GrantAudience(audience)
	}

	grant.GrantResource("https://rs.example.com")

	newExchange := func() *oauth2.AccessRequest {
		exchange := oauth2.NewAccessRequest(&DefaultSession{})
		exchange.SetID("grant")
		exchange.SetRequestedScopes(oauth2.Arguments{"read.accounts"})
		exchange.GrantScope("read.accounts")
		exchange.SetRequestedAudience(oauth2.Arguments{"api"})
		exchange.GrantAudience("api")
		exchange.SetRequestedResource(oauth2.Arguments{"https://rs.example.com/accounts"})
		exchange.GrantResource("https://rs.example.com/accounts")

		return exchange
	}

	testCases := []struct {
		name    string
		request oauth2.AccessRequester
	}{
		{name: "ShouldRestoreTheGrantWithARestorer", request: newExchange()},
		{name: "ShouldRestoreTheGrantWithoutARestorer", request: &accessRequesterOnly{AccessRequester: newExchange()}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, restorer := tc.request.(oauth2.RefreshTokenAccessRequester)
			assert.Equal(t, tc.name == "ShouldRestoreTheGrantWithARestorer", restorer)

			requester := sanitizeRefreshTokenRequester(tc.request, grant)

			assert.Equal(t, "grant", requester.GetID())
			assert.Equal(t, tc.request.GetSession(), requester.GetSession())
			assert.Equal(t, tc.request.GetRequestedAt(), requester.GetRequestedAt())
			assert.ElementsMatch(t, grant.GetRequestedScopes(), requester.GetRequestedScopes())
			assert.ElementsMatch(t, grant.GetGrantedScopes(), requester.GetGrantedScopes())
			assert.ElementsMatch(t, grant.GetRequestedAudience(), requester.GetRequestedAudience())
			assert.ElementsMatch(t, grant.GetGrantedAudience(), requester.GetGrantedAudience())
			assert.ElementsMatch(t, grant.GetRequestedResource(), requester.GetRequestedResource())
			assert.ElementsMatch(t, grant.GetGrantedResource(), requester.GetGrantedResource())
			assert.Equal(t, details, requester.GetRequestedAuthorizationDetails())
			assert.Equal(t, details, requester.GetGrantedAuthorizationDetails())
		})
	}
}

type accessRequesterOnly struct {
	oauth2.AccessRequester
}
