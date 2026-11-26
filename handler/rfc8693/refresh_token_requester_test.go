// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc8693

import (
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/handler/openid"
)

func TestSanitizeRefreshTokenRequester(t *testing.T) {
	details := oauth2.AuthorizationDetails{{Type: "payment", Actions: []string{"initiate", "status"}}}

	grant := oauth2.NewAccessRequest(&DefaultSession{DefaultSession: &openid.DefaultSession{Username: "peter"}})
	grant.SetID("grant")
	grant.Form = url.Values{"grant_type": {"authorization_code"}, "code": {"abc"}}
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
		exchange := oauth2.NewAccessRequest(&DefaultSession{DefaultSession: &openid.DefaultSession{Username: "exchange"}})
		exchange.SetID("grant")
		exchange.Form = url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:token-exchange"}, "subject_token": {"abc"}}
		exchange.GetSession().SetExpiresAt(oauth2.RefreshToken, time.Unix(2000000000, 0).UTC())
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

			requester, err := sanitizeRefreshTokenRequester(tc.request, grant)
			require.NoError(t, err)

			assert.Equal(t, "grant", requester.GetID())
			assert.Equal(t, "peter", requester.GetSession().GetUsername())
			assert.NotSame(t, grant.GetSession(), requester.GetSession())
			assert.Equal(t, tc.request.GetSession().GetExpiresAt(oauth2.RefreshToken), requester.GetSession().GetExpiresAt(oauth2.RefreshToken))
			assert.Equal(t, url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:token-exchange"}}, requester.GetRequestForm())
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
