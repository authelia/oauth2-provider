// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc8693_test

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	. "authelia.com/provider/oauth2/handler/rfc8693"
	"authelia.com/provider/oauth2/internal/consts"
)

func TestExchangePolicy(t *testing.T) {
	const requesterID = "requester"

	grants := []string{consts.GrantTypeOAuthTokenExchange, consts.GrantTypeRefreshToken}

	plain := func() oauth2.Client {
		return &oauth2.DefaultClient{ID: "owner", GrantTypes: grants}
	}

	registered := func(permitted ...string) func() oauth2.Client {
		return func() oauth2.Client {
			return &oauth2.DefaultRegisteredClient{
				DefaultClient:                   &oauth2.DefaultClient{ID: "owner", GrantTypes: grants},
				TokenExchangePermittedClientIDs: permitted,
			}
		}
	}

	const (
		hintNotAudience  = "does not include the OAuth 2.0 client"
		hintNotPermitted = "not permitted to exchange"
		hintNotIssued    = "was not issued to the OAuth 2.0 client"
		hintOwnAccess    = "on their own access tokens"
	)

	testCases := []struct {
		name      string
		refresh   bool
		actor     bool
		owner     func() oauth2.Client
		self      bool
		unaddress bool
		requested string
		hint      string
	}{
		{name: "ShouldAcceptAnAddressedAccessTokenOfAPlainClient", owner: plain},
		{name: "ShouldAcceptAnAddressedAccessTokenWithAnEmptyList", owner: registered()},
		{name: "ShouldRejectAnUnaddressedAccessTokenOfAPlainClient", owner: plain, unaddress: true, hint: hintNotAudience},
		{name: "ShouldRejectAnUnaddressedAccessTokenWithAnEmptyList", owner: registered(), unaddress: true, hint: hintNotAudience},
		{name: "ShouldRejectAnUnaddressedAccessTokenWhenListed", owner: registered(requesterID), unaddress: true, hint: hintNotAudience},
		{name: "ShouldRejectAnAccessTokenWhenAnotherClientIsListed", owner: registered("someone-else"), hint: hintNotPermitted},
		{name: "ShouldAcceptAnAccessTokenWhenListed", owner: registered(requesterID)},
		{name: "ShouldRejectTheRequestersOwnAccessToken", self: true, hint: hintOwnAccess},
		{name: "ShouldRejectAnAddressedActorAccessTokenOfAPlainClient", actor: true, owner: plain, hint: hintNotPermitted},
		{name: "ShouldRejectAnAddressedActorAccessTokenWithAnEmptyList", actor: true, owner: registered(), hint: hintNotPermitted},
		{name: "ShouldRejectAnUnaddressedActorAccessTokenWhenListed", actor: true, owner: registered(requesterID), unaddress: true, hint: hintNotAudience},
		{name: "ShouldRejectAnActorAccessTokenWhenAnotherClientIsListed", actor: true, owner: registered("someone-else"), hint: hintNotPermitted},
		{name: "ShouldAcceptAnActorAccessTokenWhenListed", actor: true, owner: registered(requesterID)},
		{name: "ShouldAcceptTheRequestersOwnActorAccessToken", actor: true, self: true},
		{name: "ShouldAcceptTheRequestersOwnRefreshToken", refresh: true, self: true},
		{name: "ShouldRejectARefreshTokenOfAPlainClient", refresh: true, owner: plain, hint: hintNotIssued},
		{name: "ShouldRejectARefreshTokenWithAnEmptyList", refresh: true, owner: registered(), hint: hintNotIssued},
		{name: "ShouldRejectARefreshTokenEvenWhenListed", refresh: true, owner: registered(requesterID), hint: hintNotIssued},
		{name: "ShouldRejectAnIDTokenFromARefreshTokenEvenWhenListed", refresh: true, owner: registered(requesterID), requested: consts.TokenTypeRFC8693IDToken, hint: hintNotIssued},
		{name: "ShouldAcceptTheRequestersOwnActorRefreshToken", refresh: true, actor: true, self: true},
		{name: "ShouldRejectAnActorRefreshTokenEvenWhenListed", refresh: true, actor: true, owner: registered(requesterID), hint: hintNotIssued},
	}

	for _, sc := range bindingExchangeStores() {
		for _, tc := range testCases {
			t.Run(sc.name+"/"+tc.name, func(t *testing.T) {
				store := sc.newStore()
				config, strategy := newBindingExchangeConfig()
				config.RefreshTokenScopes = []string{}
				config.RFC8693TokenTypes[consts.TokenTypeRFC8693RefreshToken] = &DefaultTokenType{Name: consts.TokenTypeRFC8693RefreshToken}
				config.RFC8693TokenTypes[consts.TokenTypeRFC8693IDToken] = &DefaultTokenType{Name: consts.TokenTypeRFC8693IDToken}

				requester := &oauth2.DefaultClient{ID: requesterID, GrantTypes: grants}

				var owner oauth2.Client = requester
				if !tc.self {
					owner = tc.owner()
				}

				token := policyToken(t, strategy, store, owner, tc.refresh, !tc.unaddress)

				tokenType := consts.TokenTypeRFC8693AccessToken
				if tc.refresh {
					tokenType = consts.TokenTypeRFC8693RefreshToken
				}

				form := url.Values{consts.FormParameterGrantType: {consts.GrantTypeOAuthTokenExchange}}

				if tc.actor {
					form.Set(consts.FormParameterActorTokenType, tokenType)
					form.Set(consts.FormParameterActorToken, token)
				} else {
					form.Set(consts.FormParameterSubjectTokenType, tokenType)
					form.Set(consts.FormParameterSubjectToken, token)
				}

				if tc.requested != "" {
					form.Set(consts.FormParameterRequestedTokenType, tc.requested)
				}

				request := newExchangeRequest(t, requester, newSpecSession("peter"), form)

				var handler oauth2.TokenEndpointHandler = newLifetimeAccessTokenHandler(config, strategy, store)
				if tc.refresh {
					handler = newLifetimeRefreshTokenHandler(config, strategy, store)
				}

				err := handler.HandleTokenEndpointRequest(t.Context(), request)

				if tc.hint == "" {
					require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

					return
				}

				// RFC 8693 Section 2.2.2.
				assert.ErrorIs(t, err, oauth2.ErrInvalidRequest)
				assert.ErrorContains(t, oauth2.ErrorToDebugRFC6749Error(err), tc.hint)
			})
		}
	}
}

func policyToken(t *testing.T, strategy hoauth2.CoreStrategy, store rfc8693ExchangeStore, owner oauth2.Client, refresh, addressed bool) string {
	t.Helper()

	request := newUnaddressedRequest(owner, "peter", []string{consts.ScopeOpenID}, oauth2.AccessToken)

	if addressed {
		grantFixtureAudience(request)
	}

	if refresh {
		request = newIssuedRequest(owner, "peter", []string{consts.ScopeOpenID}, oauth2.RefreshToken)

		token, signature, err := strategy.GenerateRefreshToken(t.Context(), request)
		require.NoError(t, err)
		require.NoError(t, store.(hoauth2.TokenRevocationStorage).CreateRefreshTokenSession(t.Context(), signature, "", request.Sanitize(nil)))

		return token
	}

	token, signature, err := strategy.GenerateAccessToken(t.Context(), request)
	require.NoError(t, err)
	require.NoError(t, store.(hoauth2.AccessTokenStorage).CreateAccessTokenSession(t.Context(), signature, request.Sanitize(nil)))

	return token
}
