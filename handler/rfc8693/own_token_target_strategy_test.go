// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc8693_test

import (
	"errors"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	. "authelia.com/provider/oauth2/handler/rfc8693"
	"authelia.com/provider/oauth2/internal/consts"
)

func TestOwnTokenExchangeTargetUsesHandlerStrategies(t *testing.T) {
	const (
		audience = "https://api.example.com"
		resource = "https://resource.example.com"
	)

	deny := func(_, needle []string) error {
		if len(needle) != 0 {
			return errors.New("denied")
		}

		return nil
	}

	testCases := []struct {
		name     string
		refresh  bool
		audience oauth2.AudienceStrategy
		resource oauth2.ResourceStrategy
		named    bool
		err      error
	}{
		{name: "ShouldInheritWithTheConfigStrategies"},
		{name: "ShouldRejectAnInheritedAudienceTheHandlerStrategyDenies", audience: deny, err: oauth2.ErrInvalidTarget},
		{name: "ShouldRejectAnInheritedResourceTheHandlerStrategyDenies", resource: deny, err: oauth2.ErrInvalidTarget},
		{name: "ShouldRejectANamedAudienceTheHandlerStrategyDenies", audience: deny, named: true, err: oauth2.ErrInvalidTarget},
		{name: "ShouldInheritARefreshTokenWithTheConfigStrategies", refresh: true},
		{name: "ShouldRejectARefreshTokenInheritedAudienceTheHandlerStrategyDenies", refresh: true, audience: deny, err: oauth2.ErrInvalidTarget},
		{name: "ShouldRejectARefreshTokenInheritedResourceTheHandlerStrategyDenies", refresh: true, resource: deny, err: oauth2.ErrInvalidTarget},
	}

	for _, sc := range bindingExchangeStores() {
		for _, tc := range testCases {
			t.Run(sc.name+"/"+tc.name, func(t *testing.T) {
				store := sc.newStore()
				config, strategy := newBindingExchangeConfig()
				config.RFC8693TokenTypes[consts.TokenTypeRFC8693RefreshToken] = &DefaultTokenType{Name: consts.TokenTypeRFC8693RefreshToken}

				client := &oauth2.DefaultRegisteredClient{
					DefaultClient:                &oauth2.DefaultClient{ID: "requester", GrantTypes: []string{consts.GrantTypeOAuthTokenExchange, consts.GrantTypeRefreshToken}, Audience: []string{audience}, Resource: []string{resource}},
					TokenExchangeOwnAccessToken:  true,
					TokenExchangeOwnRefreshToken: true,

					TokenExchangeOwnAccessTokenRestrictTargets: true,
				}

				subjectTokenType, key := consts.TokenTypeRFC8693AccessToken, oauth2.AccessToken
				if tc.refresh {
					subjectTokenType, key = consts.TokenTypeRFC8693RefreshToken, oauth2.RefreshToken
				}

				issued := newUnaddressedRequest(client, "peter", []string{consts.ScopeOpenID}, key)
				issued.GrantAudience(audience)
				issued.GrantResource(resource)

				var (
					token, signature string
					err              error
				)

				if tc.refresh {
					token, signature, err = strategy.GenerateRefreshToken(t.Context(), issued)
					require.NoError(t, err)
					require.NoError(t, store.CreateRefreshTokenSession(t.Context(), signature, "", issued.Sanitize(nil)))
				} else {
					token, signature, err = strategy.GenerateAccessToken(t.Context(), issued)
					require.NoError(t, err)
					require.NoError(t, store.(hoauth2.AccessTokenStorage).CreateAccessTokenSession(t.Context(), signature, issued.Sanitize(nil)))
				}

				request := newExchangeRequest(t, client, newSpecSession("peter"), url.Values{
					consts.FormParameterSubjectTokenType: {subjectTokenType},
					consts.FormParameterSubjectToken:     {token},
				})

				if tc.named {
					request.RequestedAudience = []string{audience}
				}

				var handler oauth2.TokenEndpointHandler

				if tc.refresh {
					refresh := newLifetimeRefreshTokenHandler(config, strategy, store)
					refresh.RefreshTokenScopes = []string{}
					refresh.AudienceStrategy, refresh.ResourceStrategy = tc.audience, tc.resource

					handler = refresh
				} else {
					access := newLifetimeAccessTokenHandler(config, strategy, store)
					access.AudienceStrategy, access.ResourceStrategy = tc.audience, tc.resource

					handler = access
				}

				err = handler.HandleTokenEndpointRequest(t.Context(), request)

				if tc.err != nil {
					require.ErrorIs(t, err, tc.err)
					assert.Empty(t, request.GetGrantedAudience())
					assert.Empty(t, request.GetGrantedResource())

					return
				}

				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
				assert.Equal(t, oauth2.Arguments{audience}, request.GetGrantedAudience())
				assert.Equal(t, oauth2.Arguments{resource}, request.GetGrantedResource())
			})
		}
	}
}
