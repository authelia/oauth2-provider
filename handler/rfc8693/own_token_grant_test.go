// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc8693_test

import (
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	. "authelia.com/provider/oauth2/handler/rfc8693"
	"authelia.com/provider/oauth2/internal/consts"
)

func TestOwnTokenExchangeTargetDefaultsToTheGrant(t *testing.T) {
	const (
		audience = "https://api.example.com"
		resource = "https://resource.example.com"
		other    = "https://other.example.com"
	)

	testCases := []struct {
		name               string
		refresh            bool
		restrict           bool
		audience           []string
		resource           []string
		registeredAudience []string
		registeredResource []string
		expectedAudience   oauth2.Arguments
		expectedResource   oauth2.Arguments
		err                error
	}{
		{name: "ShouldDefaultARefreshTokenToTheGrant", refresh: true, expectedAudience: oauth2.Arguments{audience}, expectedResource: oauth2.Arguments{resource}},
		{name: "ShouldNotDefaultARefreshTokenNamingAnAudience", refresh: true, audience: []string{audience}, expectedAudience: oauth2.Arguments{audience}},
		{name: "ShouldNotDefaultARefreshTokenNamingAResource", refresh: true, resource: []string{resource}, expectedResource: oauth2.Arguments{resource}},
		{name: "ShouldDefaultARestrictedAccessTokenToTheGrant", restrict: true, expectedAudience: oauth2.Arguments{audience}, expectedResource: oauth2.Arguments{resource}},
		{name: "ShouldNotDefaultARestrictedAccessTokenNamingAnAudience", restrict: true, audience: []string{audience}, expectedAudience: oauth2.Arguments{audience}},
		{name: "ShouldNotDefaultAnUnrestrictedAccessToken"},
		{name: "ShouldDefaultARefreshTokenToTargetsStillRegistered", refresh: true, registeredAudience: []string{other, audience}, registeredResource: []string{other, resource}, expectedAudience: oauth2.Arguments{audience}, expectedResource: oauth2.Arguments{resource}},
		{name: "ShouldDefaultARestrictedAccessTokenToTargetsStillRegistered", restrict: true, registeredAudience: []string{other, audience}, registeredResource: []string{other, resource}, expectedAudience: oauth2.Arguments{audience}, expectedResource: oauth2.Arguments{resource}},
		{name: "ShouldRejectARefreshTokenInheritingAnAudienceNoLongerRegistered", refresh: true, registeredAudience: []string{other}, err: oauth2.ErrInvalidTarget},
		{name: "ShouldRejectARefreshTokenInheritingAnAudienceWithNoneRegistered", refresh: true, registeredAudience: []string{}, err: oauth2.ErrInvalidTarget},
		{name: "ShouldRejectARefreshTokenInheritingAResourceNoLongerRegistered", refresh: true, registeredResource: []string{other}, err: oauth2.ErrInvalidTarget},
		{name: "ShouldRejectARestrictedAccessTokenInheritingAnAudienceNoLongerRegistered", restrict: true, registeredAudience: []string{other}, err: oauth2.ErrInvalidTarget},
		{name: "ShouldRejectARestrictedAccessTokenInheritingAResourceNoLongerRegistered", restrict: true, registeredResource: []string{other}, err: oauth2.ErrInvalidTarget},
		{name: "ShouldRejectARestrictedAccessTokenInheritingAResourceWithNoneRegistered", restrict: true, registeredResource: []string{}, err: oauth2.ErrInvalidTarget},
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

					TokenExchangeOwnAccessTokenRestrictTargets: tc.restrict,
				}

				subjectTokenType, token := consts.TokenTypeRFC8693AccessToken, ""

				if tc.refresh {
					subjectTokenType = consts.TokenTypeRFC8693RefreshToken

					issued := newUnaddressedRequest(client, "peter", []string{consts.ScopeOpenID}, oauth2.RefreshToken)
					issued.GrantAudience(audience)
					issued.GrantResource(resource)

					var (
						signature string
						err       error
					)

					token, signature, err = strategy.GenerateRefreshToken(t.Context(), issued)
					require.NoError(t, err)
					require.NoError(t, store.CreateRefreshTokenSession(t.Context(), signature, "", issued.Sanitize(nil)))
				} else {
					issued := newUnaddressedRequest(client, "peter", []string{consts.ScopeOpenID}, oauth2.AccessToken)
					issued.GrantAudience(audience)
					issued.GrantResource(resource)

					var (
						signature string
						err       error
					)

					token, signature, err = strategy.GenerateAccessToken(t.Context(), issued)
					require.NoError(t, err)
					require.NoError(t, store.(hoauth2.AccessTokenStorage).CreateAccessTokenSession(t.Context(), signature, issued.Sanitize(nil)))
				}

				// The registration may change while the token remains valid.
				if tc.registeredAudience != nil {
					client.Audience = tc.registeredAudience
				}

				if tc.registeredResource != nil {
					client.Resource = tc.registeredResource
				}

				request := newExchangeRequest(t, client, newSpecSession("peter"), url.Values{
					consts.FormParameterSubjectTokenType: {subjectTokenType},
					consts.FormParameterSubjectToken:     {token},
				})

				// The grant handler grants the named targets before a token type handler runs.
				request.RequestedAudience = tc.audience
				request.GrantedAudience = tc.audience
				request.RequestedResource = tc.resource
				request.GrantedResource = tc.resource

				var handler oauth2.TokenEndpointHandler = newLifetimeAccessTokenHandler(config, strategy, store)

				if tc.refresh {
					refresh := newLifetimeRefreshTokenHandler(config, strategy, store)
					refresh.RefreshTokenScopes = []string{}

					handler = refresh
				}

				err := handler.HandleTokenEndpointRequest(t.Context(), request)

				if tc.err != nil {
					// See: https://www.rfc-editor.org/rfc/rfc8693#section-2.2.2
					require.ErrorIs(t, err, tc.err)
					assert.Empty(t, request.GetGrantedAudience())
					assert.Empty(t, request.GetGrantedResource())

					return
				}

				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

				// See: https://www.rfc-editor.org/rfc/rfc8707#section-2.2
				assert.Equal(t, tc.expectedAudience, request.GetRequestedAudience())
				assert.Equal(t, tc.expectedAudience, request.GetGrantedAudience())
				assert.Equal(t, tc.expectedResource, request.GetRequestedResource())
				assert.Equal(t, tc.expectedResource, request.GetGrantedResource())
			})
		}
	}
}

func TestExchangedRefreshTokenResponseScope(t *testing.T) {
	granted := []string{consts.ScopeOpenID, consts.ScopeOfflineAccess, "read"}

	testCases := []struct {
		name     string
		scope    []string
		expected string
	}{
		{name: "ShouldReportTheGrantScopeWhenNarrowed", scope: []string{"read"}, expected: "openid offline_access read"},
		{name: "ShouldReportTheGrantScopeWhenOmitted", expected: "openid offline_access read"},
	}

	for _, sc := range bindingExchangeStores() {
		for _, tc := range testCases {
			t.Run(sc.name+"/"+tc.name, func(t *testing.T) {
				store := sc.newStore()
				config, strategy := newBindingExchangeConfig()
				config.RFC8693TokenTypes[consts.TokenTypeRFC8693RefreshToken] = &DefaultTokenType{Name: consts.TokenTypeRFC8693RefreshToken}

				client := &oauth2.DefaultRegisteredClient{
					DefaultClient:                &oauth2.DefaultClient{ID: "requester", GrantTypes: []string{consts.GrantTypeOAuthTokenExchange, consts.GrantTypeRefreshToken}, Scopes: granted},
					TokenExchangeRefreshToken:    true,
					TokenExchangeOwnRefreshToken: true,
				}

				issued := newUnaddressedRequest(client, "peter", granted, oauth2.RefreshToken)

				token, signature, err := strategy.GenerateRefreshToken(t.Context(), issued)
				require.NoError(t, err)
				require.NoError(t, store.CreateRefreshTokenSession(t.Context(), signature, "", issued.Sanitize(nil)))

				request := newExchangeRequest(t, client, newSpecSession("peter"), url.Values{
					consts.FormParameterSubjectTokenType:   {consts.TokenTypeRFC8693RefreshToken},
					consts.FormParameterSubjectToken:       {token},
					consts.FormParameterRequestedTokenType: {consts.TokenTypeRFC8693RefreshToken},
				})
				request.RequestedScope = tc.scope
				request.GrantedScope = tc.scope

				handler := newLifetimeRefreshTokenHandler(config, strategy, store)
				handler.RefreshTokenScopes = []string{}

				response := oauth2.NewAccessResponse()

				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(handler.HandleTokenEndpointRequest(t.Context(), request)))
				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(handler.PopulateTokenEndpointResponse(t.Context(), request, response)))

				stored, err := store.GetRefreshTokenSession(t.Context(), strategy.RefreshTokenSignature(t.Context(), response.GetAccessToken()), NewDefaultSession())
				require.NoError(t, err)

				// See: https://datatracker.ietf.org/doc/html/rfc8693#section-2.2.1
				assert.Equal(t, tc.expected, response.GetExtra(consts.AccessResponseScope))
				assert.Equal(t, tc.expected, strings.Join(stored.GetGrantedScopes(), " "))
			})
		}
	}
}

func TestExchangedRefreshTokenKeepsTheClaimsRequest(t *testing.T) {
	granted := []string{consts.ScopeOpenID, consts.ScopeOfflineAccess, "read"}

	claims := &oauth2.ClaimsRequest{
		IDToken:  map[string]*oauth2.ClaimRequest{"email": {Essential: true}},
		UserInfo: map[string]*oauth2.ClaimRequest{"email": nil},
	}

	testCases := []struct {
		name      string
		requested string
	}{
		{name: "ShouldKeepTheClaimsWithAnAccessToken", requested: consts.TokenTypeRFC8693AccessToken},
		{name: "ShouldKeepTheClaimsOnARefreshToken", requested: consts.TokenTypeRFC8693RefreshToken},
	}

	for _, sc := range bindingExchangeStores() {
		for _, tc := range testCases {
			t.Run(sc.name+"/"+tc.name, func(t *testing.T) {
				store := sc.newStore()
				config, strategy := newBindingExchangeConfig()
				config.RefreshTokenScopes = []string{}
				config.RFC8693TokenTypes[consts.TokenTypeRFC8693RefreshToken] = &DefaultTokenType{Name: consts.TokenTypeRFC8693RefreshToken}

				client := &oauth2.DefaultRegisteredClient{
					DefaultClient:                &oauth2.DefaultClient{ID: "requester", GrantTypes: []string{consts.GrantTypeOAuthTokenExchange, consts.GrantTypeRefreshToken}, Scopes: granted},
					TokenExchangeRefreshToken:    true,
					TokenExchangeOwnRefreshToken: true,
				}

				issued := newUnaddressedRequest(client, "peter", granted, oauth2.RefreshToken)
				issued.Session = newOptInSubject()
				issued.Session.SetExpiresAt(oauth2.RefreshToken, time.Now().UTC().Add(10*time.Minute))
				issued.SetClaims(claims)

				token, signature, err := strategy.GenerateRefreshToken(t.Context(), issued)
				require.NoError(t, err)
				require.NoError(t, store.CreateRefreshTokenSession(t.Context(), signature, "", issued.Sanitize(nil)))

				request := newExchangeRequest(t, client, newSpecSession("peter"), url.Values{
					consts.FormParameterSubjectTokenType:   {consts.TokenTypeRFC8693RefreshToken},
					consts.FormParameterSubjectToken:       {token},
					consts.FormParameterRequestedTokenType: {tc.requested},
				})
				request.RequestedScope = []string{"read"}
				request.GrantedScope = []string{"read"}

				refresh := newLifetimeRefreshTokenHandler(config, strategy, store)
				refresh.RefreshTokenScopes = []string{}

				access := newLifetimeAccessTokenHandler(config, strategy, store)
				access.RefreshTokenScopes = []string{}

				response := oauth2.NewAccessResponse()

				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(refresh.HandleTokenEndpointRequest(t.Context(), request)))

				exchanged := ""

				if tc.requested == consts.TokenTypeRFC8693RefreshToken {
					require.NoError(t, oauth2.ErrorToDebugRFC6749Error(refresh.PopulateTokenEndpointResponse(t.Context(), request, response)))

					exchanged = response.GetAccessToken()
				} else {
					require.NoError(t, oauth2.ErrorToDebugRFC6749Error(access.PopulateTokenEndpointResponse(t.Context(), request, response)))

					exchanged, _ = response.GetExtra(consts.FormParameterRefreshToken).(string)
				}

				require.NotEmpty(t, exchanged)

				stored, err := store.GetRefreshTokenSession(t.Context(), strategy.RefreshTokenSignature(t.Context(), exchanged), NewDefaultSession())
				require.NoError(t, err)

				// See: https://openid.net/specs/openid-connect-core-1_0.html#ClaimsParameter
				assert.Equal(t, claims, stored.(oauth2.ClaimsRequester).GetClaims())

				grant := &hoauth2.RefreshTokenGrantHandler{
					TokenRevocationStorage: store,
					RefreshTokenStrategy:   strategy,
					AccessTokenStrategy:    strategy,
					Config:                 config,
				}

				refreshing := &oauth2.AccessRequest{
					GrantTypes: oauth2.Arguments{consts.GrantTypeRefreshToken},
					Request: oauth2.Request{
						ID:          "refreshing",
						RequestedAt: time.Now().UTC(),
						Client:      client,
						Form:        url.Values{consts.FormParameterRefreshToken: {exchanged}},
						Session:     NewDefaultSession(),
					},
				}

				refreshed := oauth2.NewAccessResponse()

				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(grant.HandleTokenEndpointRequest(t.Context(), refreshing)))
				assert.Equal(t, claims, refreshing.GetClaims())

				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(grant.PopulateTokenEndpointResponse(t.Context(), refreshing, refreshed)))

				rotated, _ := refreshed.GetExtra(consts.AccessResponseRefreshToken).(string)
				require.NotEmpty(t, rotated)

				stored, err = store.GetRefreshTokenSession(t.Context(), strategy.RefreshTokenSignature(t.Context(), rotated), NewDefaultSession())
				require.NoError(t, err)

				assert.Equal(t, claims, stored.(oauth2.ClaimsRequester).GetClaims())
			})
		}
	}
}
