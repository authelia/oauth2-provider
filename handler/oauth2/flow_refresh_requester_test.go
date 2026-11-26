// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal"
	"authelia.com/provider/oauth2/internal/consts"
)

func TestRefreshTokenRequesterKeepsTheFullGrant(t *testing.T) {
	details := oauth2.AuthorizationDetails{{Type: internal.AuthorizationDetailsTypePaymentInitiation, Actions: []string{testRARActionInitiate, testRARActionStatus}}}
	narrowed := oauth2.AuthorizationDetails{{Type: internal.AuthorizationDetailsTypePaymentInitiation, Actions: []string{testRARActionStatus}}}

	requestedAt := time.Now().UTC().Truncate(time.Second)

	newGrant := func() *oauth2.Request {
		return &oauth2.Request{
			ID:                            "grant",
			RequestedAt:                   requestedAt.Add(-time.Hour),
			Client:                        &oauth2.DefaultClient{ID: "foo"},
			RequestedScope:                oauth2.Arguments{"read", "write", consts.ScopeOfflineAccess},
			GrantedScope:                  oauth2.Arguments{"read", consts.ScopeOfflineAccess},
			RequestedAudience:             oauth2.Arguments{"https://api.example.com", "https://other.example.com", "https://denied.example.com"},
			GrantedAudience:               oauth2.Arguments{"https://api.example.com", "https://other.example.com"},
			RequestedResource:             oauth2.Arguments{"https://rs.example.com", "https://other.example.com", "https://denied.example.com"},
			GrantedResource:               oauth2.Arguments{"https://rs.example.com", "https://other.example.com"},
			RequestedAuthorizationDetails: details,
			GrantedAuthorizationDetails:   details,
			Session:                       &oauth2.DefaultSession{Subject: "grant"},
			Form:                          url.Values{consts.FormParameterResponseType: {consts.ResponseTypeAuthorizationCodeFlow}, consts.FormParameterState: {"state"}},
		}
	}

	newRequest := func() *oauth2.AccessRequest {
		return &oauth2.AccessRequest{
			GrantTypes: oauth2.Arguments{consts.GrantTypeAuthorizationCode},
			Request: oauth2.Request{
				ID:                            "grant",
				RequestedAt:                   requestedAt,
				Client:                        &oauth2.DefaultClient{ID: "foo"},
				RequestedScope:                oauth2.Arguments{"read.accounts"},
				GrantedScope:                  oauth2.Arguments{"read.accounts"},
				RequestedAudience:             oauth2.Arguments{"https://api.example.com/accounts"},
				GrantedAudience:               oauth2.Arguments{"https://api.example.com/accounts"},
				RequestedResource:             oauth2.Arguments{"https://rs.example.com/accounts"},
				GrantedResource:               oauth2.Arguments{"https://rs.example.com/accounts"},
				RequestedAuthorizationDetails: narrowed,
				GrantedAuthorizationDetails:   narrowed,
				Session:                       &oauth2.DefaultSession{Subject: "request"},
				Form:                          url.Values{consts.FormParameterGrantType: {consts.GrantTypeAuthorizationCode}, consts.FormParameterAuthorizationCode: {"code"}},
			},
		}
	}

	testCases := []struct {
		name     string
		request  func() oauth2.AccessRequester
		restorer bool
	}{
		{
			name:     "ShouldRestoreTheGrantForARestoringRequester",
			request:  func() oauth2.AccessRequester { return newRequest() },
			restorer: true,
		},
		{
			name:    "ShouldRestoreTheGrantForAnyOtherRequester",
			request: func() oauth2.AccessRequester { return &plainAccessRequester{AccessRequester: newRequest()} },
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			grant := newGrant()
			request := tc.request()

			_, restorer := request.(oauth2.RefreshTokenAccessRequester)
			require.Equal(t, tc.restorer, restorer)

			requester := refreshTokenRequester(request, grant)

			assert.Equal(t, grant.RequestedScope, requester.GetRequestedScopes())
			assert.Equal(t, grant.GrantedScope, requester.GetGrantedScopes())
			assert.Equal(t, grant.RequestedAudience, requester.GetRequestedAudience())
			assert.Equal(t, grant.GrantedAudience, requester.GetGrantedAudience())
			assert.Equal(t, grant.RequestedResource, requester.GetRequestedResource())
			assert.Equal(t, grant.GrantedResource, requester.GetGrantedResource())
			assert.Equal(t, details, requester.GetRequestedAuthorizationDetails())
			assert.Equal(t, details, requester.GetGrantedAuthorizationDetails())

			assert.Equal(t, "grant", requester.GetID())
			assert.Equal(t, "foo", requester.GetClient().GetID())
			assert.Same(t, request.GetSession(), requester.GetSession())
			assert.Equal(t, requestedAt, requester.GetRequestedAt())
			assert.Equal(t, url.Values{consts.FormParameterGrantType: {consts.GrantTypeAuthorizationCode}}, requester.GetRequestForm())

			assert.Equal(t, oauth2.Arguments{"read.accounts"}, request.GetGrantedScopes())
			assert.Equal(t, oauth2.Arguments{"https://api.example.com/accounts"}, request.GetGrantedAudience())
			assert.Equal(t, oauth2.Arguments{"https://rs.example.com/accounts"}, request.GetGrantedResource())
			assert.Equal(t, narrowed, request.GetGrantedAuthorizationDetails())
			assert.Equal(t, "code", request.GetRequestForm().Get(consts.FormParameterAuthorizationCode))

			assert.Equal(t, oauth2.Arguments{"https://api.example.com", "https://other.example.com"}, grant.GetGrantedAudience())
			assert.Equal(t, "state", grant.GetRequestForm().Get(consts.FormParameterState))
			assert.Equal(t, "grant", grant.GetSession().GetSubject())
		})
	}
}

func TestRefreshGrantKeepsTheOriginalGrant(t *testing.T) {
	const (
		api        = "https://api.example.com"
		other      = "https://other.example.com"
		rs         = "https://rs.example.com"
		rsAccounts = "https://rs.example.com/accounts"
	)

	granted := oauth2.AuthorizationDetails{{Type: internal.AuthorizationDetailsTypePaymentInitiation, Actions: []string{testRARActionInitiate, testRARActionStatus}, Identifier: new(testRARIdentifierEnriched)}}
	full := oauth2.AuthorizationDetails{{Type: internal.AuthorizationDetailsTypePaymentInitiation, Actions: []string{testRARActionInitiate, testRARActionStatus}}}
	narrow := oauth2.AuthorizationDetails{{Type: internal.AuthorizationDetailsTypePaymentInitiation, Actions: []string{testRARActionStatus}}}
	narrowed := oauth2.AuthorizationDetails{{Type: internal.AuthorizationDetailsTypePaymentInitiation, Actions: []string{testRARActionStatus}, Identifier: new(testRARIdentifierEnriched)}}

	scopes := oauth2.Arguments{"foo", "bar", consts.ScopeOfflineAccess}
	audience := oauth2.Arguments{api, other}
	resource := oauth2.Arguments{rs, other}

	testCases := []struct {
		name    string
		disable bool
	}{
		{name: "ShouldKeepTheGrantOnARotatedRefreshToken"},
		{name: "ShouldKeepTheGrantOnAnUnrotatedRefreshToken", disable: true},
	}

	for _, s := range onlineRefreshTokenStores() {
		for _, tc := range testCases {
			t.Run(s.name+"/"+tc.name, func(t *testing.T) {
				store := s.new()
				strategy := &hmacshaStrategy
				now := time.Now().UTC()

				client := newOnlineRefreshTokenClient(true)
				client.Scopes = scopes
				client.Audience = audience
				client.Resource = resource

				original := &oauth2.Request{
					ID:                            "req-id",
					Client:                        client,
					RequestedAt:                   now,
					RequestedScope:                scopes,
					GrantedScope:                  scopes,
					RequestedAudience:             audience,
					GrantedAudience:               audience,
					RequestedResource:             resource,
					GrantedResource:               resource,
					RequestedAuthorizationDetails: full,
					GrantedAuthorizationDetails:   granted,
					Session: &oauth2.DefaultSession{
						Subject:          "peter",
						ExpiresAt:        map[oauth2.TokenType]time.Time{oauth2.RefreshToken: now.Add(time.Hour)},
						RefreshTokenMode: oauth2.RefreshTokenModeOffline,
					},
					Form: url.Values{},
				}

				token, signature, err := strategy.GenerateRefreshToken(t.Context(), nil)
				require.NoError(t, err)

				_, accessSignature, err := strategy.GenerateAccessToken(t.Context(), nil)
				require.NoError(t, err)

				require.NoError(t, store.CreateAccessTokenSession(t.Context(), accessSignature, original))
				require.NoError(t, store.CreateRefreshTokenSession(t.Context(), signature, accessSignature, original))

				handler := &RefreshTokenGrantHandler{
					TokenRevocationStorage: store,
					RefreshTokenStrategy:   strategy,
					AccessTokenStrategy:    strategy,
					Config: &oauth2.Config{
						AccessTokenLifespan:              time.Hour,
						RefreshTokenLifespan:             time.Hour,
						ScopeStrategy:                    oauth2.HierarchicScopeStrategy,
						AudienceStrategy:                 oauth2.DefaultAudienceStrategy,
						ResourceStrategy:                 oauth2.PrefixResourceStrategy,
						DisableRefreshTokenRotation:      tc.disable,
						AuthorizationDetailsTypeHandlers: []oauth2.AuthorizationDetailsTypeHandler{internal.PaymentInitiationTypeHandler{}},
					},
				}

				refresh := func(token string, scopes, audience, resource oauth2.Arguments, details oauth2.AuthorizationDetails) (request *oauth2.AccessRequest, next string) {
					request = oauth2.NewAccessRequest(&oauth2.DefaultSession{})
					request.GrantTypes = oauth2.Arguments{consts.GrantTypeRefreshToken}
					request.Client = client
					request.Form = url.Values{consts.FormParameterRefreshToken: {token}}
					request.SetRequestedScopes(scopes)
					request.SetRequestedAudience(audience)
					request.SetRequestedResource(resource)
					request.SetRequestedAuthorizationDetails(details)

					require.NoError(t, oauth2.ErrorToDebugRFC6749Error(handler.HandleTokenEndpointRequest(t.Context(), request)))

					response := oauth2.NewAccessResponse()
					require.NoError(t, oauth2.ErrorToDebugRFC6749Error(handler.PopulateTokenEndpointResponse(t.Context(), request, response)))

					if tc.disable {
						assert.NotContains(t, response.ToMap(), consts.AccessResponseRefreshToken)

						return request, token
					}

					next, ok := response.ToMap()[consts.AccessResponseRefreshToken].(string)
					require.True(t, ok)

					return request, next
				}

				request, token := refresh(token, oauth2.Arguments{"foo"}, oauth2.Arguments{api}, oauth2.Arguments{rsAccounts}, narrow)

				assert.Equal(t, oauth2.Arguments{"foo"}, request.GetGrantedScopes())
				assert.Equal(t, oauth2.Arguments{api}, request.GetGrantedAudience())
				assert.Equal(t, oauth2.Arguments{rsAccounts}, request.GetGrantedResource())
				assert.Equal(t, narrowed, request.GetGrantedAuthorizationDetails())

				stored, err := store.GetRefreshTokenSession(t.Context(), strategy.RefreshTokenSignature(t.Context(), token), &oauth2.DefaultSession{})
				require.NoError(t, err)

				assert.Equal(t, scopes, stored.GetRequestedScopes())
				assert.Equal(t, scopes, stored.GetGrantedScopes())
				assert.Equal(t, audience, stored.GetRequestedAudience())
				assert.Equal(t, audience, stored.GetGrantedAudience())
				assert.Equal(t, resource, stored.GetRequestedResource())
				assert.Equal(t, resource, stored.GetGrantedResource())
				assert.Equal(t, full, stored.GetRequestedAuthorizationDetails())
				assert.Equal(t, granted, stored.GetGrantedAuthorizationDetails())
				assert.Equal(t, oauth2.RefreshTokenModeOffline, storedRefreshTokenMode(t, stored))

				request, _ = refresh(token, scopes, audience, resource, full)

				assert.Equal(t, scopes, request.GetGrantedScopes())
				assert.Equal(t, audience, request.GetGrantedAudience())
				assert.Equal(t, resource, request.GetGrantedResource())
				assert.Equal(t, granted, request.GetGrantedAuthorizationDetails())
			})
		}
	}
}

type plainAccessRequester struct {
	oauth2.AccessRequester
}
