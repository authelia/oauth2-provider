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

func TestRefreshTokenSubjectExchangeOptIn(t *testing.T) {
	const hint = "Clients are not allowed to perform a token exchange on their own refresh tokens."

	testCases := []struct {
		name      string
		optedIn   bool
		actor     bool
		requested string
		refused   bool
	}{
		{name: "ShouldRejectAnAccessTokenByDefault", requested: consts.TokenTypeRFC8693AccessToken, refused: true},
		{name: "ShouldRejectTheDefaultTokenTypeByDefault", refused: true},
		{name: "ShouldRejectARefreshTokenByDefault", requested: consts.TokenTypeRFC8693RefreshToken, refused: true},
		{name: "ShouldRejectAnIDTokenByDefault", requested: consts.TokenTypeRFC8693IDToken, refused: true},
		{name: "ShouldRejectAJWTByDefault", requested: grantPartnerType, refused: true},
		{name: "ShouldAcceptAJWTAuthorizationGrantByDefault", requested: consts.TokenTypeRFC8693JWT},
		{name: "ShouldAcceptAnAccessTokenWhenOptedIn", optedIn: true, requested: consts.TokenTypeRFC8693AccessToken},
		{name: "ShouldAcceptTheDefaultTokenTypeWhenOptedIn", optedIn: true},
		{name: "ShouldAcceptARefreshTokenWhenOptedIn", optedIn: true, requested: consts.TokenTypeRFC8693RefreshToken},
		{name: "ShouldAcceptAnIDTokenWhenOptedIn", optedIn: true, requested: consts.TokenTypeRFC8693IDToken},
		{name: "ShouldAcceptAJWTWhenOptedIn", optedIn: true, requested: grantPartnerType},
		{name: "ShouldAcceptAJWTAuthorizationGrantWhenOptedIn", optedIn: true, requested: consts.TokenTypeRFC8693JWT},
		{name: "ShouldAcceptAnIDJAGByDefault", requested: consts.TokenTypeRFC8693IDJAG},
		{name: "ShouldAcceptAnIDJAGWhenOptedIn", optedIn: true, requested: consts.TokenTypeRFC8693IDJAG},
		{name: "ShouldAcceptAnActorTokenByDefault", actor: true, requested: consts.TokenTypeRFC8693AccessToken},
	}

	for _, sc := range bindingExchangeStores() {
		for _, tc := range testCases {
			t.Run(sc.name+"/"+tc.name, func(t *testing.T) {
				f := newRefreshSubjectGrantFixture(t, sc.newStore(), false)
				f.client.TokenExchangeOwnRefreshToken = tc.optedIn
				f.config.RFC8693TokenTypes[consts.TokenTypeRFC8693IDToken] = &DefaultTokenType{Name: consts.TokenTypeRFC8693IDToken}
				f.config.RFC8693TokenTypes[consts.TokenTypeRFC8693IDJAG] = &DefaultTokenType{Name: consts.TokenTypeRFC8693IDJAG}
				f.config.RFC8693TokenTypes[grantPartnerType] = &JWTType{Name: grantPartnerType, Issue: &JWTIssueConfig{Issuer: grantIssuer}}
				f.config.RFC8693TokenTypes[consts.TokenTypeRFC8693JWT] = &JWTType{Name: consts.TokenTypeRFC8693JWT, Issue: &JWTIssueConfig{Issuer: grantIssuer, AuthorizationGrant: true}}

				request := f.request(t, f.mint(t), tc.requested)

				if tc.actor {
					form := request.GetRequestForm()

					form.Set(consts.FormParameterActorTokenType, consts.TokenTypeRFC8693RefreshToken)
					form.Set(consts.FormParameterActorToken, form.Get(consts.FormParameterSubjectToken))
					form.Set(consts.FormParameterSubjectTokenType, consts.TokenTypeRFC8693AccessToken)
					form.Set(consts.FormParameterSubjectToken, "opaque-subject-token")
				}

				session := newSpecSession("other")
				request.Session = session

				err := f.refresh.HandleTokenEndpointRequest(t.Context(), request)

				if !tc.refused {
					require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

					if tc.actor {
						assert.Equal(t, "peter", session.GetActorToken()[consts.ClaimSubject])
						assert.Equal(t, f.client.GetID(), session.GetActorToken()[consts.ClaimClientIdentifier])
						assert.Equal(t, "other", session.GetSubject())
						assert.Nil(t, session.GetSubjectToken())
						assert.Nil(t, session.GetSubjectRequester())

						return
					}

					assert.Equal(t, "peter", session.GetSubject())
					assert.Equal(t, "peter", session.GetSubjectToken()[consts.ClaimSubject])
					assert.Equal(t, f.client.GetID(), session.GetSubjectToken()[consts.ClaimClientIdentifier])
					assert.Nil(t, session.GetActorToken())

					require.NotNil(t, session.GetSubjectRequester())
					assert.Equal(t, f.grant.GetID(), session.GetSubjectRequester().GetID())

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
}

func TestRefreshTokenSubjectExchangeTarget(t *testing.T) {
	const (
		audience = "https://api.example.com"
		resource = "https://resource.example.com"
		other    = "https://other.example.com"
	)

	testCases := []struct {
		name      string
		requested string
		audience  []string
		resource  []string
		err       error
	}{
		{name: "ShouldAcceptNoTarget"},
		{name: "ShouldAcceptTheGrantedAudience", audience: []string{audience}},
		{name: "ShouldAcceptTheGrantedResource", resource: []string{resource}},
		{name: "ShouldRejectAnotherAudience", audience: []string{other}, err: oauth2.ErrInvalidTarget},
		{name: "ShouldRejectAnotherResource", resource: []string{other}, err: oauth2.ErrInvalidTarget},
		{name: "ShouldRejectTheGrantedResourceAsAnAudience", audience: []string{resource}, err: oauth2.ErrInvalidTarget},
		{name: "ShouldRejectOneAudienceOutsideTheGrant", audience: []string{audience, other}, err: oauth2.ErrInvalidTarget},
		{name: "ShouldRejectAnotherAudienceForARefreshToken", requested: consts.TokenTypeRFC8693RefreshToken, audience: []string{other}, err: oauth2.ErrInvalidTarget},
		{name: "ShouldRejectAnotherAudienceForAnIDToken", requested: consts.TokenTypeRFC8693IDToken, audience: []string{other}, err: oauth2.ErrInvalidTarget},
		{name: "ShouldRejectAnotherAudienceForAJWT", requested: grantPartnerType, audience: []string{other}, err: oauth2.ErrInvalidTarget},
		{name: "ShouldAcceptAnotherAudienceForAJWTAuthorizationGrant", requested: consts.TokenTypeRFC8693JWT, audience: []string{other}},
	}

	for _, sc := range bindingExchangeStores() {
		for _, tc := range testCases {
			t.Run(sc.name+"/"+tc.name, func(t *testing.T) {
				f := newRefreshSubjectGrantFixture(t, sc.newStore(), false)
				f.config.RFC8693TokenTypes[consts.TokenTypeRFC8693IDToken] = &DefaultTokenType{Name: consts.TokenTypeRFC8693IDToken}
				f.config.RFC8693TokenTypes[grantPartnerType] = &JWTType{Name: grantPartnerType, Issue: &JWTIssueConfig{Issuer: grantIssuer}}
				f.config.RFC8693TokenTypes[consts.TokenTypeRFC8693JWT] = &JWTType{Name: consts.TokenTypeRFC8693JWT, Issue: &JWTIssueConfig{Issuer: grantIssuer, AuthorizationGrant: true}}

				f.grant.GrantAudience(audience)
				f.grant.GrantResource(resource)

				request := f.request(t, f.mint(t), tc.requested)
				request.RequestedAudience = tc.audience
				request.RequestedResource = tc.resource

				err := f.refresh.HandleTokenEndpointRequest(t.Context(), request)

				if tc.err != nil {
					// See: https://www.rfc-editor.org/rfc/rfc8707#section-2.2
					assert.ErrorIs(t, err, tc.err)

					return
				}

				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
			})
		}
	}
}

func TestRefreshTokenSubjectExchangeIsLinkedToTheGrant(t *testing.T) {
	testCases := []struct {
		name      string
		requested string
		issue     bool
		rotate    bool
	}{
		{name: "ShouldLinkAnAccessToken", requested: consts.TokenTypeRFC8693AccessToken},
		{name: "ShouldLinkAnAccessTokenIssuedWithARefreshToken", requested: consts.TokenTypeRFC8693AccessToken, issue: true, rotate: true},
		{name: "ShouldLinkAnAccessTokenIssuedWithARefreshTokenWithoutRotation", requested: consts.TokenTypeRFC8693AccessToken, issue: true},
		{name: "ShouldLinkARefreshToken", requested: consts.TokenTypeRFC8693RefreshToken, issue: true, rotate: true},
		{name: "ShouldLinkARefreshTokenWithoutRotation", requested: consts.TokenTypeRFC8693RefreshToken, issue: true},
	}

	for _, sc := range bindingExchangeStores() {
		for _, tc := range testCases {
			t.Run(sc.name+"/"+tc.name, func(t *testing.T) {
				f := newRefreshSubjectGrantFixture(t, sc.newStore(), tc.issue)
				f.client.TokenExchangeRefreshTokenRotationOverride = true
				f.client.TokenExchangeRefreshTokenRotation = tc.rotate

				f.grant.GrantAudience("https://api.example.com")

				subject := f.mint(t)

				request := f.request(t, subject, tc.requested)
				request.RequestedScope = oauth2.Arguments{"read"}
				request.GrantedScope = oauth2.Arguments{"read"}

				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(f.refresh.HandleTokenEndpointRequest(t.Context(), request)))

				response := oauth2.NewAccessResponse()

				var handler oauth2.TokenEndpointHandler = f.access
				if tc.requested == consts.TokenTypeRFC8693RefreshToken {
					handler = f.refresh
				}

				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(handler.PopulateTokenEndpointResponse(t.Context(), request, response)))

				assert.Equal(t, f.grant.GetID(), request.GetID())

				var access string

				refresh := response.GetAccessToken()

				if tc.requested == consts.TokenTypeRFC8693AccessToken {
					access = response.GetAccessToken()
					refresh, _ = response.GetExtra(consts.FormParameterRefreshToken).(string)

					issued, err := f.store.GetAccessTokenSession(t.Context(), f.strategy.AccessTokenSignature(t.Context(), access), NewDefaultSession())
					require.NoError(t, err)

					assert.Equal(t, f.grant.GetID(), issued.GetID())
					assert.Equal(t, oauth2.Arguments{"read"}, issued.GetGrantedScopes())
					assert.Equal(t, f.grant.GetGrantedAudience(), issued.GetGrantedAudience())
				}

				if tc.issue {
					require.NotEmpty(t, refresh)

					// See: https://www.rfc-editor.org/rfc/rfc8707#section-2.2
					issued, err := f.store.GetRefreshTokenSession(t.Context(), f.strategy.RefreshTokenSignature(t.Context(), refresh), NewDefaultSession())
					require.NoError(t, err)

					assert.Equal(t, f.grant.GetID(), issued.GetID())
					assert.Equal(t, f.grant.GetGrantedScopes(), issued.GetGrantedScopes())
					assert.Equal(t, f.grant.GetGrantedAudience(), issued.GetGrantedAudience())
				} else {
					assert.Empty(t, refresh)
				}

				_, err := f.store.GetRefreshTokenSession(t.Context(), f.strategy.RefreshTokenSignature(t.Context(), subject), NewDefaultSession())

				if tc.rotate {
					assert.ErrorIs(t, err, oauth2.ErrInactiveToken)
				} else {
					assert.NoError(t, err)
				}

				// See: https://datatracker.ietf.org/doc/html/rfc7009#section-2.1
				require.NoError(t, f.store.RevokeRefreshToken(t.Context(), f.grant.GetID()))
				require.NoError(t, f.store.RevokeAccessToken(t.Context(), f.grant.GetID()))

				if access != "" {
					_, err = f.store.GetAccessTokenSession(t.Context(), f.strategy.AccessTokenSignature(t.Context(), access), NewDefaultSession())
					assert.ErrorIs(t, err, oauth2.ErrNotFound)
				}

				for _, token := range []string{subject, refresh} {
					if token == "" {
						continue
					}

					_, err = f.store.GetRefreshTokenSession(t.Context(), f.strategy.RefreshTokenSignature(t.Context(), token), NewDefaultSession())
					assert.ErrorIs(t, err, oauth2.ErrInactiveToken)
				}
			})
		}
	}
}

func TestRefreshTokenSubjectExchangeRequiresTheGrant(t *testing.T) {
	testCases := []struct {
		name      string
		requested string
	}{
		{name: "ShouldRefuseAnAccessToken", requested: consts.TokenTypeRFC8693AccessToken},
		{name: "ShouldRefuseARefreshToken", requested: consts.TokenTypeRFC8693RefreshToken},
	}

	for _, sc := range bindingExchangeStores() {
		for _, tc := range testCases {
			t.Run(sc.name+"/"+tc.name, func(t *testing.T) {
				f := newRefreshSubjectGrantFixture(t, sc.newStore(), true)

				request := f.request(t, f.mint(t), tc.requested)

				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(f.refresh.HandleTokenEndpointRequest(t.Context(), request)))

				request.GetSession().(*DefaultSession).SetSubjectRequester(nil)

				var handler oauth2.TokenEndpointHandler = f.access
				if tc.requested == consts.TokenTypeRFC8693RefreshToken {
					handler = f.refresh
				}

				response := oauth2.NewAccessResponse()

				assert.ErrorIs(t, handler.PopulateTokenEndpointResponse(t.Context(), request, response), oauth2.ErrServerError)
				assert.Empty(t, response.GetAccessToken())
			})
		}
	}
}

type refreshSubjectGrantFixture struct {
	config   *oauth2.Config
	store    rfc8693ExchangeStore
	strategy hoauth2.CoreStrategy
	client   *oauth2.DefaultRegisteredClient
	grant    *oauth2.AccessRequest
	access   *AccessTokenTypeHandler
	refresh  *RefreshTokenTypeHandler
}

func newRefreshSubjectGrantFixture(t *testing.T, store rfc8693ExchangeStore, issue bool) *refreshSubjectGrantFixture {
	t.Helper()

	config, strategy := newBindingExchangeConfig()
	config.RefreshTokenScopes = []string{}
	config.RFC8693TokenTypes[consts.TokenTypeRFC8693RefreshToken] = &DefaultTokenType{Name: consts.TokenTypeRFC8693RefreshToken}

	client := &oauth2.DefaultRegisteredClient{
		DefaultClient: &oauth2.DefaultClient{
			ID:         "requester",
			GrantTypes: []string{consts.GrantTypeOAuthTokenExchange, consts.GrantTypeRefreshToken},
			Audience:   []string{"https://api.example.com"},
			Resource:   []string{"https://resource.example.com"},
		},
		TokenExchangeRefreshToken: issue, TokenExchangeOwnRefreshToken: true,
	}

	access := newLifetimeAccessTokenHandler(config, strategy, store)
	access.RefreshTokenScopes = []string{}

	refresh := newLifetimeRefreshTokenHandler(config, strategy, store)
	refresh.RefreshTokenScopes = []string{}

	return &refreshSubjectGrantFixture{
		config:   config,
		store:    store,
		strategy: strategy,
		client:   client,
		grant:    newUnaddressedRequest(client, "peter", []string{consts.ScopeOpenID, "read", "write"}, oauth2.RefreshToken),
		access:   access,
		refresh:  refresh,
	}
}

func (f *refreshSubjectGrantFixture) mint(t *testing.T) string {
	t.Helper()

	token, signature, err := f.strategy.GenerateRefreshToken(t.Context(), f.grant)
	require.NoError(t, err)
	require.NoError(t, f.store.CreateRefreshTokenSession(t.Context(), signature, "", f.grant.Sanitize(nil)))

	return token
}

func (f *refreshSubjectGrantFixture) request(t *testing.T, subject, requested string) *oauth2.AccessRequest {
	t.Helper()

	form := url.Values{
		consts.FormParameterSubjectTokenType: {consts.TokenTypeRFC8693RefreshToken},
		consts.FormParameterSubjectToken:     {subject},
	}

	if requested != "" {
		form.Set(consts.FormParameterRequestedTokenType, requested)
	}

	return newExchangeRequest(t, f.client, newSpecSession("peter"), form)
}
