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
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/handler/openid"
	. "authelia.com/provider/oauth2/handler/rfc8693"
	"authelia.com/provider/oauth2/internal"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestIDJAGRequestGrantHandler(t *testing.T) {
	testCases := []struct {
		name             string
		subjectTokenType string
		audience         string
		scope            string
		err              error
	}{
		{name: "ShouldSkipClientAudienceAndScopeChecks", subjectTokenType: consts.TokenTypeRFC8693IDToken, audience: idjagAudience, scope: idjagScope},
		{name: "ShouldAcceptARefreshToken", subjectTokenType: consts.TokenTypeRFC8693RefreshToken, audience: idjagAudience},
		{name: "ShouldRejectAnAccessTokenSubject", subjectTokenType: consts.TokenTypeRFC8693AccessToken, err: oauth2.ErrInvalidRequest},
		{name: "ShouldRejectAnIDJAG", subjectTokenType: consts.TokenTypeRFC8693IDJAG, err: oauth2.ErrInvalidRequest},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := newIDJAGSpecConfig(t)
			store := storage.NewExampleStore()

			form := url.Values{
				consts.FormParameterSubjectToken:       {idjagSubjectToken},
				consts.FormParameterSubjectTokenType:   {tc.subjectTokenType},
				consts.FormParameterRequestedTokenType: {consts.TokenTypeRFC8693IDJAG},
			}

			request := newExchangeRequest(t, store.Clients[idjagClientID], newSpecSession(idjagSubject), form)
			if tc.audience != "" {
				request.RequestedAudience = oauth2.Arguments{tc.audience}
			}

			if tc.scope != "" {
				request.RequestedScope = oauth2.Arguments{tc.scope}
			}

			err := runGrantHandler(t, cfg, request)

			if tc.err != nil {
				require.ErrorIs(t, err, tc.err)

				return
			}

			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
			assert.Empty(t, request.GetGrantedAudience())
			assert.Empty(t, request.GetGrantedScopes())
		})
	}
}

func TestIDJAGRequestIDTokenSubjectAllowsScope(t *testing.T) {
	store := storage.NewExampleStore()
	cfg := newIDJAGSpecConfig(t)
	client := store.Clients[idjagClientID]

	jwtStrategy := &jwt.DefaultStrategy{Config: cfg, Issuer: jwt.NewDefaultIssuerRS256Unverified(key)}

	handler := &IDTokenTypeHandler{
		Config:             cfg,
		Strategy:           jwtStrategy,
		IssueStrategy:      &openid.DefaultStrategy{Strategy: jwtStrategy, Config: cfg},
		ValidationStrategy: &openid.DefaultIDTokenValidationStrategy{Strategy: jwtStrategy},
		Storage:            store,
	}

	idToken := createJWT(t.Context(), client, jwtStrategy, jwt.MapClaims{
		consts.ClaimSubject:        idjagSubject,
		consts.ClaimAudience:       []string{client.GetID()},
		consts.ClaimExpirationTime: time.Now().Add(10 * time.Minute).Unix(),
		consts.ClaimIssuedAt:       time.Now().Unix(),
	})

	request := newExchangeRequest(t, client, newSpecSession(idjagSubject), url.Values{
		consts.FormParameterSubjectToken:       {idToken},
		consts.FormParameterSubjectTokenType:   {consts.TokenTypeRFC8693IDToken},
		consts.FormParameterRequestedTokenType: {consts.TokenTypeRFC8693IDJAG},
	})
	request.RequestedScope = oauth2.Arguments{idjagScope}
	request.RequestedAudience = oauth2.Arguments{idjagOtherAudience}

	require.NoError(t, oauth2.ErrorToDebugRFC6749Error(handler.HandleTokenEndpointRequest(t.Context(), request)))
}

func TestIDJAGRequestRefreshTokenSubject(t *testing.T) {
	testCases := []struct {
		name               string
		owner              string
		grantedScopes      []string
		grantedAudience    []string
		grantedResources   []string
		requestedScopes    []string
		requestedAudience  string
		requestedResources []string
		narrow             func(client *oauth2.DefaultClient)
		err                error
	}{
		// Section 4.3.3: the refresh token is bound to the authenticated client.
		{name: "ShouldAcceptTheRequestersRefreshToken", owner: idjagClientID, grantedScopes: []string{idjagScope}, grantedAudience: []string{idjagAudience}, requestedScopes: []string{idjagScope}, requestedAudience: idjagAudience},
		{name: "ShouldRejectAnotherClientsRefreshToken", owner: idjagOtherOwner, grantedScopes: []string{idjagScope}, grantedAudience: []string{idjagAudience}, requestedScopes: []string{idjagScope}, requestedAudience: idjagAudience, err: oauth2.ErrInvalidGrant},
		// Section 4.3.3: the requested scopes remain within the authorization context of the refresh token.
		{name: "ShouldAcceptAScopeSubset", owner: idjagClientID, grantedScopes: []string{idjagScope, idjagOtherScope}, grantedAudience: []string{idjagAudience}, requestedScopes: []string{idjagScope}, requestedAudience: idjagAudience},
		{name: "ShouldAcceptNoScope", owner: idjagClientID, grantedScopes: []string{idjagScope}, grantedAudience: []string{idjagAudience}, requestedAudience: idjagAudience},
		{name: "ShouldRejectAScopeNotGranted", owner: idjagClientID, grantedScopes: []string{idjagOtherScope}, grantedAudience: []string{idjagAudience}, requestedScopes: []string{idjagScope}, requestedAudience: idjagAudience, err: oauth2.ErrInvalidScope},
		{name: "ShouldRejectAScopeOutsideAPartialGrant", owner: idjagClientID, grantedScopes: []string{idjagScope}, grantedAudience: []string{idjagAudience}, requestedScopes: []string{idjagScope, idjagOtherScope}, requestedAudience: idjagAudience, err: oauth2.ErrInvalidScope},
		// Section 4.3.3: the requested audience remains within the authorization context of the refresh token.
		{name: "ShouldRejectAnAudienceNotGranted", owner: idjagClientID, grantedScopes: []string{idjagScope}, grantedAudience: []string{idjagOtherAudience}, requestedScopes: []string{idjagScope}, requestedAudience: idjagAudience, err: oauth2.ErrInvalidTarget},
		{name: "ShouldRejectAnAudienceWhenNoneWasGranted", owner: idjagClientID, grantedScopes: []string{idjagScope}, requestedScopes: []string{idjagScope}, requestedAudience: idjagAudience, err: oauth2.ErrInvalidTarget},
		// Section 4.3.3: the requested resources remain within the authorization context of the refresh token.
		{name: "ShouldAcceptAGrantedResource", owner: idjagClientID, grantedScopes: []string{idjagScope}, grantedAudience: []string{idjagAudience}, grantedResources: []string{idjagResource, idjagOtherResource}, requestedScopes: []string{idjagScope}, requestedAudience: idjagAudience, requestedResources: []string{idjagResource}},
		{name: "ShouldRejectAResourceNotGranted", owner: idjagClientID, grantedScopes: []string{idjagScope}, grantedAudience: []string{idjagAudience}, grantedResources: []string{idjagOtherResource}, requestedScopes: []string{idjagScope}, requestedAudience: idjagAudience, requestedResources: []string{idjagResource}, err: oauth2.ErrInvalidTarget},
		{name: "ShouldRejectAResourceWhenNoneWasGranted", owner: idjagClientID, grantedScopes: []string{idjagScope}, grantedAudience: []string{idjagAudience}, requestedScopes: []string{idjagScope}, requestedAudience: idjagAudience, requestedResources: []string{idjagResource}, err: oauth2.ErrInvalidTarget},
		// Section 4.3.3: the refresh token is validated as for a refresh_token grant, against the current registration.
		{name: "ShouldRejectAScopeRemovedFromTheClient", owner: idjagClientID, grantedScopes: []string{idjagScope}, grantedAudience: []string{idjagAudience}, requestedScopes: []string{idjagScope}, requestedAudience: idjagAudience, narrow: func(client *oauth2.DefaultClient) { client.Scopes = []string{idjagOtherScope} }, err: oauth2.ErrInvalidScope},
		{name: "ShouldRejectAnAudienceRemovedFromTheClient", owner: idjagClientID, grantedScopes: []string{idjagScope}, grantedAudience: []string{idjagAudience}, requestedScopes: []string{idjagScope}, requestedAudience: idjagAudience, narrow: func(client *oauth2.DefaultClient) { client.Audience = []string{idjagResource} }, err: oauth2.ErrInvalidTarget},
		{name: "ShouldRejectAResourceRemovedFromTheClient", owner: idjagClientID, grantedScopes: []string{idjagScope}, grantedAudience: []string{idjagAudience}, grantedResources: []string{idjagResource}, requestedScopes: []string{idjagScope}, requestedAudience: idjagAudience, requestedResources: []string{idjagResource}, narrow: func(client *oauth2.DefaultClient) { client.Audience = []string{idjagAudience} }, err: oauth2.ErrInvalidTarget},
		{name: "ShouldRejectWhenTheRefreshTokenGrantIsRemovedFromTheClient", owner: idjagClientID, grantedScopes: []string{idjagScope}, grantedAudience: []string{idjagAudience}, requestedScopes: []string{idjagScope}, requestedAudience: idjagAudience, narrow: func(client *oauth2.DefaultClient) { client.GrantTypes = []string{consts.GrantTypeOAuthTokenExchange} }, err: oauth2.ErrInvalidRequest},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, store, strategy := newExchangeFixture(t)
			cfg.RFC8693TokenTypes[consts.TokenTypeRFC8693IDJAG] = &DefaultTokenType{Name: consts.TokenTypeRFC8693IDJAG}

			handler := newRefreshTokenTypeHandler(cfg, store, strategy)

			registered := newIDJAGRegisteredClient()

			var owner oauth2.Client = registered
			if tc.owner != idjagClientID {
				owner = store.Clients[tc.owner]
			}

			refreshToken := createIDJAGRefreshToken(t, strategy, store, owner, tc.grantedScopes, tc.grantedAudience, tc.grantedResources)

			current := newIDJAGRegisteredClient()
			if tc.narrow != nil {
				tc.narrow(current)
			}

			request := newExchangeRequest(t, current, newSpecSession(idjagSubject), url.Values{
				consts.FormParameterSubjectToken:       {refreshToken},
				consts.FormParameterSubjectTokenType:   {consts.TokenTypeRFC8693RefreshToken},
				consts.FormParameterRequestedTokenType: {consts.TokenTypeRFC8693IDJAG},
			})
			request.RequestedScope = tc.requestedScopes
			request.RequestedAudience = oauth2.Arguments{tc.requestedAudience}
			request.RequestedResource = tc.requestedResources

			err := handler.HandleTokenEndpointRequest(t.Context(), request)

			if tc.err != nil {
				require.ErrorIs(t, err, tc.err)

				return
			}

			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
			assert.Equal(t, idjagSubject, request.GetSession().GetSubject())
		})
	}
}

func TestIDJAGRequestRefreshTokenSubjectAuthorizationDetails(t *testing.T) {
	initiate := oauth2.AuthorizationDetail{Type: internal.AuthorizationDetailsTypePaymentInitiation, Actions: []string{idjagActionInitiate}}
	status := oauth2.AuthorizationDetail{Type: internal.AuthorizationDetailsTypePaymentInitiation, Actions: []string{idjagActionStatus}}
	both := oauth2.AuthorizationDetail{Type: internal.AuthorizationDetailsTypePaymentInitiation, Actions: []string{idjagActionInitiate, idjagActionStatus}}

	testCases := []struct {
		name      string
		granted   oauth2.AuthorizationDetails
		requested oauth2.AuthorizationDetails
		err       error
	}{
		// Section 4.3.3: the requested details remain within the authorization context of the refresh token.
		{name: "ShouldAcceptContainedDetails", granted: oauth2.AuthorizationDetails{both}, requested: oauth2.AuthorizationDetails{status}},
		{name: "ShouldAcceptNoDetails", granted: oauth2.AuthorizationDetails{both}},
		{name: "ShouldAcceptNoDetailsWhenNoneWereGranted"},
		{name: "ShouldRejectDetailsNotGranted", granted: oauth2.AuthorizationDetails{initiate}, requested: oauth2.AuthorizationDetails{status}, err: oauth2.ErrInvalidAuthorizationDetails},
		{name: "ShouldRejectDetailsWhenNoneWereGranted", requested: oauth2.AuthorizationDetails{initiate}, err: oauth2.ErrInvalidAuthorizationDetails},
		{name: "ShouldRejectTwoDetailsContainedByOneGrantedDetail", granted: oauth2.AuthorizationDetails{both}, requested: oauth2.AuthorizationDetails{initiate, status}, err: oauth2.ErrInvalidAuthorizationDetails},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, store, strategy := newExchangeFixture(t)
			cfg.RFC8693TokenTypes[consts.TokenTypeRFC8693IDJAG] = &DefaultTokenType{Name: consts.TokenTypeRFC8693IDJAG}
			cfg.AuthorizationDetailsTypeHandlers = []oauth2.AuthorizationDetailsTypeHandler{internal.PaymentInitiationTypeHandler{}}

			handler := newRefreshTokenTypeHandler(cfg, store, strategy)

			client := newIDJAGRegisteredClient()

			original := newIssuedRequest(client, idjagSubject, []string{idjagScope}, oauth2.RefreshToken)
			original.GrantedAudience = []string{idjagAudience}
			original.SetGrantedAuthorizationDetails(tc.granted)

			refreshToken, signature, err := strategy.GenerateRefreshToken(t.Context(), original)
			require.NoError(t, err)
			require.NoError(t, store.CreateRefreshTokenSession(t.Context(), signature, "", original.Sanitize(nil)))

			request := newExchangeRequest(t, client, newSpecSession(idjagSubject), url.Values{
				consts.FormParameterSubjectToken:       {refreshToken},
				consts.FormParameterSubjectTokenType:   {consts.TokenTypeRFC8693RefreshToken},
				consts.FormParameterRequestedTokenType: {consts.TokenTypeRFC8693IDJAG},
			})
			request.RequestedScope = []string{idjagScope}
			request.RequestedAudience = oauth2.Arguments{idjagAudience}
			request.SetRequestedAuthorizationDetails(tc.requested)

			err = handler.HandleTokenEndpointRequest(t.Context(), request)

			if tc.err != nil {
				require.ErrorIs(t, err, tc.err)

				return
			}

			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
		})
	}
}

func TestIDJAGRequestRefreshTokenActor(t *testing.T) {
	testCases := []struct {
		name            string
		grantedScopes   []string
		grantedAudience []string
	}{
		{name: "ShouldAcceptAnActorWithANarrowerGrant", grantedScopes: []string{idjagOtherScope}, grantedAudience: []string{idjagOtherAudience}},
		{name: "ShouldAcceptAnActorWithoutAudience", grantedScopes: []string{consts.ScopeOpenID}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, store, strategy := newExchangeFixture(t)
			cfg.RFC8693TokenTypes[consts.TokenTypeRFC8693IDJAG] = &DefaultTokenType{Name: consts.TokenTypeRFC8693IDJAG}

			handler := newRefreshTokenTypeHandler(cfg, store, strategy)
			client := newIDJAGRegisteredClient()

			request := newExchangeRequest(t, client, newSpecSession(idjagSubject), url.Values{
				consts.FormParameterSubjectToken:       {createIDJAGRefreshToken(t, strategy, store, client, []string{idjagScope}, []string{idjagAudience}, []string{idjagResource})},
				consts.FormParameterSubjectTokenType:   {consts.TokenTypeRFC8693RefreshToken},
				consts.FormParameterActorToken:         {createIDJAGRefreshToken(t, strategy, store, client, tc.grantedScopes, tc.grantedAudience, nil)},
				consts.FormParameterActorTokenType:     {consts.TokenTypeRFC8693RefreshToken},
				consts.FormParameterRequestedTokenType: {consts.TokenTypeRFC8693IDJAG},
			})
			request.RequestedScope = oauth2.Arguments{idjagScope}
			request.RequestedAudience = oauth2.Arguments{idjagAudience}
			request.RequestedResource = oauth2.Arguments{idjagResource}

			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(handler.HandleTokenEndpointRequest(t.Context(), request)))
		})
	}
}

func TestIDJAGRequestRefreshTokenAuthenticationContext(t *testing.T) {
	authTime := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)

	login := &jwt.IDTokenClaims{
		Subject:                             idjagSubject,
		AuthTime:                            jwt.NewNumericDate(authTime),
		AuthenticationContextClassReference: idjagACR,
		AuthenticationMethodsReferences:     []string{idjagAMR},
	}

	testCases := []struct {
		name      string
		owner     string
		requested string
		login     *jwt.IDTokenClaims
		expected  map[string]any
	}{
		// Section 4.3.3: the claims are assembled as for an Identity Assertion issued at a token request.
		{name: "ShouldCarryTheAuthenticationContextIntoAnIDJAG", owner: idjagClientID, requested: consts.TokenTypeRFC8693IDJAG, login: login, expected: map[string]any{consts.ClaimAuthenticationTime: authTime.Unix(), consts.ClaimAuthenticationContextClassReference: idjagACR, consts.ClaimAuthenticationMethodsReference: []string{idjagAMR}}},
		{name: "ShouldCarryOnlyThePresentAuthenticationContext", owner: idjagClientID, requested: consts.TokenTypeRFC8693IDJAG, login: &jwt.IDTokenClaims{Subject: idjagSubject, AuthenticationContextClassReference: idjagACR}, expected: map[string]any{consts.ClaimAuthenticationContextClassReference: idjagACR}},
		{name: "ShouldOmitAnAuthenticationContextTheLoginLacks", owner: idjagClientID, requested: consts.TokenTypeRFC8693IDJAG, login: &jwt.IDTokenClaims{Subject: idjagSubject}},
		{name: "ShouldOmitTheAuthenticationContextWithoutIDTokenClaims", owner: idjagClientID, requested: consts.TokenTypeRFC8693IDJAG},
		{name: "ShouldNotCarryTheAuthenticationContextIntoAnAccessToken", owner: idjagOtherOwner, requested: consts.TokenTypeRFC8693AccessToken, login: login},
		{name: "ShouldNotCarryTheAuthenticationContextIntoARefreshToken", owner: idjagOtherOwner, requested: consts.TokenTypeRFC8693RefreshToken, login: login},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, store, strategy := newExchangeFixture(t)
			cfg.RFC8693TokenTypes[consts.TokenTypeRFC8693IDJAG] = &DefaultTokenType{Name: consts.TokenTypeRFC8693IDJAG}

			handler := newRefreshTokenTypeHandler(cfg, store, strategy)

			var owner oauth2.Client = newIDJAGRegisteredClient()
			if tc.owner != idjagClientID {
				owner = store.Clients[tc.owner]
			}

			issued := newIssuedRequest(owner, idjagSubject, []string{idjagScope}, oauth2.RefreshToken)
			issued.GrantedAudience = []string{idjagAudience}

			if tc.login != nil {
				issued.Session = &openid.DefaultSession{
					Claims:    tc.login,
					Headers:   &jwt.Headers{},
					Subject:   idjagSubject,
					Username:  idjagSubject,
					ExpiresAt: issued.Session.(*oauth2.DefaultSession).ExpiresAt,
				}
			}

			token, signature, err := strategy.GenerateRefreshToken(t.Context(), issued)
			require.NoError(t, err)
			require.NoError(t, store.CreateRefreshTokenSession(t.Context(), signature, "", issued.Sanitize(nil)))

			session := newSpecSession(idjagSubject)

			request := newExchangeRequest(t, newIDJAGRegisteredClient(), session, url.Values{
				consts.FormParameterSubjectToken:       {token},
				consts.FormParameterSubjectTokenType:   {consts.TokenTypeRFC8693RefreshToken},
				consts.FormParameterRequestedTokenType: {tc.requested},
			})
			request.RequestedAudience = oauth2.Arguments{idjagAudience}

			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(handler.HandleTokenEndpointRequest(t.Context(), request)))

			subject := session.GetSubjectToken()
			require.NotNil(t, subject)

			for _, claim := range []string{consts.ClaimAuthenticationTime, consts.ClaimAuthenticationContextClassReference, consts.ClaimAuthenticationMethodsReference} {
				if expected, ok := tc.expected[claim]; ok {
					assert.Equal(t, expected, subject[claim], claim)
				} else {
					assert.NotContains(t, subject, claim)
				}
			}
		})
	}
}

func TestIDJAGRequestOtherExchangesKeepTheRefreshTokenAudience(t *testing.T) {
	testCases := []struct {
		name      string
		requested string
	}{
		{name: "ShouldAcceptAnAudienceOutsideTheGrantForAnAccessToken", requested: consts.TokenTypeRFC8693AccessToken},
		{name: "ShouldAcceptAnAudienceOutsideTheGrantForARefreshToken", requested: consts.TokenTypeRFC8693RefreshToken},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, store, strategy := newExchangeFixture(t)
			cfg.RFC8693TokenTypes[consts.TokenTypeRFC8693IDJAG] = &DefaultTokenType{Name: consts.TokenTypeRFC8693IDJAG}

			handler := newRefreshTokenTypeHandler(cfg, store, strategy)

			request := newExchangeRequest(t, store.Clients[idjagClientID], newSpecSession(idjagSubject), url.Values{
				consts.FormParameterSubjectToken:       {createIDJAGRefreshToken(t, strategy, store, store.Clients[idjagOtherOwner], []string{idjagScope}, nil, nil)},
				consts.FormParameterSubjectTokenType:   {consts.TokenTypeRFC8693RefreshToken},
				consts.FormParameterRequestedTokenType: {tc.requested},
			})
			request.RequestedAudience = oauth2.Arguments{idjagAudience}
			request.RequestedResource = oauth2.Arguments{idjagResource}

			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(handler.HandleTokenEndpointRequest(t.Context(), request)))
		})
	}
}

func TestIDJAGRequestOtherRequestedTypesUnchanged(t *testing.T) {
	cfg, store, strategy := newExchangeFixture(t)
	handler := newRefreshTokenTypeHandler(cfg, store, strategy)

	client := store.Clients[idjagClientID]
	refreshToken := createExchangeRefreshToken(t, strategy, store, client, idjagSubject, "openid")

	request := newExchangeRequest(t, client, newSpecSession(idjagSubject), url.Values{
		consts.FormParameterSubjectToken:       {refreshToken},
		consts.FormParameterSubjectTokenType:   {consts.TokenTypeRFC8693RefreshToken},
		consts.FormParameterRequestedTokenType: {consts.TokenTypeRFC8693AccessToken},
	})

	require.ErrorIs(t, handler.HandleTokenEndpointRequest(t.Context(), request), oauth2.ErrInvalidGrant)
}

func TestIDJAGCustomJWTSubjectRejected(t *testing.T) {
	store := storage.NewExampleStore()
	cfg := newIDJAGSpecConfig(t)

	jwtStrategy := &jwt.DefaultStrategy{Config: cfg, Issuer: jwt.NewDefaultIssuerRS256Unverified(key)}

	handler := &CustomJWTTypeHandler{Config: cfg, Strategy: jwtStrategy, Storage: store}

	token, _, err := jwtStrategy.Encode(t.Context(), jwt.MapClaims{
		consts.ClaimSubject:        idjagSubject,
		consts.ClaimIssuer:         idjagIssuer,
		consts.ClaimExpirationTime: time.Now().Add(time.Minute).Unix(),
		consts.ClaimIssuedAt:       time.Now().Unix(),
	}, jwt.WithHeaders(&jwt.Headers{Extra: map[string]any{jwt.JSONWebTokenHeaderType: consts.JSONWebTokenTypeIDJAG}}))
	require.NoError(t, err)

	// Section 9.3: an ID-JAG is never an exchange input.
	request := newExchangeRequest(t, store.Clients[idjagClientID], newSpecSession(idjagSubject), url.Values{
		consts.FormParameterSubjectToken:       {token},
		consts.FormParameterSubjectTokenType:   {idjagSubjectType},
		consts.FormParameterRequestedTokenType: {consts.TokenTypeRFC8693AccessToken},
	})

	require.ErrorIs(t, handler.HandleTokenEndpointRequest(t.Context(), request), oauth2.ErrInvalidRequest)
}

func TestIDJAGCustomJWTNeverIssuesIDJAG(t *testing.T) {
	store := storage.NewExampleStore()
	cfg := newIDJAGSpecConfig(t)
	cfg.RFC8693TokenTypes[consts.TokenTypeRFC8693IDJAG] = &JWTType{Name: consts.TokenTypeRFC8693IDJAG, Issuer: idjagIssuer}

	jwtStrategy := &jwt.DefaultStrategy{Config: cfg, Issuer: jwt.NewDefaultIssuerRS256Unverified(key)}
	handler := &CustomJWTTypeHandler{Config: cfg, Strategy: jwtStrategy, Storage: store}

	session := newValidatedSpecSession(idjagSubject)
	request := newExchangeRequest(t, store.Clients[idjagClientID], session, url.Values{
		consts.FormParameterSubjectToken:       {idjagSubjectToken},
		consts.FormParameterSubjectTokenType:   {consts.TokenTypeRFC8693AccessToken},
		consts.FormParameterRequestedTokenType: {consts.TokenTypeRFC8693IDJAG},
	})

	response := oauth2.NewAccessResponse()

	require.NoError(t, handler.PopulateTokenEndpointResponse(t.Context(), request, response))
	assert.Empty(t, response.GetAccessToken())
}

func TestIDJAGRequestCustomJWTSubject(t *testing.T) {
	testCases := []struct {
		name      string
		requested string
		aud       any
		typ       string
		scope     string
		err       error
	}{
		// Section 4.3.3: the audience of the assertion MUST match the requesting client.
		{name: "ShouldAcceptAnAssertionIssuedToTheClient", requested: consts.TokenTypeRFC8693IDJAG, aud: []string{idjagClientID}},
		{name: "ShouldAcceptAStringAudience", requested: consts.TokenTypeRFC8693IDJAG, aud: idjagClientID},
		{name: "ShouldRejectAnAssertionIssuedToAnotherClient", requested: consts.TokenTypeRFC8693IDJAG, aud: []string{idjagOtherClient}, err: oauth2.ErrInvalidRequest},
		{name: "ShouldRejectAnAssertionWithoutAudience", requested: consts.TokenTypeRFC8693IDJAG, err: oauth2.ErrInvalidRequest},
		// Section 4.3: the subject token is an Identity Assertion, never an access token.
		{name: "ShouldRejectAnAccessTokenAssertion", requested: consts.TokenTypeRFC8693IDJAG, aud: []string{idjagClientID}, typ: consts.JSONWebTokenTypeAccessToken, err: oauth2.ErrInvalidRequest},
		{name: "ShouldRejectAnApplicationAccessToken", requested: consts.TokenTypeRFC8693IDJAG, aud: []string{idjagClientID}, typ: "application/AT+JWT", err: oauth2.ErrInvalidRequest},
		// Section 4.3.3: the requested scopes are governed by the relationship, not the assertion.
		{name: "ShouldAllowAScopeTheAssertionDoesNotCarry", requested: consts.TokenTypeRFC8693IDJAG, aud: []string{idjagClientID}, scope: idjagScope},
		{name: "ShouldLeaveOtherExchangesWithoutAudience", requested: consts.TokenTypeRFC8693AccessToken},
		{name: "ShouldLeaveOtherExchangesWithAnAccessToken", requested: consts.TokenTypeRFC8693AccessToken, typ: consts.JSONWebTokenTypeAccessToken},
		{name: "ShouldKeepTheScopeRuleForOtherExchanges", requested: consts.TokenTypeRFC8693AccessToken, scope: idjagScope, err: oauth2.ErrInvalidScope},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			store := storage.NewExampleStore()
			cfg := newIDJAGSpecConfig(t)
			cfg.RFC8693TokenTypes[idjagSubjectType].(*JWTType).Types = []string{consts.JSONWebTokenTypeJWT, consts.JSONWebTokenTypeAccessToken}

			jwtStrategy := &jwt.DefaultStrategy{Config: cfg, Issuer: jwt.NewDefaultIssuerRS256Unverified(key)}
			handler := &CustomJWTTypeHandler{Config: cfg, Strategy: jwtStrategy, Storage: store}

			claims := jwt.MapClaims{
				consts.ClaimSubject:        idjagSubject,
				consts.ClaimIssuer:         idjagIssuer,
				consts.ClaimExpirationTime: time.Now().Add(time.Minute).Unix(),
				consts.ClaimIssuedAt:       time.Now().Unix(),
				idjagSubjectToken:          idjagSubject,
			}

			if tc.aud != nil {
				claims[consts.ClaimAudience] = tc.aud
			}

			var opts []jwt.StrategyOpt

			if tc.typ != "" {
				opts = append(opts, jwt.WithHeaders(&jwt.Headers{Extra: map[string]any{jwt.JSONWebTokenHeaderType: tc.typ}}))
			}

			token, _, err := jwtStrategy.Encode(t.Context(), claims, opts...)
			require.NoError(t, err)

			request := newExchangeRequest(t, store.Clients[idjagClientID], newSpecSession(idjagSubject), url.Values{
				consts.FormParameterSubjectToken:       {token},
				consts.FormParameterSubjectTokenType:   {idjagSubjectType},
				consts.FormParameterRequestedTokenType: {tc.requested},
			})

			if tc.scope != "" {
				request.RequestedScope = oauth2.Arguments{tc.scope}
			}

			err = handler.HandleTokenEndpointRequest(t.Context(), request)

			if tc.err != nil {
				require.ErrorIs(t, err, tc.err)

				return
			}

			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
		})
	}
}

func newIDJAGSpecConfig(t *testing.T) *oauth2.Config {
	t.Helper()

	cfg := newSpecConfig(t)
	cfg.RFC8693TokenTypes[consts.TokenTypeRFC8693IDJAG] = &DefaultTokenType{Name: consts.TokenTypeRFC8693IDJAG}

	return cfg
}

func createIDJAGRefreshToken(t *testing.T, strategy hoauth2.CoreStrategy, store *storage.MemoryStore, client oauth2.Client, scopes, audience, resources []string) string {
	t.Helper()

	request := newIssuedRequest(client, idjagSubject, scopes, oauth2.RefreshToken)
	request.GrantedAudience = audience
	request.GrantedResource = resources

	token, signature, err := strategy.GenerateRefreshToken(t.Context(), request)
	require.NoError(t, err)
	require.NoError(t, store.CreateRefreshTokenSession(t.Context(), signature, "", request.Sanitize(nil)))

	return token
}

func newIDJAGRegisteredClient() *oauth2.DefaultClient {
	return &oauth2.DefaultClient{
		ID:         idjagClientID,
		GrantTypes: []string{consts.GrantTypeOAuthTokenExchange, consts.GrantTypeRefreshToken},
		Scopes:     []string{idjagScope, idjagOtherScope},
		Audience:   []string{idjagAudience, idjagResource},
	}
}
