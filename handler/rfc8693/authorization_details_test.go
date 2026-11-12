// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc8693_test

import (
	"context"
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	. "authelia.com/provider/oauth2/handler/rfc8693"
	"authelia.com/provider/oauth2/internal"
	"authelia.com/provider/oauth2/internal/consts"
)

func TestAccessTokenTypeHandlerCarriesTheSubjectTokenAuthorizationDetails(t *testing.T) {
	subjectDetails := oauth2.AuthorizationDetails{{Type: internal.AuthorizationDetailsTypePaymentInitiation, Actions: []string{idjagActionStatus}}}
	actorDetails := oauth2.AuthorizationDetails{{Type: internal.AuthorizationDetailsTypePaymentInitiation, Actions: []string{"initiate"}}}

	testCases := []struct {
		name               string
		disabled           bool
		requestedTokenType string
		subject            oauth2.AuthorizationDetails
		actor              oauth2.AuthorizationDetails
		expected           oauth2.AuthorizationDetails
	}{
		{name: "ShouldCarryTheSubjectTokenDetails", subject: subjectDetails, actor: actorDetails, expected: subjectDetails},
		{name: "ShouldNotInheritTheActorTokenDetails", actor: actorDetails},
		{name: "ShouldNotCarryDetailsWhenDisabled", disabled: true, subject: subjectDetails},
		{name: "ShouldNotCarryDetailsIntoAnIDToken", requestedTokenType: consts.TokenTypeRFC8693IDToken, subject: subjectDetails},
	}

	for _, sc := range bindingExchangeStores() {
		t.Run(sc.name, func(t *testing.T) {
			for _, tc := range testCases {
				t.Run(tc.name, func(t *testing.T) {
					store := sc.newStore()
					config, coreStrategy := newBindingExchangeConfig()

					if !tc.disabled {
						config.AuthorizationDetailsTypeHandlers = []oauth2.AuthorizationDetailsTypeHandler{internal.PaymentInitiationTypeHandler{}}
					}

					client := store.GetClients()["my-client"]

					subject := NewDefaultSession()
					subject.SetSubject("u2")

					actor := NewDefaultSession()
					actor.SetSubject("u1")

					form := url.Values{
						consts.FormParameterGrantType:        []string{consts.GrantTypeOAuthTokenExchange},
						consts.FormParameterSubjectTokenType: []string{consts.TokenTypeRFC8693AccessToken},
						consts.FormParameterSubjectToken:     []string{createDetailedAccessToken(t.Context(), t, coreStrategy, store, store.GetClients()["custom-lifespan-client"], subject, tc.subject)},
						consts.FormParameterActorTokenType:   []string{consts.TokenTypeRFC8693AccessToken},
						consts.FormParameterActorToken:       []string{createDetailedAccessToken(t.Context(), t, coreStrategy, store, client, actor, tc.actor)},
					}

					if tc.requestedTokenType != "" {
						form.Set(consts.FormParameterRequestedTokenType, tc.requestedTokenType)
					}

					request := &oauth2.AccessRequest{
						GrantTypes: oauth2.Arguments{consts.GrantTypeOAuthTokenExchange},
						Request: oauth2.Request{
							ID:      uuid.New().String(),
							Client:  client,
							Form:    form,
							Session: NewDefaultSession(),
						},
					}

					handler := &AccessTokenTypeHandler{
						Config:               config,
						AccessTokenLifespan:  5 * time.Minute,
						RefreshTokenLifespan: 5 * time.Minute,
						CoreStrategy:         coreStrategy,
						ScopeStrategy:        config.ScopeStrategy,
						Storage:              store,
					}

					require.NoError(t, oauth2.ErrorToDebugRFC6749Error(handler.HandleTokenEndpointRequest(t.Context(), request)))

					assert.Equal(t, tc.expected, request.GetGrantedAuthorizationDetails())
				})
			}
		})
	}
}

func createDetailedAccessToken(ctx context.Context, t *testing.T, coreStrategy hoauth2.CoreStrategy, store hoauth2.AccessTokenStorage, client oauth2.Client, session oauth2.Session, details oauth2.AuthorizationDetails) string {
	t.Helper()

	session.SetExpiresAt(oauth2.AccessToken, time.Now().UTC().Add(10*time.Minute))

	request := &oauth2.AccessRequest{
		GrantTypes: oauth2.Arguments{consts.GrantTypeAuthorizationCode},
		Request: oauth2.Request{
			ID:      uuid.New().String(),
			Client:  permittingOwner(client),
			Session: session,
		},
	}

	grantFixtureAudience(request)
	request.SetGrantedAuthorizationDetails(details)

	token, signature, err := coreStrategy.GenerateAccessToken(ctx, request)
	require.NoError(t, err)
	require.NoError(t, store.CreateAccessTokenSession(ctx, signature, request.Sanitize([]string{})))

	return token
}
