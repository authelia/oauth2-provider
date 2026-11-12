// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc8693_test

import (
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	. "authelia.com/provider/oauth2/handler/rfc8693"
	"authelia.com/provider/oauth2/internal"
	"authelia.com/provider/oauth2/internal/consts"
)

func TestAccessTokenTypeHandlerRecordsTheSubjectRequester(t *testing.T) {
	details := oauth2.AuthorizationDetails{{Type: internal.AuthorizationDetailsTypePaymentInitiation, Actions: []string{idjagActionStatus}}}

	testCases := []struct {
		name    string
		subject bool
	}{
		{name: "ShouldRecordTheSubjectTokenRequest", subject: true},
		{name: "ShouldNotRecordTheActorTokenRequest"},
	}

	for _, sc := range bindingExchangeStores() {
		t.Run(sc.name, func(t *testing.T) {
			for _, tc := range testCases {
				t.Run(tc.name, func(t *testing.T) {
					store := sc.newStore()
					config, coreStrategy := newBindingExchangeConfig()
					client := store.GetClients()["my-client"]
					owner := store.GetClients()["custom-lifespan-client"]

					actor := NewDefaultSession()
					actor.SetSubject("u1")

					form := url.Values{
						consts.FormParameterGrantType:      []string{consts.GrantTypeOAuthTokenExchange},
						consts.FormParameterActorTokenType: []string{consts.TokenTypeRFC8693AccessToken},
						consts.FormParameterActorToken:     []string{createDetailedAccessToken(t.Context(), t, coreStrategy, store, client, actor, nil)},
					}

					if tc.subject {
						subject := NewDefaultSession()
						subject.SetSubject("u2")

						form.Set(consts.FormParameterSubjectTokenType, consts.TokenTypeRFC8693AccessToken)
						form.Set(consts.FormParameterSubjectToken, createDetailedAccessToken(t.Context(), t, coreStrategy, store, owner, subject, details))
					}

					session := NewDefaultSession()
					request := newSubjectRequesterExchange(client, form, session)

					handler := &AccessTokenTypeHandler{
						Config:               config,
						AccessTokenLifespan:  5 * time.Minute,
						RefreshTokenLifespan: 5 * time.Minute,
						CoreStrategy:         coreStrategy,
						ScopeStrategy:        config.ScopeStrategy,
						Storage:              store,
					}

					require.NoError(t, oauth2.ErrorToDebugRFC6749Error(handler.HandleTokenEndpointRequest(t.Context(), request)))

					if !tc.subject {
						assert.Nil(t, session.GetSubjectRequester())

						return
					}

					original := session.GetSubjectRequester()
					require.NotNil(t, original)
					assert.Equal(t, owner.GetID(), original.GetClient().GetID())
					assert.Equal(t, "u2", original.GetSession().GetSubject())
					assert.Equal(t, details, original.GetGrantedAuthorizationDetails())
					assert.NotSame(t, session, original.GetSession())
				})
			}
		})
	}
}

func TestRefreshTokenTypeHandlerRecordsTheSubjectRequester(t *testing.T) {
	for _, sc := range bindingExchangeStores() {
		t.Run(sc.name, func(t *testing.T) {
			store := sc.newStore()
			config, coreStrategy := newBindingExchangeConfig()
			client := store.GetClients()["my-client"]

			form := url.Values{
				consts.FormParameterGrantType:        []string{consts.GrantTypeOAuthTokenExchange},
				consts.FormParameterSubjectTokenType: []string{consts.TokenTypeRFC8693RefreshToken},
				consts.FormParameterSubjectToken:     []string{createSessionRefreshToken(t.Context(), coreStrategy, store, client, time.Now().UTC().Add(time.Hour))},
			}

			session := NewDefaultSession()
			request := newSubjectRequesterExchange(client, form, session)

			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(newLifetimeRefreshTokenHandler(config, coreStrategy, store).HandleTokenEndpointRequest(t.Context(), request)))

			original := session.GetSubjectRequester()
			require.NotNil(t, original)
			assert.Equal(t, client.GetID(), original.GetClient().GetID())
			assert.Equal(t, "peter", original.GetSession().GetSubject())
			assert.NotSame(t, session, original.GetSession())
		})
	}
}

func TestDefaultSessionSubjectRequesterIsTransient(t *testing.T) {
	session := NewDefaultSession()
	session.SetSubjectRequester(oauth2.NewAccessRequest(NewDefaultSession()))

	require.NotNil(t, session.GetSubjectRequester())

	cloned, ok := session.Clone().(*DefaultSession)
	require.True(t, ok)
	assert.Nil(t, cloned.GetSubjectRequester())
}

func newSubjectRequesterExchange(client oauth2.Client, form url.Values, session *DefaultSession) *oauth2.AccessRequest {
	return &oauth2.AccessRequest{
		GrantTypes: oauth2.Arguments{consts.GrantTypeOAuthTokenExchange},
		Request: oauth2.Request{
			ID:      uuid.New().String(),
			Client:  client,
			Form:    form,
			Session: session,
		},
	}
}
