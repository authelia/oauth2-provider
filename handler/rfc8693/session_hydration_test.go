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
	"authelia.com/provider/oauth2/handler/openid"
	. "authelia.com/provider/oauth2/handler/rfc8693"
	"authelia.com/provider/oauth2/internal/consts"
)

func TestTokenExchangeKeepsSubjectAndActorClaimsApart(t *testing.T) {
	for _, sc := range bindingExchangeStores() {
		t.Run(sc.name, func(t *testing.T) {
			store := sc.newStore()
			config, coreStrategy := newBindingExchangeConfig()

			client := store.GetClients()["my-client"]

			actor := NewDefaultSession()
			actor.SetSubject("u1")
			actor.Extra[consts.ClaimAuthorizedActor] = map[string]any{consts.ClaimClientIdentifier: "my-client"}
			actor.Extra["roles"] = "admin"

			subject := NewDefaultSession()
			subject.SetSubject("u2")

			form := url.Values{
				consts.FormParameterGrantType:        []string{consts.GrantTypeOAuthTokenExchange},
				consts.FormParameterSubjectTokenType: []string{consts.TokenTypeRFC8693AccessToken},
				consts.FormParameterSubjectToken:     []string{createSessionAccessToken(t.Context(), coreStrategy, store, store.GetClients()["custom-lifespan-client"], subject)},
				consts.FormParameterActorTokenType:   []string{consts.TokenTypeRFC8693AccessToken},
				consts.FormParameterActorToken:       []string{createSessionAccessToken(t.Context(), coreStrategy, store, client, actor)},
			}

			session := &DefaultSession{DefaultSession: &openid.DefaultSession{}}

			request := &oauth2.AccessRequest{
				GrantTypes: oauth2.Arguments{consts.GrantTypeOAuthTokenExchange},
				ID:         uuid.New().String(),
				Client:     client,
				Form:       form,
				Session:    session,
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

			assert.Equal(t, "u2", session.GetSubject())
			assert.Equal(t, "u2", session.GetSubjectToken()[consts.ClaimSubject])
			assert.Nil(t, session.GetSubjectToken()[consts.ClaimAuthorizedActor])
			assert.Nil(t, session.GetSubjectToken()["roles"])
			assert.Equal(t, "u1", session.GetActorToken()[consts.ClaimSubject])
			assert.NotContains(t, session.Extra, "roles")

			validator := &ActorTokenValidationHandler{}

			require.EqualError(t, oauth2.ErrorToDebugRFC6749Error(validator.HandleTokenEndpointRequest(t.Context(), request)), "The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client. The subject token does not authorize delegation: no 'may_act' claim is present. The OAuth 2.0 client supplied an 'actor_token' but the subject token does not contain a 'may_act' claim authorizing the actor to act on behalf of the subject. Either set the 'may_act' claim on the subject token, or configure the client to use an out-of-band authorization policy by implementing the ActorTokenPolicyClient interface.")
		})
	}
}

func TestTokenExchangeReadsMayActFromTheSubjectToken(t *testing.T) {
	for _, sc := range bindingExchangeStores() {
		t.Run(sc.name, func(t *testing.T) {
			store := sc.newStore()
			config, coreStrategy := newBindingExchangeConfig()

			client := store.GetClients()["my-client"]

			subject := NewDefaultSession()
			subject.SetSubject("u2")
			subject.Extra[consts.ClaimAuthorizedActor] = map[string]any{consts.ClaimClientIdentifier: "my-client"}

			form := url.Values{
				consts.FormParameterGrantType:        []string{consts.GrantTypeOAuthTokenExchange},
				consts.FormParameterSubjectTokenType: []string{consts.TokenTypeRFC8693AccessToken},
				consts.FormParameterSubjectToken:     []string{createSessionAccessToken(t.Context(), coreStrategy, store, store.GetClients()["custom-lifespan-client"], subject)},
			}

			session := &DefaultSession{DefaultSession: &openid.DefaultSession{}}

			request := &oauth2.AccessRequest{
				GrantTypes: oauth2.Arguments{consts.GrantTypeOAuthTokenExchange},
				ID:         uuid.New().String(),
				Client:     client,
				Form:       form,
				Session:    session,
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

			assert.Equal(t, map[string]any{consts.ClaimClientIdentifier: "my-client"}, session.GetSubjectToken()[consts.ClaimAuthorizedActor])

			validator := &ActorTokenValidationHandler{}

			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(validator.HandleTokenEndpointRequest(t.Context(), request)))
		})
	}
}

func TestTokenExchangeReadsExtraClaimsFromAForeignSession(t *testing.T) {
	store := bindingExchangeStores()[0].newStore()
	config, coreStrategy := newBindingExchangeConfig()

	client := store.GetClients()["my-client"]

	subject := &oauth2.DefaultSession{
		Subject:  "u2",
		Username: "user2",
		Extra: map[string]any{
			consts.ClaimAuthorizedActor: map[string]any{consts.ClaimClientIdentifier: "my-client"},
			consts.ClaimSubject:         "u1",
			consts.ClaimUsername:        "user1",
		},
	}

	form := url.Values{
		consts.FormParameterGrantType:        []string{consts.GrantTypeOAuthTokenExchange},
		consts.FormParameterSubjectTokenType: []string{consts.TokenTypeRFC8693AccessToken},
		consts.FormParameterSubjectToken:     []string{createSessionAccessToken(t.Context(), coreStrategy, store, store.GetClients()["custom-lifespan-client"], subject)},
	}

	session := &DefaultSession{DefaultSession: &openid.DefaultSession{}}

	request := &oauth2.AccessRequest{
		GrantTypes: oauth2.Arguments{consts.GrantTypeOAuthTokenExchange},
		ID:         uuid.New().String(),
		Client:     client,
		Form:       form,
		Session:    session,
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

	claims := session.GetSubjectToken()

	assert.Equal(t, map[string]any{consts.ClaimClientIdentifier: "my-client"}, claims[consts.ClaimAuthorizedActor])
	assert.Equal(t, "u2", claims[consts.ClaimSubject])
	assert.Equal(t, "user2", claims[consts.ClaimUsername])
}

func createSessionAccessToken(ctx context.Context, coreStrategy hoauth2.CoreStrategy, store hoauth2.AccessTokenStorage, client oauth2.Client, session oauth2.Session) string {
	session.SetExpiresAt(oauth2.AccessToken, time.Now().UTC().Add(10*time.Minute))

	request := &oauth2.AccessRequest{
		GrantTypes: oauth2.Arguments{"password"},
			Session: session,
			Client:  client,
	}

	token, signature, err := coreStrategy.GenerateAccessToken(ctx, request)
	if err != nil {
		panic(err.Error())
	} else if err = store.CreateAccessTokenSession(ctx, signature, request.Sanitize([]string{})); err != nil {
		panic(err.Error())
	}

	return token
}
