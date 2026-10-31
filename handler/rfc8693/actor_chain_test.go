// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc8693_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	. "authelia.com/provider/oauth2/handler/rfc8693"
	"authelia.com/provider/oauth2/internal/consts"
)

func TestSubjectActorChainIsNotDropped(t *testing.T) {
	const hint = "The subject token has an 'act' claim so an 'actor_token' is required"

	for _, sc := range bindingExchangeStores() {
		t.Run(sc.name, func(t *testing.T) {
			testCases := []struct {
				name    string
				refresh bool
				act     map[string]any
				actor   bool
				err     string
			}{
				{name: "ShouldAcceptASubjectWithoutAnActClaim"},
				{name: "ShouldRejectAnAccessTokenWithAnActClaim", act: map[string]any{consts.ClaimSubject: "service-a"}, err: hint},
				{name: "ShouldRejectARefreshTokenWithAnActClaim", refresh: true, act: map[string]any{consts.ClaimSubject: "service-a"}, err: hint},
				{name: "ShouldAcceptAnActClaimWithAnActorToken", act: map[string]any{consts.ClaimSubject: "service-a"}, actor: true},
			}

			for _, tc := range testCases {
				t.Run(tc.name, func(t *testing.T) {
					store := sc.newStore()
					config, strategy := newBindingExchangeConfig()
					config.RefreshTokenScopes = []string{}
					config.RFC8693TokenTypes[consts.TokenTypeRFC8693RefreshToken] = &DefaultTokenType{Name: consts.TokenTypeRFC8693RefreshToken}

					owner := store.GetClients()["custom-lifespan-client"]
					tokenType := consts.TokenTypeRFC8693AccessToken

					if tc.refresh {
						owner = store.GetClients()["my-client"]
						tokenType = consts.TokenTypeRFC8693RefreshToken
					}

					session := NewDefaultSession()
					session.SetSubject("peter")

					if tc.act != nil {
						session.SetClaimActor(tc.act)
					}

					token := chainSubjectToken(t, strategy, store, owner, session, tc.refresh)

					request := newLifetimeExchangeRequest(store, tokenType, token, consts.TokenTypeRFC8693AccessToken)

					if tc.actor {
						actor := NewDefaultSession()
						actor.SetSubject("service-b")

						form := request.GetRequestForm()
						form.Set(consts.FormParameterActorTokenType, consts.TokenTypeRFC8693AccessToken)
						form.Set(consts.FormParameterActorToken, createSessionAccessToken(t.Context(), strategy, store, store.GetClients()["custom-lifespan-client"], actor))
					}

					var handler oauth2.TokenEndpointHandler = newLifetimeAccessTokenHandler(config, strategy, store)
					if tc.refresh {
						handler = newLifetimeRefreshTokenHandler(config, strategy, store)
					}

					require.NoError(t, oauth2.ErrorToDebugRFC6749Error(handler.HandleTokenEndpointRequest(t.Context(), request)))

					if tc.actor {
						require.NoError(t, oauth2.ErrorToDebugRFC6749Error(newLifetimeAccessTokenHandler(config, strategy, store).HandleTokenEndpointRequest(t.Context(), request)))
					}

					err := (&TokenExchangeGrantHandler{Config: config}).PopulateTokenEndpointResponse(t.Context(), request, oauth2.NewAccessResponse())

					if tc.err != "" {
						assert.ErrorIs(t, err, oauth2.ErrInvalidRequest)
						assert.ErrorContains(t, oauth2.ErrorToDebugRFC6749Error(err), tc.err)

						return
					}

					require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
				})
			}
		})
	}
}

func TestActorChainDepth(t *testing.T) {
	const hint = "would exceed the permitted"

	testCases := []struct {
		name     string
		limit    int
		existing int
		err      bool
	}{
		{name: "ShouldAcceptAFirstActor"},
		{name: "ShouldAcceptTheDefaultDepth", existing: 7},
		{name: "ShouldRejectBeyondTheDefaultDepth", existing: 8, err: true},
		{name: "ShouldTreatANegativeLimitAsTheDefault", limit: -1, existing: 8, err: true},
		{name: "ShouldAcceptAConfiguredDepth", limit: 2, existing: 1},
		{name: "ShouldRejectBeyondAConfiguredDepth", limit: 2, existing: 2, err: true},
		{name: "ShouldAcceptBeyondTheDefaultWhenConfigured", limit: 20, existing: 8},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := newSpecConfig(t)
			cfg.RFC8693MaxActorChainDepth = tc.limit

			session := newSpecSession("alice")
			session.SetSubjectToken(map[string]any{consts.ClaimSubject: "alice", consts.ClaimActor: actorChain(tc.existing)})
			session.SetActorToken(map[string]any{consts.ClaimSubject: "bob"})

			err := runGrantHandler(t, cfg, newSpecRequest(t, newConfidentialClient(), session, nil))

			if tc.err {
				assert.ErrorIs(t, err, oauth2.ErrInvalidRequest)
				assert.ErrorContains(t, oauth2.ErrorToDebugRFC6749Error(err), hint)

				return
			}

			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
		})
	}

	t.Run("ShouldLimitTheChainBeforeBuildingTheActClaim", func(t *testing.T) {
		session := newSpecSession("alice")
		session.SetSubjectToken(map[string]any{consts.ClaimSubject: "alice", consts.ClaimActor: actorChain(8)})
		session.SetActorToken(map[string]any{"unidentified": true})

		err := runGrantHandler(t, newSpecConfig(t), newSpecRequest(t, newConfidentialClient(), session, nil))

		assert.ErrorContains(t, oauth2.ErrorToDebugRFC6749Error(err), hint)
	})

	t.Run("ShouldLimitTheChainAnAuthorizationGrantCarriesOver", func(t *testing.T) {
		f := newGrantFixture(t, nil)
		f.cfg.RFC8693MaxActorChainDepth = 2

		_, err := f.exchange(t, grantExchange{audience: []string{grantTarget}, subjectActor: actorChain(3)})

		assert.ErrorIs(t, err, oauth2.ErrInvalidRequest)
		assert.ErrorContains(t, oauth2.ErrorToDebugRFC6749Error(err), hint)
	})

	t.Run("ShouldAcceptTheChainAnAuthorizationGrantCarriesOverAtTheLimit", func(t *testing.T) {
		f := newGrantFixture(t, nil)
		f.cfg.RFC8693MaxActorChainDepth = 2

		_, err := f.exchange(t, grantExchange{audience: []string{grantTarget}, subjectActor: actorChain(2)})

		require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
	})
}

func TestActorChainDepthOfAnOwnAccessToken(t *testing.T) {
	for _, sc := range bindingExchangeStores() {
		testCases := []struct {
			name     string
			existing int
			err      bool
		}{
			{name: "ShouldAcceptWithinTheLimit", existing: 7},
			{name: "ShouldRejectBeyondTheLimit", existing: 8, err: true},
		}

		for _, tc := range testCases {
			t.Run(sc.name+"/"+tc.name, func(t *testing.T) {
				store := sc.newStore()
				config, strategy := newBindingExchangeConfig()

				client := &oauth2.DefaultRegisteredClient{
					DefaultClient:               store.GetClients()["my-client"].(*oauth2.DefaultClient),
					TokenExchangeOwnAccessToken: true,
				}

				subject := NewDefaultSession()
				subject.SetSubject("peter")
				subject.SetClaimActor(actorChain(tc.existing))

				actor := NewDefaultSession()
				actor.SetSubject("service-b")

				request := newLifetimeExchangeRequest(store, consts.TokenTypeRFC8693AccessToken, createSessionAccessToken(t.Context(), strategy, store, client, subject), consts.TokenTypeRFC8693AccessToken)
				request.Client = client

				form := request.GetRequestForm()
				form.Set(consts.FormParameterActorTokenType, consts.TokenTypeRFC8693AccessToken)
				form.Set(consts.FormParameterActorToken, createSessionAccessToken(t.Context(), strategy, store, client, actor))

				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(newLifetimeAccessTokenHandler(config, strategy, store).HandleTokenEndpointRequest(t.Context(), request)))

				err := (&TokenExchangeGrantHandler{Config: config}).PopulateTokenEndpointResponse(t.Context(), request, oauth2.NewAccessResponse())

				if tc.err {
					assert.ErrorIs(t, err, oauth2.ErrInvalidRequest)
					assert.ErrorContains(t, oauth2.ErrorToDebugRFC6749Error(err), "would exceed the permitted")

					return
				}

				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
			})
		}
	}
}

func actorChain(depth int) (act map[string]any) {
	for range depth {
		next := map[string]any{consts.ClaimSubject: "service"}

		if act != nil {
			next[consts.ClaimActor] = act
		}

		act = next
	}

	return act
}

func chainSubjectToken(t *testing.T, strategy hoauth2.CoreStrategy, store rfc8693ExchangeStore, owner oauth2.Client, session *DefaultSession, refresh bool) string {
	t.Helper()

	if !refresh {
		return createSessionAccessToken(t.Context(), strategy, store, owner, session)
	}

	session.SetExpiresAt(oauth2.RefreshToken, session.GetExpiresAt(oauth2.AccessToken))

	request := newUnaddressedRequest(owner, "peter", nil, oauth2.RefreshToken)
	request.Session = session

	token, signature, err := strategy.GenerateRefreshToken(t.Context(), request)
	require.NoError(t, err)
	require.NoError(t, store.(hoauth2.TokenRevocationStorage).CreateRefreshTokenSession(t.Context(), signature, "", request.Sanitize(nil)))

	return token
}
