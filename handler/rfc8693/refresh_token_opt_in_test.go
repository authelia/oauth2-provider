// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc8693_test

import (
	"net/url"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	. "authelia.com/provider/oauth2/handler/rfc8693"
	"authelia.com/provider/oauth2/internal/consts"
)

func TestTokenExchangeRefreshTokenOptIn(t *testing.T) {
	testCases := []struct {
		name      string
		optedIn   bool
		required  []string
		requested string
		issued    bool
		err       error
	}{
		{name: "ShouldNotIssueWithAnAccessTokenWithoutOptingIn", requested: consts.TokenTypeRFC8693AccessToken},
		{name: "ShouldIssueWithAnAccessTokenWhenOptedIn", optedIn: true, requested: consts.TokenTypeRFC8693AccessToken, issued: true},
		{name: "ShouldNotIssueWithAnAccessTokenWithoutTheRefreshScope", optedIn: true, required: []string{consts.ScopeOfflineAccess}, requested: consts.TokenTypeRFC8693AccessToken},
		{name: "ShouldRefuseARefreshTokenWithoutOptingIn", requested: consts.TokenTypeRFC8693RefreshToken, err: oauth2.ErrUnauthorizedClient},
		{name: "ShouldIssueARefreshTokenWhenOptedIn", optedIn: true, requested: consts.TokenTypeRFC8693RefreshToken, issued: true},
		{name: "ShouldRefuseARefreshTokenWithoutTheRefreshScope", optedIn: true, required: []string{consts.ScopeOfflineAccess}, requested: consts.TokenTypeRFC8693RefreshToken, err: oauth2.ErrInvalidScope},
	}

	for _, sc := range bindingExchangeStores() {
		for _, tc := range testCases {
			t.Run(sc.name+"/"+tc.name, func(t *testing.T) {
				store := sc.newStore()
				config, strategy := newBindingExchangeConfig()
				config.RefreshTokenScopes = []string{}
				config.RFC8693TokenTypes[consts.TokenTypeRFC8693RefreshToken] = &DefaultTokenType{Name: consts.TokenTypeRFC8693RefreshToken}

				client := store.GetClients()["my-client"].(*oauth2.DefaultClient)
				token := chainSubjectToken(t, strategy, store, client, newOptInSubject(), true)

				request := newLifetimeExchangeRequest(store, consts.TokenTypeRFC8693RefreshToken, token, tc.requested)
				request.Client = &oauth2.DefaultRegisteredClient{DefaultClient: client, TokenExchangeRefreshToken: tc.optedIn}

				access := newLifetimeAccessTokenHandler(config, strategy, store)
				access.RefreshTokenScopes = tc.required

				refresh := newLifetimeRefreshTokenHandler(config, strategy, store)
				refresh.RefreshTokenScopes = []string{}

				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(refresh.HandleTokenEndpointRequest(t.Context(), request)))

				refresh.RefreshTokenScopes = tc.required

				response := oauth2.NewAccessResponse()

				var err error

				if tc.requested == consts.TokenTypeRFC8693RefreshToken {
					err = refresh.PopulateTokenEndpointResponse(t.Context(), request, response)
				} else {
					err = access.PopulateTokenEndpointResponse(t.Context(), request, response)
				}

				if tc.err != nil {
					assert.ErrorIs(t, err, tc.err)

					return
				}

				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

				if tc.requested == consts.TokenTypeRFC8693RefreshToken {
					assert.NotEmpty(t, response.GetAccessToken())

					return
				}

				if tc.issued {
					assert.NotEmpty(t, response.GetExtra(consts.FormParameterRefreshToken))
				} else {
					assert.Empty(t, response.GetExtra(consts.FormParameterRefreshToken))
				}
			})
		}
	}
}

func TestCustomJWTIsNotConsumedWhenARefreshTokenIsNotPermitted(t *testing.T) {
	testCases := []struct {
		name    string
		optedIn bool
	}{
		{name: "ShouldNotConsumeWithoutOptingIn"},
		{name: "ShouldConsumeWhenOptedIn", optedIn: true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			f := newCustomJWTConsumeFixture(t, true)

			request := f.request(url.Values{
				consts.FormParameterSubjectTokenType:   {"urn:spec:jwt"},
				consts.FormParameterSubjectToken:       {f.token(t, uuid.New().String())},
				consts.FormParameterActorTokenType:     {"urn:spec:jwt"},
				consts.FormParameterActorToken:         {f.token(t, uuid.New().String())},
				consts.FormParameterRequestedTokenType: {consts.TokenTypeRFC8693RefreshToken},
			})
			request.Client = &oauth2.DefaultRegisteredClient{DefaultClient: f.client.(*oauth2.DefaultClient), TokenExchangeRefreshToken: tc.optedIn}

			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(f.custom.HandleTokenEndpointRequest(t.Context(), request)))

			err := f.grant.PopulateTokenEndpointResponse(t.Context(), request, oauth2.NewAccessResponse())

			if tc.optedIn {
				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
				assert.NotEmpty(t, f.store.TokenExchangeJTIs)

				return
			}

			assert.ErrorIs(t, err, oauth2.ErrUnauthorizedClient)
			assert.Empty(t, f.store.TokenExchangeJTIs)
		})
	}
}

func newOptInSubject() *DefaultSession {
	session := NewDefaultSession()
	session.SetSubject("peter")

	return session
}
