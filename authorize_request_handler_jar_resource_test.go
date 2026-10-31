// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/jose"

	. "authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/gen"
	"authelia.com/provider/oauth2/storage"
)

func TestRequestObjectResourceAndAudienceClaims(t *testing.T) {
	const (
		first  = "https://a.example.com/"
		second = "https://b.example.com/"
	)

	key := gen.MustRSAKey()

	testCases := []struct {
		name     string
		claims   map[string]any
		resource Arguments
		audience Arguments
		err      error
	}{
		{name: "ShouldAcceptAResourceString", claims: map[string]any{consts.FormParameterResource: first}, resource: Arguments{first}},
		{name: "ShouldAcceptAOneValueResourceArray", claims: map[string]any{consts.FormParameterResource: []string{first}}, resource: Arguments{first}},
		{name: "ShouldAcceptAResourceArray", claims: map[string]any{consts.FormParameterResource: []string{first, second}}, resource: Arguments{first, second}},
		{name: "ShouldAcceptAnEmptyResourceArray", claims: map[string]any{consts.FormParameterResource: []string{}}},
		{name: "ShouldAcceptAnAudienceString", claims: map[string]any{consts.FormParameterAudience: first}, audience: Arguments{first}},
		{name: "ShouldAcceptAnAudienceArray", claims: map[string]any{consts.FormParameterAudience: []string{first, second}}, audience: Arguments{first, second}},
		{name: "ShouldRejectAResourceArrayWithANonString", claims: map[string]any{consts.FormParameterResource: []any{first, 1}}, err: ErrInvalidRequestObject},
		{name: "ShouldRejectAResourceNumber", claims: map[string]any{consts.FormParameterResource: 1}, err: ErrInvalidRequestObject},
		{name: "ShouldRejectAnAudienceObject", claims: map[string]any{consts.FormParameterAudience: map[string]any{"a": first}}, err: ErrInvalidRequestObject},
		{name: "ShouldRejectAnInvalidResourceInAnArray", claims: map[string]any{consts.FormParameterResource: []string{first, "not a uri"}}, err: ErrInvalidTarget},
		{name: "ShouldRejectAResourceTheClientMayNotRequest", claims: map[string]any{consts.FormParameterResource: []string{first, "https://never.example.com/"}}, err: ErrInvalidTarget},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			client := &DefaultJARClient{
				DefaultClient: &DefaultClient{
					ID:            "foo",
					RedirectURIs:  []string{"https://client.example.com/cb"},
					ResponseTypes: []string{consts.ResponseTypeAuthorizationCodeFlow},
					Scopes:        []string{consts.ScopeOpenID},
					Audience:      []string{first, second},
					Resource:      []string{first, second},
				},
				JSONWebKeys:             &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{KeyID: "k", Use: "sig", Algorithm: "RS256", Key: &key.PublicKey}}},
				RequestObjectSigningAlg: "RS256",
			}

			store := storage.NewMemoryStore()
			store.Clients[client.GetID()] = client

			signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: key, KeyID: "k"}}, (&jose.SignerOptions{}).WithType("oauth-authz-req+jwt"))
			require.NoError(t, err)

			claims := map[string]any{consts.FormParameterClientID: "foo", consts.FormParameterResponseType: consts.ResponseTypeAuthorizationCodeFlow}

			for k, v := range tc.claims {
				claims[k] = v
			}

			payload, err := json.Marshal(claims)
			require.NoError(t, err)

			signed, err := signer.Sign(payload)
			require.NoError(t, err)

			assertion, err := signed.CompactSerialize()
			require.NoError(t, err)

			form := url.Values{
				consts.FormParameterClientID:     {"foo"},
				consts.FormParameterResponseType: {consts.ResponseTypeAuthorizationCodeFlow},
				consts.FormParameterScope:        {consts.ScopeOpenID},
				consts.FormParameterRedirectURI:  {"https://client.example.com/cb"},
				consts.FormParameterState:        {"0123456789abcdef"},
				consts.FormParameterRequest:      {assertion},
			}

			r := httptest.NewRequest(http.MethodGet, "https://auth.example.com/authorize?"+form.Encode(), nil)

			provider := &Fosite{Store: store, Config: &Config{ScopeStrategy: ExactScopeStrategy, IDTokenIssuer: "https://auth.example.com"}}

			requester, err := provider.NewAuthorizeRequest(t.Context(), r)

			if tc.err != nil {
				assert.ErrorIs(t, err, tc.err)

				return
			}

			require.NoError(t, ErrorToDebugRFC6749Error(err))

			assert.ElementsMatch(t, tc.resource, requester.GetRequestedResource())
			assert.ElementsMatch(t, tc.audience, requester.GetRequestedAudience())
		})
	}
}
