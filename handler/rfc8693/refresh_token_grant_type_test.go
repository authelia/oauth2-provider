// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc8693_test

import (
	"context"
	"errors"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	. "authelia.com/provider/oauth2/handler/rfc8693"
	"authelia.com/provider/oauth2/internal/consts"
)

func TestRefreshTokenRequiresTheRefreshTokenGrant(t *testing.T) {
	const hintNoGrant = "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The OAuth 2.0 Client the refresh token was issued to is not allowed to use authorization grant 'refresh_token'."

	testCases := []struct {
		name         string
		actor        bool
		grantTypes   []string
		unregistered bool
		expected     string
	}{
		{
			name:       "ShouldAcceptASubjectTokenOfAClientWithTheGrant",
			grantTypes: []string{consts.GrantTypeAuthorizationCode, consts.GrantTypeRefreshToken},
		},
		{
			name:       "ShouldRejectASubjectTokenOfAClientWithoutTheGrant",
			grantTypes: []string{consts.GrantTypeAuthorizationCode},
			expected:   hintNoGrant,
		},
		{
			name:       "ShouldAcceptAnActorTokenOfAClientWithTheGrant",
			actor:      true,
			grantTypes: []string{consts.GrantTypeAuthorizationCode, consts.GrantTypeRefreshToken},
		},
		{
			name:       "ShouldRejectAnActorTokenOfAClientWithoutTheGrant",
			actor:      true,
			grantTypes: []string{consts.GrantTypeAuthorizationCode},
			expected:   hintNoGrant,
		},
		{
			name:         "ShouldRejectATokenOfAClientNoLongerRegistered",
			unregistered: true,
			expected:     "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The OAuth 2.0 Client the refresh token was issued to is not registered.",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, store, strategy := newExchangeFixture(t)
			cfg.RFC8693TokenTypes[consts.TokenTypeRFC8693RefreshToken] = &DefaultTokenType{Name: consts.TokenTypeRFC8693RefreshToken}

			owner := &oauth2.DefaultClient{ID: "refresh-token-owner", GrantTypes: []string{consts.GrantTypeAuthorizationCode, consts.GrantTypeRefreshToken}, Scopes: []string{consts.ScopeOpenID}}
			store.Clients[owner.ID] = owner

			original := newIssuedRequest(owner, "peter", []string{consts.ScopeOpenID}, oauth2.RefreshToken)

			token, signature, err := strategy.GenerateRefreshToken(t.Context(), original)
			require.NoError(t, err)
			require.NoError(t, store.CreateRefreshTokenSession(t.Context(), signature, "", original.Sanitize(nil)))

			if tc.unregistered {
				delete(store.Clients, owner.ID)
			} else {
				store.Clients[owner.ID] = &oauth2.DefaultClient{ID: owner.ID, GrantTypes: tc.grantTypes, Scopes: owner.Scopes}
			}

			form := url.Values{
				consts.FormParameterSubjectTokenType: {consts.TokenTypeRFC8693RefreshToken},
				consts.FormParameterSubjectToken:     {token},
			}

			if tc.actor {
				form = url.Values{
					consts.FormParameterSubjectTokenType: {consts.TokenTypeRFC8693AccessToken},
					consts.FormParameterSubjectToken:     {"opaque-subject-token"},
					consts.FormParameterActorTokenType:   {consts.TokenTypeRFC8693RefreshToken},
					consts.FormParameterActorToken:       {token},
				}
			}

			request := newExchangeRequest(t, store.Clients["my-client"], newSpecSession(""), form)

			err = newRefreshTokenTypeHandler(cfg, store, strategy).HandleTokenEndpointRequest(t.Context(), request)

			if tc.expected == "" {
				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
			} else {
				assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), tc.expected)
			}
		})
	}
}

func TestRefreshTokenOfAnUnresolvableClientIDMetadataDocumentClient(t *testing.T) {
	const id = "https://client.example.com/metadata.json"

	unavailable := errors.New("the resolver is unavailable")

	testCases := []struct {
		name     string
		err      error
		expected error
		debug    string
	}{
		{
			name:     "ShouldRejectATokenOfAClientWhoseDocumentNoLongerResolves",
			err:      oauth2.ErrInvalidClient.WithHint("The Client ID Metadata Document could not be used.").WithDebug("The status code was 404."),
			expected: oauth2.ErrInvalidRequest,
			debug:    "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The OAuth 2.0 Client the refresh token was issued to is not registered.",
		},
		{
			name:     "ShouldReportAnyOtherResolverErrorAsAServerError",
			err:      unavailable,
			expected: oauth2.ErrServerError,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, store, strategy := newExchangeFixture(t)
			cfg.RFC8693TokenTypes[consts.TokenTypeRFC8693RefreshToken] = &DefaultTokenType{Name: consts.TokenTypeRFC8693RefreshToken}

			resolver := &failingDocumentResolver{err: tc.err}

			cfg.ClientIDMetadataDocumentResolver = resolver

			owner := &oauth2.DefaultClient{ID: id, GrantTypes: []string{consts.GrantTypeAuthorizationCode, consts.GrantTypeRefreshToken}, Scopes: []string{consts.ScopeOpenID}}

			original := newIssuedRequest(owner, "peter", []string{consts.ScopeOpenID}, oauth2.RefreshToken)

			token, signature, err := strategy.GenerateRefreshToken(t.Context(), original)
			require.NoError(t, err)
			require.NoError(t, store.CreateRefreshTokenSession(t.Context(), signature, "", original.Sanitize(nil)))

			request := newExchangeRequest(t, store.Clients["my-client"], newSpecSession(""), url.Values{
				consts.FormParameterSubjectTokenType: {consts.TokenTypeRFC8693RefreshToken},
				consts.FormParameterSubjectToken:     {token},
			})

			err = newRefreshTokenTypeHandler(cfg, store, strategy).HandleTokenEndpointRequest(t.Context(), request)

			require.ErrorIs(t, err, tc.expected)
			assert.Equal(t, 1, resolver.calls)

			if tc.debug != "" {
				assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), tc.debug)
			}
		})
	}
}

type failingDocumentResolver struct {
	err   error
	calls int
}

func (r *failingDocumentResolver) ResolveClientIDMetadataDocumentClient(_ context.Context, _ string) (oauth2.Client, error) {
	r.calls++

	return nil, r.err
}
