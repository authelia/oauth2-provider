// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/storage"
)

func TestAuthorizeCode_TokenRequestRedirectURIOptional(t *testing.T) {
	const (
		redirectA = "https://client.example.com/a"
		redirectB = "https://client.example.com/b"
		verifier  = "dBjftJeZ4CVP-mJ0dRhn6kW1Rgrt2kZhAlJ1cqVkXNM"
		challenge = "k9Rs5yroLXuCEojrbNsT-TikmQIGrrrg7ePsFgVfZSc"
		mismatch  = "The 'redirect_uri' from this request does not match the one from the authorize request."
	)

	enabled, disabled := true, false

	testCases := []struct {
		name     string
		global   bool
		client   *bool
		pkce     bool
		verified bool
		scopes   oauth2.Arguments
		redirect []string
		err      string
	}{
		{
			name:     "ShouldRejectOmittedRedirectURIWhenDisabled",
			pkce:     true,
			verified: true,
			scopes:   oauth2.Arguments{"foo"},
			err:      mismatch,
		},
		{
			name:     "ShouldAcceptMatchingRedirectURIWhenDisabled",
			pkce:     true,
			verified: true,
			scopes:   oauth2.Arguments{"foo"},
			redirect: []string{redirectA},
		},
		{
			name:     "ShouldAcceptOmittedRedirectURIWithPKCE",
			global:   true,
			pkce:     true,
			verified: true,
			scopes:   oauth2.Arguments{"foo"},
		},
		{
			name:     "ShouldAcceptMatchingRedirectURIWithPKCE",
			global:   true,
			pkce:     true,
			verified: true,
			scopes:   oauth2.Arguments{"foo"},
			redirect: []string{redirectA},
		},
		{
			name:     "ShouldRejectMismatchedRedirectURIWithPKCE",
			global:   true,
			pkce:     true,
			verified: true,
			scopes:   oauth2.Arguments{"foo"},
			redirect: []string{redirectB},
			err:      mismatch,
		},
		{
			name:     "ShouldRejectEmptyRedirectURIWithPKCE",
			global:   true,
			pkce:     true,
			verified: true,
			scopes:   oauth2.Arguments{"foo"},
			redirect: []string{""},
			err:      mismatch,
		},
		{
			name:     "ShouldRejectOmittedRedirectURIForOpenID",
			global:   true,
			pkce:     true,
			verified: true,
			scopes:   oauth2.Arguments{consts.ScopeOpenID},
			err:      mismatch,
		},
		{
			name:     "ShouldRejectOmittedRedirectURIWithoutPKCE",
			global:   true,
			verified: true,
			scopes:   oauth2.Arguments{"foo"},
			err:      mismatch,
		},
		{
			name:   "ShouldRejectOmittedRedirectURIWhenPKCEIsNotVerified",
			global: true,
			pkce:   true,
			scopes: oauth2.Arguments{"foo"},
			err:    mismatch,
		},
		{
			name:     "ShouldAcceptOmittedRedirectURIWhenClientEnables",
			client:   &enabled,
			pkce:     true,
			verified: true,
			scopes:   oauth2.Arguments{"foo"},
		},
		{
			name:     "ShouldRejectOmittedRedirectURIWhenClientDisables",
			global:   true,
			client:   &disabled,
			pkce:     true,
			verified: true,
			scopes:   oauth2.Arguments{"foo"},
			err:      mismatch,
		},
		{
			name:     "ShouldRejectMismatchedRedirectURIWhenClientEnables",
			client:   &enabled,
			pkce:     true,
			verified: true,
			scopes:   oauth2.Arguments{"foo"},
			redirect: []string{redirectB},
			err:      mismatch,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			store := storage.NewMemoryStore()
			strategy := &hmacshaStrategy

			config := &oauth2.Config{
				ScopeStrategy:                   oauth2.HierarchicScopeStrategy,
				AudienceStrategy:                oauth2.DefaultAudienceStrategy,
				AccessTokenLifespan:             time.Minute,
				AuthorizeCodeLifespan:           time.Minute,
				TokenRequestRedirectURIOptional: tc.global,
			}

			if tc.verified {
				config.TokenEndpointHandlers = oauth2.TokenEndpointHandlers{&codeChallengeMethodsHandler{}}
			}

			handler := AuthorizeExplicitGrantHandler{
				CoreStorage:            store,
				TokenRevocationStorage: store,
				AuthorizeCodeStrategy:  strategy,
				AccessTokenStrategy:    strategy,
				RefreshTokenStrategy:   strategy,
				Config:                 config,
			}

			var client oauth2.Client = &oauth2.DefaultClient{
				ID:            "foo",
				GrantTypes:    oauth2.Arguments{consts.GrantTypeAuthorizationCode},
				ResponseTypes: oauth2.Arguments{consts.ResponseTypeAuthorizationCodeFlow},
				RedirectURIs:  []string{redirectA, redirectB},
				Scopes:        []string{"foo", consts.ScopeOpenID},
			}

			if tc.client != nil {
				client = &tokenRequestRedirectURIOptionalClient{DefaultClient: client.(*oauth2.DefaultClient), optional: *tc.client}
			}

			form := url.Values{consts.FormParameterRedirectURI: []string{redirectA}}

			if tc.pkce {
				form.Set(consts.FormParameterCodeChallenge, challenge)
				form.Set(consts.FormParameterCodeChallengeMethod, consts.PKCEChallengeMethodSHA256)
			}

			authorize := &oauth2.AuthorizeRequest{
				ResponseTypes: oauth2.Arguments{consts.ResponseTypeAuthorizationCodeFlow},
				RedirectURI:   parseUrl(redirectA),
				Request: oauth2.Request{
					Client:         client,
					Form:           form,
					RequestedScope: tc.scopes,
					GrantedScope:   tc.scopes,
					Session:        &oauth2.DefaultSession{},
					RequestedAt:    time.Now().UTC(),
				},
			}

			aresp := oauth2.NewAuthorizeResponse()
			require.NoError(t, handler.HandleAuthorizeEndpointRequest(t.Context(), authorize, aresp))

			code := aresp.GetCode()
			require.NotEmpty(t, code)

			access := &oauth2.AccessRequest{
				GrantTypes: oauth2.Arguments{consts.GrantTypeAuthorizationCode},
				Request: oauth2.Request{
					Client: client,
					Form: url.Values{
						consts.FormParameterAuthorizationCode: []string{code},
						consts.FormParameterCodeVerifier:      []string{verifier},
					},
					Session:     &oauth2.DefaultSession{},
					RequestedAt: time.Now().UTC(),
				},
			}

			if tc.redirect != nil {
				access.Form[consts.FormParameterRedirectURI] = tc.redirect
			}

			// OAuth 2.1 Section 10.2.
			err := handler.HandleTokenEndpointRequest(t.Context(), access)

			if tc.err == "" {
				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
			} else {
				require.ErrorIs(t, err, oauth2.ErrInvalidGrant)
				require.ErrorContains(t, oauth2.ErrorToDebugRFC6749Error(err), tc.err)
			}

			require.NoError(t, store.InvalidateAuthorizeCodeSession(t.Context(), strategy.AuthorizeCodeSignature(t.Context(), code)))

			// OAuth 2.1 Section 7.5.3.
			err = handler.HandleTokenEndpointRequest(t.Context(), access)

			require.ErrorIs(t, err, oauth2.ErrInvalidGrant)

			if tc.err == "" {
				require.ErrorContains(t, oauth2.ErrorToDebugRFC6749Error(err), "The authorization code has already been used.")
			} else {
				require.ErrorContains(t, oauth2.ErrorToDebugRFC6749Error(err), tc.err)
			}
		})
	}
}

type codeChallengeMethodsHandler struct {
	oauth2.TokenEndpointHandler
}

func (h *codeChallengeMethodsHandler) CodeChallengeMethodsSupported(_ context.Context) (methods []string) {
	return []string{consts.PKCEChallengeMethodSHA256}
}

func (h *codeChallengeMethodsHandler) CanHandleTokenEndpointRequest(_ context.Context, _ oauth2.AccessRequester) (handle bool) {
	return false
}

type tokenRequestRedirectURIOptionalClient struct {
	*oauth2.DefaultClient

	optional bool
}

func (c *tokenRequestRedirectURIOptionalClient) GetTokenRequestRedirectURIOptional() (optional bool) {
	return c.optional
}
