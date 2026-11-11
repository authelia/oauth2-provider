// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package compose

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/gen"
	"authelia.com/provider/oauth2/storage"
)

// RFC 9207 Section 2.
func TestComposeReturnsTheIssuerAuthorizationResponseParameter(t *testing.T) {
	const (
		issuer      = "https://as.example.com"
		clientID    = "rfc9207-client"
		redirectURI = "https://client.example.com/callback"
	)

	testCases := []struct {
		name     string
		config   *oauth2.Config
		expected string
	}{
		{
			name:     "ShouldReturnTheIssuer",
			config:   &oauth2.Config{Issuer: issuer},
			expected: issuer,
		},
		{
			name:   "ShouldNotReturnTheIssuerWhenDisabled",
			config: &oauth2.Config{Issuer: issuer, DisableAuthorizationServerIdentification: true},
		},
		{
			name:   "ShouldNotReturnTheIssuerWithoutAnIssuer",
			config: &oauth2.Config{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tc.config.GlobalSecret = []byte("some-cool-secret-that-is-32bytes")
			tc.config.RFC7591ClientRegistrationGlobalSecret = []byte("a-completely-different-secret-at-least-32b")

			store := storage.NewMemoryStore()
			store.Clients[clientID] = &oauth2.DefaultClient{
				ID:            clientID,
				Public:        true,
				RedirectURIs:  []string{redirectURI},
				ResponseTypes: []string{consts.ResponseTypeAuthorizationCodeFlow},
				GrantTypes:    []string{consts.GrantTypeAuthorizationCode},
			}

			provider := ComposeAllEnabled(tc.config, store, gen.MustRSAKey())

			sum := sha256.Sum256([]byte(rand.Text() + rand.Text()))

			form := url.Values{
				consts.FormParameterClientID:            {clientID},
				consts.FormParameterResponseType:        {consts.ResponseTypeAuthorizationCodeFlow},
				consts.FormParameterRedirectURI:         {redirectURI},
				consts.FormParameterState:               {"abcdefghijklmnop"},
				consts.FormParameterCodeChallenge:       {base64.RawURLEncoding.EncodeToString(sum[:])},
				consts.FormParameterCodeChallengeMethod: {consts.PKCEChallengeMethodSHA256},
			}

			requester, err := provider.NewAuthorizeRequest(context.Background(), httptest.NewRequest(http.MethodGet, issuer+"/authorize?"+form.Encode(), nil))
			require.NoError(t, err)

			responder, err := provider.NewAuthorizeResponse(context.Background(), requester, &oauth2.DefaultSession{Subject: "peter"})
			require.NoError(t, err)

			rw := httptest.NewRecorder()

			provider.WriteAuthorizeResponse(context.Background(), rw, requester, responder)

			location, err := url.Parse(rw.Header().Get(consts.HeaderLocation))
			require.NoError(t, err)

			assert.NotEmpty(t, location.Query().Get(consts.FormParameterAuthorizationCode))
			assert.Equal(t, tc.expected, location.Query().Get(consts.FormParameterIssuer))
		})
	}
}

func TestComposeRegistersTheIssuerAuthorizationResponseParameterHandlerOnce(t *testing.T) {
	config := &oauth2.Config{GlobalSecret: []byte("some-cool-secret-that-is-32bytes")}
	config.ResponseModeParameterHandlers.Append(&oauth2.RFC9207ResponseModeParameterHandler{Config: config})

	_ = Compose(config, storage.NewMemoryStore(), NewOAuth2HMACStrategy(config), OAuth2AuthorizeExplicitFactory)

	require.Len(t, config.ResponseModeParameterHandlers, 1)
	assert.IsType(t, &oauth2.RFC9207ResponseModeParameterHandler{}, config.ResponseModeParameterHandlers[0])
}
