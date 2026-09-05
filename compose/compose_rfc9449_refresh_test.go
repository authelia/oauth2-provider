// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package compose

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/storage"
)

func TestDPoPIsEnforcedOnRefreshTokenRequests(t *testing.T) {
	provider, _ := newRefreshProvider(t)

	key := newPARProofKey(t)
	jkt := thumbprintOf(t, key)

	code := authorizeForCode(t, provider, jkt)

	response, err := tokenRequest(t, provider, url.Values{
		consts.FormParameterGrantType:         []string{consts.GrantTypeAuthorizationCode},
		consts.FormParameterAuthorizationCode: []string{code},
		consts.FormParameterRedirectURI:       []string{rtRedirectURI},
	}, signPARProof(t, key, "rt-1", rtTokenEndpoint, nil))
	require.NoError(t, err)

	assert.Equal(t, oauth2.DPoPAccessToken, response.GetTokenType())

	refreshToken, _ := response.ToMap()[consts.AccessResponseRefreshToken].(string)
	require.NotEmpty(t, refreshToken)

	t.Run("ShouldRejectRefreshWithoutAProof", func(t *testing.T) {
		_, err := tokenRequest(t, provider, url.Values{
			consts.FormParameterGrantType:    []string{consts.GrantTypeRefreshToken},
			consts.FormParameterRefreshToken: []string{refreshToken},
		}, "")

		require.Error(t, err)
		assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), "The DPoP proof is missing or invalid. The request requires a DPoP proof but none was provided.")
	})

	t.Run("ShouldRejectRefreshWithAnotherKey", func(t *testing.T) {
		_, err := tokenRequest(t, provider, url.Values{
			consts.FormParameterGrantType:    []string{consts.GrantTypeRefreshToken},
			consts.FormParameterRefreshToken: []string{refreshToken},
		}, signPARProof(t, newPARProofKey(t), "rt-other", rtTokenEndpoint, nil))

		require.Error(t, err)
		assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), "The DPoP proof is missing or invalid. The DPoP proof key does not match the key the grant is bound to.")
	})

	t.Run("ShouldAcceptRefreshWithTheBoundKeyAndStayBound", func(t *testing.T) {
		response, err := tokenRequest(t, provider, url.Values{
			consts.FormParameterGrantType:    []string{consts.GrantTypeRefreshToken},
			consts.FormParameterRefreshToken: []string{refreshToken},
		}, signPARProof(t, key, "rt-2", rtTokenEndpoint, nil))

		require.NoError(t, err)

		assert.Equal(t, oauth2.DPoPAccessToken, response.GetTokenType())

		rotated, _ := response.ToMap()[consts.AccessResponseRefreshToken].(string)
		require.NotEmpty(t, rotated)

		_, err = tokenRequest(t, provider, url.Values{
			consts.FormParameterGrantType:    []string{consts.GrantTypeRefreshToken},
			consts.FormParameterRefreshToken: []string{rotated},
		}, "")

		require.Error(t, err)
		assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), "The DPoP proof is missing or invalid. The request requires a DPoP proof but none was provided.")
	})
}

func TestTokenEndpointDPoPNonceRoundTrip(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	store := storage.NewMemoryStore()
	config := &oauth2.Config{DPoPEnabled: true, DPoPNonceRequired: true, GlobalSecret: []byte("some-cool-secret-that-is-32bytes"), RFC7591ClientRegistrationGlobalSecret: []byte("a-completely-different-secret-at-least-32b")}

	provider := ComposeAllEnabled(config, store, key)

	store.Clients[rtClientID] = &oauth2.DefaultClient{
		ID:            rtClientID,
		ClientSecret:  oauth2.NewPlainTextClientSecret(rtSecret),
		RedirectURIs:  []string{rtRedirectURI},
		ResponseTypes: []string{consts.ResponseTypeAuthorizationCodeFlow},
		GrantTypes:    []string{consts.GrantTypeAuthorizationCode, consts.GrantTypeRefreshToken},
		Scopes:        []string{consts.ScopeOffline},
	}

	proofKey := newPARProofKey(t)
	code := authorizeForCode(t, provider, thumbprintOf(t, proofKey))

	ctx := context.Background()

	form := func() url.Values {
		return url.Values{
			consts.FormParameterGrantType:         []string{consts.GrantTypeAuthorizationCode},
			consts.FormParameterAuthorizationCode: []string{code},
			consts.FormParameterRedirectURI:       []string{rtRedirectURI},
		}
	}

	_, err = tokenRequest(t, provider, form(), signPARProof(t, proofKey, "nonce-1", rtTokenEndpoint, nil))
	require.Error(t, err)

	assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), "Authorization server requires nonce in DPoP proof. The DPoP proof is missing the required 'nonce' claim.")

	rw := httptest.NewRecorder()
	provider.WriteAccessError(ctx, rw, nil, err)

	nonce := rw.Header().Get(consts.HeaderDPoPNonce)
	require.NotEmpty(t, nonce)

	response, err := tokenRequest(t, provider, form(),
		signPARProof(t, proofKey, "nonce-2", rtTokenEndpoint, map[string]any{consts.ClaimNonce: nonce}))
	require.NoError(t, err)

	assert.Equal(t, oauth2.DPoPAccessToken, response.GetTokenType())

	rw = httptest.NewRecorder()

	requester := oauth2.NewAccessRequest(&oauth2.DefaultSession{})
	requester.Session.(*oauth2.DefaultSession).SetDPoPJWKThumbprint(thumbprintOf(t, proofKey))

	provider.WriteAccessResponse(ctx, rw, requester, response)

	assert.NotEmpty(t, rw.Header().Get(consts.HeaderDPoPNonce))
}

func newRefreshProvider(t *testing.T) (oauth2.Provider, *storage.MemoryStore) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	store := storage.NewMemoryStore()
	config := &oauth2.Config{DPoPEnabled: true, GlobalSecret: []byte("some-cool-secret-that-is-32bytes"), RFC7591ClientRegistrationGlobalSecret: []byte("a-completely-different-secret-at-least-32b")}

	provider := ComposeAllEnabled(config, store, key)

	store.Clients[rtClientID] = &oauth2.DefaultClient{
		ID:            rtClientID,
		ClientSecret:  oauth2.NewPlainTextClientSecret(rtSecret),
		RedirectURIs:  []string{rtRedirectURI},
		ResponseTypes: []string{consts.ResponseTypeAuthorizationCodeFlow},
		GrantTypes:    []string{consts.GrantTypeAuthorizationCode, consts.GrantTypeRefreshToken},
		Scopes:        []string{consts.ScopeOffline},
	}

	return provider, store
}

func tokenRequest(t *testing.T, provider oauth2.Provider, form url.Values, proof string) (oauth2.AccessResponder, error) {
	t.Helper()

	form.Set(consts.FormParameterClientID, rtClientID)
	form.Set(consts.FormParameterClientSecret, rtSecret)

	r := httptest.NewRequest(http.MethodPost, rtTokenEndpoint, strings.NewReader(form.Encode()))
	r.Header.Set(consts.HeaderContentType, consts.ContentTypeApplicationURLEncodedForm)

	if proof != "" {
		r.Header.Set(consts.HeaderDPoP, proof)
	}

	requester, err := provider.NewAccessRequest(context.Background(), r, &oauth2.DefaultSession{})
	if err != nil {
		return nil, err
	}

	return provider.NewAccessResponse(context.Background(), requester)
}

func authorizeForCode(t *testing.T, provider oauth2.Provider, jkt string) string {
	t.Helper()

	form := url.Values{
		consts.FormParameterClientID:     []string{rtClientID},
		consts.FormParameterResponseType: []string{consts.ResponseTypeAuthorizationCodeFlow},
		consts.FormParameterRedirectURI:  []string{rtRedirectURI},
		consts.FormParameterScope:        []string{consts.ScopeOffline},
		consts.FormParameterState:        []string{"abcdefghijklmnop"},
		consts.FormParameterDPoPJKT:      []string{jkt},
	}

	r := httptest.NewRequest(http.MethodGet, "https://as.example.com/authorize?"+form.Encode(), nil)

	requester, err := provider.NewAuthorizeRequest(context.Background(), r)
	require.NoError(t, err)

	requester.GrantScope(consts.ScopeOffline)

	responder, err := provider.NewAuthorizeResponse(context.Background(), requester, &oauth2.DefaultSession{Subject: "peter"})
	require.NoError(t, err)

	code := responder.GetParameters().Get(consts.FormParameterAuthorizationCode)
	require.NotEmpty(t, code)

	return code
}

const (
	rtTokenEndpoint = "https://as.example.com/token"
	rtClientID      = "refresh-client"
	rtSecret        = "refresh-client-secret"
	rtRedirectURI   = "https://rp.example.com/cb"
)
