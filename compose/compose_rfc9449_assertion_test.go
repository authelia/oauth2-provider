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
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/jose"
	josejwt "authelia.com/provider/jose/jwt"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/storage"
)

func TestTokenEndpointDPoPNonceRoundTripKeepsJWTBearerAssertion(t *testing.T) {
	provider, form := newAssertionProvider(t, true)

	proofKey := newPARProofKey(t)

	_, err := tokenRequest(t, provider, form(), signPARProof(t, proofKey, "assertion-proof-1", rtTokenEndpoint, nil))
	require.Error(t, err)

	assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), "Authorization server requires nonce in DPoP proof. The DPoP proof is missing the required 'nonce' claim.")

	rw := httptest.NewRecorder()
	provider.WriteAccessError(context.Background(), rw, nil, err)

	nonce := rw.Header().Get(consts.HeaderDPoPNonce)
	require.NotEmpty(t, nonce)

	response, err := tokenRequest(t, provider, form(),
		signPARProof(t, proofKey, "assertion-proof-2", rtTokenEndpoint, map[string]any{consts.ClaimNonce: nonce}))
	require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

	assert.Equal(t, oauth2.DPoPAccessToken, response.GetTokenType())

	_, err = tokenRequest(t, provider, form(),
		signPARProof(t, proofKey, "assertion-proof-3", rtTokenEndpoint, map[string]any{consts.ClaimNonce: nonce}))
	require.Error(t, err)

	assert.ErrorIs(t, err, oauth2.ErrInvalidGrant)
}

func TestTokenEndpointJWTBearerAssertionIsRedeemedOnceByConcurrentRequests(t *testing.T) {
	provider, form := newAssertionProvider(t, false)

	const n = 2

	var (
		ready, done sync.WaitGroup
		start       = make(chan struct{})
		errs        = make([]error, n)
		responses   = make([]oauth2.AccessResponder, n)
	)

	for i := range n {
		values := form()
		values.Set(consts.FormParameterClientID, rtClientID)
		values.Set(consts.FormParameterClientSecret, rtSecret)

		r := httptest.NewRequest(http.MethodPost, rtTokenEndpoint, strings.NewReader(values.Encode()))
		r.Header.Set(consts.HeaderContentType, consts.ContentTypeApplicationURLEncodedForm)

		requester, err := provider.NewAccessRequest(context.Background(), r, &oauth2.DefaultSession{})
		require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

		ready.Add(1)
		done.Add(1)

		go func() {
			defer done.Done()

			ready.Done()
			<-start

			responses[i], errs[i] = provider.NewAccessResponse(context.Background(), requester)
		}()
	}

	ready.Wait()
	close(start)
	done.Wait()

	var succeeded int

	for i, err := range errs {
		if err == nil {
			succeeded++

			assert.NotEmpty(t, responses[i].GetAccessToken())

			continue
		}

		assert.ErrorIs(t, err, oauth2.ErrInvalidGrant)
	}

	assert.Equal(t, 1, succeeded)
}

func newAssertionProvider(t *testing.T, nonceRequired bool) (provider oauth2.Provider, form func() url.Values) {
	t.Helper()

	const (
		issuer  = "https://issuer.example.com"
		subject = "peter"
		kid     = "assertion-key"
	)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	store := storage.NewMemoryStore()
	config := &oauth2.Config{
		DPoPEnabled:                           true,
		DPoPNonceRequired:                     nonceRequired,
		GlobalSecret:                          []byte("some-cool-secret-that-is-32bytes"),
		RFC7591ClientRegistrationGlobalSecret: []byte("a-completely-different-secret-at-least-32b"),
		AllowedJWTAssertionAudiences:          []string{rtTokenEndpoint},
	}

	provider = ComposeAllEnabled(config, store, key)

	store.Clients[rtClientID] = &oauth2.DefaultClient{
		ID:           rtClientID,
		ClientSecret: oauth2.NewPlainTextClientSecret(rtSecret),
		GrantTypes:   []string{consts.GrantTypeOAuthJWTBearer},
	}

	assertionKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	store.IssuerPublicKeys[issuer] = storage.IssuerPublicKeys{
		Issuer: issuer,
		KeysBySub: map[string]storage.SubjectPublicKeys{
			subject: {
				Subject: subject,
				Keys: map[string]storage.PublicKeyScopes{
					kid: {Key: &jose.JSONWebKey{Key: assertionKey.Public(), KeyID: kid, Algorithm: string(jose.RS256), Use: consts.JSONWebTokenUseSignature}},
				},
			},
		},
	}

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: assertionKey, KeyID: kid}},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	require.NoError(t, err)

	assertion, err := josejwt.Signed(signer).Claims(josejwt.Claims{
		Issuer:   issuer,
		Subject:  subject,
		Audience: josejwt.Audience{rtTokenEndpoint},
		Expiry:   josejwt.NewNumericDate(time.Now().Add(time.Hour)),
		IssuedAt: josejwt.NewNumericDate(time.Now()),
		ID:       "assertion-1",
	}).Serialize()
	require.NoError(t, err)

	return provider, func() url.Values {
		return url.Values{
			consts.FormParameterGrantType: []string{consts.GrantTypeOAuthJWTBearer},
			consts.FormParameterAssertion: []string{assertion},
		}
	}
}
