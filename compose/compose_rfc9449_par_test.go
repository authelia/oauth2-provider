// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package compose

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/token/jose"
	josejwt "authelia.com/provider/oauth2/token/jose/jwt"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestPARDPoPProofIsTreatedAsDPoPJKT(t *testing.T) {
	provider, store, _ := newPARProvider(t, false)

	key := newPARProofKey(t)
	jkt := thumbprintOf(t, key)

	r := newPARRequest(defaultPARForm(), signPARProof(t, key, "par-1", parEndpoint, nil))

	ctx := context.Background()

	requester, err := provider.NewPushedAuthorizeRequest(ctx, r)
	require.NoError(t, err)

	assert.Equal(t, jkt, requester.GetRequestForm().Get(consts.FormParameterDPoPJKT),
		"the proof thumbprint was not recorded as 'dpop_jkt' on the pushed request")

	responder, err := provider.NewPushedAuthorizeResponse(ctx, requester, &oauth2.DefaultSession{Subject: "peter"})
	require.NoError(t, err)

	requestURI := responder.GetRequestURI()
	require.NotEmpty(t, requestURI)

	authForm := url.Values{
		consts.FormParameterClientID:   []string{parClientID},
		consts.FormParameterRequestURI: []string{requestURI},
	}

	ar := httptest.NewRequest(http.MethodGet, "https://as.example.com/authorize?"+authForm.Encode(), nil)

	authRequester, err := provider.NewAuthorizeRequest(ctx, ar)
	require.NoError(t, err)

	assert.Equal(t, jkt, authRequester.GetRequestForm().Get(consts.FormParameterDPoPJKT),
		"the binding did not survive the pushed authorization request round trip")

	session := &oauth2.DefaultSession{Subject: "peter"}

	_, err = provider.NewAuthorizeResponse(ctx, authRequester, session)
	require.NoError(t, err)

	assert.Equal(t, jkt, session.GetDPoPJWKThumbprint())

	require.Len(t, store.AuthorizeCodes, 1)

	for _, code := range store.AuthorizeCodes {
		bound, ok := code.Requester.GetSession().(oauth2.DPoPBoundSession)
		require.True(t, ok)
		assert.Equal(t, jkt, bound.GetDPoPJWKThumbprint())
	}
}

func TestPARDPoPProofAndDPoPJKT(t *testing.T) {
	t.Run("ShouldAcceptMatching", func(t *testing.T) {
		provider, _, _ := newPARProvider(t, false)

		key := newPARProofKey(t)
		jkt := thumbprintOf(t, key)

		form := defaultPARForm()
		form.Set(consts.FormParameterDPoPJKT, jkt)

		r := newPARRequest(form, signPARProof(t, key, "par-match", parEndpoint, nil))

		requester, err := provider.NewPushedAuthorizeRequest(context.Background(), r)
		require.NoError(t, err)

		assert.Equal(t, jkt, requester.GetRequestForm().Get(consts.FormParameterDPoPJKT))
	})

	t.Run("ShouldRejectMismatched", func(t *testing.T) {
		provider, _, _ := newPARProvider(t, false)

		key := newPARProofKey(t)

		form := defaultPARForm()
		form.Set(consts.FormParameterDPoPJKT, thumbprintOf(t, newPARProofKey(t)))

		r := newPARRequest(form, signPARProof(t, key, "par-mismatch", parEndpoint, nil))

		_, err := provider.NewPushedAuthorizeRequest(context.Background(), r)
		require.Error(t, err)

		assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The 'dpop_jkt' parameter does not match the thumbprint of the public key in the DPoP proof.")
	})
}

func TestPARDPoPProofRejections(t *testing.T) {
	testCases := []struct {
		name     string
		proofs   func(t *testing.T, key *jose.JSONWebKey) []string
		expected string
	}{
		{
			name: "ShouldRejectMultipleProofs",
			proofs: func(t *testing.T, key *jose.JSONWebKey) []string {
				proof := signPARProof(t, key, "par-multi", parEndpoint, nil)

				return []string{proof, proof}
			},
			expected: "The DPoP proof is missing or invalid. The request contains more than one DPoP proof but only one is allowed.",
		},
		{
			name: "ShouldRejectProofBoundToAnotherEndpoint",
			proofs: func(t *testing.T, key *jose.JSONWebKey) []string {
				return []string{signPARProof(t, key, "par-htu", "https://as.example.com/token", nil)}
			},
			expected: "The DPoP proof is missing or invalid. The DPoP proof 'htu' claim 'https://as.example.com/token' does not match the request URI 'https://as.example.com/par'.",
		},
		{
			name: "ShouldRejectMalformedProof",
			proofs: func(t *testing.T, key *jose.JSONWebKey) []string {
				return []string{"not-a-jwt"}
			},
			expected: "The DPoP proof is missing or invalid. The DPoP proof could not be parsed: go-jose/go-jose: compact JWS format must have three parts.",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			provider, _, _ := newPARProvider(t, false)

			r := newPARRequest(defaultPARForm(), tc.proofs(t, newPARProofKey(t))...)

			_, err := provider.NewPushedAuthorizeRequest(context.Background(), r)
			require.Error(t, err)

			assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), tc.expected)
		})
	}
}

func TestPARWithoutDPoPProofIsUnaffected(t *testing.T) {
	t.Run("ShouldPassThroughBareDPoPJKT", func(t *testing.T) {
		provider, _, _ := newPARProvider(t, false)

		form := defaultPARForm()
		form.Set(consts.FormParameterDPoPJKT, "kM1FTfCFVzO9tGKBVBEAWCVoWZ2WcOK1EbSPxNjQfSw")

		requester, err := provider.NewPushedAuthorizeRequest(context.Background(), newPARRequest(form))
		require.NoError(t, err)

		assert.Equal(t, "kM1FTfCFVzO9tGKBVBEAWCVoWZ2WcOK1EbSPxNjQfSw", requester.GetRequestForm().Get(consts.FormParameterDPoPJKT))
	})

	t.Run("ShouldRejectMalformedBareDPoPJKT", func(t *testing.T) {
		provider, _, _ := newPARProvider(t, false)

		form := defaultPARForm()
		form.Set(consts.FormParameterDPoPJKT, "not-a-thumbprint")

		_, err := provider.NewPushedAuthorizeRequest(context.Background(), newPARRequest(form))
		require.Error(t, err)

		assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The 'dpop_jkt' parameter must be the base64url encoded SHA-256 JWK Thumbprint of the DPoP proof-of-possession public key, which is 43 characters long.")
	})

	t.Run("ShouldAcceptNoDPoPAtAll", func(t *testing.T) {
		provider, _, _ := newPARProvider(t, false)

		requester, err := provider.NewPushedAuthorizeRequest(context.Background(), newPARRequest(defaultPARForm()))
		require.NoError(t, err)

		assert.Empty(t, requester.GetRequestForm().Get(consts.FormParameterDPoPJKT))
	})
}

func TestPARDPoPNonceChallenge(t *testing.T) {
	provider, _, config := newPARProvider(t, true)

	key := newPARProofKey(t)

	ctx := context.Background()

	_, err := provider.NewPushedAuthorizeRequest(ctx, newPARRequest(defaultPARForm(), signPARProof(t, key, "par-nonce-1", parEndpoint, nil)))
	require.Error(t, err)

	assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), "Authorization server requires nonce in DPoP proof. The DPoP proof is missing the required 'nonce' claim.")

	rw := httptest.NewRecorder()
	provider.WritePushedAuthorizeError(ctx, rw, nil, err)

	nonce := rw.Header().Get(consts.HeaderDPoPNonce)
	require.NotEmpty(t, nonce)

	require.NotNil(t, config.GetDPoPStrategy(ctx))

	requester, err := provider.NewPushedAuthorizeRequest(ctx, newPARRequest(defaultPARForm(),
		signPARProof(t, key, "par-nonce-2", parEndpoint, map[string]any{consts.ClaimNonce: nonce})))
	require.NoError(t, err)

	assert.Equal(t, thumbprintOf(t, key), requester.GetRequestForm().Get(consts.FormParameterDPoPJKT))
}

func newPARProvider(t *testing.T, nonceRequired bool) (oauth2.Provider, *storage.MemoryStore, *oauth2.Config) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	store := storage.NewMemoryStore()

	config := &oauth2.Config{
		DPoPEnabled:                           true,
		DPoPNonceRequired:                     nonceRequired,
		GlobalSecret:                          []byte("some-cool-secret-that-is-32bytes"),
		RFC7591ClientRegistrationGlobalSecret: []byte("a-completely-different-secret-at-least-32b"),
	}

	provider := ComposeAllEnabled(config, store, key)

	store.Clients[parClientID] = &oauth2.DefaultClient{
		ID:            parClientID,
		ClientSecret:  oauth2.NewPlainTextClientSecret(parSecret),
		RedirectURIs:  []string{parRedirectURI},
		ResponseTypes: []string{consts.ResponseTypeAuthorizationCodeFlow},
		GrantTypes:    []string{consts.GrantTypeAuthorizationCode},
		Scopes:        []string{"foo"},
	}

	return provider, store, config
}

func newPARProofKey(t *testing.T) *jose.JSONWebKey {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	return &jose.JSONWebKey{Key: key, Algorithm: string(jose.ES256)}
}

func signPARProof(t *testing.T, key *jose.JSONWebKey, jti, htu string, claims map[string]any) string {
	t.Helper()

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.SignatureAlgorithm(key.Algorithm), Key: key},
		(&jose.SignerOptions{EmbedJWK: true}).WithType(jose.ContentType(jwt.JSONWebTokenTypeDPoP)),
	)
	require.NoError(t, err)

	all := map[string]any{
		consts.ClaimJWTID:      jti,
		consts.ClaimHTTPMethod: http.MethodPost,
		consts.ClaimHTTPURI:    htu,
		consts.ClaimIssuedAt:   time.Now().Unix(),
	}

	maps.Copy(all, claims)

	raw, err := josejwt.Signed(signer).Claims(all).Serialize()
	require.NoError(t, err)

	return raw
}

func thumbprintOf(t *testing.T, key *jose.JSONWebKey) string {
	t.Helper()

	pub := key.Public()

	jkt, err := jwt.ThumbprintJWK(&pub)
	require.NoError(t, err)

	return jkt
}

func newPARRequest(form url.Values, proofs ...string) *http.Request {
	form.Set(consts.FormParameterClientID, parClientID)
	form.Set(consts.FormParameterClientSecret, parSecret)

	r := httptest.NewRequest(http.MethodPost, parEndpoint, strings.NewReader(form.Encode()))
	r.Header.Set(consts.HeaderContentType, consts.ContentTypeApplicationURLEncodedForm)

	for _, proof := range proofs {
		r.Header.Add(consts.HeaderDPoP, proof)
	}

	return r
}

func defaultPARForm() url.Values {
	return url.Values{
		consts.FormParameterResponseType: []string{consts.ResponseTypeAuthorizationCodeFlow},
		consts.FormParameterRedirectURI:  []string{parRedirectURI},
		consts.FormParameterScope:        []string{"foo"},
		consts.FormParameterState:        []string{"abcdefghijklmnop"},
	}
}

const (
	parEndpoint    = "https://as.example.com/par"
	parRedirectURI = "https://rp.example.com/cb"
	parClientID    = "par-client"
	parSecret      = "par-client-secret"
)
