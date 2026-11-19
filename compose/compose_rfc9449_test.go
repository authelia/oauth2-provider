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
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/jose"
	josejwt "authelia.com/provider/jose/jwt"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/handler/openid"
	"authelia.com/provider/oauth2/handler/rfc9449"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/gen"
	"authelia.com/provider/oauth2/storage"
)

func TestDPoPFactory(t *testing.T) {
	config := &oauth2.Config{DPoPEnabled: true}
	store := storage.NewMemoryStore()

	h := DPoPTokenFactory(config, store, nil)

	require.IsType(t, &rfc9449.Handler{}, h)
	assert.NotNil(t, config.DPoPStrategy)

	var _ oauth2.TokenEndpointBindingHandler = h.(*rfc9449.Handler)
}

func TestDPoPAuthorizeFactory(t *testing.T) {
	config := &oauth2.Config{DPoPEnabled: true}
	store := storage.NewMemoryStore()

	h := DPoPAuthorizeFactory(config, store, nil)

	require.IsType(t, &rfc9449.AuthorizeHandler{}, h)

	var _ oauth2.AuthorizeEndpointBindingHandler = h.(*rfc9449.AuthorizeHandler)
}

// RFC 10027 Section 6.1.12.
func TestComposeAllEnabledBindsTheDeviceCodeToTheDPoPJKT(t *testing.T) {
	const jkt = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"

	testCases := []struct {
		name     string
		form     url.Values
		expected string
		err      error
	}{
		{name: "ShouldRecordTheDPoPJKT", form: url.Values{consts.FormParameterDPoPJKT: {jkt}}, expected: jkt},
		{name: "ShouldRecordNothingWithoutADPoPJKT", form: url.Values{}},
		{name: "ShouldRejectAnInvalidDPoPJKT", form: url.Values{consts.FormParameterDPoPJKT: {"invalid"}}, err: oauth2.ErrInvalidRequest},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			store := storage.NewMemoryStore()

			provider := ComposeAllEnabled(&oauth2.Config{
				DPoPEnabled:                           true,
				GlobalSecret:                          []byte("some-cool-secret-that-is-32bytes"),
				RFC7591ClientRegistrationGlobalSecret: []byte("a-completely-different-secret-at-least-32b"),
				RFC8628UserVerificationURL:            "https://example.com/device",
			}, store, gen.MustRSAKey())

			request := oauth2.NewDeviceAuthorizeRequest()
			request.Client = &oauth2.DefaultClient{ID: "device", GrantTypes: oauth2.Arguments{consts.GrantTypeOAuthDeviceCode}}
			request.Form = tc.form

			_, err := provider.NewRFC862DeviceAuthorizeResponse(t.Context(), request, openid.NewDefaultSession())

			if tc.err != nil {
				require.ErrorIs(t, err, tc.err)

				return
			}

			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

			stored, err := store.GetDeviceCodeSession(t.Context(), request.GetDeviceCodeSignature(), openid.NewDefaultSession())
			require.NoError(t, err)

			session, ok := stored.GetSession().(oauth2.DPoPBoundSession)
			require.True(t, ok)

			assert.Equal(t, tc.expected, session.GetDPoPJWKThumbprint())
			assert.Equal(t, tc.expected, session.GetRequestedDPoPJWKThumbprint())
		})
	}
}

func TestDPoPFactoryPanicsWithoutUsableStrategy(t *testing.T) {
	config := &oauth2.Config{DPoPEnabled: true}

	assert.Panics(t, func() {
		DPoPTokenFactory(config, struct{}{}, nil)
	})

	assert.Nil(t, config.DPoPStrategy)
}

func TestDPoPTokenFactoryStatelessNonceSecret(t *testing.T) {
	assert.PanicsWithValue(t, "oauth2: DPoPFactory requires Config.GlobalSecret to be at least 32 bytes when Config.DPoPNonceStateless is enabled, as the stateless nonce key is derived from it", func() {
		DPoPTokenFactory(&oauth2.Config{DPoPNonceStateless: true, GlobalSecret: make([]byte, 31)}, storage.NewMemoryStore(), nil)
	})

	assert.NotPanics(t, func() {
		DPoPTokenFactory(&oauth2.Config{DPoPNonceStateless: true, GlobalSecret: make([]byte, 32)}, storage.NewMemoryStore(), nil)
	})
}

func TestDPoPJKTIsBoundBeforeTheAuthorizationCodeSessionIsPersisted(t *testing.T) {
	const jkt = "kM1FTfCFVzO9tGKBVBEAWCVoWZ2WcOK1EbSPxNjQfSw"

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	store := &snapshotStore{MemoryStore: storage.NewMemoryStore()}
	config := &oauth2.Config{DPoPEnabled: true, GlobalSecret: []byte("some-cool-secret-that-is-32bytes"), RFC7591ClientRegistrationGlobalSecret: []byte("a-completely-different-secret-at-least-32b")}

	provider := ComposeAllEnabled(config, store, key)

	client := &oauth2.DefaultClient{
		ID:            "test-client",
		RedirectURIs:  []string{"https://rp.example.com/cb"},
		ResponseTypes: []string{consts.ResponseTypeAuthorizationCodeFlow},
		GrantTypes:    []string{consts.GrantTypeAuthorizationCode},
		Scopes:        []string{"foo"},
	}

	store.Clients[client.ID] = client

	request := oauth2.NewAuthorizeRequest()
	request.Client = client
	request.Form = url.Values{
		consts.FormParameterDPoPJKT:     []string{jkt},
		consts.FormParameterRedirectURI: []string{"https://rp.example.com/cb"},
	}
	request.ResponseTypes = oauth2.Arguments{consts.ResponseTypeAuthorizationCodeFlow}
	request.RedirectURI, _ = url.Parse("https://rp.example.com/cb")
	request.State = "abcdefghijklmnop"
	request.GrantScope("foo")

	session := &oauth2.DefaultSession{Subject: "peter"}

	_, err = provider.NewAuthorizeResponse(context.Background(), request, session)
	require.NoError(t, err)

	require.True(t, store.persisted)

	assert.Equal(t, jkt, store.jkt)
}

func TestUnknownGrantTypeIsNotSatisfiedByTheDPoPHandler(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	store := storage.NewMemoryStore()
	config := &oauth2.Config{DPoPEnabled: true, GlobalSecret: []byte("some-cool-secret-that-is-32bytes"), RFC7591ClientRegistrationGlobalSecret: []byte("a-completely-different-secret-at-least-32b")}

	provider := ComposeAllEnabled(config, store, key)

	proofKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: &jose.JSONWebKey{Key: proofKey, Algorithm: string(jose.ES256)}},
		(&jose.SignerOptions{EmbedJWK: true}).WithType(jose.ContentType(consts.JSONWebTokenTypeDPoP)),
	)
	require.NoError(t, err)

	proof, err := josejwt.Signed(signer).Claims(map[string]any{
		consts.ClaimJWTID:      "unknown-grant-poc",
		consts.ClaimHTTPMethod: http.MethodPost,
		consts.ClaimHTTPURI:    "https://as.example.com/token",
		consts.ClaimIssuedAt:   time.Now().Unix(),
	}).Serialize()
	require.NoError(t, err)

	form := url.Values{consts.FormParameterGrantType: []string{"urn:example:not-a-real-grant"}}

	r := httptest.NewRequest(http.MethodPost, "https://as.example.com/token", strings.NewReader(form.Encode()))
	r.Header.Set(consts.HeaderContentType, consts.ContentTypeApplicationURLEncodedForm)
	r.Header.Set(consts.HeaderDPoP, proof)

	_, err = provider.NewAccessRequest(context.Background(), r, &oauth2.DefaultSession{})
	require.Error(t, err)

	assert.Equal(t, http.StatusBadRequest, oauth2.ErrorToRFC6749Error(err).CodeField)
	assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), "The authorization grant type is not supported by the authorization server. The client with id '' requested grant type 'urn:example:not-a-real-grant' which is invalid, unknown, not supported, or not configured to be handled.")

	assert.Empty(t, store.DPoPProofJTIs)
}

type snapshotStore struct {
	*storage.MemoryStore

	jkt       string
	persisted bool
}

func (s *snapshotStore) CreateAuthorizeCodeSession(ctx context.Context, code string, req oauth2.Requester) error {
	s.persisted = true

	if session, ok := req.GetSession().(oauth2.DPoPBoundSession); ok {
		s.jkt = session.GetDPoPJWKThumbprint()
	}

	return s.MemoryStore.CreateAuthorizeCodeSession(ctx, code, req)
}
