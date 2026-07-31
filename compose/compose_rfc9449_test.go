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

	"github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	oauth2handler "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/handler/openid"
	"authelia.com/provider/oauth2/handler/rfc9449"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/storage"
)

func TestDPoPFactory(t *testing.T) {
	config := &oauth2.Config{DPoPEnabled: true}
	store := storage.NewMemoryStore()

	h := DPoPFactory(config, store, nil)

	require.IsType(t, &rfc9449.Handler{}, h)
	assert.NotNil(t, config.DPoPStrategy)

	var _ oauth2.TokenEndpointHandler = h.(*rfc9449.Handler)
}

func TestDPoPAuthorizeFactory(t *testing.T) {
	config := &oauth2.Config{DPoPEnabled: true}
	store := storage.NewMemoryStore()

	h := DPoPAuthorizeFactory(config, store, nil)

	require.IsType(t, &rfc9449.AuthorizeHandler{}, h)

	var _ oauth2.AuthorizeEndpointHandler = h.(*rfc9449.AuthorizeHandler)
}

func TestDPoPAuthorizeFactoryPrecedesCodeIssuingFactories(t *testing.T) {
	config := &oauth2.Config{DPoPEnabled: true, GlobalSecret: []byte("some-cool-secret-that-is-32bytes")}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	ComposeAllEnabled(config, storage.NewMemoryStore(), key)

	handlers := config.GetAuthorizeEndpointHandlers(context.Background())

	var dpop = -1

	for i, h := range handlers {
		if _, ok := h.(*rfc9449.AuthorizeHandler); ok {
			dpop = i

			break
		}
	}

	require.NotEqual(t, -1, dpop, "the DPoP authorize handler is not registered by ComposeAllEnabled")

	for i, h := range handlers {
		switch h.(type) {
		case *oauth2handler.AuthorizeExplicitGrantHandler, *openid.OpenIDConnectExplicitHandler, *openid.OpenIDConnectHybridHandler:
			assert.Greater(t, i, dpop, "the code issuing handler %T at index %d runs before the DPoP authorize handler at index %d", h, i, dpop)
		}
	}
}

func TestDPoPFactoryPanicsWithoutUsableStrategy(t *testing.T) {
	config := &oauth2.Config{DPoPEnabled: true}

	assert.Panics(t, func() {
		DPoPFactory(config, struct{}{}, nil)
	})

	assert.Nil(t, config.DPoPStrategy)
}

// snapshotStore records the DPoP binding present on the session at the moment the authorization code session is handed
// to storage. The bundled MemoryStore retains the session pointer, so a mutation made after this point is still
// observable through it; a store which serializes the session on write, as any real one does, would not see it.
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

func TestDPoPJKTIsBoundBeforeTheAuthorizationCodeSessionIsPersisted(t *testing.T) {
	const jkt = "kM1FTfCFVzO9tGKBVBEAWCVoWZ2WcOK1EbSPxNjQfSw"

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	store := &snapshotStore{MemoryStore: storage.NewMemoryStore()}
	config := &oauth2.Config{DPoPEnabled: true, GlobalSecret: []byte("some-cool-secret-that-is-32bytes")}

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

	require.True(t, store.persisted, "the authorization code session was never persisted")

	assert.Equal(t, jkt, store.jkt)
}

func TestUnknownGrantTypeIsNotSatisfiedByTheDPoPHandler(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	store := storage.NewMemoryStore()
	config := &oauth2.Config{DPoPEnabled: true, GlobalSecret: []byte("some-cool-secret-that-is-32bytes")}

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

	rfc := oauth2.ErrorToRFC6749Error(err)

	assert.Equal(t, http.StatusBadRequest, rfc.CodeField)
	assert.Equal(t, "invalid_request", rfc.ErrorField)

	assert.Empty(t, store.DPoPProofJTIs, "an unauthenticated caller wrote a replay marker to the store")
}
