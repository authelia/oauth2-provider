// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc9449

import (
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/jose"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/token/jwt"
)

const (
	testBackChannelURL      = "https://as.example.com/bc-authorize"
	testBackChannelAliasURL = "https://mtls.as.example.com/bc-authorize"
)

func TestBackChannelDPoPProof(t *testing.T) {
	const otherJKT = "dnfb1T9jil_gOhti60baHs_WD_a4D8JN9VDJXbmBmGw"

	stores := []struct {
		name string
		new  func() Storage
	}{
		{name: "MemoryStore", new: func() Storage { return storage.NewMemoryStore() }},
		{name: "HydratingMemoryStore", new: func() Storage { return storage.NewHydratingMemoryStore() }},
	}

	for _, st := range stores {
		t.Run(st.name, func(t *testing.T) {
			newHandler := func() *Handler {
				h, _, cfg := newTestHandler(false)

				cfg.urls = oauth2.EndpointURLs{
					BackChannelAuthentication: testBackChannelURL,
					MutualTLSAliases:          oauth2.RFC8705MutualTLSEndpointAliases{BackChannelAuthentication: testBackChannelAliasURL},
				}

				h.Strategy = NewDefaultStrategy(cfg, st.new())
				cfg.strategy = h.Strategy

				return h
			}

			t.Run("ShouldRecordTheProofKey", func(t *testing.T) {
				h := newHandler()
				key := newTestProofKey(t)

				session := &oauth2.DefaultSession{}
				request := newTestBackChannelRequest(session, consts.CIBAModePoll, &oauth2.DefaultClient{}, "")

				ctx := ctxWithDPoP(http.MethodPost, testBackChannelURL, signBackChannelProof(t, key, "bc-1", testBackChannelURL))

				require.NoError(t, h.BindBackChannelAuthenticationRequest(ctx, request))

				expected := thumbprint(t, key)

				assert.Equal(t, expected, session.GetDPoPJWKThumbprint())
				assert.Equal(t, expected, session.GetRequestedDPoPJWKThumbprint())

				var jwk jose.JSONWebKey

				require.NoError(t, jwk.UnmarshalJSON(session.GetDPoPPublicKeyJWK()))
				assert.True(t, jwk.IsPublic())
			})

			t.Run("ShouldAcceptTheMutualTLSAlias", func(t *testing.T) {
				h := newHandler()
				key := newTestProofKey(t)

				session := &oauth2.DefaultSession{}
				request := newTestBackChannelRequest(session, consts.CIBAModePoll, &oauth2.DefaultClient{}, "")

				ctx := ctxWithDPoP(http.MethodPost, testBackChannelURL, signBackChannelProof(t, key, "bc-alias", testBackChannelAliasURL))

				require.NoError(t, h.BindBackChannelAuthenticationRequest(ctx, request))
				assert.Equal(t, thumbprint(t, key), session.GetDPoPJWKThumbprint())
			})

			t.Run("ShouldRejectTheWrongHTU", func(t *testing.T) {
				h := newHandler()
				key := newTestProofKey(t)

				session := &oauth2.DefaultSession{}
				request := newTestBackChannelRequest(session, consts.CIBAModePoll, &oauth2.DefaultClient{}, "")

				ctx := ctxWithDPoP(http.MethodPost, testBackChannelURL, signBackChannelProof(t, key, "bc-htu", "https://as.example.com/token"))

				assert.ErrorIs(t, h.BindBackChannelAuthenticationRequest(ctx, request), oauth2.ErrInvalidDPoPProof)
				assert.Empty(t, session.GetDPoPJWKThumbprint())
			})

			t.Run("ShouldRejectTheWrongHTM", func(t *testing.T) {
				h := newHandler()
				key := newTestProofKey(t)

				raw := signProof(t, key, jwt.JSONWebTokenTypeDPoP, map[string]any{
					jwt.ClaimJWTID: "bc-htm", jwt.ClaimHTTPMethod: http.MethodGet, jwt.ClaimHTTPURI: testBackChannelURL, jwt.ClaimIssuedAt: time.Now().Unix(),
				})

				session := &oauth2.DefaultSession{}
				request := newTestBackChannelRequest(session, consts.CIBAModePoll, &oauth2.DefaultClient{}, "")

				assert.ErrorIs(t, h.BindBackChannelAuthenticationRequest(ctxWithDPoP(http.MethodPost, testBackChannelURL, raw), request), oauth2.ErrInvalidDPoPProof)
				assert.Empty(t, session.GetDPoPJWKThumbprint())
			})

			t.Run("ShouldRejectAReplayedProof", func(t *testing.T) {
				h := newHandler()
				key := newTestProofKey(t)

				raw := signBackChannelProof(t, key, "bc-replay", testBackChannelURL)

				first := newTestBackChannelRequest(&oauth2.DefaultSession{}, consts.CIBAModePoll, &oauth2.DefaultClient{}, "")
				require.NoError(t, h.BindBackChannelAuthenticationRequest(ctxWithDPoP(http.MethodPost, testBackChannelURL, raw), first))

				session := &oauth2.DefaultSession{}
				second := newTestBackChannelRequest(session, consts.CIBAModePoll, &oauth2.DefaultClient{}, "")

				assert.ErrorIs(t, h.BindBackChannelAuthenticationRequest(ctxWithDPoP(http.MethodPost, testBackChannelURL, raw), second), oauth2.ErrInvalidDPoPProof)
				assert.Empty(t, session.GetDPoPJWKThumbprint())
			})

			t.Run("ShouldRejectMultipleProofs", func(t *testing.T) {
				h := newHandler()
				key := newTestProofKey(t)
				raw := signBackChannelProof(t, key, "bc-multi", testBackChannelURL)

				ctx := ctxWithDPoP(http.MethodPost, testBackChannelURL, raw)
				ctx.Value(oauth2.RequestContextKey).(*http.Request).Header.Add(consts.HeaderDPoP, raw)

				request := newTestBackChannelRequest(&oauth2.DefaultSession{}, consts.CIBAModePoll, &oauth2.DefaultClient{}, "")

				assert.ErrorIs(t, h.BindBackChannelAuthenticationRequest(ctx, request), oauth2.ErrInvalidDPoPProof)
			})

			t.Run("ShouldRecordTheDPoPJKTAlone", func(t *testing.T) {
				h := newHandler()

				session := &oauth2.DefaultSession{}
				request := newTestBackChannelRequest(session, consts.CIBAModePoll, &oauth2.DefaultClient{}, otherJKT)

				require.NoError(t, h.BindBackChannelAuthenticationRequest(ctxWithDPoP(http.MethodPost, testBackChannelURL, ""), request))

				assert.Equal(t, otherJKT, session.GetDPoPJWKThumbprint())
				assert.Equal(t, otherJKT, session.GetRequestedDPoPJWKThumbprint())
				assert.Empty(t, session.GetDPoPPublicKeyJWK())
			})

			t.Run("ShouldRecordTheDPoPJKTWithoutAnHTTPRequest", func(t *testing.T) {
				h := newHandler()

				session := &oauth2.DefaultSession{}
				request := newTestBackChannelRequest(session, consts.CIBAModePoll, &oauth2.DefaultClient{}, otherJKT)

				require.NoError(t, h.BindBackChannelAuthenticationRequest(t.Context(), request))
				assert.Equal(t, otherJKT, session.GetDPoPJWKThumbprint())
			})

			t.Run("ShouldRecordAMatchingDPoPJKTAndProof", func(t *testing.T) {
				h := newHandler()
				key := newTestProofKey(t)

				session := &oauth2.DefaultSession{}
				request := newTestBackChannelRequest(session, consts.CIBAModePoll, &oauth2.DefaultClient{}, thumbprint(t, key))

				ctx := ctxWithDPoP(http.MethodPost, testBackChannelURL, signBackChannelProof(t, key, "bc-match", testBackChannelURL))

				require.NoError(t, h.BindBackChannelAuthenticationRequest(ctx, request))
				assert.Equal(t, thumbprint(t, key), session.GetDPoPJWKThumbprint())
			})

			t.Run("ShouldRejectAMismatchedDPoPJKTAndProof", func(t *testing.T) {
				h := newHandler()
				key := newTestProofKey(t)

				session := &oauth2.DefaultSession{}
				request := newTestBackChannelRequest(session, consts.CIBAModePoll, &oauth2.DefaultClient{}, otherJKT)

				ctx := ctxWithDPoP(http.MethodPost, testBackChannelURL, signBackChannelProof(t, key, "bc-mismatch", testBackChannelURL))

				assert.ErrorIs(t, h.BindBackChannelAuthenticationRequest(ctx, request), oauth2.ErrInvalidDPoPProof)
				assert.Empty(t, session.GetDPoPJWKThumbprint())
				assert.Empty(t, session.GetRequestedDPoPJWKThumbprint())
			})

			t.Run("ShouldRejectAMalformedDPoPJKT", func(t *testing.T) {
				h := newHandler()

				request := newTestBackChannelRequest(&oauth2.DefaultSession{}, consts.CIBAModePoll, &oauth2.DefaultClient{}, "short")

				assert.ErrorIs(t, h.BindBackChannelAuthenticationRequest(ctxWithDPoP(http.MethodPost, testBackChannelURL, ""), request), oauth2.ErrInvalidRequest)
			})

			t.Run("ShouldSkipWhenDisabled", func(t *testing.T) {
				h := newHandler()
				h.Config.(*testHandlerConfig).enabled = false

				key := newTestProofKey(t)

				session := &oauth2.DefaultSession{}
				request := newTestBackChannelRequest(session, consts.CIBAModePoll, &oauth2.DefaultClient{}, otherJKT)

				ctx := ctxWithDPoP(http.MethodPost, testBackChannelURL, signBackChannelProof(t, key, "bc-disabled", testBackChannelURL))

				require.NoError(t, h.BindBackChannelAuthenticationRequest(ctx, request))
				assert.Empty(t, session.GetDPoPJWKThumbprint())
			})

			t.Run("ShouldSkipWithoutKeyMaterial", func(t *testing.T) {
				h := newHandler()

				session := &oauth2.DefaultSession{}
				request := newTestBackChannelRequest(session, consts.CIBAModePush, &oauth2.DefaultClient{}, "")

				require.NoError(t, h.BindBackChannelAuthenticationRequest(ctxWithDPoP(http.MethodPost, testBackChannelURL, ""), request))
				assert.Empty(t, session.GetDPoPJWKThumbprint())
			})

			t.Run("ShouldNotRequireKeyMaterialForAPollClient", func(t *testing.T) {
				h := newHandler()

				request := newTestBackChannelRequest(&oauth2.DefaultSession{}, consts.CIBAModePoll, &oauth2.DefaultClient{DPoPBoundAccessTokens: true}, "")

				require.NoError(t, h.BindBackChannelAuthenticationRequest(ctxWithDPoP(http.MethodPost, testBackChannelURL, ""), request))
			})

			t.Run("ShouldRequireKeyMaterialForABoundPushClient", func(t *testing.T) {
				h := newHandler()

				request := newTestBackChannelRequest(&oauth2.DefaultSession{}, consts.CIBAModePush, &oauth2.DefaultClient{DPoPBoundAccessTokens: true}, "")

				assert.ErrorIs(t, h.BindBackChannelAuthenticationRequest(ctxWithDPoP(http.MethodPost, testBackChannelURL, ""), request), oauth2.ErrInvalidRequest)
			})

			t.Run("ShouldRequireKeyMaterialForAPushClientWhenEnforced", func(t *testing.T) {
				h := newHandler()
				h.Config.(*testHandlerConfig).enforce = true

				request := newTestBackChannelRequest(&oauth2.DefaultSession{}, consts.CIBAModePush, &oauth2.DefaultClient{}, "")

				assert.ErrorIs(t, h.BindBackChannelAuthenticationRequest(ctxWithDPoP(http.MethodPost, testBackChannelURL, ""), request), oauth2.ErrInvalidRequest)
			})

			t.Run("ShouldRejectASessionWithoutDPoPSupport", func(t *testing.T) {
				h := newHandler()

				request := newTestBackChannelRequest(nonDPoPSession{}, consts.CIBAModePoll, &oauth2.DefaultClient{}, otherJKT)

				assert.ErrorIs(t, h.BindBackChannelAuthenticationRequest(ctxWithDPoP(http.MethodPost, testBackChannelURL, ""), request), oauth2.ErrServerError)
			})
		})
	}
}

func newTestBackChannelRequest(session oauth2.Session, mode string, client oauth2.Client, jkt string) *oauth2.BackChannelAuthenticationRequest {
	request := oauth2.NewBackChannelAuthenticationRequest()
	request.Form = url.Values{}
	request.DeliveryMode = mode
	request.Client = client
	request.SetSession(session)

	if jkt != "" {
		request.Form.Set(consts.FormParameterDPoPJKT, jkt)
	}

	return request
}

func signBackChannelProof(t *testing.T, key *jose.JSONWebKey, jti, htu string) string {
	t.Helper()

	return signProof(t, key, jwt.JSONWebTokenTypeDPoP, map[string]any{
		jwt.ClaimJWTID: jti, jwt.ClaimHTTPMethod: http.MethodPost, jwt.ClaimHTTPURI: htu, jwt.ClaimIssuedAt: time.Now().Unix(),
	})
}
