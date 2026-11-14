// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/gen"
)

const (
	cibaTestSubject = "alice"
	cibaTestNonce   = "nonce"
)

func TestPushRequiresKeyMaterialWhenEnforced(t *testing.T) {
	const (
		jkt = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"
		x5t = "A4DtL2JmUMhAsvJj5tAtEqYFn7uHnaMbNKmoNcE7dnE"
	)

	testCases := []struct {
		name    string
		mode    string
		enforce bool
		bind    func(session *oauth2.DefaultSession)
		err     bool
	}{
		{name: "ShouldRejectPushWithoutKeyMaterial", mode: consts.CIBAModePush, enforce: true, err: true},
		{name: "ShouldRejectPushWithOnlyARequestedThumbprint", mode: consts.CIBAModePush, enforce: true, bind: func(s *oauth2.DefaultSession) { s.SetRequestedDPoPJWKThumbprint(jkt) }, err: true},
		{name: "ShouldAcceptPushWithADPoPThumbprint", mode: consts.CIBAModePush, enforce: true, bind: func(s *oauth2.DefaultSession) { s.SetDPoPJWKThumbprint(jkt) }},
		{name: "ShouldAcceptPushWithACertificateThumbprint", mode: consts.CIBAModePush, enforce: true, bind: func(s *oauth2.DefaultSession) { s.SetClientCertificateSHA256Thumbprint(x5t) }},
		{name: "ShouldAcceptPushWhenNotEnforced", mode: consts.CIBAModePush},
		{name: "ShouldAcceptPollWithoutKeyMaterial", mode: consts.CIBAModePoll, enforce: true},
		{name: "ShouldAcceptPingWithoutKeyMaterial", mode: consts.CIBAModePing, enforce: true},
	}

	for _, sc := range cibaDecisionTestStores {
		t.Run(sc.name, func(t *testing.T) {
			for _, tc := range testCases {
				t.Run(tc.name, func(t *testing.T) {
					store := sc.new()
					provider := newCIBADecisionTestProvider(store)

					config := provider.Config.(*oauth2.Config)
					config.EnforceSenderConstrainedAccessTokens = tc.enforce
					config.DPoPEnabled = true
					config.MTLSEnabled = true

					session := &oauth2.DefaultSession{Subject: cibaTestSubject}

					config.BackChannelAuthenticationEndpointBindingHandlers.Append(&cibaTestBindingHandler{fn: func(context.Context, oauth2.BackChannelAuthenticationRequester) error {
						if tc.bind != nil {
							tc.bind(session)
						}

						return nil
					}})

					request := newCIBADecisionTestRequest(session)
					request.DeliveryMode = tc.mode

					response, err := provider.NewBackChannelAuthenticationResponse(t.Context(), request)

					if tc.err {
						require.ErrorIs(t, err, oauth2.ErrInvalidRequest)
						assert.Contains(t, oauth2.ErrorToRFC6749Error(err).GetDescription(), "push mode requires key material at the backchannel authentication endpoint")
						assert.Nil(t, response)

						_, err = store.GetCIBASession(t.Context(), request.GetAuthRequestIDSignature(), &oauth2.DefaultSession{})
						assert.Error(t, err)

						return
					}

					require.NoError(t, err)
					assert.NotEmpty(t, response.GetAuthRequestID())
				})
			}
		})
	}
}

func TestNewBackChannelAuthenticationResponseExposesTheHTTPRequest(t *testing.T) {
	config, provider, _ := newCIBATestProvider(gen.MustRSAKey(), gen.MustRSAKey())

	var seen *http.Request

	config.BackChannelAuthenticationEndpointBindingHandlers.Append(&cibaTestBindingHandler{fn: func(ctx context.Context, _ oauth2.BackChannelAuthenticationRequester) error {
		seen, _ = ctx.Value(oauth2.RequestContextKey).(*http.Request)

		return nil
	}})

	r := newCIBATestRequest(t, nil, "", cibaTestClientPoll, "", "scope=openid&login_hint=alice")

	request, err := provider.NewBackChannelAuthenticationRequest(t.Context(), r, &oauth2.DefaultSession{})
	require.NoError(t, err)

	request.GetSession().(*oauth2.DefaultSession).Subject = cibaTestSubject

	// No endpoint handler is registered, so the response is not persisted; only the binding phase is observed.
	_, err = provider.NewBackChannelAuthenticationResponse(t.Context(), request)
	require.NoError(t, err)

	assert.Same(t, r, seen)
}

func TestWriteBackChannelAuthenticationErrorDPoPNonce(t *testing.T) {
	config, provider, _ := newCIBATestProvider(gen.MustRSAKey(), gen.MustRSAKey())

	config.DPoPEnabled = true
	config.DPoPStrategy = &cibaTestNonceStrategy{}

	t.Run("ShouldSetTheNonceForUseDPoPNonce", func(t *testing.T) {
		rw := httptest.NewRecorder()

		provider.WriteBackChannelAuthenticationError(t.Context(), rw, oauth2.NewBackChannelAuthenticationRequest(), oauth2.ErrUseDPoPNonce)

		assert.Equal(t, http.StatusBadRequest, rw.Code)
		assert.Equal(t, cibaTestNonce, rw.Header().Get(consts.HeaderDPoPNonce))
	})

	t.Run("ShouldNotSetTheNonceForOtherErrors", func(t *testing.T) {
		rw := httptest.NewRecorder()

		provider.WriteBackChannelAuthenticationError(t.Context(), rw, oauth2.NewBackChannelAuthenticationRequest(), oauth2.ErrInvalidDPoPProof)

		assert.Empty(t, rw.Header().Get(consts.HeaderDPoPNonce))
	})
}

type cibaTestBindingHandler struct {
	fn func(ctx context.Context, request oauth2.BackChannelAuthenticationRequester) error
}

func (h *cibaTestBindingHandler) BindBackChannelAuthenticationRequest(ctx context.Context, request oauth2.BackChannelAuthenticationRequester) error {
	return h.fn(ctx, request)
}

type cibaTestNonceStrategy struct {
	oauth2.DPoPStrategy
}

func (s *cibaTestNonceStrategy) NewDPoPNonce(context.Context) (string, error) {
	return cibaTestNonce, nil
}

func TestNewBackChannelAuthenticationResponseDoesNotPersistTheHTTPRequest(t *testing.T) {
	for _, sc := range cibaDecisionTestStores {
		t.Run(sc.name, func(t *testing.T) {
			store := sc.new()
			provider := newCIBADecisionTestProvider(store)

			r := httptest.NewRequest(http.MethodPost, "https://as.example.com/bc-authorize", nil)
			r.Header.Set(consts.HeaderAuthorization, "Basic secret")

			var seen *http.Request

			provider.Config.(*oauth2.Config).BackChannelAuthenticationEndpointBindingHandlers.Append(&cibaTestBindingHandler{fn: func(ctx context.Context, _ oauth2.BackChannelAuthenticationRequester) error {
				seen, _ = ctx.Value(oauth2.RequestContextKey).(*http.Request)

				return nil
			}})

			request := newCIBADecisionTestRequest(&oauth2.DefaultSession{Subject: cibaTestSubject})
			request.SetHTTPRequestForTest(r)

			_, err := provider.NewBackChannelAuthenticationResponse(t.Context(), request)
			require.NoError(t, err)

			assert.Same(t, r, seen)
			assert.Nil(t, request.HTTPRequestForTest())

			stored, err := store.GetCIBASession(t.Context(), request.GetAuthRequestIDSignature(), &oauth2.DefaultSession{})
			require.NoError(t, err)

			require.IsType(t, &oauth2.BackChannelAuthenticationRequest{}, stored)
			assert.Nil(t, stored.(*oauth2.BackChannelAuthenticationRequest).HTTPRequestForTest())
		})
	}
}
