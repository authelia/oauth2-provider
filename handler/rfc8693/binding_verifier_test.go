// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc8693_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	. "authelia.com/provider/oauth2/handler/rfc8693"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestTokenExchangeRequiresAnEnabledVerifierForABinding(t *testing.T) {
	const (
		dpopDisabled = "Unable to exchange a subject token bound to a DPoP key because DPoP is not enabled."
		mtlsDisabled = "Unable to exchange a subject token bound to a client certificate because mutual-TLS is not enabled."
	)

	testCases := []struct {
		name     string
		jkt, x5t string
		dpop     bool
		mtls     bool
		expected string
	}{
		{name: "ShouldRejectADPoPBindingWhenDPoPIsDisabled", jkt: bindingJKT, mtls: true, expected: dpopDisabled},
		{name: "ShouldRejectACertificateBindingWhenMTLSIsDisabled", x5t: bindingX5T, dpop: true, expected: mtlsDisabled},
		{name: "ShouldAcceptADPoPBindingWhenDPoPIsEnabled", jkt: bindingJKT, dpop: true},
		{name: "ShouldAcceptACertificateBindingWhenMTLSIsEnabled", x5t: bindingX5T, mtls: true},
		{name: "ShouldAcceptAnUnboundTokenWhenBothAreDisabled"},
	}

	for _, tc := range testCases {
		bind := func(session *oauth2.DefaultSession) {
			session.SetDPoPJWKThumbprint(tc.jkt)
			session.SetClientCertificateSHA256Thumbprint(tc.x5t)
		}

		check := func(t *testing.T, err error) {
			t.Helper()

			if tc.expected == "" {
				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

				return
			}

			assert.ErrorIs(t, err, oauth2.ErrInvalidRequest)
			assert.ErrorContains(t, oauth2.ErrorToDebugRFC6749Error(err), tc.expected)
		}

		for _, sc := range bindingExchangeStores() {
			t.Run(tc.name+"/"+sc.name, func(t *testing.T) {
				t.Run("AccessToken", func(t *testing.T) {
					store := sc.newStore()
					config, strategy := newBindingExchangeConfig()
					config.DPoPEnabled, config.MTLSEnabled = tc.dpop, tc.mtls

					token := createBoundAccessToken(t.Context(), strategy, store, store.GetClients()["custom-lifespan-client"], bind)

					check(t, newLifetimeAccessTokenHandler(config, strategy, store).HandleTokenEndpointRequest(t.Context(), newLifetimeExchangeRequest(store, consts.TokenTypeRFC8693AccessToken, token, "")))
				})

				t.Run("RefreshToken", func(t *testing.T) {
					store := sc.newStore()
					config, strategy := newBindingExchangeConfig()
					config.DPoPEnabled, config.MTLSEnabled = tc.dpop, tc.mtls

					token := createBoundRefreshToken(t.Context(), strategy, store, store.GetClients()["custom-lifespan-client"], bind)

					check(t, newLifetimeRefreshTokenHandler(config, strategy, store).HandleTokenEndpointRequest(t.Context(), newLifetimeExchangeRequest(store, consts.TokenTypeRFC8693RefreshToken, token, "")))
				})
			})
		}

		t.Run(tc.name+"/CustomJWT", func(t *testing.T) {
			f := newCustomJWTConsumeFixture(t, false)
			config := newSpecConfig(t)
			config.DPoPEnabled, config.MTLSEnabled = tc.dpop, tc.mtls
			f.custom.Config = config

			var cnf any

			switch {
			case tc.jkt != "":
				cnf = map[string]any{jwt.ClaimConfirmationJWKThumbprint: tc.jkt}
			case tc.x5t != "":
				cnf = map[string]any{jwt.ClaimConfirmationX509SHA256Thumbprint: tc.x5t}
			}

			check(t, f.custom.HandleTokenEndpointRequest(t.Context(), f.request(map[string][]string{
				consts.FormParameterSubjectTokenType: {"urn:spec:jwt"},
				consts.FormParameterSubjectToken:     {customJWTWithConfirmation(t, f, cnf)},
			})))
		})
	}
}

func TestTokenExchangeRequiresAConfigurationReportingTheVerifierForABinding(t *testing.T) {
	testCases := []struct {
		name     string
		jkt, x5t string
		expected string
	}{
		{name: "ShouldRejectADPoPBinding", jkt: bindingJKT, expected: "Unable to exchange a subject token bound to a DPoP key because DPoP is not enabled."},
		{name: "ShouldRejectACertificateBinding", x5t: bindingX5T, expected: "Unable to exchange a subject token bound to a client certificate because mutual-TLS is not enabled."},
		{name: "ShouldAcceptAnUnboundToken"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			store := bindingExchangeStores()[0].newStore()
			config, strategy := newBindingExchangeConfig()

			token := createBoundAccessToken(t.Context(), strategy, store, store.GetClients()["custom-lifespan-client"], func(session *oauth2.DefaultSession) {
				session.SetDPoPJWKThumbprint(tc.jkt)
				session.SetClientCertificateSHA256Thumbprint(tc.x5t)
			})

			handler := newLifetimeAccessTokenHandler(config, strategy, store)
			handler.Config = struct{ oauth2.RFC8693ConfigProvider }{config}

			err := handler.HandleTokenEndpointRequest(t.Context(), newLifetimeExchangeRequest(store, consts.TokenTypeRFC8693AccessToken, token, ""))

			if tc.expected == "" {
				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

				return
			}

			assert.ErrorIs(t, err, oauth2.ErrInvalidRequest)
			assert.ErrorContains(t, oauth2.ErrorToDebugRFC6749Error(err), tc.expected)
		})
	}
}

func TestTokenExchangeRequiresAnEnabledVerifierForARefreshTokenActor(t *testing.T) {
	testCases := []struct {
		name     string
		enabled  bool
		expected string
	}{
		{name: "ShouldRecordTheBindingWhenDPoPIsEnabled", enabled: true},
		{name: "ShouldRejectTheBindingWhenDPoPIsDisabled", expected: "Unable to exchange an actor token bound to a DPoP key because DPoP is not enabled."},
	}

	for _, tc := range testCases {
		for _, sc := range bindingExchangeStores() {
			t.Run(tc.name+"/"+sc.name, func(t *testing.T) {
				store := sc.newStore()
				config, strategy := newBindingExchangeConfig()
				config.DPoPEnabled = tc.enabled

				token := createBoundRefreshToken(t.Context(), strategy, store, store.GetClients()["custom-lifespan-client"], func(session *oauth2.DefaultSession) {
					session.SetDPoPJWKThumbprint(bindingJKT)
				})

				request := newLifetimeExchangeRequest(store, consts.TokenTypeRFC8693AccessToken, createBoundAccessToken(t.Context(), strategy, store, store.GetClients()["custom-lifespan-client"], func(_ *oauth2.DefaultSession) {}), "")
				request.Form.Set(consts.FormParameterActorTokenType, consts.TokenTypeRFC8693RefreshToken)
				request.Form.Set(consts.FormParameterActorToken, token)

				err := newLifetimeRefreshTokenHandler(config, strategy, store).HandleTokenEndpointRequest(t.Context(), request)

				if tc.expected != "" {
					assert.ErrorIs(t, err, oauth2.ErrInvalidRequest)
					assert.ErrorContains(t, oauth2.ErrorToDebugRFC6749Error(err), tc.expected)

					return
				}

				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
				assert.Equal(t, bindingJKT, request.GetSession().(oauth2.DPoPBoundSession).GetDPoPJWKThumbprint())
			})
		}
	}
}

func createBoundRefreshToken(ctx context.Context, strategy hoauth2.CoreStrategy, store rfc8693ExchangeStore, client oauth2.Client, bind func(session *oauth2.DefaultSession)) string {
	session := &oauth2.DefaultSession{
		Username:  "peter",
		Subject:   "peter",
		ExpiresAt: map[oauth2.TokenType]time.Time{oauth2.RefreshToken: time.Now().UTC().Add(time.Hour)},
	}

	bind(session)

	request := &oauth2.AccessRequest{
		GrantTypes: oauth2.Arguments{consts.GrantTypeAuthorizationCode},
		Request:    oauth2.Request{ID: uuid.New().String(), Session: session, Client: client},
	}

	token, signature, err := strategy.GenerateRefreshToken(ctx, request)
	if err != nil {
		panic(err.Error())
	}

	if err = store.(hoauth2.TokenRevocationStorage).CreateRefreshTokenSession(ctx, signature, "", request.Sanitize([]string{})); err != nil {
		panic(err.Error())
	}

	return token
}

func TestTokenExchangeRequiresASessionAbleToRecordABinding(t *testing.T) {
	testCases := []struct {
		name     string
		cnf      map[string]any
		expected string
	}{
		{
			name:     "ShouldFailForADPoPBinding",
			cnf:      map[string]any{jwt.ClaimConfirmationJWKThumbprint: bindingJKT},
			expected: "The session does not support DPoP binding, which is required to exchange a subject token bound to a DPoP proof-of-possession key.",
		},
		{
			name:     "ShouldFailForACertificateBinding",
			cnf:      map[string]any{jwt.ClaimConfirmationX509SHA256Thumbprint: bindingX5T},
			expected: "The session does not support mutual-TLS certificate binding, which is required to exchange a subject token bound to a client certificate.",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			f := newCustomJWTConsumeFixture(t, false)

			request := f.request(map[string][]string{
				consts.FormParameterSubjectTokenType: {"urn:spec:jwt"},
				consts.FormParameterSubjectToken:     {customJWTWithConfirmation(t, f, tc.cnf)},
			})

			session := newSpecSession("peter")
			request.Session = &unbindableSession{Session: session, baseSession: session}

			err := f.custom.HandleTokenEndpointRequest(t.Context(), request)

			assert.ErrorIs(t, err, oauth2.ErrServerError)
			assert.ErrorContains(t, oauth2.ErrorToDebugRFC6749Error(err), tc.expected)
		})
	}
}

type baseSession = oauth2.Session

type unbindableSession struct {
	Session
	baseSession
}

func (s *unbindableSession) SetSubject(subject string) {
	s.Session.SetSubject(subject)
}
