// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package ciba_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/handler/ciba"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/storage"
)

type testStore interface {
	ciba.Storage
}

type failingStorage struct {
	ciba.Storage
}

func (failingStorage) CreateCIBASession(_ context.Context, _ string, _ oauth2.BackChannelAuthenticationRequester) error {
	return errors.New("create failed")
}

func newProvider(store ciba.Storage) (provider *oauth2.Fosite) {
	config := &oauth2.Config{GlobalSecret: []byte("foobarfoobarfoobarfoobarfoobarfoobarfoobarfoobar")}

	handler := &ciba.EndpointHandler{
		Strategy: hoauth2.NewHMACCoreStrategy(config, "authelia_%s_"),
		Storage:  store,
		Config:   config,
	}

	config.BackChannelAuthenticationEndpointHandlers.Append(handler)

	return &oauth2.Fosite{Config: config}
}

func TestNewBackChannelAuthenticationResponse(t *testing.T) {
	stores := []struct {
		name string
		new  func() testStore
	}{
		{"MemoryStore", func() testStore { return storage.NewMemoryStore() }},
		{"HydratingMemoryStore", func() testStore { return storage.NewHydratingMemoryStore() }},
	}

	testCases := []struct {
		name      string
		mode      string
		requested time.Duration
		subject   string
		err       string
		expiresIn int64
		interval  int64
		rawID     bool
	}{
		{name: "ShouldRequireSubject", mode: consts.CIBAModePoll, err: "server_error"},
		{name: "ShouldIssuePoll", mode: consts.CIBAModePoll, subject: "john", expiresIn: 300, interval: 5},
		{name: "ShouldIssuePing", mode: consts.CIBAModePing, subject: "john", expiresIn: 300, interval: 5, rawID: true},
		{name: "ShouldIssuePushWithoutInterval", mode: consts.CIBAModePush, subject: "john", expiresIn: 300, rawID: true},
		{name: "ShouldClampRequestedExpiryUp", mode: consts.CIBAModePoll, subject: "john", requested: 10 * time.Second, expiresIn: 30, interval: 5},
		{name: "ShouldClampRequestedExpiryDown", mode: consts.CIBAModePoll, subject: "john", requested: 99999 * time.Second, expiresIn: 1800, interval: 5},
		{name: "ShouldHonourRequestedExpiry", mode: consts.CIBAModePoll, subject: "john", requested: 120 * time.Second, expiresIn: 120, interval: 5},
	}

	for _, sc := range stores {
		t.Run(sc.name, func(t *testing.T) {
			for _, tc := range testCases {
				t.Run(tc.name, func(t *testing.T) {
					store := sc.new()
					provider := newProvider(store)

					request := oauth2.NewBackChannelAuthenticationRequest()
					request.SetID("request-id")
					request.DeliveryMode = tc.mode
					request.RequestedExpiry = tc.requested
					request.ClientNotificationToken = "tok"
					request.Client = &oauth2.DefaultClient{ID: "client"}
					request.Session = &oauth2.DefaultSession{Subject: tc.subject}

					response, err := provider.NewBackChannelAuthenticationResponse(t.Context(), request)

					if tc.err != "" {
						require.Error(t, err)
						assert.Equal(t, tc.err, oauth2.ErrorToRFC6749Error(err).ErrorField)
						assert.Contains(t, oauth2.ErrorToDebugRFC6749Error(err).Error(), "the application must resolve the end-user and set the session subject before NewBackChannelAuthenticationResponse")
						assert.Nil(t, response)

						return
					}

					require.NoError(t, err)

					assert.NotEmpty(t, response.GetAuthRequestID())
					assert.Equal(t, tc.expiresIn, response.GetExpiresIn())
					assert.Equal(t, tc.interval, response.GetInterval())

					_, hasInterval := response.ToMap()["interval"]
					assert.Equal(t, tc.interval > 0, hasInterval)

					signature, err := hoauth2.NewHMACCoreStrategy(&oauth2.Config{GlobalSecret: []byte("foobarfoobarfoobarfoobarfoobarfoobarfoobarfoobar")}, "authelia_%s_").CIBAAuthRequestIDSignature(t.Context(), response.GetAuthRequestID())
					require.NoError(t, err)

					bySignature, err := store.GetCIBASession(t.Context(), signature, &oauth2.DefaultSession{})
					require.NoError(t, err)

					byID, err := store.GetCIBASessionByRequestID(t.Context(), "request-id", &oauth2.DefaultSession{})
					require.NoError(t, err)

					for _, got := range []oauth2.BackChannelAuthenticationRequester{bySignature, byID} {
						assert.Equal(t, oauth2.CIBAStatusPending, got.GetStatus())
						assert.Equal(t, signature, got.GetAuthRequestIDSignature())
						assert.Equal(t, 5*time.Second, got.GetPollingInterval())
						assert.Equal(t, "tok", oauth2.GetClientNotificationToken(got))

						if tc.rawID {
							assert.Equal(t, response.GetAuthRequestID(), oauth2.GetAuthRequestID(got))
						} else {
							assert.Empty(t, oauth2.GetAuthRequestID(got))
						}

						expiresAt := got.GetSession().GetExpiresAt(oauth2.CIBAAuthRequestID)
						assert.WithinDuration(t, time.Now().Add(time.Duration(tc.expiresIn)*time.Second), expiresAt, 3*time.Second)
					}
				})
			}
		})
	}
}

func TestNewBackChannelAuthenticationResponseShouldRoundUpToWholeSeconds(t *testing.T) {
	testCases := []struct {
		name      string
		lifespan  time.Duration
		interval  time.Duration
		expiresIn int64
		polling   int64
	}{
		{name: "ShouldRoundUpSubSecondDurations", lifespan: 500 * time.Millisecond, interval: 200 * time.Millisecond, expiresIn: 1, polling: 1},
		{name: "ShouldRoundUpFractionalSeconds", lifespan: 90500 * time.Millisecond, interval: 2500 * time.Millisecond, expiresIn: 91, polling: 3},
		{name: "ShouldKeepWholeSeconds", lifespan: 90 * time.Second, interval: 2 * time.Second, expiresIn: 90, polling: 2},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			store := storage.NewMemoryStore()
			provider := newProvider(store)

			config := provider.Config.(*oauth2.Config)
			config.CIBAAuthRequestLifespan = tc.lifespan
			config.CIBAPollingInterval = tc.interval

			request := oauth2.NewBackChannelAuthenticationRequest()
			request.DeliveryMode = consts.CIBAModePoll
			request.Client = &oauth2.DefaultClient{ID: "client"}
			request.Session = &oauth2.DefaultSession{Subject: "john"}

			response, err := provider.NewBackChannelAuthenticationResponse(t.Context(), request)
			require.NoError(t, err)

			assert.Equal(t, tc.expiresIn, response.GetExpiresIn())
			assert.Equal(t, tc.polling, response.GetInterval())
			assert.Equal(t, time.Duration(tc.polling)*time.Second, request.GetPollingInterval())
		})
	}
}

func TestEndpointHandlerShouldFailWhenStorageFails(t *testing.T) {
	provider := newProvider(failingStorage{})

	request := oauth2.NewBackChannelAuthenticationRequest()
	request.DeliveryMode = consts.CIBAModePoll
	request.Session = &oauth2.DefaultSession{Subject: "john"}

	_, err := provider.NewBackChannelAuthenticationResponse(t.Context(), request)

	require.Error(t, err)
	assert.Equal(t, "server_error", oauth2.ErrorToRFC6749Error(err).ErrorField)
}

type bindingFunc func(request oauth2.BackChannelAuthenticationRequester) error

func (b bindingFunc) BindBackChannelAuthenticationRequest(_ context.Context, request oauth2.BackChannelAuthenticationRequester) error {
	return b(request)
}

func TestNewBackChannelAuthenticationResponseShouldRunBindingHandlersFirst(t *testing.T) {
	store := storage.NewMemoryStore()
	provider := newProvider(store)

	bound := false

	provider.Config.(*oauth2.Config).BackChannelAuthenticationEndpointBindingHandlers.Append(bindingFunc(func(r oauth2.BackChannelAuthenticationRequester) error {
		assert.Empty(t, r.GetAuthRequestIDSignature())

		bound = true

		return oauth2.ErrInvalidRequest
	}))

	request := oauth2.NewBackChannelAuthenticationRequest()
	request.DeliveryMode = consts.CIBAModePoll
	request.Session = &oauth2.DefaultSession{Subject: "john"}

	_, err := provider.NewBackChannelAuthenticationResponse(t.Context(), request)

	assert.True(t, bound)
	assert.ErrorIs(t, err, oauth2.ErrInvalidRequest)
	assert.Empty(t, store.CIBASessions)
}
