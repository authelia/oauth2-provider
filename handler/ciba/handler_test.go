// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package ciba_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	. "authelia.com/provider/oauth2/handler/ciba"
	"authelia.com/provider/oauth2/handler/openid"
)

// fakeAuthRequestIDStrategy is a deterministic AuthRequestIDStrategy used to drive the CIBA handler under test.
type fakeAuthRequestIDStrategy struct {
	id          string
	signature   string
	generateErr error
}

func (s *fakeAuthRequestIDStrategy) GenerateAuthRequestID(_ context.Context) (string, string, error) {
	if s.generateErr != nil {
		return "", "", s.generateErr
	}

	return s.id, s.signature, nil
}

func (s *fakeAuthRequestIDStrategy) AuthRequestIDSignature(_ context.Context, _ string) (string, error) {
	return s.signature, nil
}

func (s *fakeAuthRequestIDStrategy) ValidateAuthRequestID(_ context.Context, _ oauth2.Requester, _ string) error {
	return nil
}

// memoryCIBAStorage is a minimal in-memory implementation of the CIBA Storage interface for handler tests.
type memoryCIBAStorage struct {
	mu        sync.Mutex
	sessions  map[string]oauth2.CIBARequester
	invalid   map[string]bool
	createErr error
}

func newMemoryCIBAStorage() *memoryCIBAStorage {
	return &memoryCIBAStorage{
		sessions: map[string]oauth2.CIBARequester{},
		invalid:  map[string]bool{},
	}
}

func (s *memoryCIBAStorage) CreateOpenIDCIBASession(_ context.Context, signature string, request oauth2.CIBARequester) error {
	if s.createErr != nil {
		return s.createErr
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[signature] = request

	return nil
}

func (s *memoryCIBAStorage) UpdateOpenIDCIBASession(_ context.Context, signature string, request oauth2.CIBARequester) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[signature] = request

	return nil
}

func (s *memoryCIBAStorage) GetOpenIDCIBASession(_ context.Context, signature string, _ oauth2.Session) (oauth2.CIBARequester, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.invalid[signature] {
		return nil, errors.New("session invalidated")
	}

	r, ok := s.sessions[signature]
	if !ok {
		return nil, oauth2.ErrNotFound
	}

	return r, nil
}

func (s *memoryCIBAStorage) InvalidateOpenIDCIBASession(_ context.Context, signature string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.invalid[signature] = true

	return nil
}

func TestOpenIDConnectCIBAHandler_HandleOpenIDCIBAEndpointRequest(t *testing.T) {
	t.Run("ShouldIssueAuthRequestIDAndPersistSession", func(t *testing.T) {
		store := newMemoryCIBAStorage()
		strategy := &fakeAuthRequestIDStrategy{id: "the-id", signature: "the-sig"}

		handler := &OpenIDConnectCIBAHandler{
			Storage:  store,
			Strategy: strategy,
			Config: &oauth2.Config{
				OpenIDCIBALifespan:        time.Minute * 10,
				OpenIDCIBAPollingInterval: time.Second * 5,
			},
		}

		request := oauth2.NewCIBARequest()
		request.SetSession(openid.NewDefaultSession())
		response := oauth2.NewCIBAResponse()

		require.NoError(t, handler.HandleOpenIDCIBAEndpointRequest(t.Context(), request, response))

		assert.Equal(t, "the-id", response.GetAuthRequestID())
		assert.Equal(t, 5, response.GetInterval())
		assert.InDelta(t, int64(600), response.GetExpiresIn(), 2, "expires_in should approximate the configured lifespan")

		assert.Equal(t, oauth2.CIBAStatusNew, request.GetStatus())
		assert.Equal(t, "the-sig", request.GetAuthRequestIDSignature())

		persisted, err := store.GetOpenIDCIBASession(t.Context(), "the-sig", request.GetSession())
		require.NoError(t, err)
		assert.Equal(t, "the-sig", persisted.GetAuthRequestIDSignature())

		expires := request.GetSession().GetExpiresAt(oauth2.CIBAAuthRequestID)
		assert.False(t, expires.IsZero(), "session expiry should be recorded for the auth_req_id token type")
	})

	t.Run("ShouldFailWhenSessionMissing", func(t *testing.T) {
		handler := &OpenIDConnectCIBAHandler{
			Storage:  newMemoryCIBAStorage(),
			Strategy: &fakeAuthRequestIDStrategy{id: "the-id", signature: "the-sig"},
			Config:   &oauth2.Config{},
		}

		request := oauth2.NewCIBARequest()
		// deliberately do not call SetSession
		response := oauth2.NewCIBAResponse()

		err := handler.HandleOpenIDCIBAEndpointRequest(t.Context(), request, response)
		require.Error(t, err)
		assert.ErrorIs(t, err, oauth2.ErrServerError)
	})

	t.Run("ShouldFailWhenStrategyGenerateFails", func(t *testing.T) {
		handler := &OpenIDConnectCIBAHandler{
			Storage:  newMemoryCIBAStorage(),
			Strategy: &fakeAuthRequestIDStrategy{generateErr: errors.New("strategy boom")},
			Config:   &oauth2.Config{},
		}

		request := oauth2.NewCIBARequest()
		request.SetSession(openid.NewDefaultSession())
		response := oauth2.NewCIBAResponse()

		err := handler.HandleOpenIDCIBAEndpointRequest(t.Context(), request, response)
		require.Error(t, err)
		assert.ErrorIs(t, err, oauth2.ErrServerError)
	})

	t.Run("ShouldFailWhenStorageCreateFails", func(t *testing.T) {
		store := newMemoryCIBAStorage()
		store.createErr = errors.New("storage boom")

		handler := &OpenIDConnectCIBAHandler{
			Storage:  store,
			Strategy: &fakeAuthRequestIDStrategy{id: "the-id", signature: "the-sig"},
			Config:   &oauth2.Config{},
		}

		request := oauth2.NewCIBARequest()
		request.SetSession(openid.NewDefaultSession())
		response := oauth2.NewCIBAResponse()

		err := handler.HandleOpenIDCIBAEndpointRequest(t.Context(), request, response)
		require.Error(t, err)
		assert.ErrorIs(t, err, oauth2.ErrServerError)
	})
}
