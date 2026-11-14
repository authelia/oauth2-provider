// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package ciba_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/handler/ciba"
	"authelia.com/provider/oauth2/storage"
)

type decideFailingStorage struct {
	ciba.Storage

	err error
}

func (s decideFailingStorage) DecideCIBASession(_ context.Context, _ string, _ oauth2.BackChannelAuthenticationRequester) error {
	return s.err
}

func newDecisionTestRequest(status oauth2.CIBAStatus) (request *oauth2.BackChannelAuthenticationRequest) {
	request = oauth2.NewBackChannelAuthenticationRequest()
	request.SetID("request-id")
	request.SetAuthRequestIDSignature("signature")
	request.Client = &oauth2.DefaultClient{ID: "client"}
	request.Session = &oauth2.DefaultSession{Subject: "john"}
	request.SetStatus(status)

	return request
}

func TestDecisionHandlerShouldRecordTheDecision(t *testing.T) {
	stores := []struct {
		name string
		new  func() testStore
	}{
		{"MemoryStore", func() testStore { return storage.NewMemoryStore() }},
		{"HydratingMemoryStore", func() testStore { return storage.NewHydratingMemoryStore() }},
	}

	for _, sc := range stores {
		t.Run(sc.name, func(t *testing.T) {
			for _, status := range []oauth2.CIBAStatus{oauth2.CIBAStatusApproved, oauth2.CIBAStatusDenied, oauth2.CIBAStatusFailed} {
				t.Run(statusName(status), func(t *testing.T) {
					store := sc.new()

					require.NoError(t, store.CreateCIBASession(t.Context(), "signature", newDecisionTestRequest(oauth2.CIBAStatusPending)))

					handler := &ciba.DecisionHandler{Storage: store}

					decided := newDecisionTestRequest(status)
					decided.Session = &oauth2.DefaultSession{Subject: "john", Username: "approved"}
					decided.UserCode = "1234"

					require.NoError(t, handler.HandleBackChannelAuthenticationDecision(t.Context(), decided, &oauth2.BackChannelAuthenticationDecisionResult{}))

					stored, err := store.GetCIBASession(t.Context(), "signature", &oauth2.DefaultSession{})
					require.NoError(t, err)

					assert.Equal(t, status, stored.GetStatus())
					assert.Equal(t, "approved", stored.GetSession().GetUsername())
					assert.Empty(t, stored.GetUserCode())
					assert.Equal(t, "1234", decided.UserCode)

					err = handler.HandleBackChannelAuthenticationDecision(t.Context(), newDecisionTestRequest(status), &oauth2.BackChannelAuthenticationDecisionResult{})
					require.Error(t, err)
					assert.ErrorIs(t, err, oauth2.ErrInvalidRequest)
					assert.ErrorIs(t, err, oauth2.ErrCIBADecided)
					assert.Contains(t, oauth2.ErrorToRFC6749Error(err).GetDescription(), "already decided")
				})
			}
		})
	}
}

func TestDecisionHandlerShouldMapErrors(t *testing.T) {
	testCases := []struct {
		name     string
		status   oauth2.CIBAStatus
		err      error
		expected error
	}{
		{name: "ShouldRejectAPendingStatus", status: oauth2.CIBAStatusPending, expected: oauth2.ErrServerError},
		{name: "ShouldMapDecided", status: oauth2.CIBAStatusApproved, err: oauth2.ErrCIBADecided, expected: oauth2.ErrInvalidRequest},
		{name: "ShouldPassNotFound", status: oauth2.CIBAStatusDenied, err: oauth2.ErrNotFound, expected: oauth2.ErrNotFound},
		{name: "ShouldMapAStorageFailure", status: oauth2.CIBAStatusFailed, err: errors.New("decide failed"), expected: oauth2.ErrServerError},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			handler := &ciba.DecisionHandler{Storage: decideFailingStorage{err: tc.err}}

			err := handler.HandleBackChannelAuthenticationDecision(t.Context(), newDecisionTestRequest(tc.status), &oauth2.BackChannelAuthenticationDecisionResult{})

			require.Error(t, err)
			assert.ErrorIs(t, err, tc.expected)
		})
	}
}

func statusName(status oauth2.CIBAStatus) string {
	switch status {
	case oauth2.CIBAStatusApproved:
		return "Approved"
	case oauth2.CIBAStatusDenied:
		return "Denied"
	case oauth2.CIBAStatusFailed:
		return "Failed"
	default:
		return "Pending"
	}
}

// customDecisionTestRequest is a custom oauth2.BackChannelAuthenticationRequester.
type customDecisionTestRequest struct {
	*oauth2.BackChannelAuthenticationRequest
}

func TestDecisionHandlerShouldRejectACustomRequestWithAUserCode(t *testing.T) {
	store := storage.NewMemoryStore()

	require.NoError(t, store.CreateCIBASession(t.Context(), "signature", newDecisionTestRequest(oauth2.CIBAStatusPending)))

	decided := newDecisionTestRequest(oauth2.CIBAStatusApproved)
	decided.UserCode = "1234"

	handler := &ciba.DecisionHandler{Storage: store}

	err := handler.HandleBackChannelAuthenticationDecision(t.Context(), &customDecisionTestRequest{decided}, &oauth2.BackChannelAuthenticationDecisionResult{})
	assert.ErrorIs(t, err, oauth2.ErrServerError)

	stored, err := store.GetCIBASession(t.Context(), "signature", &oauth2.DefaultSession{})
	require.NoError(t, err)
	assert.Equal(t, oauth2.CIBAStatusPending, stored.GetStatus())

	decided.UserCode = ""

	require.NoError(t, handler.HandleBackChannelAuthenticationDecision(t.Context(), &customDecisionTestRequest{decided}, &oauth2.BackChannelAuthenticationDecisionResult{}))
}
