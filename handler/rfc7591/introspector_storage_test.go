// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc7591

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"

	"authelia.com/provider/oauth2"
)

func TestClientRegistrationTokenIntrospectorStorageFailure(t *testing.T) {
	testCases := []struct {
		name     string
		failure  error
		expected error
	}{
		{name: "ShouldReportAStoreFailure", failure: errors.New("the database is unavailable"), expected: oauth2.ErrServerError},
		{name: "ShouldReportAStoreServerError", failure: oauth2.ErrServerError, expected: oauth2.ErrServerError},
		{name: "ShouldReportAStoreRejection", failure: oauth2.ErrInactiveToken, expected: oauth2.ErrRequestUnauthorized},
		{name: "ShouldDeferAnUnknownToken", failure: oauth2.ErrNotFound, expected: oauth2.ErrUnknownRequest},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			introspector, _, store, _, token := newIntrospectionFixture(t)

			introspector.Store = &failingRegistrationTokenStore{Storage: store, failure: tc.failure}

			_, err := introspector.IntrospectToken(context.Background(), token, oauth2.AccessToken, oauth2.NewAccessRequest(&oauth2.DefaultSession{}), nil)

			assert.ErrorIs(t, err, tc.expected)
		})
	}
}

type failingRegistrationTokenStore struct {
	Storage

	failure error
}

func (s *failingRegistrationTokenStore) GetClientRegistrationTokenSession(_ context.Context, _ string, _ oauth2.Session) (oauth2.Requester, error) {
	return nil, s.failure
}
