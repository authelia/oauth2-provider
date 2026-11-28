// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateBearerAuthorizationRegistration(t *testing.T) {
	registered := &DefaultRegisteredClient{DefaultClient: &DefaultClient{ID: "client"}, FAPI2SecurityProfile: true}

	testCases := []struct {
		name     string
		store    ClientGetter
		recorded Client
		expected Client
		err      error
		debug    string
	}{
		{name: "ShouldRejectAnUnboundTokenOfAFAPI2Registration", store: bearerClients{"client": registered}, recorded: &DefaultClient{ID: "client"}, err: ErrInvalidToken, debug: "this credential records no binding of an enabled method"},
		{name: "ShouldAcceptAnUnboundTokenWithoutAStore", recorded: &DefaultClient{ID: "client"}},
		{name: "ShouldReturnTheRegistration", store: bearerClients{"client": &DefaultClient{ID: "client"}}, recorded: &DefaultClient{ID: "client"}, expected: &DefaultClient{ID: "client"}},
		{name: "ShouldRejectAnUnregisteredClient", store: bearerClients{}, recorded: &DefaultClient{ID: "client"}, err: ErrInvalidToken, debug: "The client with id 'client' the credential was issued to could not be found."},
		{name: "ShouldReportAStorageFailure", store: bearerClientsFailure{}, recorded: &DefaultClient{ID: "client"}, err: ErrServerError},
		{name: "ShouldSkipACredentialWithoutAClient", store: bearerClients{}},
		{name: "ShouldSkipACredentialWithAnEmptyClientID", store: bearerClients{}, recorded: &DefaultClient{}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			requester := newBearerRequester([]string{"read"}, []string{"urn:aud"}).(*Request)
			requester.Client = tc.recorded

			client, err := ValidateBearerAuthorization(t.Context(), &Config{}, tc.store, newBearerRequest(), requester, "token", BearerAuthorization{Audiences: []string{"urn:aud"}, Scopes: []string{"read"}})

			if tc.err != nil {
				require.ErrorIs(t, err, tc.err)
				assert.Nil(t, client)
				assert.Contains(t, ErrorToDebugRFC6749Error(err).Error(), tc.debug)

				return
			}

			require.NoError(t, ErrorToDebugRFC6749Error(err))
			assert.Equal(t, tc.expected, client)
		})
	}
}

func TestValidateBearerAuthorizationDPoPProofUsesTheRegistration(t *testing.T) {
	registered := &DefaultRegisteredClient{DefaultClient: &DefaultClient{ID: "client"}, FAPI2SecurityProfile: true}
	strategy := &fapi2DPoPStrategy{}

	requester := newBearerRequester(nil, []string{"urn:aud"}).(*Request)
	requester.Client = &DefaultClient{ID: "client"}
	requester.Session = &DefaultSession{JWKThumbprint: "some-jkt"}

	_, err := ValidateBearerAuthorization(t.Context(), &Config{DPoPEnabled: true, DPoPStrategy: strategy}, bearerClients{"client": registered}, newBearerRequest(), requester, "token", BearerAuthorization{Audiences: []string{"urn:aud"}})

	require.ErrorIs(t, err, ErrInvalidDPoPProof)
	assert.Equal(t, Client(registered), strategy.client)
}

type bearerClients map[string]Client

func (c bearerClients) GetClient(_ context.Context, id string) (client Client, err error) {
	var ok bool

	if client, ok = c[id]; !ok {
		return nil, ErrNotFound
	}

	return client, nil
}

type bearerClientsFailure struct{}

func (bearerClientsFailure) GetClient(context.Context, string) (client Client, err error) {
	return nil, errors.New("storage failure")
}
