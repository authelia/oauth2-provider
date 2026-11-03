// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package idjag_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/handler/idjag"
	"authelia.com/provider/oauth2/storage"
)

const issueAudienceUnrestricted = "urn:example:unrestricted"

// Section 4.3.3: the IdP MAY require the client to include resource, and answers invalid_target when it is absent.
func TestIssueHandlerRequiresResource(t *testing.T) {
	testCases := []struct {
		name     string
		audience string
		resource oauth2.Arguments
		global   bool
		client   *bool
		err      error
	}{
		{name: "ShouldRejectAMissingResourceWhenTheRelationshipListsResources", audience: redeemAudience, err: oauth2.ErrInvalidTarget},
		{name: "ShouldGrantARequestedResource", audience: redeemAudience, resource: oauth2.Arguments{redeemResource}},
		{name: "ShouldPermitAMissingResourceWhenTheRelationshipListsNone", audience: issueAudienceUnrestricted},
		{name: "ShouldPermitAMissingResourceWhenWaivedGlobally", audience: redeemAudience, global: true},
		{name: "ShouldPermitAMissingResourceWhenWaivedForTheClient", audience: redeemAudience, client: new(true)},
		{name: "ShouldRejectAMissingResourceWhenTheClientDoesNotWaiveIt", audience: redeemAudience, client: new(false), err: oauth2.ErrInvalidTarget},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			handler, config, _ := newIssueFixture(t, false)
			config.IDJAGResourceOptional = tc.global

			store := handler.Storage.(*storage.MemoryStore)

			unrestricted := store.IDJAGRelationships[storage.IDJAGRelationshipKey{ClientID: issueClient, Audience: redeemAudience}]
			unrestricted.Resources = nil

			store.IDJAGRelationships[storage.IDJAGRelationshipKey{ClientID: issueClient, Audience: issueAudienceUnrestricted}] = unrestricted

			request := newIssueRequest(t, newIssueSession(time.Now().Add(time.Hour)), nil)
			request.RequestedAudience = oauth2.Arguments{tc.audience}
			request.RequestedResource = tc.resource

			if tc.client != nil {
				request.Client = &resourceOptionalClient{DefaultClient: request.Client.(*oauth2.DefaultClient), optional: *tc.client}
			}

			err := handler.HandleTokenEndpointRequest(t.Context(), request)

			if tc.err != nil {
				require.ErrorIs(t, err, tc.err)

				return
			}

			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
			assert.Equal(t, tc.resource, request.GetGrantedResource())
		})
	}
}

func TestIssueHandlerRequiresResourceWithoutTheOptionalProvider(t *testing.T) {
	handler, config, _ := newIssueFixture(t, false)
	config.IDJAGResourceOptional = true

	handler.Config = issueConfigOnly{IssueConfig: config}

	request := newIssueRequest(t, newIssueSession(time.Now().Add(time.Hour)), nil)
	request.RequestedAudience = oauth2.Arguments{redeemAudience}
	request.RequestedResource = nil

	require.ErrorIs(t, handler.HandleTokenEndpointRequest(t.Context(), request), oauth2.ErrInvalidTarget)
}

// issueConfigOnly hides every method of the wrapped configuration outside idjag.IssueConfig.
type issueConfigOnly struct {
	idjag.IssueConfig
}

type resourceOptionalClient struct {
	*oauth2.DefaultClient

	optional bool
}

func (c *resourceOptionalClient) GetIDJAGResourceOptional() bool {
	return c.optional
}
