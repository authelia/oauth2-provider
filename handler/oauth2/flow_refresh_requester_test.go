// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"authelia.com/provider/oauth2"
)

func TestRefreshTokenRequesterKeepsTheFullGrant(t *testing.T) {
	newGrant := func() *oauth2.Request {
		return &oauth2.Request{
			RequestedAudience: oauth2.Arguments{"aud-a", "aud-b", "aud-c"},
			GrantedAudience:   oauth2.Arguments{"aud-a", "aud-b"},
			RequestedResource: oauth2.Arguments{"res-a", "res-b", "res-c"},
			GrantedResource:   oauth2.Arguments{"res-a", "res-b"},
		}
	}

	newRequest := func() *oauth2.AccessRequest {
		return &oauth2.AccessRequest{
			Request: oauth2.Request{
				RequestedAudience: oauth2.Arguments{"aud-b"},
				GrantedAudience:   oauth2.Arguments{"aud-b"},
				RequestedResource: oauth2.Arguments{"res-b"},
				GrantedResource:   oauth2.Arguments{"res-b"},
			},
		}
	}

	testCases := []struct {
		name    string
		request func() oauth2.AccessRequester
	}{
		{
			name:    "ShouldRestoreTheGrantForARestoringRequester",
			request: func() oauth2.AccessRequester { return newRequest() },
		},
		{
			name:    "ShouldRestoreTheGrantForAnyOtherRequester",
			request: func() oauth2.AccessRequester { return &plainAccessRequester{AccessRequester: newRequest()} },
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			grant := newGrant()
			request := tc.request()

			requester := refreshTokenRequester(request, grant)

			assert.Equal(t, grant.RequestedAudience, requester.GetRequestedAudience())
			assert.Equal(t, grant.RequestedResource, requester.GetRequestedResource())
			assert.ElementsMatch(t, grant.GrantedAudience, requester.GetGrantedAudience())
			assert.ElementsMatch(t, grant.GrantedResource, requester.GetGrantedResource())

			assert.Equal(t, oauth2.Arguments{"aud-b"}, request.GetGrantedAudience())
			assert.Equal(t, oauth2.Arguments{"res-b"}, request.GetGrantedResource())
		})
	}
}

type plainAccessRequester struct {
	oauth2.AccessRequester
}
