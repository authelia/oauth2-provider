// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc7591

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
)

func grantableFixture(kind Kind, scopes oauth2.Arguments) oauth2.Requester {
	session := NewDefaultSession()
	session.SetClientRegistrationKind(kind)
	session.SetGrantableScopes(scopes)

	requester := oauth2.NewRequest()
	requester.Session = session

	return requester
}

func TestCheckGrantableScopes(t *testing.T) {
	ctx := context.Background()
	config := &oauth2.Config{ScopeStrategy: oauth2.ExactScopeStrategy}

	testCases := []struct {
		name          string
		authenticated oauth2.Requester
		scope         string
		err           string
	}{
		{
			"ShouldAllowExactMatch",
			grantableFixture(KindCreate, oauth2.Arguments{"openid", "profile"}),
			"openid profile",
			"",
		},
		{
			"ShouldAllowStrictSubset",
			grantableFixture(KindCreate, oauth2.Arguments{"openid", "profile"}),
			"openid",
			"",
		},
		{
			"ShouldAllowOmittedScope",
			grantableFixture(KindCreate, oauth2.Arguments{"openid"}),
			"",
			"",
		},
		{
			"ShouldRejectExcess",
			grantableFixture(KindCreate, oauth2.Arguments{"openid"}),
			"openid profile",
			"The request requested the scopes 'profile' which the presented Client Registration Token is not permitted to grant.",
		},
		{
			"ShouldRejectAllWhenCeilingEmpty",
			grantableFixture(KindCreate, nil),
			"openid",
			"The request requested the scopes 'openid' which the presented Client Registration Token is not permitted to grant.",
		},
		{
			// Unauthenticated registration has no creation token and therefore no ceiling to enforce.
			"ShouldSkipWhenUnauthenticated",
			nil,
			"openid profile",
			"",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			metadata := &oauth2.ClientRegistrationMetadata{Scope: tc.scope}

			err := checkGrantableScopes(ctx, config, tc.authenticated, metadata)

			if tc.err == "" {
				require.NoError(t, err)

				return
			}

			require.Error(t, err)
			assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), "The value of one of the client metadata fields is invalid and the server has rejected this request. "+tc.err)
		})
	}
}
