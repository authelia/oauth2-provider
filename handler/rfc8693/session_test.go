// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc8693

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2/handler/openid"
	"authelia.com/provider/oauth2/internal/consts"
)

func TestDefaultSessionSetClaimActor(t *testing.T) {
	act := map[string]any{consts.ClaimSubject: "actor"}

	testCases := []struct {
		name    string
		session *DefaultSession
	}{
		{
			name:    "ShouldNotPanicOnZeroValueSession",
			session: &DefaultSession{},
		},
		{
			name:    "ShouldNotPanicWithEmbeddedSessionButNilExtra",
			session: &DefaultSession{DefaultSession: openid.NewDefaultSession()},
		},
		{
			name:    "ShouldNotPanicOnConstructedSession",
			session: NewDefaultSession(),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			require.NotPanics(t, func() {
				tc.session.SetClaimActor(act)
			})

			assert.Equal(t, act, tc.session.Extra[consts.ClaimActor])
			assert.Equal(t, act, tc.session.AccessTokenClaimsMap()[consts.ClaimActor])
		})
	}
}

func TestDefaultSessionSetClaimActorAfterRoundTrip(t *testing.T) {
	data, err := json.Marshal(NewDefaultSession())
	require.NoError(t, err)

	members := map[string]json.RawMessage{}

	require.NoError(t, json.Unmarshal(data, &members))
	assert.NotContains(t, members, "extra", "omitempty is what makes the nil map reachable through storage")

	session := &DefaultSession{}

	require.NoError(t, json.Unmarshal(data, session))
	require.Nil(t, session.Extra, "the round trip must reproduce the nil map this guards against")

	act := map[string]any{consts.ClaimSubject: "actor"}

	require.NotPanics(t, func() {
		session.SetClaimActor(act)
	})

	assert.Equal(t, act, session.Extra[consts.ClaimActor])
}

func TestNewDefaultSession(t *testing.T) {
	session := NewDefaultSession()

	require.NotNil(t, session.Extra)
	require.NotNil(t, session.DefaultSession)
	require.NotNil(t, session.DefaultSession.Claims)
	require.NotNil(t, session.DefaultSession.Headers)
}
