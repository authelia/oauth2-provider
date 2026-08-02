// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc7591

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
)

func TestDefaultSessionKind(t *testing.T) {
	session := NewDefaultSession()

	assert.Equal(t, KindNone, session.GetClientRegistrationKind())
	assert.False(t, session.IsClientRegistration())

	session.SetClientRegistrationKind(KindCreate)
	assert.Equal(t, KindCreate, session.GetClientRegistrationKind())
	assert.True(t, session.IsClientRegistration())

	session.SetClientRegistrationKind(KindManage)
	assert.Equal(t, KindManage, session.GetClientRegistrationKind())
	assert.True(t, session.IsClientRegistration())
}

func TestDefaultSessionGrantableScopes(t *testing.T) {
	session := NewDefaultSession()

	assert.Empty(t, session.GetGrantableScopes())

	session.SetGrantableScopes(oauth2.Arguments{"openid", "profile"})
	assert.Equal(t, oauth2.Arguments{"openid", "profile"}, session.GetGrantableScopes())
}

// TestDefaultSessionCloneRetainsRegistrationFields is the regression guard for the embedded JWTSession.Clone, which
// would deep-copy only the embedded value and silently drop both registration fields.
func TestDefaultSessionCloneRetainsRegistrationFields(t *testing.T) {
	session := NewDefaultSession()
	session.SetClientRegistrationKind(KindManage)
	session.SetGrantableScopes(oauth2.Arguments{"openid"})
	session.SetSubject("client-one")

	cloned, ok := session.Clone().(*DefaultSession)
	require.True(t, ok, "Clone must return a *DefaultSession, not the embedded *hoauth2.JWTSession")

	assert.Equal(t, KindManage, cloned.GetClientRegistrationKind())
	assert.Equal(t, oauth2.Arguments{"openid"}, cloned.GetGrantableScopes())
	assert.Equal(t, "client-one", cloned.GetSubject())

	// Mutating the clone must not affect the original.
	cloned.SetClientRegistrationKind(KindCreate)
	assert.Equal(t, KindManage, session.GetClientRegistrationKind())
}

func TestDefaultSessionImplementsOAuth2Session(t *testing.T) {
	assert.Implements(t, (*oauth2.Session)(nil), NewDefaultSession())
	assert.Implements(t, (*Session)(nil), NewDefaultSession())
}

// TestDefaultSessionJSONRoundTrip pins the storage contract the whole fail-closed argument rests on. Every other test
// in this package uses MemoryStore, which hands back the very object it was given and so never exercises hydration; a
// real store serialises the session and reconstitutes it, and it is that path which decides whether a foreign token
// presented at a registration endpoint is rejected.
func TestDefaultSessionJSONRoundTrip(t *testing.T) {
	t.Run("ShouldPreserveRegistrationFields", func(t *testing.T) {
		session := NewDefaultSession()
		session.SetClientRegistrationKind(KindManage)
		session.SetGrantableScopes(oauth2.Arguments{"openid", "profile"})
		session.SetSubject("client-one")
		session.SetExpiresAt(oauth2.AccessToken, time.Unix(1767225600, 0).UTC())

		data, err := json.Marshal(session)
		require.NoError(t, err)

		// The Kind is persisted as the bare integer its iota evaluates to, which is why the const block may only ever
		// be appended to. This assertion is what would break if a value were inserted into the middle of it.
		assert.Contains(t, string(data), `"client_registration_kind":2`)

		hydrated := NewDefaultSession()
		require.NoError(t, json.Unmarshal(data, hydrated))

		assert.Equal(t, KindManage, hydrated.GetClientRegistrationKind())
		assert.True(t, hydrated.IsClientRegistration())
		assert.Equal(t, oauth2.Arguments{"openid", "profile"}, hydrated.GetGrantableScopes())
		assert.Equal(t, "client-one", hydrated.GetSubject())
		assert.Equal(t, time.Unix(1767225600, 0).UTC(), hydrated.GetExpiresAt(oauth2.AccessToken))
	})

	// An ordinary access token's session carries no registration keys at all, so hydrating one into a DefaultSession
	// leaves both registration fields at their zero values. KindNone is what then rejects it at
	// DefaultEndpointAuthStrategy step 4 - no store has to know registration sessions exist.
	t.Run("ShouldHydrateAForeignSessionToKindNone", func(t *testing.T) {
		for name, foreign := range map[string]any{
			"JWTSession":     &hoauth2.JWTSession{Subject: "ordinary", Username: "user"},
			"DefaultSession": &oauth2.DefaultSession{Subject: "ordinary", Username: "user"},
		} {
			t.Run(name, func(t *testing.T) {
				data, err := json.Marshal(foreign)
				require.NoError(t, err)

				hydrated := NewDefaultSession()
				require.NoError(t, json.Unmarshal(data, hydrated))

				assert.Equal(t, KindNone, hydrated.GetClientRegistrationKind())
				assert.False(t, hydrated.IsClientRegistration())
				assert.Empty(t, hydrated.GetGrantableScopes())
			})
		}
	})
}
