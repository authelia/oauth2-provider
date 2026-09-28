// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc8693

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/handler/openid"
	"authelia.com/provider/oauth2/internal/clone/clonetest"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/token/jwt"
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

func TestDefaultSessionClone(t *testing.T) {
	t.Run("ShouldReturnNilForNilReceiver", func(t *testing.T) {
		var s *DefaultSession

		assert.Nil(t, s.Clone())
	})

	t.Run("ShouldDeepCopyEveryField", func(t *testing.T) {
		now := time.Unix(1700000000, 0).UTC()

		s := &DefaultSession{
			DefaultSession: &openid.DefaultSession{
				Claims: &jwt.IDTokenClaims{
					JTI:                                 "jti",
					Issuer:                              "https://auth.example.com",
					Subject:                             "peter",
					Audience:                            []string{"client"},
					ExpirationTime:                      jwt.NewNumericDate(now.Add(time.Hour)),
					IssuedAt:                            jwt.NewNumericDate(now),
					AuthTime:                            jwt.NewNumericDate(now),
					Nonce:                               "nonce",
					SessionID:                           "sid",
					AuthenticationContextClassReference: "acr",
					AuthenticationMethodsReferences:     []string{"pwd"},
					AuthorizedParty:                     "client",
					AccessTokenHash:                     "at_hash",
					CodeHash:                            "c_hash",
					StateHash:                           "s_hash",
					Confirmation:                        map[string]any{"jwk": map[string]any{"kty": "EC"}},
					Extra:                               map[string]any{consts.ClaimActor: map[string]any{consts.ClaimSubject: "actor"}},
				},
				Headers:                     &jwt.Headers{Extra: map[string]any{"typ": "JWT"}},
				ExpiresAt:                   map[oauth2.TokenType]time.Time{oauth2.IDToken: now.Add(time.Hour)},
				Username:                    "peter@example",
				Subject:                     "peter",
				JWKThumbprint:               "jkt",
				ClientCertificateThumbprint: "x5t",
				PublicKeyJWK:                []byte(`{"kty":"EC"}`),
				RequestedJWKThumbprint:      "requested-jkt",
				KeyBindingGranted:           true,
				RequestedAt:                 now,
			},
			ActorToken:     map[string]any{consts.ClaimSubject: "actor"},
			SubjectToken:   map[string]any{consts.ClaimSubject: "peter"},
			Extra:          map[string]any{consts.ClaimActor: map[string]any{consts.ClaimSubject: "actor"}},
			ExpiryDeadline: now.Add(time.Hour),
		}

		cloned, ok := s.Clone().(*DefaultSession)
		require.True(t, ok)

		assert.Equal(t, s.ActorToken, cloned.ActorToken)
		assert.Equal(t, s.SubjectToken, cloned.SubjectToken)
		assert.Equal(t, s.Extra, cloned.Extra)
		assert.Equal(t, s.GetSubject(), cloned.GetSubject())

		clonetest.AssertDeepCopy(t, s, cloned)
	})
}
