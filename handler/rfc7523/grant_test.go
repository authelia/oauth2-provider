// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc7523

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"authelia.com/provider/jose/jwt"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal"
	"authelia.com/provider/oauth2/internal/consts"
)

func TestHandlerScope(t *testing.T) {
	testCases := []struct {
		name      string
		claim     any
		issuer    []string
		client    []string
		anonymous bool
		requested []string
		granted   []string
		err       error
	}{
		{
			name:      "ShouldGrantARequestedScopeWithinEveryBound",
			claim:     "a b",
			issuer:    []string{"a", "b", "c"},
			client:    []string{"a", "b"},
			requested: []string{"a"},
			granted:   []string{"a"},
		},
		{
			name:      "ShouldRejectARequestedScopeOutsideTheGrant",
			claim:     "a",
			issuer:    []string{"a", "b"},
			client:    []string{"a", "b"},
			requested: []string{"b"},
			err:       oauth2.ErrInvalidScope,
		},
		{
			name:      "ShouldRejectARequestedScopeOutsideTheIssuer",
			claim:     "a b",
			issuer:    []string{"a"},
			client:    []string{"a", "b"},
			requested: []string{"b"},
			err:       oauth2.ErrInvalidScope,
		},
		{
			name:      "ShouldRejectARequestedScopeOutsideTheClient",
			claim:     "a b",
			issuer:    []string{"a", "b"},
			client:    []string{"a"},
			requested: []string{"b"},
			err:       oauth2.ErrInvalidScope,
		},
		{
			name:    "ShouldGrantTheIntersectionWhenNoScopeIsRequested",
			claim:   "a b c",
			issuer:  []string{"a", "b"},
			client:  []string{"b", "c"},
			granted: []string{"b"},
		},
		{
			name:   "ShouldGrantNothingWhenNoScopeIsRequestedAndTheGrantHasNoScopeClaim",
			issuer: []string{"a"},
			client: []string{"a"},
		},
		{
			name:      "ShouldBoundARequestByTheIssuerAndClientWhenTheGrantHasNoScopeClaim",
			issuer:    []string{"a"},
			client:    []string{"a"},
			requested: []string{"a"},
			granted:   []string{"a"},
		},
		{
			name:      "ShouldRejectARequestedScopeOutsideTheIssuerWhenTheGrantHasNoScopeClaim",
			issuer:    []string{"a"},
			client:    []string{"a", "b"},
			requested: []string{"b"},
			err:       oauth2.ErrInvalidScope,
		},
		{
			name:      "ShouldRejectARequestedScopeForAnEmptyScopeClaim",
			claim:     "",
			issuer:    []string{"a"},
			client:    []string{"a"},
			requested: []string{"a"},
			err:       oauth2.ErrInvalidScope,
		},
		{
			name:   "ShouldGrantNothingForAnEmptyScopeClaim",
			claim:  "",
			issuer: []string{"a"},
			client: []string{"a"},
		},
		{
			name:   "ShouldRejectAScopeClaimThatIsNotAString",
			claim:  []any{"a"},
			issuer: []string{"a"},
			client: []string{"a"},
			err:    oauth2.ErrInvalidGrant,
		},
		{
			name:      "ShouldRejectAScopeClaimThatIsNotAStringWhenAScopeIsRequested",
			claim:     []any{"a"},
			issuer:    []string{"a"},
			client:    []string{"a"},
			requested: []string{"a"},
			err:       oauth2.ErrInvalidGrant,
		},
		{
			name:      "ShouldIgnoreTheClientForAnAnonymousRequest",
			claim:     "a b",
			issuer:    []string{"a"},
			anonymous: true,
			granted:   []string{"a"},
		},
		{
			name:      "ShouldRejectAnAnonymousRequestedScopeOutsideTheIssuer",
			claim:     "a b",
			issuer:    []string{"a"},
			anonymous: true,
			requested: []string{"b"},
			err:       oauth2.ErrInvalidScope,
		},
		{
			name:      "ShouldRejectARequestedOfflineAccessScope",
			claim:     consts.ScopeOfflineAccess,
			issuer:    []string{consts.ScopeOfflineAccess},
			client:    []string{consts.ScopeOfflineAccess},
			requested: []string{consts.ScopeOfflineAccess},
			err:       oauth2.ErrInvalidScope,
		},
		{
			name:      "ShouldRejectARequestedOfflineScope",
			claim:     consts.ScopeOffline,
			issuer:    []string{consts.ScopeOffline},
			client:    []string{consts.ScopeOffline},
			requested: []string{consts.ScopeOffline},
			err:       oauth2.ErrInvalidScope,
		},
		{
			name:      "ShouldRejectARequestedOfflineAccessScopeWhenTheGrantHasNoScopeClaim",
			issuer:    []string{consts.ScopeOfflineAccess},
			client:    []string{consts.ScopeOfflineAccess},
			requested: []string{consts.ScopeOfflineAccess},
			err:       oauth2.ErrInvalidScope,
		},
		{
			name:    "ShouldNotGrantOfflineScopesByDefault",
			claim:   "a offline offline_access",
			issuer:  []string{"a", consts.ScopeOffline, consts.ScopeOfflineAccess},
			client:  []string{"a", consts.ScopeOffline, consts.ScopeOfflineAccess},
			granted: []string{"a"},
		},
	}

	for _, store := range jwtBearerStores {
		t.Run(store.name, func(t *testing.T) {
			for _, tc := range testCases {
				t.Run(tc.name, func(t *testing.T) {
					f := newJWTBearerFixture(t, store.new())

					f.trust(func(trusted *oauth2.RFC7523TrustedIssuer) { trusted.Scopes = tc.issuer })

					if tc.anonymous {
						f.handler.Config.(*oauth2.Config).GrantTypeJWTBearerCanSkipClientAuth = true
						f.requester.Client = &oauth2.DefaultClient{}
					} else {
						f.requester.Client = &oauth2.DefaultClient{ID: "my-client", GrantTypes: []string{consts.GrantTypeOAuthJWTBearer}, Scopes: tc.client}
					}

					var extra map[string]any

					if tc.claim != nil {
						extra = map[string]any{consts.ClaimScope: tc.claim}
					}

					f.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
					f.requester.RequestedScope = tc.requested
					f.requester.Form.Add(consts.FormParameterAssertion, f.sign(f.createStandardClaim(), extra, keyID, consts.JSONWebTokenTypeJWT))

					err := f.handler.HandleTokenEndpointRequest(f.ctx, f.requester)

					if tc.err != nil {
						assert.ErrorIs(t, err, tc.err)
						assert.Empty(t, f.requester.GetGrantedScopes())
						assert.Empty(t, f.requester.GetSession().GetSubject())

						return
					}

					require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
					assert.ElementsMatch(t, tc.granted, f.requester.GetGrantedScopes())
				})
			}
		})
	}
}

func TestHandlerExpiry(t *testing.T) {
	for _, store := range jwtBearerStores {
		t.Run(store.name, func(t *testing.T) {
			t.Run("ShouldCapTheAccessTokenAtTheGrantExpiry", func(t *testing.T) {
				f := newJWTBearerFixture(t, store.new())

				exp := time.Now().Add(2 * time.Minute).Truncate(time.Second)

				f.redeem(exp)

				assert.True(t, f.requester.GetSession().GetExpiresAt(oauth2.AccessToken).Equal(exp))

				expiresIn, ok := f.responder.GetExtra(consts.AccessResponseExpiresIn).(int64)

				require.True(t, ok)
				assert.GreaterOrEqual(t, expiresIn, int64(110))
				assert.LessOrEqual(t, expiresIn, int64(120))
			})

			t.Run("ShouldNotRoundTheGrantExpiryUp", func(t *testing.T) {
				f := newJWTBearerFixture(t, store.new())

				exp := time.Now().Add(2 * time.Second).Truncate(time.Second)

				f.redeem(exp)

				assert.False(t, f.requester.GetSession().GetExpiresAt(oauth2.AccessToken).After(exp))
			})

			t.Run("ShouldUseTheLifespanWhenTheGrantOutlivesIt", func(t *testing.T) {
				f := newJWTBearerFixture(t, store.new())

				f.handler.HandleHelper.Config.(*oauth2.Config).AccessTokenLifespan = time.Minute

				f.redeem(time.Now().Add(10 * time.Minute).Truncate(time.Second))

				assert.WithinDuration(t, time.Now().Add(time.Minute), f.requester.GetSession().GetExpiresAt(oauth2.AccessToken), 2*time.Second)

				expiresIn, ok := f.responder.GetExtra(consts.AccessResponseExpiresIn).(int64)

				require.True(t, ok)
				assert.GreaterOrEqual(t, expiresIn, int64(58))
				assert.LessOrEqual(t, expiresIn, int64(61))
			})

			t.Run("ShouldUseTheClientLifespanWhenItIsShorter", func(t *testing.T) {
				f := newJWTBearerFixture(t, store.new())

				f.requester.Client = &oauth2.DefaultClientWithCustomTokenLifespans{
					DefaultClient:  &oauth2.DefaultClient{GrantTypes: []string{consts.GrantTypeOAuthJWTBearer}},
					TokenLifespans: &internal.TestLifespans,
				}

				f.redeem(time.Now().AddDate(0, 0, 10).Truncate(time.Second))

				lifespan := *internal.TestLifespans.JwtBearerGrantAccessTokenLifespan

				assert.WithinDuration(t, time.Now().Add(lifespan), f.requester.GetSession().GetExpiresAt(oauth2.AccessToken), 2*time.Second)
			})
		})
	}
}

func TestHandlerIssuesNoRefreshToken(t *testing.T) {
	for _, store := range jwtBearerStores {
		t.Run(store.name, func(t *testing.T) {
			f := newJWTBearerFixture(t, store.new())

			scopes := []string{"valid_scope", consts.ScopeOfflineAccess}

			f.trust(func(trusted *oauth2.RFC7523TrustedIssuer) { trusted.Scopes = scopes })

			f.requester.Client = &oauth2.DefaultClient{ID: "my-client", GrantTypes: []string{consts.GrantTypeOAuthJWTBearer, consts.GrantTypeRefreshToken}, Scopes: scopes}
			f.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
			f.requester.Form.Add(consts.FormParameterAssertion, f.sign(f.createStandardClaim(), map[string]any{consts.ClaimScope: "valid_scope offline_access"}, keyID, consts.JSONWebTokenTypeJWT))
			f.mockAccessTokenStrategy.EXPECT().GenerateAccessToken(f.ctx, f.requester).Return(token, sig, nil)

			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(f.handler.HandleTokenEndpointRequest(f.ctx, f.requester)))
			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(f.handler.PopulateTokenEndpointResponse(f.ctx, f.requester, f.responder)))

			assert.Equal(t, token, f.responder.AccessToken)
			assert.Nil(t, f.responder.GetExtra(consts.AccessResponseRefreshToken))
			assert.Equal(t, []string{"valid_scope"}, []string(f.requester.GetGrantedScopes()))
		})
	}
}

func TestHandlerGrantClaims(t *testing.T) {
	actor := map[string]any{consts.ClaimSubject: "https://client.a.example"}

	for _, store := range jwtBearerStores {
		t.Run(store.name, func(t *testing.T) {
			t.Run("ShouldHandTheVerifiedClaimsToTheSession", func(t *testing.T) {
				f := newJWTBearerFixture(t, store.new())

				session := &claimsSession{DefaultSession: new(oauth2.DefaultSession)}

				f.requester.Session = session
				f.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
				f.requester.Form.Add(consts.FormParameterAssertion, f.sign(f.createStandardClaim(), map[string]any{consts.ClaimActor: actor, consts.ClaimScope: "valid_scope"}, keyID, consts.JSONWebTokenTypeJWT))

				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(f.handler.HandleTokenEndpointRequest(f.ctx, f.requester)))

				assert.Equal(t, testTrustedIssuer, session.claims[consts.ClaimIssuer])
				assert.Equal(t, "some_ro", session.claims[consts.ClaimSubject])
				assert.Equal(t, actor, session.claims[consts.ClaimActor])
				assert.Equal(t, "valid_scope", session.claims[consts.ClaimScope])
				assert.Equal(t, "local_ro", session.GetSubject())
				assert.Equal(t, 0, session.actor)
			})

			t.Run("ShouldAcceptASessionWithoutTheInterface", func(t *testing.T) {
				f := newJWTBearerFixture(t, store.new())

				f.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
				f.requester.Form.Add(consts.FormParameterAssertion, f.sign(f.createStandardClaim(), map[string]any{consts.ClaimActor: actor}, keyID, consts.JSONWebTokenTypeJWT))

				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(f.handler.HandleTokenEndpointRequest(f.ctx, f.requester)))

				assert.Equal(t, "local_ro", f.requester.GetSession().GetSubject())
			})

			t.Run("ShouldNotHandClaimsToTheSessionWhenTheGrantIsRefused", func(t *testing.T) {
				f := newJWTBearerFixture(t, store.new())

				session := &claimsSession{DefaultSession: new(oauth2.DefaultSession)}

				cl := f.createStandardClaim()
				cl.Subject = "unmapped_ro"

				f.requester.Session = session
				f.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
				f.requester.Form.Add(consts.FormParameterAssertion, f.sign(cl, map[string]any{consts.ClaimActor: actor}, keyID, consts.JSONWebTokenTypeJWT))

				assert.ErrorIs(t, f.handler.HandleTokenEndpointRequest(f.ctx, f.requester), oauth2.ErrInvalidGrant)

				assert.Nil(t, session.claims)
				assert.Empty(t, session.GetSubject())
				assert.Equal(t, 0, session.actor)
			})
		})
	}
}

func TestHandlerGrantClaimsIsolation(t *testing.T) {
	t.Run("ShouldNotLetTheResolverChangeTheGrantedScopeOrTheSessionClaims", func(t *testing.T) {
		f := newJWTBearerMockFixture(t)

		session := &claimsSession{DefaultSession: new(oauth2.DefaultSession)}

		trusted := f.createTrustedIssuer()
		trusted.Scopes = []string{"valid_scope", "other_scope"}

		f.expectVerified(trusted)
		f.mockStore.EXPECT().ResolveRFC7523Subject(f.ctx, gomock.Any(), gomock.Any(), keyID, gomock.Any()).DoAndReturn(
			func(_ context.Context, _ oauth2.Client, _ *oauth2.RFC7523TrustedIssuer, _ string, claims map[string]any) (string, error) {
				claims[consts.ClaimScope] = "valid_scope other_scope"
				claims["injected"] = true

				return "local_ro", nil
			})

		f.requester.Session = session
		f.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
		f.requester.Form.Add(consts.FormParameterAssertion, f.sign(f.createStandardClaim(), map[string]any{consts.ClaimScope: "valid_scope"}, keyID, consts.JSONWebTokenTypeJWT))

		require.NoError(t, oauth2.ErrorToDebugRFC6749Error(f.handler.HandleTokenEndpointRequest(f.ctx, f.requester)))

		assert.Equal(t, []string{"valid_scope"}, []string(f.requester.GetGrantedScopes()))
		assert.Equal(t, "valid_scope", session.claims[consts.ClaimScope])
		assert.NotContains(t, session.claims, "injected")
		assert.Equal(t, "local_ro", session.GetSubject())
	})
}

func TestHandlerGrantClaimsNestedIsolation(t *testing.T) {
	t.Run("ShouldNotLetTheResolverChangeANestedClaim", func(t *testing.T) {
		f := newJWTBearerMockFixture(t)

		session := &claimsSession{DefaultSession: new(oauth2.DefaultSession)}

		f.expectVerified(f.createTrustedIssuer())
		f.mockStore.EXPECT().ResolveRFC7523Subject(f.ctx, gomock.Any(), gomock.Any(), keyID, gomock.Any()).DoAndReturn(
			func(_ context.Context, _ oauth2.Client, _ *oauth2.RFC7523TrustedIssuer, _ string, claims map[string]any) (string, error) {
				act := claims[consts.ClaimActor].(map[string]any)
				act[consts.ClaimSubject] = "https://attacker.example"
				act["chain"].([]any)[0] = "tampered"

				return "local_ro", nil
			})

		actor := map[string]any{consts.ClaimSubject: "https://client.a.example", "chain": []any{"original"}}

		f.requester.Session = session
		f.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
		f.requester.Form.Add(consts.FormParameterAssertion, f.sign(f.createStandardClaim(), map[string]any{consts.ClaimActor: actor}, keyID, consts.JSONWebTokenTypeJWT))

		require.NoError(t, oauth2.ErrorToDebugRFC6749Error(f.handler.HandleTokenEndpointRequest(f.ctx, f.requester)))

		assert.Equal(t, actor, session.claims[consts.ClaimActor])
	})
}

func (f *jwtBearerFixture) redeem(exp time.Time) {
	f.t.Helper()

	cl := f.createStandardClaim()
	cl.Expiry = jwt.NewNumericDate(exp)

	f.requester.GrantTypes = []string{consts.GrantTypeOAuthJWTBearer}
	f.requester.Form.Add(consts.FormParameterAssertion, f.createTestAssertion(cl, keyID))
	f.mockAccessTokenStrategy.EXPECT().GenerateAccessToken(f.ctx, f.requester).Return(token, sig, nil)

	require.NoError(f.t, oauth2.ErrorToDebugRFC6749Error(f.handler.HandleTokenEndpointRequest(f.ctx, f.requester)))
	require.NoError(f.t, oauth2.ErrorToDebugRFC6749Error(f.handler.PopulateTokenEndpointResponse(f.ctx, f.requester, f.responder)))
}

type claimsSession struct {
	*oauth2.DefaultSession

	claims map[string]any
	actor  int
}

func (s *claimsSession) SetRFC7523GrantClaims(claims map[string]any) {
	s.claims = claims
}

func (s *claimsSession) SetClaimActor(_ map[string]any) {
	s.actor++
}
