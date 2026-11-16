// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/storage"
)

func TestRefreshFlow_GracePeriodEligibility(t *testing.T) {
	grace := func(d time.Duration) *time.Duration { return &d }

	testCases := []struct {
		name     string
		global   time.Duration
		client   *time.Duration
		public   bool
		session  *oauth2.DefaultSession
		dpop     bool
		mtls     bool
		expected bool
	}{
		{name: "ShouldBeDisabledByDefault"},
		{name: "ShouldApplyTheProviderValue", global: time.Minute, expected: true},
		{name: "ShouldApplyTheClientValueWhenTheProviderHasNone", client: grace(time.Minute), expected: true},
		{name: "ShouldNotApplyWhenTheClientDisablesTheProviderValue", global: time.Minute, client: grace(0)},
		{name: "ShouldNotApplyWhenTheClientValueIsNegative", global: time.Minute, client: grace(-time.Minute)},
		{name: "ShouldNotApplyWhenTheProviderValueIsNegative", global: -time.Minute},
		{name: "ShouldNotApplyToAPublicClientWithAnUnboundToken", global: time.Minute, client: grace(time.Minute), public: true},
		{name: "ShouldNotApplyToAPublicClientWhenDPoPIsDisabled", global: time.Minute, public: true, session: &oauth2.DefaultSession{JWKThumbprint: "jkt"}},
		{name: "ShouldApplyToAPublicClientWithADPoPBoundToken", global: time.Minute, public: true, session: &oauth2.DefaultSession{JWKThumbprint: "jkt"}, dpop: true, expected: true},
		{name: "ShouldApplyToAPublicClientWithACertificateBoundToken", client: grace(time.Minute), public: true, session: &oauth2.DefaultSession{ClientCertificateThumbprint: "x5t"}, mtls: true, expected: true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			forEachGracePeriodStore(t, func(t *testing.T, f *gracePeriodFixture) {
				f.config.RefreshTokenGracePeriod = tc.global
				f.config.DPoPEnabled = tc.dpop
				f.config.MTLSEnabled = tc.mtls
				f.client.RefreshTokenGracePeriod = tc.client
				f.client.Public = tc.public

				if tc.session != nil {
					f.session.JWKThumbprint = tc.session.JWKThumbprint
					f.session.ClientCertificateThumbprint = tc.session.ClientCertificateThumbprint
				}

				f.issue()

				first, err := f.redeem(f.token)
				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

				second, err := f.redeem(f.token)

				if tc.expected {
					require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
					assert.NotEmpty(t, second.GetAccessToken())
					assert.NoError(t, f.refreshTokenError(refreshTokenOf(first)))
					assert.NoError(t, f.accessTokenError(first.GetAccessToken()))

					return
				}

				require.ErrorIs(t, err, oauth2.ErrInvalidGrant)
				assert.ErrorIs(t, f.refreshTokenError(refreshTokenOf(first)), oauth2.ErrInactiveToken)
				assert.ErrorIs(t, f.accessTokenError(first.GetAccessToken()), oauth2.ErrNotFound)
			})
		})
	}
}

func TestRefreshFlow_GracePeriodForksTheGrant(t *testing.T) {
	forEachGracePeriodStore(t, func(t *testing.T, f *gracePeriodFixture) {
		f.config.RefreshTokenGracePeriod = time.Minute

		f.issue()

		first, err := f.redeem(f.token)
		require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

		_, err = f.store.GetAccessTokenSession(t.Context(), f.accessSignature, &oauth2.DefaultSession{})
		assert.ErrorIs(t, err, oauth2.ErrNotFound)

		second, err := f.redeem(f.token)
		require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

		assert.NotEqual(t, first.GetAccessToken(), second.GetAccessToken())
		assert.NotEqual(t, refreshTokenOf(first), refreshTokenOf(second))

		for _, response := range []*oauth2.AccessResponse{first, second} {
			assert.NoError(t, f.accessTokenError(response.GetAccessToken()))

			session := &oauth2.DefaultSession{}

			stored, err := f.store.GetRefreshTokenSession(t.Context(), f.handler.RefreshTokenStrategy.RefreshTokenSignature(t.Context(), refreshTokenOf(response)), session)
			require.NoError(t, err)

			assert.Equal(t, "req-id", stored.GetID())
			assert.Equal(t, "peter", stored.GetSession().GetSubject())
			assert.True(t, stored.GetSession().GetExpiresAt(oauth2.RefreshToken).After(f.expires))
		}

		session := &oauth2.DefaultSession{}

		original, err := f.store.GetRefreshTokenSession(t.Context(), f.signature, session)
		require.NoError(t, err)
		assert.True(t, original.GetSession().GetExpiresAt(oauth2.RefreshToken).Equal(f.expires))

		third, err := f.redeem(refreshTokenOf(first))
		require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

		assert.ErrorIs(t, f.accessTokenError(first.GetAccessToken()), oauth2.ErrNotFound)
		assert.NoError(t, f.accessTokenError(second.GetAccessToken()))
		assert.NoError(t, f.accessTokenError(third.GetAccessToken()))
	})
}

func TestRefreshFlow_GracePeriodEndedRevokesTheGrant(t *testing.T) {
	forEachGracePeriodStore(t, func(t *testing.T, f *gracePeriodFixture) {
		f.config.RefreshTokenGracePeriod = time.Minute

		f.issue()

		first, err := f.redeem(f.token)
		require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

		f.offset = time.Minute + time.Second

		second, err := f.redeem(f.token)
		require.ErrorIs(t, err, oauth2.ErrInvalidGrant)
		assert.Empty(t, second.GetAccessToken())

		assert.ErrorIs(t, f.refreshTokenError(f.token), oauth2.ErrInactiveToken)
		assert.ErrorIs(t, f.refreshTokenError(refreshTokenOf(first)), oauth2.ErrInactiveToken)
		assert.ErrorIs(t, f.accessTokenError(first.GetAccessToken()), oauth2.ErrNotFound)

		_, err = f.redeem(refreshTokenOf(first))
		assert.ErrorIs(t, err, oauth2.ErrInvalidGrant)
	})
}

func TestRefreshFlow_GracePeriodIsNotExtendedByARedemption(t *testing.T) {
	forEachGracePeriodStore(t, func(t *testing.T, f *gracePeriodFixture) {
		f.config.RefreshTokenGracePeriod = time.Minute

		f.issue()

		first, err := f.redeem(f.token)
		require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

		f.offset = 40 * time.Second

		second, err := f.redeem(f.token)
		require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

		f.config.RefreshTokenGracePeriod = time.Hour

		third, err := f.redeem(refreshTokenOf(first))
		require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

		f.offset = 70 * time.Second

		require.NoError(t, f.refreshTokenError(refreshTokenOf(first)))

		_, err = f.redeem(f.token)
		require.ErrorIs(t, err, oauth2.ErrInvalidGrant)

		for _, response := range []*oauth2.AccessResponse{first, second, third} {
			assert.ErrorIs(t, f.refreshTokenError(refreshTokenOf(response)), oauth2.ErrInactiveToken)
			assert.ErrorIs(t, f.accessTokenError(response.GetAccessToken()), oauth2.ErrNotFound)
		}
	})
}

func TestRefreshFlow_GracePeriodEndsWhenTheRefreshTokenExpires(t *testing.T) {
	forEachGracePeriodStore(t, func(t *testing.T, f *gracePeriodFixture) {
		f.config.RefreshTokenGracePeriod = time.Hour
		f.expires = time.Now().UTC().Add(time.Minute).Truncate(time.Second)

		f.issue()

		recorder := &gracePeriodRecordingStore{TokenRevocationStorage: f.store}
		f.handler.TokenRevocationStorage = recorder

		_, err := f.redeem(f.token)
		require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

		require.Len(t, recorder.deadlines, 1)
		assert.True(t, recorder.deadlines[0].Equal(f.expires))

		f.offset = time.Minute + time.Second

		_, err = f.redeem(f.token)
		assert.ErrorIs(t, err, oauth2.ErrInvalidGrant)
	})
}

func TestRefreshFlow_GracePeriodRequiresStorageSupport(t *testing.T) {
	forEachGracePeriodStore(t, func(t *testing.T, f *gracePeriodFixture) {
		f.config.RefreshTokenGracePeriod = time.Minute

		f.issue()

		f.handler.TokenRevocationStorage = struct{ TokenRevocationStorage }{f.store}

		first, err := f.redeem(f.token)
		require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

		assert.ErrorIs(t, f.refreshTokenError(f.token), oauth2.ErrInactiveToken)

		_, err = f.redeem(f.token)
		require.ErrorIs(t, err, oauth2.ErrInvalidGrant)

		assert.ErrorIs(t, f.refreshTokenError(refreshTokenOf(first)), oauth2.ErrInactiveToken)
		assert.ErrorIs(t, f.accessTokenError(first.GetAccessToken()), oauth2.ErrNotFound)
	})
}

func TestRefreshFlow_GracePeriodDoesNotApplyWithoutRotation(t *testing.T) {
	forEachGracePeriodStore(t, func(t *testing.T, f *gracePeriodFixture) {
		f.config.RefreshTokenGracePeriod = time.Minute
		f.config.DisableRefreshTokenRotation = true

		f.issue()

		recorder := &gracePeriodRecordingStore{TokenRevocationStorage: f.store}
		f.handler.TokenRevocationStorage = recorder

		response, err := f.redeem(f.token)
		require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

		assert.Empty(t, refreshTokenOf(response))
		assert.Empty(t, recorder.deadlines)

		f.offset = time.Minute + time.Second

		assert.NoError(t, f.refreshTokenError(f.token))
	})
}

func TestRefreshFlow_GracePeriodRevocationCoversTheWholeGrant(t *testing.T) {
	forEachGracePeriodStore(t, func(t *testing.T, f *gracePeriodFixture) {
		f.config.RefreshTokenGracePeriod = time.Minute

		f.issue()

		first, err := f.redeem(f.token)
		require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

		second, err := f.redeem(f.token)
		require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

		require.NoError(t, RevokeRefreshTokenFamily(t.Context(), f.store, f.signature, &oauth2.Request{ID: "req-id"}))

		assert.ErrorIs(t, f.refreshTokenError(f.token), oauth2.ErrInactiveToken)

		for _, response := range []*oauth2.AccessResponse{first, second} {
			assert.ErrorIs(t, f.refreshTokenError(refreshTokenOf(response)), oauth2.ErrInactiveToken)
			assert.ErrorIs(t, f.accessTokenError(response.GetAccessToken()), oauth2.ErrNotFound)
		}

		_, err = f.redeem(f.token)
		assert.ErrorIs(t, err, oauth2.ErrInvalidGrant)
	})
}

var (
	_ RefreshTokenGracePeriodStorage = (*storage.MemoryStore)(nil)
	_ RefreshTokenGracePeriodStorage = (*storage.HydratingMemoryStore)(nil)
)

type gracePeriodFixture struct {
	t       *testing.T
	store   TokenRevocationStorage
	handler *RefreshTokenGrantHandler
	config  *oauth2.Config
	client  *oauth2.DefaultRegisteredClient
	session *oauth2.DefaultSession
	expires time.Time
	offset  time.Duration

	token, signature, accessSignature string
}

func forEachGracePeriodStore(t *testing.T, test func(t *testing.T, f *gracePeriodFixture)) {
	t.Helper()

	for _, s := range []struct {
		name string
		new  func() (TokenRevocationStorage, *storage.MemoryStore)
	}{
		{"MemoryStore", func() (TokenRevocationStorage, *storage.MemoryStore) {
			store := storage.NewMemoryStore()

			return store, store
		}},
		{"HydratingMemoryStore", func() (TokenRevocationStorage, *storage.MemoryStore) {
			store := storage.NewHydratingMemoryStore()

			return store, store.MemoryStore
		}},
	} {
		t.Run(s.name, func(t *testing.T) {
			store, memory := s.new()

			f := &gracePeriodFixture{
				t:     t,
				store: store,
				config: &oauth2.Config{
					AccessTokenLifespan:  time.Hour,
					RefreshTokenLifespan: time.Hour,
					ScopeStrategy:        oauth2.HierarchicScopeStrategy,
					AudienceStrategy:     oauth2.DefaultAudienceStrategy,
					RefreshTokenScopes:   []string{consts.ScopeOffline},
				},
				client: &oauth2.DefaultRegisteredClient{
					DefaultClient: &oauth2.DefaultClient{ID: "foo", GrantTypes: oauth2.Arguments{consts.GrantTypeRefreshToken}, Scopes: []string{consts.ScopeOffline}},
				},
				session: &oauth2.DefaultSession{Subject: "peter"},
				expires: time.Now().UTC().Add(30 * time.Minute).Truncate(time.Second),
			}

			memory.Clock = func() time.Time { return time.Now().Add(f.offset) }

			f.handler = &RefreshTokenGrantHandler{
				TokenRevocationStorage: store,
				AccessTokenStrategy:    &hmacshaStrategy,
				RefreshTokenStrategy:   &hmacshaStrategy,
				Config:                 f.config,
			}

			test(t, f)
		})
	}
}

func (f *gracePeriodFixture) issue() {
	f.t.Helper()

	f.session.SetExpiresAt(oauth2.RefreshToken, f.expires)

	original := &oauth2.Request{
		ID:             "req-id",
		Client:         f.client,
		RequestedAt:    time.Now().UTC(),
		GrantedScope:   oauth2.Arguments{consts.ScopeOffline},
		RequestedScope: oauth2.Arguments{consts.ScopeOffline},
		Session:        f.session,
		Form:           url.Values{},
	}

	var err error

	f.token, f.signature, err = f.handler.RefreshTokenStrategy.GenerateRefreshToken(f.t.Context(), nil)
	require.NoError(f.t, err)

	_, f.accessSignature, err = f.handler.AccessTokenStrategy.GenerateAccessToken(f.t.Context(), nil)
	require.NoError(f.t, err)

	require.NoError(f.t, f.store.CreateAccessTokenSession(f.t.Context(), f.accessSignature, original))
	require.NoError(f.t, f.store.CreateRefreshTokenSession(f.t.Context(), f.signature, f.accessSignature, original))
}

func (f *gracePeriodFixture) redeem(token string) (response *oauth2.AccessResponse, err error) {
	f.t.Helper()

	request := oauth2.NewAccessRequest(&oauth2.DefaultSession{})
	request.Client = f.client
	request.GrantTypes = oauth2.Arguments{consts.GrantTypeRefreshToken}
	request.Form = url.Values{consts.FormParameterRefreshToken: {token}}

	response = oauth2.NewAccessResponse()

	if err = f.handler.HandleTokenEndpointRequest(f.t.Context(), request); err != nil {
		return response, err
	}

	return response, f.handler.PopulateTokenEndpointResponse(f.t.Context(), request, response)
}

func (f *gracePeriodFixture) refreshTokenError(token string) (err error) {
	_, err = f.store.GetRefreshTokenSession(f.t.Context(), f.handler.RefreshTokenStrategy.RefreshTokenSignature(f.t.Context(), token), &oauth2.DefaultSession{})

	return err
}

func (f *gracePeriodFixture) accessTokenError(token string) (err error) {
	_, err = f.store.GetAccessTokenSession(f.t.Context(), f.handler.AccessTokenStrategy.AccessTokenSignature(f.t.Context(), token), &oauth2.DefaultSession{})

	return err
}

func refreshTokenOf(response *oauth2.AccessResponse) (token string) {
	token, _ = response.GetExtra(consts.AccessResponseRefreshToken).(string)

	return token
}

type gracePeriodRecordingStore struct {
	TokenRevocationStorage

	deadlines []time.Time
}

func (s *gracePeriodRecordingStore) RotateRefreshTokenWithGracePeriod(ctx context.Context, requestID, signature string, deadline time.Time) error {
	s.deadlines = append(s.deadlines, deadline)

	return s.TokenRevocationStorage.(RefreshTokenGracePeriodStorage).RotateRefreshTokenWithGracePeriod(ctx, requestID, signature, deadline)
}
