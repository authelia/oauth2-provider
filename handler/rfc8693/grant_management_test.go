// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc8693_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/compose"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	. "authelia.com/provider/oauth2/handler/rfc8693"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/gen"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestTokenExchangePropagatesTheGrant(t *testing.T) {
	sessions := []struct {
		name string
		new  func() oauth2.Session
	}{
		{"TokenExchangeSession", func() oauth2.Session {
			session := NewDefaultSession()
			session.SetSubject("peter")

			return session
		}},
		{"CoreSession", func() oauth2.Session { return &oauth2.DefaultSession{Subject: "peter"} }},
		{"JWTSession", func() oauth2.Session { return &hoauth2.JWTSession{Subject: "peter"} }},
	}

	testCases := []struct {
		name      string
		subject   string
		requested string
		keep      bool
		refresh   bool
		appended  bool
	}{
		{name: "ShouldPropagateFromAnAccessToken", subject: consts.TokenTypeRFC8693AccessToken, requested: consts.TokenTypeRFC8693AccessToken, appended: true},
		{name: "ShouldPropagateFromARotatedRefreshTokenToAnAccessToken", subject: consts.TokenTypeRFC8693RefreshToken, requested: consts.TokenTypeRFC8693AccessToken, refresh: true},
		{name: "ShouldPropagateFromAKeptRefreshTokenToAnAccessToken", subject: consts.TokenTypeRFC8693RefreshToken, requested: consts.TokenTypeRFC8693AccessToken, keep: true, refresh: true, appended: true},
		{name: "ShouldPropagateFromARotatedRefreshTokenToARefreshToken", subject: consts.TokenTypeRFC8693RefreshToken, requested: consts.TokenTypeRFC8693RefreshToken},
		{name: "ShouldPropagateFromAKeptRefreshTokenToARefreshToken", subject: consts.TokenTypeRFC8693RefreshToken, requested: consts.TokenTypeRFC8693RefreshToken, keep: true, appended: true},
	}

	for _, sc := range bindingExchangeStores() {
		for _, kind := range sessions {
			for _, tc := range testCases {
				t.Run(sc.name+"/"+kind.name+"/"+tc.name, func(t *testing.T) {
					store := sc.newStore()

					session := kind.new()
					session.(oauth2.GrantManagementSession).SetGrantID(grantExchangeID)
					session.(oauth2.GrantManagementSession).SetGrantManagementAction(oauth2.GrantManagementActionCreate)

					f := newGrantPropagation(t, store, store, session, tc.subject, tc.requested, tc.keep)

					own := f.request.GetSession().(oauth2.GrantManagementSession)
					own.SetGrantID("another")
					own.SetGrantManagementAction(oauth2.GrantManagementActionMerge)
					own.SetGrantPermissions(&oauth2.GrantPermissions{Scopes: []oauth2.GrantScope{{Scope: "write"}}})

					before := newGrantExchangeGrant(f.subjectID, time.Time{})
					require.NoError(t, store.(oauth2.GrantManagementStorage).CreateGrant(t.Context(), before))

					require.NoError(t, oauth2.ErrorToDebugRFC6749Error(f.exchange(t)))

					assert.Equal(t, grantExchangeID, own.GetGrantID())
					assert.Empty(t, own.GetGrantManagementAction())
					assert.Nil(t, own.GetGrantPermissions())

					expected := before.Clone()

					if tc.appended {
						require.NotEqual(t, f.subjectID, f.request.GetID())

						expected.RequestIDs = append(expected.RequestIDs, f.request.GetID())
					} else {
						require.Equal(t, f.subjectID, f.request.GetID())
					}

					actual, err := store.(oauth2.GrantManagementStorage).GetGrant(t.Context(), grantExchangeID)
					require.NoError(t, err)
					assert.Equal(t, expected, actual)

					assert.Nil(t, f.response.GetExtra(consts.AccessResponseGrantID))

					tokens := f.issued(t)

					if tc.refresh {
						require.Len(t, tokens, 2)
					} else {
						require.Len(t, tokens, 1)
					}

					for _, issued := range tokens {
						assert.Equal(t, grantExchangeID, issued.GetGrantID())
						assert.Empty(t, issued.GetGrantManagementAction())
						assert.Nil(t, issued.GetGrantPermissions())
					}
				})
			}
		}
	}
}

func TestTokenExchangeRefusesAGrantWhichIsGone(t *testing.T) {
	testCases := []struct {
		name      string
		subject   string
		requested string
		keep      bool
	}{
		{name: "FromAnAccessToken", subject: consts.TokenTypeRFC8693AccessToken, requested: consts.TokenTypeRFC8693AccessToken},
		{name: "FromARotatedRefreshTokenToAnAccessToken", subject: consts.TokenTypeRFC8693RefreshToken, requested: consts.TokenTypeRFC8693AccessToken},
		{name: "FromAKeptRefreshTokenToAnAccessToken", subject: consts.TokenTypeRFC8693RefreshToken, requested: consts.TokenTypeRFC8693AccessToken, keep: true},
		{name: "FromARotatedRefreshTokenToARefreshToken", subject: consts.TokenTypeRFC8693RefreshToken, requested: consts.TokenTypeRFC8693RefreshToken},
		{name: "FromAKeptRefreshTokenToARefreshToken", subject: consts.TokenTypeRFC8693RefreshToken, requested: consts.TokenTypeRFC8693RefreshToken, keep: true},
	}

	grants := []struct {
		name string
		new  func(subjectID string) *oauth2.Grant
	}{
		{"ShouldRefuseADeletedGrant", func(string) *oauth2.Grant { return nil }},
		{"ShouldRefuseAnExpiredGrant", func(subjectID string) *oauth2.Grant {
			return newGrantExchangeGrant(subjectID, time.Now().UTC().Add(-time.Minute))
		}},
	}

	for _, sc := range bindingExchangeStores() {
		for _, gc := range grants {
			for _, tc := range testCases {
				t.Run(sc.name+"/"+gc.name+tc.name, func(t *testing.T) {
					store := sc.newStore()

					session := NewDefaultSession()
					session.SetSubject("peter")
					session.SetGrantID(grantExchangeID)

					f := newGrantPropagation(t, store, store, session, tc.subject, tc.requested, tc.keep)

					before := gc.new(f.subjectID)
					if before != nil {
						require.NoError(t, store.(oauth2.GrantManagementStorage).CreateGrant(t.Context(), before))
					}

					err := f.exchange(t)

					require.ErrorIs(t, err, oauth2.ErrInvalidGrant)
					assert.Equal(t, "invalid_grant", oauth2.ErrorToRFC6749Error(err).ErrorField)

					assert.Empty(t, f.response.GetAccessToken())
					assert.Nil(t, f.response.GetExtra(consts.AccessResponseRefreshToken))

					if before != nil {
						actual, err := store.(oauth2.GrantManagementStorage).GetGrant(t.Context(), grantExchangeID)
						require.NoError(t, err)
						assert.Equal(t, before, actual)
					}
				})
			}
		}
	}
}

func TestTokenExchangeWithoutAGrantIsUnchanged(t *testing.T) {
	testCases := []struct {
		name      string
		subject   string
		requested string
	}{
		{name: "FromAnAccessToken", subject: consts.TokenTypeRFC8693AccessToken, requested: consts.TokenTypeRFC8693AccessToken},
		{name: "FromARefreshTokenToAnAccessToken", subject: consts.TokenTypeRFC8693RefreshToken, requested: consts.TokenTypeRFC8693AccessToken},
		{name: "FromARefreshTokenToARefreshToken", subject: consts.TokenTypeRFC8693RefreshToken, requested: consts.TokenTypeRFC8693RefreshToken},
	}

	for _, sc := range bindingExchangeStores() {
		for _, tc := range testCases {
			t.Run(sc.name+"/ShouldNotUseGrantStorageWithoutAGrantID"+tc.name, func(t *testing.T) {
				store := sc.newStore()
				spy := &grantExchangeSpyStore{rfc8693ExchangeStore: store, grants: store.(oauth2.GrantManagementStorage)}

				session := NewDefaultSession()
				session.SetSubject("peter")

				f := newGrantPropagation(t, store, spy, session, tc.subject, tc.requested, true)

				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(f.exchange(t)))

				assert.Zero(t, spy.calls)
				assert.Nil(t, f.response.GetExtra(consts.AccessResponseGrantID))

				for _, issued := range f.issued(t) {
					assert.Empty(t, issued.GetGrantID())
				}
			})

			t.Run(sc.name+"/ShouldNotPropagateWithoutGrantStorage"+tc.name, func(t *testing.T) {
				store := sc.newStore()

				session := NewDefaultSession()
				session.SetSubject("peter")
				session.SetGrantID(grantExchangeID)

				f := newGrantPropagation(t, store, &grantExchangePlainStore{rfc8693ExchangeStore: store}, session, tc.subject, tc.requested, true)

				before := newGrantExchangeGrant(f.subjectID, time.Time{})
				require.NoError(t, store.(oauth2.GrantManagementStorage).CreateGrant(t.Context(), before))

				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(f.exchange(t)))

				actual, err := store.(oauth2.GrantManagementStorage).GetGrant(t.Context(), grantExchangeID)
				require.NoError(t, err)
				assert.Equal(t, before, actual)

				assert.Nil(t, f.response.GetExtra(consts.AccessResponseGrantID))

				for _, issued := range f.issued(t) {
					assert.Empty(t, issued.GetGrantID())
				}
			})
		}
	}
}

func TestRevokingAGrantRevokesExchangedTokens(t *testing.T) {
	stores := []struct {
		name string
		new  func() (any, *storage.MemoryStore)
	}{
		{"MemoryStore", func() (any, *storage.MemoryStore) {
			store := storage.NewMemoryStore()

			return store, store
		}},
		{"HydratingMemoryStore", func() (any, *storage.MemoryStore) {
			store := storage.NewHydratingMemoryStore()

			return store, store.MemoryStore
		}},
	}

	testCases := []struct {
		name string
		keep bool
	}{
		{name: "ShouldRevokeTokensOfARotatingExchange"},
		{name: "ShouldRevokeTokensOfAnExchangeWhichKeepsTheSubjectToken", keep: true},
	}

	for _, sc := range stores {
		for _, tc := range testCases {
			t.Run(sc.name+"/"+tc.name, func(t *testing.T) {
				flow := newGrantExchangeFlow(t, sc.new, tc.keep)

				// The grant is created by an authorization with the action 'create' (Section 5.2).
				code := flow.authorize(t)

				redeemed, _ := flow.token(t, url.Values{
					consts.FormParameterGrantType:         {consts.GrantTypeAuthorizationCode},
					consts.FormParameterAuthorizationCode: {code},
					consts.FormParameterRedirectURI:       {grantExchangeRedirectURI},
				})

				grantID, ok := redeemed.GetExtra(consts.AccessResponseGrantID).(string)
				require.True(t, ok)
				require.NotEmpty(t, grantID)

				refreshToken, ok := redeemed.GetExtra(consts.AccessResponseRefreshToken).(string)
				require.True(t, ok)

				fromAccess, fromAccessID := flow.token(t, url.Values{
					consts.FormParameterGrantType:          {consts.GrantTypeOAuthTokenExchange},
					consts.FormParameterSubjectToken:       {redeemed.GetAccessToken()},
					consts.FormParameterSubjectTokenType:   {consts.TokenTypeRFC8693AccessToken},
					consts.FormParameterRequestedTokenType: {consts.TokenTypeRFC8693AccessToken},
					consts.FormParameterScope:              {"read"},
				})

				fromRefresh, fromRefreshID := flow.token(t, url.Values{
					consts.FormParameterGrantType:          {consts.GrantTypeOAuthTokenExchange},
					consts.FormParameterSubjectToken:       {refreshToken},
					consts.FormParameterSubjectTokenType:   {consts.TokenTypeRFC8693RefreshToken},
					consts.FormParameterRequestedTokenType: {consts.TokenTypeRFC8693AccessToken},
					consts.FormParameterScope:              {"read offline_access"},
				})

				exchangedRefreshToken, ok := fromRefresh.GetExtra(consts.AccessResponseRefreshToken).(string)
				require.True(t, ok)
				require.NotEmpty(t, exchangedRefreshToken)

				assert.Nil(t, fromAccess.GetExtra(consts.AccessResponseGrantID))
				assert.Nil(t, fromRefresh.GetExtra(consts.AccessResponseGrantID))

				grant, err := flow.memory.GetGrant(flow.ctx, grantID)
				require.NoError(t, err)

				require.NotEmpty(t, grant.RequestIDs)

				if tc.keep {
					assert.Equal(t, []string{grant.RequestIDs[0], fromAccessID, fromRefreshID}, grant.RequestIDs)
					assert.NotEqual(t, grant.RequestIDs[0], fromRefreshID)
				} else {
					assert.Equal(t, []string{fromRefreshID, fromAccessID}, grant.RequestIDs)
				}

				assert.Equal(t, oauth2.Arguments{"read", "offline_access"}, grant.Permissions.ScopeValues())
				assert.Equal(t, grant.CreatedAt, grant.UpdatedAt)

				require.True(t, flow.active(fromAccess.GetAccessToken()))
				require.True(t, flow.active(fromRefresh.GetAccessToken()))

				require.NoError(t, flow.provider.(oauth2.GrantManagementProvider).RevokeGrant(flow.ctx, grantID))

				assert.False(t, flow.active(fromAccess.GetAccessToken()))
				assert.False(t, flow.active(fromRefresh.GetAccessToken()))

				_, err = flow.request(url.Values{
					consts.FormParameterGrantType:    {consts.GrantTypeRefreshToken},
					consts.FormParameterRefreshToken: {exchangedRefreshToken},
				})

				require.ErrorIs(t, err, oauth2.ErrInvalidGrant)
				assert.Equal(t, "invalid_grant", oauth2.ErrorToRFC6749Error(err).ErrorField)
			})
		}
	}
}

func TestRevokingAGrantDuringATokenExchange(t *testing.T) {
	stores := []struct {
		name string
		new  func(hook *grantExchangeRevokeHook) (any, *storage.MemoryStore)
	}{
		{"MemoryStore", func(hook *grantExchangeRevokeHook) (any, *storage.MemoryStore) {
			store := storage.NewMemoryStore()

			return &grantExchangeRevokingMemoryStore{MemoryStore: store, hook: hook}, store
		}},
		{"HydratingMemoryStore", func(hook *grantExchangeRevokeHook) (any, *storage.MemoryStore) {
			store := storage.NewHydratingMemoryStore()

			return &grantExchangeRevokingHydratingStore{HydratingMemoryStore: store, hook: hook}, store.MemoryStore
		}},
	}

	for _, sc := range stores {
		t.Run(sc.name+"/ShouldRevokeTheTokensOfAnExchangeWhichAppendsWhileRevoking", func(t *testing.T) {
			hook := &grantExchangeRevokeHook{}

			flow := newGrantExchangeFlow(t, func() (any, *storage.MemoryStore) { return sc.new(hook) }, false)

			redeemed, _ := flow.token(t, url.Values{
				consts.FormParameterGrantType:         {consts.GrantTypeAuthorizationCode},
				consts.FormParameterAuthorizationCode: {flow.authorize(t)},
				consts.FormParameterRedirectURI:       {grantExchangeRedirectURI},
			})

			grantID, ok := redeemed.GetExtra(consts.AccessResponseGrantID).(string)
			require.True(t, ok)

			var (
				late   oauth2.AccessResponder
				lateID string
			)

			hook.fn = func() {
				late, lateID = flow.token(t, url.Values{
					consts.FormParameterGrantType:          {consts.GrantTypeOAuthTokenExchange},
					consts.FormParameterSubjectToken:       {redeemed.GetAccessToken()},
					consts.FormParameterSubjectTokenType:   {consts.TokenTypeRFC8693AccessToken},
					consts.FormParameterRequestedTokenType: {consts.TokenTypeRFC8693AccessToken},
					consts.FormParameterScope:              {"read"},
				})

				grant, err := flow.memory.GetGrant(flow.ctx, grantID)
				require.NoError(t, err)
				require.Equal(t, []string{lateID}, grant.RequestIDs)
				require.True(t, flow.active(late.GetAccessToken()))
			}

			// Every token issued under the grant is revoked, including one issued while it is revoked (Section 6.5).
			require.NoError(t, flow.provider.(oauth2.GrantManagementProvider).RevokeGrant(flow.ctx, grantID))

			require.NotNil(t, late)

			assert.False(t, flow.active(late.GetAccessToken()))
			assert.False(t, flow.active(redeemed.GetAccessToken()))

			_, err := flow.memory.GetGrant(flow.ctx, grantID)
			require.ErrorIs(t, err, oauth2.ErrNotFound)
		})
	}

	for _, sc := range bindingExchangeStores() {
		t.Run(sc.name+"/ShouldRefuseAnExchangeWhichAppendsAfterTheGrantIsDeleted", func(t *testing.T) {
			store := sc.newStore()

			session := NewDefaultSession()
			session.SetSubject("peter")
			session.SetGrantID(grantExchangeID)

			spy := &grantExchangeSpyStore{rfc8693ExchangeStore: store, grants: store.(oauth2.GrantManagementStorage)}

			f := newGrantPropagation(t, store, spy, session, consts.TokenTypeRFC8693AccessToken, consts.TokenTypeRFC8693AccessToken, false)

			require.NoError(t, spy.grants.CreateGrant(t.Context(), newGrantExchangeGrant(f.subjectID, time.Time{})))

			provider := &oauth2.Fosite{Config: &oauth2.Config{GrantManagement: &oauth2.GrantManagementConfig{}}, Store: store.(oauth2.Storage)}

			spy.afterGet = func() {
				spy.afterGet = nil

				require.NoError(t, provider.RevokeGrant(t.Context(), grantExchangeID))
			}

			err := f.exchange(t)

			require.ErrorIs(t, err, oauth2.ErrInvalidGrant)
			assert.Equal(t, "invalid_grant", oauth2.ErrorToRFC6749Error(err).ErrorField)
			assert.Nil(t, spy.afterGet)

			assert.Empty(t, f.response.GetAccessToken())

			_, err = spy.grants.GetGrant(t.Context(), grantExchangeID)
			require.ErrorIs(t, err, oauth2.ErrNotFound)
		})
	}
}

const (
	grantExchangeID          = "Zm9vYmFyZm9vYmFyZm9vYmFy"
	grantExchangeClientID    = "grant-exchange-client"
	grantExchangeSecret      = "foobarfoobarfoobarfoobarfoobar12"
	grantExchangeRedirectURI = "https://client.example.com/cb"
)

type grantPropagation struct {
	strategy  hoauth2.CoreStrategy
	store     rfc8693ExchangeStore
	access    *AccessTokenTypeHandler
	refresh   *RefreshTokenTypeHandler
	request   *oauth2.AccessRequest
	response  *oauth2.AccessResponse
	subjectID string
}

func newGrantPropagation(t *testing.T, store, handled rfc8693ExchangeStore, session oauth2.Session, subject, requested string, keep bool) *grantPropagation {
	t.Helper()

	config, strategy := newBindingExchangeConfig()
	config.RefreshTokenScopes = []string{}
	config.RFC8693TokenTypes[consts.TokenTypeRFC8693RefreshToken] = &DefaultTokenType{Name: consts.TokenTypeRFC8693RefreshToken}

	client := store.GetClients()["my-client"].(*oauth2.DefaultClient)

	f := &grantPropagation{
		strategy: strategy,
		store:    store,
		access:   newLifetimeAccessTokenHandler(config, strategy, handled),
		refresh:  newLifetimeRefreshTokenHandler(config, strategy, handled),
		response: oauth2.NewAccessResponse(),
	}

	f.refresh.RefreshTokenScopes = []string{}

	original := &oauth2.AccessRequest{
		GrantTypes: oauth2.Arguments{consts.GrantTypeAuthorizationCode},
		Request:    oauth2.Request{ID: uuid.New().String(), RequestedAt: time.Now().UTC(), Session: session},
	}

	f.subjectID = original.ID

	var (
		token, signature string
		err              error
	)

	if subject == consts.TokenTypeRFC8693RefreshToken {
		original.Client = client

		session.SetExpiresAt(oauth2.RefreshToken, time.Now().UTC().Add(10*time.Minute))

		token, signature, err = strategy.GenerateRefreshToken(t.Context(), original)
		require.NoError(t, err)
		require.NoError(t, store.CreateRefreshTokenSession(t.Context(), signature, "", original.Sanitize(nil)))
	} else {
		original.Client = permittingOwner(store.GetClients()["custom-lifespan-client"])

		session.SetExpiresAt(oauth2.AccessToken, time.Now().UTC().Add(10*time.Minute))
		grantFixtureAudience(original)

		token, signature, err = strategy.GenerateAccessToken(t.Context(), original)
		require.NoError(t, err)
		require.NoError(t, store.CreateAccessTokenSession(t.Context(), signature, original.Sanitize(nil)))
	}

	f.request = newLifetimeExchangeRequest(store, subject, token, requested)
	f.request.Client = &oauth2.DefaultRegisteredClient{
		DefaultClient:                             client,
		TokenExchangeRefreshToken:                 true,
		TokenExchangeRefreshTokenRotationOverride: keep,
	}

	return f
}

func (f *grantPropagation) exchange(t *testing.T) (err error) {
	t.Helper()

	form := f.request.GetRequestForm()

	if form.Get(consts.FormParameterSubjectTokenType) == consts.TokenTypeRFC8693RefreshToken {
		err = f.refresh.HandleTokenEndpointRequest(t.Context(), f.request)
	} else {
		err = f.access.HandleTokenEndpointRequest(t.Context(), f.request)
	}

	require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

	if form.Get(consts.FormParameterRequestedTokenType) == consts.TokenTypeRFC8693RefreshToken {
		return f.refresh.PopulateTokenEndpointResponse(t.Context(), f.request, f.response)
	}

	return f.access.PopulateTokenEndpointResponse(t.Context(), f.request, f.response)
}

func (f *grantPropagation) issued(t *testing.T) (sessions []oauth2.GrantManagementSession) {
	t.Helper()

	var (
		requester oauth2.Requester
		err       error
	)

	token := f.response.GetAccessToken()
	require.NotEmpty(t, token)

	if f.request.GetRequestForm().Get(consts.FormParameterRequestedTokenType) == consts.TokenTypeRFC8693RefreshToken {
		requester, err = f.store.GetRefreshTokenSession(t.Context(), f.strategy.RefreshTokenSignature(t.Context(), token), NewDefaultSession())
	} else {
		requester, err = f.store.GetAccessTokenSession(t.Context(), f.strategy.AccessTokenSignature(t.Context(), token), NewDefaultSession())
	}

	require.NoError(t, err)

	sessions = append(sessions, requester.GetSession().(oauth2.GrantManagementSession))

	if refresh, ok := f.response.GetExtra(consts.AccessResponseRefreshToken).(string); ok {
		requester, err = f.store.GetRefreshTokenSession(t.Context(), f.strategy.RefreshTokenSignature(t.Context(), refresh), NewDefaultSession())
		require.NoError(t, err)

		sessions = append(sessions, requester.GetSession().(oauth2.GrantManagementSession))
	}

	return sessions
}

func newGrantExchangeGrant(subjectID string, expires time.Time) *oauth2.Grant {
	at := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)

	return &oauth2.Grant{
		ID:          grantExchangeID,
		ClientID:    "my-client",
		Subject:     "peter",
		Permissions: oauth2.GrantPermissions{Scopes: []oauth2.GrantScope{{Scope: "read"}}},
		CreatedAt:   at,
		UpdatedAt:   at,
		ExpiresAt:   expires,
		UpdatedBy:   "client",
		RequestIDs:  []string{subjectID},
	}
}

type grantExchangePlainStore struct {
	rfc8693ExchangeStore
}

type grantExchangeSpyStore struct {
	rfc8693ExchangeStore

	grants   oauth2.GrantManagementStorage
	calls    int
	afterGet func()
}

func (s *grantExchangeSpyStore) CreateGrant(ctx context.Context, grant *oauth2.Grant) error {
	s.calls++

	return s.grants.CreateGrant(ctx, grant)
}

func (s *grantExchangeSpyStore) GetGrant(ctx context.Context, id string) (*oauth2.Grant, error) {
	s.calls++

	grant, err := s.grants.GetGrant(ctx, id)

	if s.afterGet != nil {
		s.afterGet()
	}

	return grant, err
}

func (s *grantExchangeSpyStore) UpdateGrant(ctx context.Context, grant *oauth2.Grant) error {
	s.calls++

	return s.grants.UpdateGrant(ctx, grant)
}

func (s *grantExchangeSpyStore) AppendGrantRequestID(ctx context.Context, id, requestID string) error {
	s.calls++

	return s.grants.AppendGrantRequestID(ctx, id, requestID)
}

func (s *grantExchangeSpyStore) ReplaceGrantRequestIDs(ctx context.Context, id string, requestIDs []string) ([]string, error) {
	s.calls++

	return s.grants.ReplaceGrantRequestIDs(ctx, id, requestIDs)
}

func (s *grantExchangeSpyStore) DeleteGrant(ctx context.Context, id string) ([]string, error) {
	s.calls++

	return s.grants.DeleteGrant(ctx, id)
}

var _ oauth2.GrantManagementStorage = (*grantExchangeSpyStore)(nil)

type grantExchangeRevokeHook struct {
	fn func()
}

func (h *grantExchangeRevokeHook) run() {
	if fn := h.fn; fn != nil {
		h.fn = nil

		fn()
	}
}

type grantExchangeRevokingMemoryStore struct {
	*storage.MemoryStore

	hook *grantExchangeRevokeHook
}

func (s *grantExchangeRevokingMemoryStore) RevokeRefreshToken(ctx context.Context, requestID string) error {
	s.hook.run()

	return s.MemoryStore.RevokeRefreshToken(ctx, requestID)
}

type grantExchangeRevokingHydratingStore struct {
	*storage.HydratingMemoryStore

	hook *grantExchangeRevokeHook
}

func (s *grantExchangeRevokingHydratingStore) RevokeRefreshToken(ctx context.Context, requestID string) error {
	s.hook.run()

	return s.HydratingMemoryStore.RevokeRefreshToken(ctx, requestID)
}

type grantExchangeFlow struct {
	ctx      context.Context
	provider oauth2.Provider
	memory   *storage.MemoryStore
}

func newGrantExchangeFlow(t *testing.T, stores func() (any, *storage.MemoryStore), keep bool) *grantExchangeFlow {
	t.Helper()

	store, memory := stores()

	memory.Clients[grantExchangeClientID] = &oauth2.DefaultRegisteredClient{
		TokenExchangeRefreshToken:                 true,
		TokenExchangeOwnAccessToken:               true,
		TokenExchangeRefreshTokenRotationOverride: keep,
		DefaultClient: &oauth2.DefaultClient{
			ID:            grantExchangeClientID,
			ClientSecret:  oauth2.NewPlainTextClientSecret(grantExchangeSecret),
			RedirectURIs:  []string{grantExchangeRedirectURI},
			ResponseTypes: []string{consts.ResponseTypeAuthorizationCodeFlow},
			GrantTypes:    []string{consts.GrantTypeAuthorizationCode, consts.GrantTypeRefreshToken, consts.GrantTypeOAuthTokenExchange},
			Scopes:        []string{"read", consts.ScopeOfflineAccess},
		},
	}

	config := &oauth2.Config{
		Issuer:                    "https://as.example.com",
		GlobalSecret:              []byte("super-duper-secret-that-is-at-least-32-bytes"),
		AccessTokenLifespan:       time.Hour,
		RefreshTokenLifespan:      time.Hour,
		DefaultRequestedTokenType: consts.TokenTypeRFC8693AccessToken,
		RFC8693TokenTypes: map[string]oauth2.RFC8693TokenType{
			consts.TokenTypeRFC8693AccessToken:  &DefaultTokenType{Name: consts.TokenTypeRFC8693AccessToken},
			consts.TokenTypeRFC8693RefreshToken: &DefaultTokenType{Name: consts.TokenTypeRFC8693RefreshToken},
		},
		GrantManagement: &oauth2.GrantManagementConfig{
			Actions:  []oauth2.GrantManagementAction{oauth2.GrantManagementActionCreate},
			Endpoint: "https://as.example.com/grants",
		},
	}

	strategy := &jwt.DefaultStrategy{Config: config, Issuer: jwt.NewDefaultIssuerRS256Unverified(gen.MustRSAKey())}

	return &grantExchangeFlow{
		ctx:    context.Background(),
		memory: memory,
		provider: compose.Compose(config, store,
			&compose.CommonStrategy{
				CoreStrategy:               compose.NewOAuth2HMACStrategy(config),
				OpenIDConnectTokenStrategy: compose.NewOpenIDConnectStrategy(nil, strategy, config),
				Strategy:                   strategy,
			},
			compose.OAuth2AuthorizeExplicitFactory,
			compose.OAuth2RefreshTokenGrantFactory,
			compose.RFC8693TokenExchangeGrantFactory,
			compose.RFC8693AccessTokenTypeFactory,
			compose.RFC8693RefreshTokenTypeFactory,
			compose.RFC8693ActorTokenValidationFactory,
			compose.OAuth2TokenIntrospectionFactory,
			compose.GrantManagementFactory,
		),
	}
}

func (f *grantExchangeFlow) authorize(t *testing.T) (code string) {
	t.Helper()

	form := url.Values{
		consts.FormParameterClientID:              {grantExchangeClientID},
		consts.FormParameterResponseType:          {consts.ResponseTypeAuthorizationCodeFlow},
		consts.FormParameterRedirectURI:           {grantExchangeRedirectURI},
		consts.FormParameterScope:                 {"read offline_access"},
		consts.FormParameterState:                 {"abcdefghijklmnop"},
		consts.FormParameterGrantManagementAction: {"create"},
	}

	requester, err := f.provider.NewAuthorizeRequest(f.ctx, httptest.NewRequest(http.MethodGet, "https://as.example.com/authorize?"+form.Encode(), nil))
	require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

	requester.GrantScope("read")
	requester.GrantScope(consts.ScopeOfflineAccess)

	session := NewDefaultSession()
	session.SetSubject("peter")

	responder, err := f.provider.NewAuthorizeResponse(f.ctx, requester, session)
	require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
	require.NotEmpty(t, responder.GetCode())

	return responder.GetCode()
}

func (f *grantExchangeFlow) request(form url.Values) (oauth2.AccessRequester, error) {
	r := httptest.NewRequest(http.MethodPost, "https://as.example.com/token", strings.NewReader(form.Encode()))
	r.Header.Set(consts.HeaderContentType, consts.ContentTypeApplicationURLEncodedForm)
	r.SetBasicAuth(grantExchangeClientID, grantExchangeSecret)

	return f.provider.NewAccessRequest(f.ctx, r, NewDefaultSession())
}

func (f *grantExchangeFlow) token(t *testing.T, form url.Values) (response oauth2.AccessResponder, id string) {
	t.Helper()

	request, err := f.request(form)
	require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

	if form.Get(consts.FormParameterGrantType) == consts.GrantTypeOAuthTokenExchange {
		for _, scope := range request.GetRequestedScopes() {
			request.GrantScope(scope)
		}
	}

	response, err = f.provider.NewAccessResponse(f.ctx, request)
	require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

	return response, request.GetID()
}

func (f *grantExchangeFlow) active(token string) bool {
	_, _, err := f.provider.IntrospectToken(f.ctx, token, oauth2.AccessToken, NewDefaultSession())

	return err == nil
}
