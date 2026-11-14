// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package ciba_test

import (
	"context"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/handler/ciba"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/token/jwt"
)

type tokenTestStore interface {
	ciba.Storage
	hoauth2.CoreStorage
	hoauth2.TokenRevocationStorage
}

type tokenFixture struct {
	store    tokenTestStore
	config   *oauth2.Config
	strategy *hoauth2.HMACCoreStrategy
	handler  *ciba.TokenEndpointHandler
}

func tokenTestStores() []struct {
	name string
	new  func() tokenTestStore
} {
	return []struct {
		name string
		new  func() tokenTestStore
	}{
		{"MemoryStore", func() tokenTestStore { return storage.NewMemoryStore() }},
		{"HydratingMemoryStore", func() tokenTestStore { return storage.NewHydratingMemoryStore() }},
	}
}

func newTokenFixture(store tokenTestStore, configure func(config *oauth2.Config)) *tokenFixture {
	config := &oauth2.Config{
		GlobalSecret:         []byte("some-super-cool-secret-that-nobody-knows"),
		AccessTokenLifespan:  time.Hour,
		RefreshTokenLifespan: time.Hour,
	}

	if configure != nil {
		configure(config)
	}

	strategy := hoauth2.NewHMACCoreStrategy(config, "")

	return &tokenFixture{
		store:    store,
		config:   config,
		strategy: strategy,
		handler: &ciba.TokenEndpointHandler{
			GenericCodeTokenEndpointHandler: hoauth2.GenericCodeTokenEndpointHandler{
				CodeTokenEndpointHandler: &ciba.TokenHandler{
					Storage:  store,
					Strategy: strategy,
					Config:   config,
				},
				AccessTokenStrategy:    strategy,
				RefreshTokenStrategy:   strategy,
				CoreStorage:            store,
				TokenRevocationStorage: store,
				Config:                 config,
			},
		},
	}
}

func newTokenTestClient(id, mode string) *oauth2.DefaultCIBAClient {
	return &oauth2.DefaultCIBAClient{
		BackChannelTokenDeliveryMode: mode,
		DefaultClient: &oauth2.DefaultClient{
			ID:         id,
			GrantTypes: oauth2.Arguments{consts.GrantTypeOpenIDCIBA, consts.GrantTypeRefreshToken},
			Scopes:     oauth2.Arguments{consts.ScopeOpenID, consts.ScopeOfflineAccess},
		},
	}
}

func newTokenTestRequest(client oauth2.Client, mode, signature string, expiresIn time.Duration, username string) *oauth2.BackChannelAuthenticationRequest {
	request := oauth2.NewBackChannelAuthenticationRequest()
	request.SetID("request-id")
	request.Client = client
	request.DeliveryMode = mode
	request.RequestedAt = time.Now().UTC().Add(-time.Minute)
	request.SetRequestedScopes(oauth2.Arguments{consts.ScopeOpenID, consts.ScopeOfflineAccess})
	request.GrantScope(consts.ScopeOpenID)
	request.GrantScope(consts.ScopeOfflineAccess)
	request.SetAuthRequestIDSignature(signature)
	request.SetStatus(oauth2.CIBAStatusPending)
	request.SetPollingInterval(5 * time.Second)

	session := &oauth2.DefaultSession{Subject: "john", Username: username}
	session.SetExpiresAt(oauth2.CIBAAuthRequestID, time.Now().UTC().Add(expiresIn).Truncate(jwt.TimePrecision))

	request.Session = session

	return request
}

// create stores a pending request for the client and returns its 'auth_req_id' and signature.
func (f *tokenFixture) create(t *testing.T, client oauth2.Client, mode string, expiresIn time.Duration) (id, signature string) {
	t.Helper()

	var err error

	id, signature, err = f.strategy.GenerateCIBAAuthRequestID(t.Context())
	require.NoError(t, err)

	require.NoError(t, f.store.CreateCIBASession(t.Context(), signature, newTokenTestRequest(client, mode, signature, expiresIn, "pending")))

	return id, signature
}

func (f *tokenFixture) decide(t *testing.T, ctx context.Context, client oauth2.Client, mode, signature string, status oauth2.CIBAStatus) {
	decided := newTokenTestRequest(client, mode, signature, time.Minute, "approved")
	decided.SetStatus(status)

	if status == oauth2.CIBAStatusFailed {
		decided.SetFailureCause("notification failed")
	}

	assert.NoError(t, f.store.DecideCIBASession(ctx, signature, decided))
}

func (f *tokenFixture) poll(ctx context.Context, client oauth2.Client, id string, at time.Time) (response *oauth2.AccessResponse, err error) {
	request := oauth2.NewAccessRequest(&oauth2.DefaultSession{})
	request.GrantTypes = oauth2.Arguments{consts.GrantTypeOpenIDCIBA}
	request.Client = client
	request.Form = url.Values{consts.FormParameterAuthReqID: []string{id}}
	request.RequestedAt = at

	if err = f.handler.HandleTokenEndpointRequest(ctx, request); err != nil {
		return nil, err
	}

	response = oauth2.NewAccessResponse()

	if err = f.handler.PopulateTokenEndpointResponse(ctx, request, response); err != nil {
		return nil, err
	}

	return response, nil
}

func (f *tokenFixture) stored(t *testing.T, signature string) (request oauth2.BackChannelAuthenticationRequester, err error) {
	t.Helper()

	return f.store.GetCIBASession(t.Context(), signature, &oauth2.DefaultSession{})
}

func requireRFC6749Error(t *testing.T, err error, name string) {
	t.Helper()

	require.Error(t, err)
	assert.Equal(t, name, oauth2.ErrorToRFC6749Error(err).ErrorField, "%+v", err)
}

func requireTokens(t *testing.T, response *oauth2.AccessResponse, err error) {
	t.Helper()

	require.NoError(t, err, "%+v", oauth2.ErrorToDebugRFC6749Error(err))
	require.NotNil(t, response)
	assert.NotEmpty(t, response.GetAccessToken())
	assert.NotEmpty(t, response.GetExtra(consts.AccessResponseRefreshToken))
}

func TestCIBATokenEndpoint(t *testing.T) {
	testCases := []struct {
		name      string
		configure func(config *oauth2.Config)
		run       func(t *testing.T, f *tokenFixture)
	}{
		{
			name: "ShouldReturnAuthorizationPending",
			run: func(t *testing.T, f *tokenFixture) {
				client := newTokenTestClient("client", consts.CIBAModePoll)
				id, signature := f.create(t, client, consts.CIBAModePoll, time.Minute)

				now := time.Now().UTC()

				_, err := f.poll(t.Context(), client, id, now)
				requireRFC6749Error(t, err, "authorization_pending")

				stored, err := f.stored(t, signature)
				require.NoError(t, err)
				assert.True(t, now.Equal(stored.GetLastPolled()))
				assert.Equal(t, 5*time.Second, stored.GetPollingInterval())
				assert.Equal(t, 0, stored.GetSlowDownCount())
			},
		},
		{
			name: "ShouldSlowDown",
			run: func(t *testing.T, f *tokenFixture) {
				client := newTokenTestClient("client", consts.CIBAModePoll)
				id, signature := f.create(t, client, consts.CIBAModePoll, time.Minute)

				now := time.Now().UTC()

				_, err := f.poll(t.Context(), client, id, now)
				requireRFC6749Error(t, err, "authorization_pending")

				_, err = f.poll(t.Context(), client, id, now.Add(time.Second))
				requireRFC6749Error(t, err, "slow_down")

				stored, err := f.stored(t, signature)
				require.NoError(t, err)
				assert.Equal(t, 10*time.Second, stored.GetPollingInterval())
				assert.Equal(t, 1, stored.GetSlowDownCount())

				// The increased interval applies to later polls.
				_, err = f.poll(t.Context(), client, id, now.Add(9*time.Second))
				requireRFC6749Error(t, err, "slow_down")

				_, err = f.poll(t.Context(), client, id, now.Add(30*time.Second))
				requireRFC6749Error(t, err, "authorization_pending")

				stored, err = f.stored(t, signature)
				require.NoError(t, err)
				assert.Equal(t, 15*time.Second, stored.GetPollingInterval())
				assert.Equal(t, 0, stored.GetSlowDownCount())
			},
		},
		{
			name: "ShouldSlowDownAFirstPollWithinTheIntervalOfTheRequest",
			run: func(t *testing.T, f *tokenFixture) {
				client := newTokenTestClient("client", consts.CIBAModePoll)

				id, signature, err := f.strategy.GenerateCIBAAuthRequestID(t.Context())
				require.NoError(t, err)

				request := newTokenTestRequest(client, consts.CIBAModePoll, signature, time.Minute, "pending")
				request.RequestedAt = time.Now().UTC()

				require.NoError(t, f.store.CreateCIBASession(t.Context(), signature, request))

				_, err = f.poll(t.Context(), client, id, request.RequestedAt.Add(time.Second))
				requireRFC6749Error(t, err, "slow_down")

				stored, err := f.stored(t, signature)
				require.NoError(t, err)
				assert.Equal(t, 10*time.Second, stored.GetPollingInterval())
				assert.Equal(t, 1, stored.GetSlowDownCount())

				_, err = f.poll(t.Context(), client, id, request.RequestedAt.Add(15*time.Second))
				requireRFC6749Error(t, err, "authorization_pending")
			},
		},
		{
			name:      "ShouldInvalidateAtTheSlowDownLimit",
			configure: func(config *oauth2.Config) { config.CIBASlowDownLimit = 2 },
			run: func(t *testing.T, f *tokenFixture) {
				client := newTokenTestClient("client", consts.CIBAModePoll)
				id, signature := f.create(t, client, consts.CIBAModePoll, time.Minute)

				now := time.Now().UTC()

				_, err := f.poll(t.Context(), client, id, now)
				requireRFC6749Error(t, err, "authorization_pending")

				_, err = f.poll(t.Context(), client, id, now.Add(time.Second))
				requireRFC6749Error(t, err, "slow_down")

				_, err = f.poll(t.Context(), client, id, now.Add(2*time.Second))
				requireRFC6749Error(t, err, "slow_down")

				_, err = f.poll(t.Context(), client, id, now.Add(3*time.Second))
				requireRFC6749Error(t, err, "invalid_request")

				_, err = f.stored(t, signature)
				assert.ErrorIs(t, err, oauth2.ErrInvalidatedCIBASession)

				_, err = f.poll(t.Context(), client, id, now.Add(time.Minute))
				requireRFC6749Error(t, err, "invalid_grant")
			},
		},
		{
			name: "ShouldReturnExpiredToken",
			run: func(t *testing.T, f *tokenFixture) {
				client := newTokenTestClient("client", consts.CIBAModePoll)
				id, _ := f.create(t, client, consts.CIBAModePoll, -time.Minute)

				_, err := f.poll(t.Context(), client, id, time.Now().UTC())
				requireRFC6749Error(t, err, "expired_token")
			},
		},
		{
			name: "ShouldReturnExpiredTokenForAnApprovedRequest",
			run: func(t *testing.T, f *tokenFixture) {
				client := newTokenTestClient("client", consts.CIBAModePoll)
				id, signature := f.create(t, client, consts.CIBAModePoll, -time.Minute)

				decided := newTokenTestRequest(client, consts.CIBAModePoll, signature, -time.Minute, "approved")
				decided.SetStatus(oauth2.CIBAStatusApproved)
				require.NoError(t, f.store.DecideCIBASession(t.Context(), signature, decided))

				_, err := f.poll(t.Context(), client, id, time.Now().UTC())
				requireRFC6749Error(t, err, "expired_token")

				_, err = f.stored(t, signature)
				assert.NoError(t, err)
			},
		},
		{
			name: "ShouldReturnAccessDenied",
			run: func(t *testing.T, f *tokenFixture) {
				client := newTokenTestClient("client", consts.CIBAModePoll)
				id, signature := f.create(t, client, consts.CIBAModePoll, time.Minute)
				f.decide(t, t.Context(), client, consts.CIBAModePoll, signature, oauth2.CIBAStatusDenied)

				_, err := f.poll(t.Context(), client, id, time.Now().UTC())
				requireRFC6749Error(t, err, "access_denied")

				// A denied request is not invalidated and answers the same on a repeat poll.
				_, err = f.poll(t.Context(), client, id, time.Now().UTC().Add(time.Minute))
				requireRFC6749Error(t, err, "access_denied")
			},
		},
		{
			name: "ShouldReturnTransactionFailed",
			run: func(t *testing.T, f *tokenFixture) {
				client := newTokenTestClient("client", consts.CIBAModePoll)
				id, signature := f.create(t, client, consts.CIBAModePoll, time.Minute)
				f.decide(t, t.Context(), client, consts.CIBAModePoll, signature, oauth2.CIBAStatusFailed)

				_, err := f.poll(t.Context(), client, id, time.Now().UTC())
				requireRFC6749Error(t, err, "transaction_failed")
				assert.NotErrorIs(t, err, oauth2.ErrServerError)
			},
		},
		{
			name: "ShouldRejectAnotherClientsRequest",
			run: func(t *testing.T, f *tokenFixture) {
				client := newTokenTestClient("client", consts.CIBAModePoll)
				id, signature := f.create(t, client, consts.CIBAModePoll, time.Minute)
				f.decide(t, t.Context(), client, consts.CIBAModePoll, signature, oauth2.CIBAStatusApproved)

				_, err := f.poll(t.Context(), newTokenTestClient("other", consts.CIBAModePoll), id, time.Now().UTC())
				requireRFC6749Error(t, err, "invalid_grant")

				// The request stays redeemable by the client it was issued to.
				response, err := f.poll(t.Context(), client, id, time.Now().UTC())
				requireTokens(t, response, err)
			},
		},
		{
			name: "ShouldRejectAnotherClientsPendingRequest",
			run: func(t *testing.T, f *tokenFixture) {
				client := newTokenTestClient("client", consts.CIBAModePoll)
				id, signature := f.create(t, client, consts.CIBAModePoll, time.Minute)

				_, err := f.poll(t.Context(), newTokenTestClient("other", consts.CIBAModePoll), id, time.Now().UTC())
				requireRFC6749Error(t, err, "invalid_grant")

				stored, err := f.stored(t, signature)
				require.NoError(t, err)
				assert.True(t, stored.GetLastPolled().IsZero())
			},
		},
		{
			name:      "ShouldRejectAnotherClientsPendingRequestWithLongPolling",
			configure: func(config *oauth2.Config) { config.CIBALongPollingTimeout = 2 * time.Second },
			run: func(t *testing.T, f *tokenFixture) {
				client := newTokenTestClient("client", consts.CIBAModePoll)
				id, signature := f.create(t, client, consts.CIBAModePoll, time.Minute)

				start := time.Now()

				_, err := f.poll(t.Context(), newTokenTestClient("other", consts.CIBAModePoll), id, time.Now().UTC())
				requireRFC6749Error(t, err, "invalid_grant")
				assert.Less(t, time.Since(start), time.Second)

				stored, err := f.stored(t, signature)
				require.NoError(t, err)
				assert.True(t, stored.GetLastPolled().IsZero())
			},
		},
		{
			name: "ShouldRejectAnUnknownAuthRequestID",
			run: func(t *testing.T, f *tokenFixture) {
				client := newTokenTestClient("client", consts.CIBAModePoll)

				id, _, err := f.strategy.GenerateCIBAAuthRequestID(t.Context())
				require.NoError(t, err)

				_, err = f.poll(t.Context(), client, id, time.Now().UTC())
				requireRFC6749Error(t, err, "invalid_grant")
			},
		},
		{
			name: "ShouldRequireTheAuthRequestID",
			run: func(t *testing.T, f *tokenFixture) {
				_, err := f.poll(t.Context(), newTokenTestClient("client", consts.CIBAModePoll), "", time.Now().UTC())
				requireRFC6749Error(t, err, "invalid_request")
			},
		},
		{
			name: "ShouldRejectAPushClient",
			run: func(t *testing.T, f *tokenFixture) {
				client := newTokenTestClient("client", consts.CIBAModePush)
				id, signature := f.create(t, client, consts.CIBAModePush, time.Minute)
				f.decide(t, t.Context(), client, consts.CIBAModePush, signature, oauth2.CIBAStatusApproved)

				_, err := f.poll(t.Context(), client, id, time.Now().UTC())
				requireRFC6749Error(t, err, "unauthorized_client")
			},
		},
		{
			name: "ShouldRejectAPushRequestPolledByAPollClient",
			run: func(t *testing.T, f *tokenFixture) {
				push := newTokenTestClient("client", consts.CIBAModePush)
				id, signature := f.create(t, push, consts.CIBAModePush, time.Minute)
				f.decide(t, t.Context(), push, consts.CIBAModePush, signature, oauth2.CIBAStatusApproved)

				_, err := f.poll(t.Context(), newTokenTestClient("client", consts.CIBAModePoll), id, time.Now().UTC())
				requireRFC6749Error(t, err, "unauthorized_client")
			},
		},
		{
			name: "ShouldRejectAClientWithoutTheGrant",
			run: func(t *testing.T, f *tokenFixture) {
				client := newTokenTestClient("client", consts.CIBAModePoll)
				id, _ := f.create(t, client, consts.CIBAModePoll, time.Minute)

				client.GrantTypes = oauth2.Arguments{consts.GrantTypeRefreshToken}

				_, err := f.poll(t.Context(), client, id, time.Now().UTC())
				requireRFC6749Error(t, err, "unauthorized_client")
			},
		},
		{
			name: "ShouldIssueTokensToAPingClient",
			run: func(t *testing.T, f *tokenFixture) {
				client := newTokenTestClient("client", consts.CIBAModePing)
				id, signature := f.create(t, client, consts.CIBAModePing, time.Minute)
				f.decide(t, t.Context(), client, consts.CIBAModePing, signature, oauth2.CIBAStatusApproved)

				response, err := f.poll(t.Context(), client, id, time.Now().UTC())
				requireTokens(t, response, err)
			},
		},
		{
			name: "ShouldIssueTokensOnApproval",
			run: func(t *testing.T, f *tokenFixture) {
				client := newTokenTestClient("client", consts.CIBAModePoll)
				id, signature := f.create(t, client, consts.CIBAModePoll, time.Minute)

				now := time.Now().UTC()

				_, err := f.poll(t.Context(), client, id, now)
				requireRFC6749Error(t, err, "authorization_pending")

				f.decide(t, t.Context(), client, consts.CIBAModePoll, signature, oauth2.CIBAStatusApproved)

				// An approved request is answered regardless of the polling interval.
				response, err := f.poll(t.Context(), client, id, now.Add(time.Second))
				requireTokens(t, response, err)
				assert.Equal(t, "bearer", response.GetTokenType())
				assert.Equal(t, "openid offline_access", response.GetExtra(consts.AccessResponseScope))

				stored, err := f.stored(t, signature)
				assert.ErrorIs(t, err, oauth2.ErrInvalidatedCIBASession)
				require.NotNil(t, stored)

				signatureAT := f.strategy.AccessTokenSignature(t.Context(), response.GetAccessToken())

				session, err := f.store.GetAccessTokenSession(t.Context(), signatureAT, &oauth2.DefaultSession{})
				require.NoError(t, err)
				assert.Equal(t, "request-id", session.GetID())
				assert.Equal(t, "approved", session.GetSession().GetUsername())
			},
		},
	}

	for _, sc := range tokenTestStores() {
		t.Run(sc.name, func(t *testing.T) {
			for _, tc := range testCases {
				t.Run(tc.name, func(t *testing.T) {
					tc.run(t, newTokenFixture(sc.new(), tc.configure))
				})
			}
		})
	}
}

func TestCIBATokenReplayRevokes(t *testing.T) {
	for _, sc := range tokenTestStores() {
		t.Run(sc.name, func(t *testing.T) {
			f := newTokenFixture(sc.new(), nil)

			client := newTokenTestClient("client", consts.CIBAModePoll)
			id, signature := f.create(t, client, consts.CIBAModePoll, time.Minute)
			f.decide(t, t.Context(), client, consts.CIBAModePoll, signature, oauth2.CIBAStatusApproved)

			response, err := f.poll(t.Context(), client, id, time.Now().UTC())
			requireTokens(t, response, err)

			signatureAT := f.strategy.AccessTokenSignature(t.Context(), response.GetAccessToken())

			_, err = f.store.GetAccessTokenSession(t.Context(), signatureAT, &oauth2.DefaultSession{})
			require.NoError(t, err)

			_, err = f.poll(t.Context(), client, id, time.Now().UTC())
			requireRFC6749Error(t, err, "invalid_grant")

			_, err = f.store.GetAccessTokenSession(t.Context(), signatureAT, &oauth2.DefaultSession{})
			assert.Error(t, err)
		})
	}
}

// barrierTokenTestStore holds the first two GetCIBASession calls until both have arrived, so two redemptions read the
// approved request before either invalidates it.
type barrierTokenTestStore struct {
	tokenTestStore

	calls   atomic.Int32
	arrived sync.WaitGroup
}

func newBarrierTokenTestStore(store tokenTestStore) *barrierTokenTestStore {
	s := &barrierTokenTestStore{tokenTestStore: store}
	s.arrived.Add(2)

	return s
}

func (s *barrierTokenTestStore) GetCIBASession(ctx context.Context, signature string, session oauth2.Session) (request oauth2.BackChannelAuthenticationRequester, err error) {
	if s.calls.Add(1) <= 2 {
		s.arrived.Done()
		s.arrived.Wait()
	}

	return s.tokenTestStore.GetCIBASession(ctx, signature, session)
}

// TestCIBATokenConcurrentRedemptionIssuesOnce runs against the HydratingMemoryStore only: the MemoryStore hands both
// redemptions the same stored session, which they then both write to.
func TestCIBATokenConcurrentRedemptionIssuesOnce(t *testing.T) {
	store := newBarrierTokenTestStore(storage.NewHydratingMemoryStore())
	f := newTokenFixture(store, nil)

	client := newTokenTestClient("client", consts.CIBAModePoll)
	id, signature := f.create(t, client, consts.CIBAModePoll, time.Minute)
	f.decide(t, t.Context(), client, consts.CIBAModePoll, signature, oauth2.CIBAStatusApproved)

	type outcome struct {
		response *oauth2.AccessResponse
		err      error
	}

	outcomes := make(chan outcome, 2)

	for range 2 {
		go func() {
			response, err := f.poll(context.Background(), client, id, time.Now().UTC())
			outcomes <- outcome{response, err}
		}()
	}

	var issued, rejected int

	for range 2 {
		o := <-outcomes

		if o.err == nil {
			requireTokens(t, o.response, o.err)

			issued++

			continue
		}

		requireRFC6749Error(t, o.err, "invalid_grant")

		rejected++
	}

	assert.Equal(t, 1, issued)
	assert.Equal(t, 1, rejected)
	assert.GreaterOrEqual(t, store.calls.Load(), int32(2))
}

// recordingTokenTestStore signals each UpdateCIBASession, which records a poll before it is held open.
type recordingTokenTestStore struct {
	tokenTestStore

	updated chan struct{}
}

func newRecordingTokenTestStore(store tokenTestStore) *recordingTokenTestStore {
	return &recordingTokenTestStore{tokenTestStore: store, updated: make(chan struct{}, 1)}
}

func (s *recordingTokenTestStore) UpdateCIBASession(ctx context.Context, signature string, request oauth2.BackChannelAuthenticationRequester) (err error) {
	err = s.tokenTestStore.UpdateCIBASession(ctx, signature, request)

	select {
	case s.updated <- struct{}{}:
	default:
	}

	return err
}

// waitRecorded waits until the store records a poll. It is safe to call from any goroutine.
func (s *recordingTokenTestStore) waitRecorded(t *testing.T) (recorded bool) {
	t.Helper()

	select {
	case <-s.updated:
		return true
	case <-time.After(5 * time.Second):
		t.Error("the poll was not recorded")

		return false
	}
}

func TestCIBALongPolling(t *testing.T) {
	configure := func(config *oauth2.Config) { config.CIBALongPollingTimeout = 2 * time.Second }

	for _, sc := range tokenTestStores() {
		t.Run(sc.name, func(t *testing.T) {
			t.Run("ShouldReturnTokensOnApproval", func(t *testing.T) {
				store := newRecordingTokenTestStore(sc.new())
				f := newTokenFixture(store, configure)

				client := newTokenTestClient("client", consts.CIBAModePoll)
				id, signature := f.create(t, client, consts.CIBAModePoll, time.Minute)

				done := make(chan struct{})

				go func() {
					defer close(done)

					if !store.waitRecorded(t) {
						return
					}

					f.decide(t, context.Background(), client, consts.CIBAModePoll, signature, oauth2.CIBAStatusApproved)
				}()

				start := time.Now()

				response, err := f.poll(t.Context(), client, id, time.Now().UTC())

				<-done

				requireTokens(t, response, err)
				assert.Less(t, time.Since(start), 2*time.Second)
			})

			t.Run("ShouldReturnAuthorizationPendingAfterTheTimeout", func(t *testing.T) {
				f := newTokenFixture(sc.new(), configure)

				client := newTokenTestClient("client", consts.CIBAModePoll)
				id, _ := f.create(t, client, consts.CIBAModePoll, time.Minute)

				start := time.Now()

				_, err := f.poll(t.Context(), client, id, time.Now().UTC())

				elapsed := time.Since(start)

				requireRFC6749Error(t, err, "authorization_pending")
				assert.GreaterOrEqual(t, elapsed, 2*time.Second)
				assert.Less(t, elapsed, 5*time.Second)
			})

			t.Run("ShouldSlowDownAnOverlappingPoll", func(t *testing.T) {
				store := newRecordingTokenTestStore(sc.new())
				f := newTokenFixture(store, configure)

				client := newTokenTestClient("client", consts.CIBAModePoll)
				id, signature := f.create(t, client, consts.CIBAModePoll, time.Minute)

				now := time.Now().UTC()
				first := make(chan error, 1)

				go func() {
					_, err := f.poll(context.Background(), client, id, now)
					first <- err
				}()

				// The first poll is recorded, then held open for the long polling timeout.
				require.True(t, store.waitRecorded(t))

				_, err := f.poll(t.Context(), client, id, now.Add(300*time.Millisecond))
				requireRFC6749Error(t, err, "slow_down")

				requireRFC6749Error(t, <-first, "authorization_pending")

				// The held poll does not overwrite the slow_down recorded while it was open.
				stored, err := f.stored(t, signature)
				require.NoError(t, err)
				assert.Equal(t, 10*time.Second, stored.GetPollingInterval())
				assert.Equal(t, 1, stored.GetSlowDownCount())
			})

			t.Run("ShouldStopWhenTheContextIsDone", func(t *testing.T) {
				f := newTokenFixture(sc.new(), configure)

				client := newTokenTestClient("client", consts.CIBAModePoll)
				id, _ := f.create(t, client, consts.CIBAModePoll, time.Minute)

				ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
				defer cancel()

				start := time.Now()

				_, err := f.poll(ctx, client, id, time.Now().UTC())

				requireRFC6749Error(t, err, "authorization_pending")
				assert.Less(t, time.Since(start), time.Second)
			})
		})
	}
}

func TestCIBATokenEndpointHandlerGrantTypesSupported(t *testing.T) {
	const endpoint = "https://op.example.com/bc-authorize"

	testCases := []struct {
		name     string
		modes    []string
		url      string
		handlers oauth2.BackChannelAuthenticationEndpointHandlers
		expected []string
	}{
		{"ShouldReportTheGrantByDefault", nil, endpoint, oauth2.BackChannelAuthenticationEndpointHandlers{&ciba.EndpointHandler{}}, []string{consts.GrantTypeOpenIDCIBA}},
		{"ShouldReportTheGrantForPoll", []string{consts.CIBAModePoll}, endpoint, oauth2.BackChannelAuthenticationEndpointHandlers{&ciba.EndpointHandler{}}, []string{consts.GrantTypeOpenIDCIBA}},
		{"ShouldReportTheGrantForPing", []string{consts.CIBAModePing, consts.CIBAModePush}, endpoint, oauth2.BackChannelAuthenticationEndpointHandlers{&ciba.EndpointHandler{}}, []string{consts.GrantTypeOpenIDCIBA}},
		{"ShouldNotReportTheGrantForPushOnly", []string{consts.CIBAModePush}, endpoint, oauth2.BackChannelAuthenticationEndpointHandlers{&ciba.EndpointHandler{}}, nil},
		{"ShouldNotReportTheGrantWithoutTheEndpointURL", nil, "", oauth2.BackChannelAuthenticationEndpointHandlers{&ciba.EndpointHandler{}}, nil},
		{"ShouldNotReportTheGrantWithoutTheEndpointHandler", nil, endpoint, nil, nil},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			f := newTokenFixture(storage.NewMemoryStore(), func(config *oauth2.Config) {
				config.CIBATokenDeliveryModes = tc.modes
				config.EndpointURLs.BackChannelAuthentication = tc.url
				config.BackChannelAuthenticationEndpointHandlers = tc.handlers
			})

			assert.Equal(t, tc.expected, f.handler.GrantTypesSupported(t.Context()))
		})
	}
}
