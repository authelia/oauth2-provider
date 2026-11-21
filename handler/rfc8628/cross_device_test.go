// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc8628_test

import (
	"context"
	"errors"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	. "authelia.com/provider/oauth2/handler/rfc8628"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/storage"
)

func TestUserAuthorizeHandlerUserCodeErrors(t *testing.T) {
	testCases := []struct {
		name     string
		lifespan time.Duration
		setup    func(t *testing.T, store crossDeviceStore, grant crossDeviceGrant) (code string)
		expected error
	}{
		{
			name:     "ShouldWrapUnknownForACodeNoSessionHolds",
			lifespan: time.Minute,
			setup: func(_ *testing.T, _ crossDeviceStore, _ crossDeviceGrant) string {
				return "BCDFGHJK"
			},
			expected: oauth2.ErrUserCodeUnknown,
		},
		{
			name:     "ShouldWrapExpiredForAnExpiredCode",
			lifespan: time.Nanosecond,
			setup: func(_ *testing.T, _ crossDeviceStore, grant crossDeviceGrant) string {
				time.Sleep(time.Second)

				return grant.userCode
			},
			expected: oauth2.ErrUserCodeExpired,
		},
		{
			name:     "ShouldWrapDecidedForAnApprovedCode",
			lifespan: time.Minute,
			setup: func(t *testing.T, store crossDeviceStore, grant crossDeviceGrant) string {
				decideCrossDeviceGrant(t, store, grant, oauth2.DeviceAuthorizeStatusApproved)

				return grant.userCode
			},
			expected: oauth2.ErrUserCodeDecided,
		},
		{
			name:     "ShouldWrapDecidedForADeniedCode",
			lifespan: time.Minute,
			setup: func(t *testing.T, store crossDeviceStore, grant crossDeviceGrant) string {
				decideCrossDeviceGrant(t, store, grant, oauth2.DeviceAuthorizeStatusDenied)

				return grant.userCode
			},
			expected: oauth2.ErrUserCodeDecided,
		},
		{
			name:     "ShouldWrapDecidedForARedeemedCode",
			lifespan: time.Minute,
			setup: func(t *testing.T, store crossDeviceStore, grant crossDeviceGrant) string {
				require.NoError(t, store.InvalidateDeviceCodeSession(t.Context(), grant.signature))

				return grant.userCode
			},
			expected: oauth2.ErrUserCodeDecided,
		},
	}

	for name, newStore := range crossDeviceStores() {
		for _, tc := range testCases {
			t.Run(name+"/"+tc.name, func(t *testing.T) {
				store := newStore()
				config := &oauth2.Config{RFC8628CodeLifespan: tc.lifespan, RFC8628UserVerificationURL: "https://example.com/device"}
				handler := &UserAuthorizeHandler{Storage: store, Strategy: &o2hmacshaStrategy, Config: config}

				code := tc.setup(t, store, newCrossDeviceGrant(t, store, config, time.Now().UTC()))

				err := handler.HandleRFC8628UserAuthorizeEndpointRequest(t.Context(), newUserCodeRequest(code, "alice"))

				require.ErrorIs(t, err, tc.expected)
				assert.ErrorIs(t, err, oauth2.ErrInvalidGrant)
			})
		}
	}
}

// RFC 8628 Section 5.1.
func TestUserAuthorizeHandlerUserCodeRateLimiter(t *testing.T) {
	testCases := []struct {
		name     string
		limiter  *userCodeRateLimiter
		expected error
		lookups  int
	}{
		{
			name:    "ShouldLookUpTheCodeWhenAllowed",
			limiter: &userCodeRateLimiter{},
			lookups: 1,
		},
		{
			name:     "ShouldAnswerTooManyRequestsBeforeTheLookupWhenRefused",
			limiter:  &userCodeRateLimiter{err: errors.New("refused")},
			expected: oauth2.ErrTooManyRequests,
		},
		{
			name:     "ShouldAnswerTheLimiterErrorBeforeTheLookupWhenItIsAnRFC6749Error",
			limiter:  &userCodeRateLimiter{err: oauth2.ErrAccessDenied.WithHint("blocked")},
			expected: oauth2.ErrAccessDenied,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			store := &countingUserCodeStore{crossDeviceStore: storage.NewMemoryStore()}
			config := &oauth2.Config{RFC8628UserVerificationURL: "https://example.com/device", RFC8628UserCodeRateLimiter: tc.limiter}
			handler := &UserAuthorizeHandler{Storage: store, Strategy: &o2hmacshaStrategy, Config: config}

			grant := newCrossDeviceGrant(t, store, config, time.Now().UTC())
			store.lookups = 0

			err := handler.HandleRFC8628UserAuthorizeEndpointRequest(t.Context(), newUserCodeRequest(grant.userCode, "alice"))

			if tc.expected == nil {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, tc.expected)
			}

			assert.Equal(t, 1, tc.limiter.calls)
			assert.Equal(t, tc.lookups, store.lookups)
		})
	}

	t.Run("ShouldNotLimitByDefault", func(t *testing.T) {
		assert.Nil(t, (&oauth2.Config{}).GetRFC8628UserCodeRateLimiter(t.Context()))
	})
}

// RFC 10027 Section 6.1.3.
func TestUserAuthorizeHandlerUserCodeSubjectBinding(t *testing.T) {
	for name, newStore := range crossDevicePollStores() {
		t.Run(name, func(t *testing.T) {
			store := newStore()
			config := &oauth2.Config{RFC8628UserVerificationURL: "https://example.com/device"}
			handler := &UserAuthorizeHandler{Storage: store, Strategy: &o2hmacshaStrategy, Config: config}
			grant := newCrossDeviceGrant(t, store, config, time.Now().UTC())

			err := handler.HandleRFC8628UserAuthorizeEndpointRequest(t.Context(), newUserCodeRequest(grant.userCode, "alice"))

			if _, ok := store.(ClaimStorage); ok {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, oauth2.ErrServerError)
				assert.Equal(t, oauth2.DeviceAuthorizeStatusNew, getCrossDeviceGrant(t, store, grant).GetStatus())
			}
		})
	}

	for name, newStore := range crossDeviceStores() {
		t.Run(name, func(t *testing.T) {
			t.Run("ShouldBindTheCodeToTheFirstSubject", func(t *testing.T) {
				store := newStore()
				config := &oauth2.Config{RFC8628UserVerificationURL: "https://example.com/device"}
				handler := &UserAuthorizeHandler{Storage: store, Strategy: &o2hmacshaStrategy, Config: config}
				grant := newCrossDeviceGrant(t, store, config, time.Now().UTC())

				first := newUserCodeRequest(grant.userCode, "alice")

				require.NoError(t, handler.HandleRFC8628UserAuthorizeEndpointRequest(t.Context(), first))
				assert.Equal(t, oauth2.DeviceAuthorizeStatusClaimed, first.GetStatus())
				assert.Equal(t, "alice", first.GetClaimSubject())

				stored := getCrossDeviceGrant(t, store, grant)

				assert.Equal(t, oauth2.DeviceAuthorizeStatusClaimed, stored.GetStatus())
				assert.Equal(t, "alice", stored.GetClaimSubject())

				require.NoError(t, handler.HandleRFC8628UserAuthorizeEndpointRequest(t.Context(), newUserCodeRequest(grant.userCode, "alice")))

				err := handler.HandleRFC8628UserAuthorizeEndpointRequest(t.Context(), newUserCodeRequest(grant.userCode, "mallory"))

				require.ErrorIs(t, err, oauth2.ErrUserCodeClaimed)
				assert.ErrorIs(t, err, oauth2.ErrInvalidGrant)
				assert.Equal(t, "alice", getCrossDeviceGrant(t, store, grant).GetClaimSubject())
			})

			t.Run("ShouldKeepTheBindingWhenTheClaimantDecides", func(t *testing.T) {
				store := newStore()
				config := &oauth2.Config{RFC8628UserVerificationURL: "https://example.com/device"}
				handler := &UserAuthorizeHandler{Storage: store, Strategy: &o2hmacshaStrategy, Config: config}
				grant := newCrossDeviceGrant(t, store, config, time.Now().UTC())

				request := newUserCodeRequest(grant.userCode, "alice")

				require.NoError(t, handler.HandleRFC8628UserAuthorizeEndpointRequest(t.Context(), request))

				request.SetSession(&oauth2.DefaultSession{Subject: "alice", ExpiresAt: map[oauth2.TokenType]time.Time{}})
				request.SetStatus(oauth2.DeviceAuthorizeStatusApproved)

				require.NoError(t, handler.PopulateRFC8628UserAuthorizeEndpointResponse(t.Context(), request, oauth2.NewRFC8628UserAuthorizeResponse()))

				stored := getCrossDeviceGrant(t, store, grant)

				assert.Equal(t, oauth2.DeviceAuthorizeStatusApproved, stored.GetStatus())
				assert.Equal(t, "alice", stored.GetClaimSubject())
				assert.Equal(t, "alice", stored.GetSession().GetSubject())

				err := handler.HandleRFC8628UserAuthorizeEndpointRequest(t.Context(), newUserCodeRequest(grant.userCode, "mallory"))

				assert.ErrorIs(t, err, oauth2.ErrUserCodeDecided)
			})

			t.Run("ShouldRequireASubject", func(t *testing.T) {
				store := newStore()
				config := &oauth2.Config{RFC8628UserVerificationURL: "https://example.com/device"}
				handler := &UserAuthorizeHandler{Storage: store, Strategy: &o2hmacshaStrategy, Config: config}
				grant := newCrossDeviceGrant(t, store, config, time.Now().UTC())

				err := handler.HandleRFC8628UserAuthorizeEndpointRequest(t.Context(), newUserCodeRequest(grant.userCode, ""))

				require.ErrorIs(t, err, oauth2.ErrServerError)
				assert.Equal(t, oauth2.DeviceAuthorizeStatusNew, getCrossDeviceGrant(t, store, grant).GetStatus())
			})

			t.Run("ShouldNotBindTheCodeWhenDisabled", func(t *testing.T) {
				store := newStore()
				config := &oauth2.Config{RFC8628UserVerificationURL: "https://example.com/device", RFC8628DisableUserCodeSubjectBinding: true}
				handler := &UserAuthorizeHandler{Storage: store, Strategy: &o2hmacshaStrategy, Config: config}
				grant := newCrossDeviceGrant(t, store, config, time.Now().UTC())

				for _, subject := range []string{"alice", "mallory", ""} {
					require.NoError(t, handler.HandleRFC8628UserAuthorizeEndpointRequest(t.Context(), newUserCodeRequest(grant.userCode, subject)))
				}

				stored := getCrossDeviceGrant(t, store, grant)

				assert.Equal(t, oauth2.DeviceAuthorizeStatusNew, stored.GetStatus())
				assert.Empty(t, stored.GetClaimSubject())
			})

			t.Run("ShouldAnswerPendingToTheDeviceWhileClaimed", func(t *testing.T) {
				store := newStore()
				config := &oauth2.Config{RFC8628UserVerificationURL: "https://example.com/device", RFC8628TokenPollingInterval: time.Second}
				handler := &UserAuthorizeHandler{Storage: store, Strategy: &o2hmacshaStrategy, Config: config}
				grant := newCrossDeviceGrant(t, store, config, time.Now().UTC().Add(-time.Minute))

				require.NoError(t, handler.HandleRFC8628UserAuthorizeEndpointRequest(t.Context(), newUserCodeRequest(grant.userCode, "alice")))

				token := &DeviceCodeTokenHandler{Storage: store, Strategy: &o2hmacshaStrategy, Config: config}

				_, _, _, err := token.GetCodeAndSession(t.Context(), newDevicePoll(grant, time.Now().UTC()))

				require.ErrorIs(t, err, oauth2.ErrAuthorizationPending)

				stored := getCrossDeviceGrant(t, store, grant)

				assert.Equal(t, oauth2.DeviceAuthorizeStatusClaimed, stored.GetStatus())
				assert.Equal(t, "alice", stored.GetClaimSubject())
			})
		})
	}
}

func TestUserAuthorizeHandlerConcurrentClaimsKeepTheFirst(t *testing.T) {
	for name, newStore := range crossDeviceStores() {
		t.Run(name, func(t *testing.T) {
			store := newStore()
			config := &oauth2.Config{RFC8628UserVerificationURL: "https://example.com/device"}
			handler := &UserAuthorizeHandler{Storage: store, Strategy: &o2hmacshaStrategy, Config: config}
			grant := newCrossDeviceGrant(t, store, config, time.Now().UTC())

			subjects := []string{"alice", "bob", "carol", "dave"}
			errs := make([]error, len(subjects))

			var (
				start = make(chan struct{})
				wg    sync.WaitGroup
			)

			for i, subject := range subjects {
				wg.Add(1)

				go func() {
					defer wg.Done()

					<-start

					errs[i] = handler.HandleRFC8628UserAuthorizeEndpointRequest(t.Context(), newUserCodeRequest(grant.userCode, subject))
				}()
			}

			close(start)
			wg.Wait()

			var winner string

			for i, err := range errs {
				if err == nil {
					require.Empty(t, winner)

					winner = subjects[i]

					continue
				}

				assert.ErrorIs(t, err, oauth2.ErrUserCodeClaimed)
			}

			require.NotEmpty(t, winner)
			assert.Equal(t, winner, getCrossDeviceGrant(t, store, grant).GetClaimSubject())
		})
	}
}

// RFC 10027 Section 6.1.3: a poll must not replace the decision of the End-User.
func TestDeviceCodeTokenHandlerPollKeepsAConcurrentDecision(t *testing.T) {
	testCases := []struct {
		name   string
		status oauth2.DeviceAuthorizeStatus
		poll   time.Duration
	}{
		{"ShouldKeepAnApprovalRecordedDuringASlowDownPoll", oauth2.DeviceAuthorizeStatusApproved, time.Second},
		{"ShouldKeepADenialRecordedDuringASlowDownPoll", oauth2.DeviceAuthorizeStatusDenied, time.Second},
	}

	for name, newStore := range crossDeviceStores() {
		for _, tc := range testCases {
			t.Run(name+"/"+tc.name, func(t *testing.T) {
				inner := newStore()
				config := &oauth2.Config{RFC8628UserVerificationURL: "https://example.com/device", RFC8628TokenPollingInterval: time.Minute}
				base := time.Now().UTC()
				grant := newCrossDeviceGrant(t, inner, config, base)

				store := &decidingDeviceCodeStore{crossDeviceStore: inner, decide: func() {
					decideCrossDeviceGrant(t, inner, grant, tc.status)
				}}

				first := &DeviceCodeTokenHandler{Storage: inner, Strategy: &o2hmacshaStrategy, Config: config}

				_, _, _, err := first.GetCodeAndSession(t.Context(), newDevicePoll(grant, base))

				require.ErrorIs(t, err, oauth2.ErrAuthorizationPending)

				token := &DeviceCodeTokenHandler{Storage: store, Strategy: &o2hmacshaStrategy, Config: config}

				_, _, _, err = token.GetCodeAndSession(t.Context(), newDevicePoll(grant, base.Add(tc.poll)))

				require.ErrorIs(t, err, oauth2.ErrSlowDown)

				stored := getCrossDeviceGrant(t, inner, grant)

				assert.Equal(t, tc.status, stored.GetStatus())
				assert.Equal(t, "alice", stored.GetSession().GetSubject())
				assert.Equal(t, base.Add(tc.poll), stored.GetLastChecked())
			})
		}
	}
}

// RFC 8628 Section 3.5.
func TestDeviceCodeTokenHandlerSlowDown(t *testing.T) {
	type poll struct {
		after    time.Duration
		expected error
		interval time.Duration
		count    int
	}

	testCases := []struct {
		name  string
		limit int
		polls []poll
	}{
		{
			name: "ShouldGrowTheIntervalByFiveSecondsForEachSlowDown",
			polls: []poll{
				{expected: oauth2.ErrAuthorizationPending},
				{after: time.Second, expected: oauth2.ErrSlowDown, interval: 15 * time.Second, count: 1},
				{after: 12 * time.Second, expected: oauth2.ErrSlowDown, interval: 20 * time.Second, count: 2},
				{after: 19 * time.Second, expected: oauth2.ErrSlowDown, interval: 25 * time.Second, count: 3},
			},
		},
		{
			name: "ShouldKeepTheGrownIntervalForLaterRequests",
			polls: []poll{
				{expected: oauth2.ErrAuthorizationPending},
				{after: time.Second, expected: oauth2.ErrSlowDown, interval: 15 * time.Second, count: 1},
				{after: 15 * time.Second, expected: oauth2.ErrAuthorizationPending, interval: 15 * time.Second},
				{after: 12 * time.Second, expected: oauth2.ErrSlowDown, interval: 20 * time.Second, count: 1},
				{after: 20 * time.Second, expected: oauth2.ErrAuthorizationPending, interval: 20 * time.Second},
			},
		},
		{
			name: "ShouldNotGrowTheIntervalOfADeviceWhichWaits",
			polls: []poll{
				{after: 10 * time.Second, expected: oauth2.ErrAuthorizationPending},
				{after: 10 * time.Second, expected: oauth2.ErrAuthorizationPending},
			},
		},
		{
			name:  "ShouldInvalidateTheDeviceCodeOnceTheLimitIsExceeded",
			limit: 2,
			polls: []poll{
				{expected: oauth2.ErrAuthorizationPending},
				{after: time.Second, expected: oauth2.ErrSlowDown, interval: 15 * time.Second, count: 1},
				{after: time.Second, expected: oauth2.ErrSlowDown, interval: 20 * time.Second, count: 2},
				{after: time.Second, expected: oauth2.ErrInvalidGrant, interval: 20 * time.Second, count: 2},
				{after: time.Minute, expected: oauth2.ErrInvalidatedDeviceCode, interval: 20 * time.Second, count: 2},
			},
		},
		{
			name:  "ShouldCountOnlyConsecutiveSlowDownsTowardsTheLimit",
			limit: 1,
			polls: []poll{
				{expected: oauth2.ErrAuthorizationPending},
				{after: time.Second, expected: oauth2.ErrSlowDown, interval: 15 * time.Second, count: 1},
				{after: 15 * time.Second, expected: oauth2.ErrAuthorizationPending, interval: 15 * time.Second},
				{after: time.Second, expected: oauth2.ErrSlowDown, interval: 20 * time.Second, count: 1},
			},
		},
	}

	for name, newStore := range crossDevicePollStores() {
		for _, tc := range testCases {
			t.Run(name+"/"+tc.name, func(t *testing.T) {
				store := newStore()
				config := &oauth2.Config{
					RFC8628UserVerificationURL:  "https://example.com/device",
					RFC8628TokenPollingInterval: 10 * time.Second,
					RFC8628SlowDownLimit:        tc.limit,
				}

				at := time.Now().UTC()
				grant := newCrossDeviceGrant(t, store, config, at)
				token := &DeviceCodeTokenHandler{Storage: store, Strategy: &o2hmacshaStrategy, Config: config}

				for i, p := range tc.polls {
					at = at.Add(p.after)

					_, _, _, err := token.GetCodeAndSession(t.Context(), newDevicePoll(grant, at))

					require.ErrorIs(t, err, p.expected, "poll %d", i)

					stored, gerr := store.GetDeviceCodeSession(t.Context(), grant.signature, &oauth2.DefaultSession{})
					if gerr != nil {
						require.ErrorIs(t, gerr, oauth2.ErrInvalidatedDeviceCode, "poll %d", i)
					}

					polling, ok := stored.(oauth2.DeviceAuthorizePollingRequester)
					require.True(t, ok)

					assert.Equal(t, p.interval, polling.GetPollingInterval(), "poll %d", i)
					assert.Equal(t, p.count, polling.GetSlowDownCount(), "poll %d", i)
					assert.Equal(t, oauth2.DeviceAuthorizeStatusNew, stored.GetStatus(), "poll %d", i)
				}
			})
		}
	}

	t.Run("ShouldNotLimitByDefault", func(t *testing.T) {
		assert.Equal(t, 0, (&oauth2.Config{}).GetRFC8628SlowDownLimit(t.Context()))
		assert.Equal(t, 0, (&oauth2.Config{RFC8628SlowDownLimit: -1}).GetRFC8628SlowDownLimit(t.Context()))
	})
}

// RFC 10027 Section 6.1.14.
func TestDeviceAuthorizeHandlerVerificationURIComplete(t *testing.T) {
	testCases := []struct {
		name     string
		global   bool
		client   bool
		expected bool
	}{
		{"ShouldOmitByDefault", false, false, false},
		{"ShouldIncludeWhenEnabledGlobally", true, false, true},
		{"ShouldIncludeWhenTheClientEnablesIt", false, true, true},
		{"ShouldIncludeWhenEnabledGloballyAndByTheClient", true, true, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			handler := DeviceAuthorizeHandler{
				Storage:  storage.NewMemoryStore(),
				Strategy: &o2hmacshaStrategy,
				Config: &oauth2.Config{
					RFC8628UserVerificationURL:           "https://example.com/device?tenant=a",
					RFC8628EnableVerificationURIComplete: tc.global,
				},
			}

			request := oauth2.NewDeviceAuthorizeRequest()
			request.Client = &oauth2.DefaultRegisteredClient{DefaultClient: &oauth2.DefaultClient{ID: "device"}, RFC8628VerificationURIComplete: tc.client}
			request.SetSession(&oauth2.DefaultSession{})

			response := oauth2.NewDeviceAuthorizeResponse()

			require.NoError(t, handler.HandleRFC8628DeviceAuthorizeEndpointRequest(t.Context(), request, response))
			assert.Equal(t, "https://example.com/device?tenant=a", response.GetVerificationURI())

			_, present := response.ToMap()[consts.DeviceCodeResponseVerificationURIComplete]

			assert.Equal(t, tc.expected, present)

			if tc.expected {
				assert.Equal(t, "https://example.com/device?tenant=a&user_code="+response.GetUserCode(), response.GetVerificationURIComplete())
			} else {
				assert.Empty(t, response.GetVerificationURIComplete())
			}
		})
	}
}

// RFC 10027 Section 6.1.2.
func TestDeviceAuthorizeHandlerCodeLifespan(t *testing.T) {
	short, negative, zero := time.Minute, -time.Minute, time.Duration(0)

	testCases := []struct {
		name     string
		global   time.Duration
		client   *time.Duration
		expected time.Duration
	}{
		{"ShouldDefaultToTenMinutes", 0, nil, 10 * time.Minute},
		{"ShouldDefaultToTenMinutesWhenNegative", -time.Hour, nil, 10 * time.Minute},
		{"ShouldUseTheConfiguredLifespan", 5 * time.Minute, nil, 5 * time.Minute},
		{"ShouldUseTheClientLifespan", 5 * time.Minute, &short, time.Minute},
		{"ShouldUseTheConfiguredLifespanWhenTheClientLifespanIsNegative", 5 * time.Minute, &negative, 5 * time.Minute},
		{"ShouldUseTheConfiguredLifespanWhenTheClientLifespanIsZero", 5 * time.Minute, &zero, 5 * time.Minute},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			handler := DeviceAuthorizeHandler{
				Storage:  storage.NewMemoryStore(),
				Strategy: &o2hmacshaStrategy,
				Config:   &oauth2.Config{RFC8628UserVerificationURL: "https://example.com/device", RFC8628CodeLifespan: tc.global},
			}

			request := oauth2.NewDeviceAuthorizeRequest()
			request.Client = &oauth2.DefaultClientWithCustomTokenLifespans{
				DefaultClient:  &oauth2.DefaultClient{ID: "device"},
				TokenLifespans: &oauth2.ClientLifespanConfig{DeviceCodeGrantDeviceCodeLifespan: tc.client},
			}
			request.SetSession(&oauth2.DefaultSession{})

			response := oauth2.NewDeviceAuthorizeResponse()

			require.NoError(t, handler.HandleRFC8628DeviceAuthorizeEndpointRequest(t.Context(), request, response))

			expected := time.Now().UTC().Add(tc.expected)

			assert.WithinDuration(t, expected, request.GetSession().GetExpiresAt(oauth2.DeviceCode), 5*time.Second)
			assert.Equal(t, request.GetSession().GetExpiresAt(oauth2.DeviceCode), request.GetSession().GetExpiresAt(oauth2.UserCode))
			assert.InDelta(t, tc.expected.Seconds(), response.GetExpiresIn(), 5)
		})
	}
}

type crossDeviceStore interface {
	Storage
	DecisionStorage
}

type crossDeviceGrant struct {
	userCode   string
	deviceCode string
	signature  string
}

type updateOnlyDeviceCodeStore struct {
	inner crossDeviceStore
}

func (s *updateOnlyDeviceCodeStore) CreateDeviceCodeSession(ctx context.Context, signature string, request oauth2.DeviceAuthorizeRequester) error {
	return s.inner.CreateDeviceCodeSession(ctx, signature, request)
}

func (s *updateOnlyDeviceCodeStore) UpdateDeviceCodeSession(ctx context.Context, signature string, request oauth2.DeviceAuthorizeRequester) error {
	return s.inner.UpdateDeviceCodeSession(ctx, signature, request)
}

func (s *updateOnlyDeviceCodeStore) DecideDeviceCodeSession(ctx context.Context, signature string, request oauth2.DeviceAuthorizeRequester) error {
	return s.inner.DecideDeviceCodeSession(ctx, signature, request)
}

func (s *updateOnlyDeviceCodeStore) GetDeviceCodeSession(ctx context.Context, signature string, session oauth2.Session) (oauth2.DeviceAuthorizeRequester, error) {
	return s.inner.GetDeviceCodeSession(ctx, signature, session)
}

func (s *updateOnlyDeviceCodeStore) GetDeviceCodeSessionByUserCode(ctx context.Context, signature string, session oauth2.Session) (oauth2.DeviceAuthorizeRequester, error) {
	return s.inner.GetDeviceCodeSessionByUserCode(ctx, signature, session)
}

func (s *updateOnlyDeviceCodeStore) InvalidateDeviceCodeSession(ctx context.Context, signature string) error {
	return s.inner.InvalidateDeviceCodeSession(ctx, signature)
}

type decidingDeviceCodeStore struct {
	crossDeviceStore

	decide  func()
	decided bool
}

func (s *decidingDeviceCodeStore) GetDeviceCodeSession(ctx context.Context, signature string, session oauth2.Session) (oauth2.DeviceAuthorizeRequester, error) {
	request, err := s.crossDeviceStore.GetDeviceCodeSession(ctx, signature, session)

	if !s.decided {
		s.decided = true

		s.decide()
	}

	return request, err
}

func (s *decidingDeviceCodeStore) UpdateDeviceCodeSessionPolling(ctx context.Context, signature string, request oauth2.DeviceAuthorizeRequester) error {
	return s.crossDeviceStore.(PollStorage).UpdateDeviceCodeSessionPolling(ctx, signature, request)
}

type countingUserCodeStore struct {
	crossDeviceStore

	lookups int
}

func (s *countingUserCodeStore) ClaimDeviceCodeSession(ctx context.Context, signature string, subject string) error {
	return s.crossDeviceStore.(ClaimStorage).ClaimDeviceCodeSession(ctx, signature, subject)
}

func (s *countingUserCodeStore) GetDeviceCodeSessionByUserCode(ctx context.Context, signature string, session oauth2.Session) (oauth2.DeviceAuthorizeRequester, error) {
	s.lookups++

	return s.crossDeviceStore.GetDeviceCodeSessionByUserCode(ctx, signature, session)
}

type userCodeRateLimiter struct {
	err   error
	calls int
}

func (l *userCodeRateLimiter) AllowRFC8628UserCodeAttempt(_ context.Context, _ oauth2.DeviceAuthorizeRequester) error {
	l.calls++

	return l.err
}

func crossDeviceStores() map[string]func() crossDeviceStore {
	return map[string]func() crossDeviceStore{
		"MemoryStore":          func() crossDeviceStore { return storage.NewMemoryStore() },
		"HydratingMemoryStore": func() crossDeviceStore { return storage.NewHydratingMemoryStore() },
	}
}

func crossDevicePollStores() map[string]func() crossDeviceStore {
	stores := crossDeviceStores()

	for name, newStore := range crossDeviceStores() {
		stores[name+"WithoutOptionalStorage"] = func() crossDeviceStore { return &updateOnlyDeviceCodeStore{inner: newStore()} }
	}

	return stores
}

func newCrossDeviceGrant(t *testing.T, store Storage, config *oauth2.Config, requestedAt time.Time) (grant crossDeviceGrant) {
	t.Helper()

	handler := DeviceAuthorizeHandler{Storage: store, Strategy: &o2hmacshaStrategy, Config: config}

	request := oauth2.NewDeviceAuthorizeRequest()
	request.SetID("cross-device-grant")
	request.RequestedAt = requestedAt
	request.Client = &oauth2.DefaultClient{ID: "device", GrantTypes: oauth2.Arguments{consts.GrantTypeOAuthDeviceCode}}
	request.SetSession(&oauth2.DefaultSession{})

	response := oauth2.NewDeviceAuthorizeResponse()

	require.NoError(t, handler.HandleRFC8628DeviceAuthorizeEndpointRequest(t.Context(), request, response))

	return crossDeviceGrant{userCode: response.GetUserCode(), deviceCode: response.GetDeviceCode(), signature: request.GetDeviceCodeSignature()}
}

func newUserCodeRequest(code, subject string) (request *oauth2.DeviceAuthorizeRequest) {
	request = oauth2.NewDeviceAuthorizeRequest()
	request.SetSession(&oauth2.DefaultSession{Subject: subject})
	request.GetRequestForm().Set(consts.FormParameterUserCode, code)

	return request
}

func newDevicePoll(grant crossDeviceGrant, at time.Time) (request *oauth2.AccessRequest) {
	return &oauth2.AccessRequest{
		GrantTypes: oauth2.Arguments{consts.GrantTypeOAuthDeviceCode},
		Request: oauth2.Request{
			Client:      &oauth2.DefaultClient{ID: "device", GrantTypes: oauth2.Arguments{consts.GrantTypeOAuthDeviceCode}},
			Form:        url.Values{consts.FormParameterDeviceCode: {grant.deviceCode}},
			Session:     &oauth2.DefaultSession{},
			RequestedAt: at,
		},
	}
}

func getCrossDeviceGrant(t *testing.T, store Storage, grant crossDeviceGrant) (request *oauth2.DeviceAuthorizeRequest) {
	t.Helper()

	stored, err := store.GetDeviceCodeSession(t.Context(), grant.signature, &oauth2.DefaultSession{})
	require.NoError(t, err)

	request, ok := stored.(*oauth2.DeviceAuthorizeRequest)
	require.True(t, ok)

	return request
}

func decideCrossDeviceGrant(t *testing.T, store crossDeviceStore, grant crossDeviceGrant, status oauth2.DeviceAuthorizeStatus) {
	t.Helper()

	decided := *getCrossDeviceGrant(t, store, grant)
	request := &decided

	session := &oauth2.DefaultSession{Subject: "alice"}
	session.SetExpiresAt(oauth2.DeviceCode, request.GetSession().GetExpiresAt(oauth2.DeviceCode))
	session.SetExpiresAt(oauth2.UserCode, request.GetSession().GetExpiresAt(oauth2.UserCode))

	request.SetSession(session)
	request.SetStatus(status)

	require.NoError(t, store.DecideDeviceCodeSession(t.Context(), grant.signature, request))
}
