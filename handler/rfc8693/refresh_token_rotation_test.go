// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc8693_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	. "authelia.com/provider/oauth2/handler/rfc8693"
	"authelia.com/provider/oauth2/internal/consts"
)

func TestTokenExchangeRotatesRefreshTokenSubject(t *testing.T) {
	testCases := []struct {
		name          string
		configDisable bool
		clientDisable bool
		override      bool
		rotate        bool
		rotated       bool
	}{
		{name: "ShouldRotateByDefault", rotated: true},
		{name: "ShouldNotRotateWhenDisabledByConfig", configDisable: true},
		{name: "ShouldNotRotateWhenDisabledByClient", clientDisable: true},
		{name: "ShouldRotateWhenOverriddenOverConfig", configDisable: true, override: true, rotate: true, rotated: true},
		{name: "ShouldRotateWhenOverriddenOverClient", clientDisable: true, override: true, rotate: true, rotated: true},
		{name: "ShouldNotRotateWhenOverridden", override: true},
		{name: "ShouldIgnoreTheValueWithoutTheOverride", rotate: true, configDisable: true},
	}

	requested := []string{consts.TokenTypeRFC8693AccessToken, consts.TokenTypeRFC8693RefreshToken}

	for _, sc := range bindingExchangeStores() {
		for _, tokenType := range requested {
			for _, tc := range testCases {
				t.Run(sc.name+"/"+tokenType+"/"+tc.name, func(t *testing.T) {
					f := newRotationFixture(t, sc.newStore())
					f.config.DisableRefreshTokenRotation = tc.configDisable
					f.client.DisableRefreshTokenRotation = tc.clientDisable
					f.client.TokenExchangeRefreshTokenRotationOverride = tc.override
					f.client.TokenExchangeRefreshTokenRotation = tc.rotate

					issued, err := f.exchange(t, tokenType)
					require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
					assert.NotEqual(t, f.subject, issued)

					_, err = f.store.GetRefreshTokenSession(t.Context(), f.strategy.RefreshTokenSignature(t.Context(), f.subject), nil)

					if tc.rotated {
						assert.ErrorIs(t, err, oauth2.ErrInactiveToken)
					} else {
						assert.NoError(t, err)
					}

					_, err = f.store.GetRefreshTokenSession(t.Context(), f.strategy.RefreshTokenSignature(t.Context(), issued), nil)
					assert.NoError(t, err)
				})
			}
		}
	}
}

func TestTokenExchangeRefreshTokenSubjectReplayRevokesTheIssuedToken(t *testing.T) {
	for _, sc := range bindingExchangeStores() {
		for _, tokenType := range []string{consts.TokenTypeRFC8693AccessToken, consts.TokenTypeRFC8693RefreshToken} {
			t.Run(sc.name+"/"+tokenType, func(t *testing.T) {
				f := newRotationFixture(t, sc.newStore())

				issued, err := f.exchange(t, tokenType)
				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

				_, err = f.exchange(t, tokenType)
				require.ErrorIs(t, err, oauth2.ErrInvalidRequest)

				_, err = f.store.GetRefreshTokenSession(t.Context(), f.strategy.RefreshTokenSignature(t.Context(), issued), nil)
				assert.Error(t, err)
			})
		}
	}
}

func TestTokenExchangeConcurrentRefreshTokenSubjectRevokesTheIssuedToken(t *testing.T) {
	for _, sc := range bindingExchangeStores() {
		for _, tokenType := range []string{consts.TokenTypeRFC8693AccessToken, consts.TokenTypeRFC8693RefreshToken} {
			t.Run(sc.name+"/"+tokenType, func(t *testing.T) {
				f := newRotationFixture(t, sc.newStore())

				barrier := newRotationBarrier(f.store)
				f.access.TokenRevocationStorage = barrier
				f.refresh.TokenRevocationStorage = barrier

				type result struct {
					issued string
					err    error
				}

				results := make(chan result, 2)

				for range 2 {
					go func() {
						issued, err := f.exchange(t, tokenType)

						results <- result{issued: issued, err: err}
					}()
				}

				winner := <-results
				close(barrier.release)
				loser := <-results

				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(winner.err))
				require.NotEmpty(t, winner.issued)
				require.ErrorIs(t, loser.err, oauth2.ErrInvalidRequest)

				_, err := f.store.GetRefreshTokenSession(t.Context(), f.strategy.RefreshTokenSignature(t.Context(), winner.issued), nil)
				assert.Error(t, err)
			})
		}
	}
}

func TestTokenExchangeSerializationFailure(t *testing.T) {
	testCases := []struct {
		name   string
		winner bool
	}{
		{name: "ShouldRevokeWhenAnotherRequestRotatedTheToken", winner: true},
		{name: "ShouldKeepTheTokenForContention"},
	}

	for _, sc := range bindingExchangeStores() {
		for _, tokenType := range []string{consts.TokenTypeRFC8693AccessToken, consts.TokenTypeRFC8693RefreshToken} {
			for _, tc := range testCases {
				t.Run(sc.name+"/"+tokenType+"/"+tc.name, func(t *testing.T) {
					f := newRotationFixture(t, sc.newStore())

					signature := f.strategy.RefreshTokenSignature(t.Context(), f.subject)

					request, err := f.store.GetRefreshTokenSession(t.Context(), signature, &oauth2.DefaultSession{})
					require.NoError(t, err)

					store := &rotationSerializationStore{TokenRevocationStorage: f.store}

					if tc.winner {
						store.failure = func(ctx context.Context) {
							require.NoError(t, f.store.RotateRefreshToken(ctx, request.GetID(), signature))
							require.NoError(t, f.store.CreateRefreshTokenSession(ctx, "winner-rt", "", request))
						}
					}

					f.access.TokenRevocationStorage = store
					f.refresh.TokenRevocationStorage = store

					_, err = f.exchange(t, tokenType)
					require.ErrorIs(t, err, oauth2.ErrInvalidRequest)

					_, errSubject := f.store.GetRefreshTokenSession(t.Context(), signature, nil)

					if !tc.winner {
						assert.NoError(t, errSubject)

						return
					}

					_, err = f.store.GetRefreshTokenSession(t.Context(), "winner-rt", nil)
					assert.ErrorIs(t, err, oauth2.ErrInactiveToken)
				})
			}
		}
	}
}

func TestTokenExchangeWritesTheTokensAtomicallyWithoutRotation(t *testing.T) {
	testCases := []struct {
		name      string
		issue     bool
		create    error
		commit    error
		rollback  error
		expected  error
		debug     []string
		begins    int
		commits   int
		rollbacks int
		applied   int
	}{
		{name: "ShouldCommitBothTokens", issue: true, begins: 1, commits: 1, applied: 2},
		{name: "ShouldRollBackWhenTheRefreshTokenCannotBeWritten", issue: true, create: errors.New("real db failure"), expected: oauth2.ErrServerError, debug: []string{"real db failure"}, begins: 1, rollbacks: 1},
		{name: "ShouldRollBackWhenTheCommitFails", issue: true, commit: errors.New("commit failure"), expected: oauth2.ErrServerError, debug: []string{"commit failure"}, begins: 1, commits: 1, rollbacks: 1},
		{name: "ShouldKeepTheCauseWhenTheRollbackFails", issue: true, create: errors.New("real db failure"), rollback: errors.New("rollback failure"), expected: oauth2.ErrServerError, debug: []string{"real db failure", "rollback failure"}, begins: 1, rollbacks: 1},
		{name: "ShouldNotBeginATransactionForASingleWrite", applied: 1},
	}

	for _, sc := range bindingExchangeStores() {
		for _, tc := range testCases {
			t.Run(sc.name+"/"+tc.name, func(t *testing.T) {
				f := newRotationFixture(t, sc.newStore())
				f.config.DisableRefreshTokenRotation = true
				f.client.TokenExchangeRefreshToken = tc.issue

				store := &bufferedExchangeStore{rfc8693ExchangeStore: f.store, create: tc.create, commit: tc.commit, rollback: tc.rollback}

				f.access.Storage = store

				_, err := f.exchange(t, consts.TokenTypeRFC8693AccessToken)

				if tc.expected != nil {
					require.ErrorIs(t, err, tc.expected)

					for _, debug := range tc.debug {
						assert.Contains(t, oauth2.ErrorToRFC6749Error(err).DebugField, debug)
					}
				} else {
					require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
				}

				assert.Equal(t, tc.begins, store.begins)
				assert.Equal(t, tc.commits, store.commits)
				assert.Equal(t, tc.rollbacks, store.rollbacks)
				assert.Equal(t, tc.applied, store.applied)
			})
		}
	}
}

func TestTokenExchangeRotationKeepsTheCauseWhenTheRollbackFails(t *testing.T) {
	for _, sc := range bindingExchangeStores() {
		t.Run(sc.name, func(t *testing.T) {
			f := newRotationFixture(t, sc.newStore())

			store := &bufferedExchangeStore{rfc8693ExchangeStore: f.store, create: errors.New("real db failure"), rollback: errors.New("rollback failure")}

			f.access.Storage = store
			f.access.TokenRevocationStorage = store

			_, err := f.exchange(t, consts.TokenTypeRFC8693AccessToken)
			require.ErrorIs(t, err, oauth2.ErrServerError)

			debug := oauth2.ErrorToRFC6749Error(err).DebugField

			assert.Contains(t, debug, "real db failure")
			assert.Contains(t, debug, "rollback failure")
		})
	}
}

func TestTokenExchangeDoesNotRotateWithoutIssuingARefreshToken(t *testing.T) {
	for _, sc := range bindingExchangeStores() {
		t.Run(sc.name, func(t *testing.T) {
			f := newRotationFixture(t, sc.newStore())
			f.client.TokenExchangeRefreshToken = false

			_, err := f.exchange(t, consts.TokenTypeRFC8693AccessToken)
			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

			_, err = f.store.GetRefreshTokenSession(t.Context(), f.strategy.RefreshTokenSignature(t.Context(), f.subject), nil)
			assert.NoError(t, err)
		})
	}
}

func TestTokenExchangeRotationRefusedWithoutRevocationStorage(t *testing.T) {
	for _, sc := range bindingExchangeStores() {
		t.Run(sc.name, func(t *testing.T) {
			f := newRotationFixture(t, sc.newStore())
			f.access.TokenRevocationStorage = nil

			_, err := f.exchange(t, consts.TokenTypeRFC8693AccessToken)
			require.ErrorIs(t, err, oauth2.ErrServerError)

			_, err = f.store.GetRefreshTokenSession(t.Context(), f.strategy.RefreshTokenSignature(t.Context(), f.subject), nil)
			assert.NoError(t, err)
		})
	}
}

type rotationBarrier struct {
	hoauth2.TokenRevocationStorage

	calls   atomic.Int32
	arrived chan struct{}
	release chan struct{}
}

func newRotationBarrier(store hoauth2.TokenRevocationStorage) *rotationBarrier {
	return &rotationBarrier{TokenRevocationStorage: store, arrived: make(chan struct{}), release: make(chan struct{})}
}

func (b *rotationBarrier) RotateRefreshToken(ctx context.Context, requestID, signature string) (err error) {
	wait := b.arrived

	if b.calls.Add(1) == 2 {
		close(b.arrived)

		wait = b.release
	}

	select {
	case <-wait:
		return b.TokenRevocationStorage.RotateRefreshToken(ctx, requestID, signature)
	case <-time.After(10 * time.Second):
		return errors.New("timed out waiting for the concurrent exchange")
	}
}

type rotationSerializationStore struct {
	hoauth2.TokenRevocationStorage

	failure func(ctx context.Context)
}

func (s *rotationSerializationStore) RotateRefreshToken(ctx context.Context, _, _ string) error {
	if s.failure != nil {
		s.failure(ctx)
	}

	return oauth2.ErrSerializationFailure
}

type bufferedExchangeKey struct{}

type bufferedExchangeWrites struct {
	writes []func(ctx context.Context) error
}

type bufferedExchangeStore struct {
	rfc8693ExchangeStore

	create, commit, rollback error

	begins, commits, rollbacks, applied int
}

func (s *bufferedExchangeStore) write(ctx context.Context, write func(ctx context.Context) error) error {
	if tx, ok := ctx.Value(bufferedExchangeKey{}).(*bufferedExchangeWrites); ok {
		tx.writes = append(tx.writes, write)

		return nil
	}

	s.applied++

	return write(ctx)
}

func (s *bufferedExchangeStore) CreateAccessTokenSession(ctx context.Context, signature string, request oauth2.Requester) error {
	return s.write(ctx, func(ctx context.Context) error {
		return s.rfc8693ExchangeStore.CreateAccessTokenSession(ctx, signature, request)
	})
}

func (s *bufferedExchangeStore) CreateRefreshTokenSession(ctx context.Context, signature, accessSignature string, request oauth2.Requester) error {
	if s.create != nil {
		return s.create
	}

	return s.write(ctx, func(ctx context.Context) error {
		return s.rfc8693ExchangeStore.CreateRefreshTokenSession(ctx, signature, accessSignature, request)
	})
}

func (s *bufferedExchangeStore) BeginTX(ctx context.Context) (context.Context, error) {
	s.begins++

	return context.WithValue(ctx, bufferedExchangeKey{}, &bufferedExchangeWrites{}), nil
}

func (s *bufferedExchangeStore) Commit(ctx context.Context) error {
	s.commits++

	if s.commit != nil {
		return s.commit
	}

	for _, write := range ctx.Value(bufferedExchangeKey{}).(*bufferedExchangeWrites).writes {
		if err := write(context.Background()); err != nil {
			return err
		}

		s.applied++
	}

	return nil
}

func (s *bufferedExchangeStore) Rollback(_ context.Context) error {
	s.rollbacks++

	return s.rollback
}

type rotationFixture struct {
	config   *oauth2.Config
	store    rfc8693ExchangeStore
	strategy interface {
		RefreshTokenSignature(ctx context.Context, token string) string
	}
	client  *oauth2.DefaultRegisteredClient
	access  *AccessTokenTypeHandler
	refresh *RefreshTokenTypeHandler
	subject string
}

func newRotationFixture(t *testing.T, store rfc8693ExchangeStore) *rotationFixture {
	t.Helper()

	config, strategy := newBindingExchangeConfig()
	config.RefreshTokenScopes = []string{}
	config.RFC8693TokenTypes[consts.TokenTypeRFC8693RefreshToken] = &DefaultTokenType{Name: consts.TokenTypeRFC8693RefreshToken}

	client := store.GetClients()["my-client"].(*oauth2.DefaultClient)

	access := newLifetimeAccessTokenHandler(config, strategy, store)
	access.RefreshTokenScopes = []string{}

	refresh := newLifetimeRefreshTokenHandler(config, strategy, store)
	refresh.RefreshTokenScopes = []string{}

	return &rotationFixture{
		config:   config,
		store:    store,
		strategy: strategy,
		client:   &oauth2.DefaultRegisteredClient{DefaultClient: client, TokenExchangeRefreshToken: true},
		access:   access,
		refresh:  refresh,
		subject:  chainSubjectToken(t, strategy, store, client, newOptInSubject(), true),
	}
}

func (f *rotationFixture) exchange(t *testing.T, tokenType string) (issued string, err error) {
	t.Helper()

	request := newLifetimeExchangeRequest(f.store, consts.TokenTypeRFC8693RefreshToken, f.subject, tokenType)
	request.Client = f.client

	if err = f.refresh.HandleTokenEndpointRequest(t.Context(), request); err != nil {
		return "", err
	}

	response := oauth2.NewAccessResponse()

	if tokenType == consts.TokenTypeRFC8693RefreshToken {
		if err = f.refresh.PopulateTokenEndpointResponse(t.Context(), request, response); err != nil {
			return "", err
		}

		return response.GetAccessToken(), nil
	}

	if err = f.access.PopulateTokenEndpointResponse(t.Context(), request, response); err != nil {
		return "", err
	}

	issued, _ = response.GetExtra(consts.FormParameterRefreshToken).(string)

	return issued, nil
}
