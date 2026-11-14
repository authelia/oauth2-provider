// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package storage

import (
	"context"
	"encoding/json"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/token/jwt"
)

// cibaTestStore mirrors ciba.Storage, which this package cannot import as handler/ciba imports it.
type cibaTestStore interface {
	CreateCIBASession(ctx context.Context, signature string, request oauth2.BackChannelAuthenticationRequester) (err error)
	GetCIBASession(ctx context.Context, signature string, session oauth2.Session) (request oauth2.BackChannelAuthenticationRequester, err error)
	GetCIBASessionByRequestID(ctx context.Context, requestID string, session oauth2.Session) (request oauth2.BackChannelAuthenticationRequester, err error)
	UpdateCIBASession(ctx context.Context, signature string, request oauth2.BackChannelAuthenticationRequester) (err error)
	DecideCIBASession(ctx context.Context, signature string, request oauth2.BackChannelAuthenticationRequester) (err error)
	InvalidateCIBASession(ctx context.Context, signature string) (err error)
}

func newCIBATestRequest() *oauth2.BackChannelAuthenticationRequest {
	r := oauth2.NewBackChannelAuthenticationRequest()
	r.SetID("request-id")
	r.SetRequestedAt(time.Now().UTC().Truncate(time.Second))
	r.Session = &oauth2.DefaultSession{Subject: "john"}
	r.Client = &oauth2.DefaultClient{ID: "client"}
	r.DeliveryMode = "ping"
	r.HintKind = oauth2.CIBAHintKindLoginHint
	r.HintValue = "john"
	r.IDTokenHintClaims = jwt.MapClaims{"sub": "john"}
	r.BindingMessage = "bm"
	r.UserCode = "uc"
	r.RequestedExpiry = time.Minute
	r.RequestContext = json.RawMessage(`{"a":1}`)
	r.ClientNotificationToken = "tok"
	r.AuthRequestID = "raw-id"
	r.SetAuthRequestIDSignature("sig")
	r.SetStatus(oauth2.CIBAStatusPending)
	r.SetLastPolled(time.Now().UTC().Truncate(time.Second))
	r.SetPollingInterval(5 * time.Second)
	r.SetSlowDownCount(2)
	r.SetFailureCause("cause")

	return r
}

func TestMemoryStoreCIBA(t *testing.T) {
	stores := []struct {
		name string
		new  func() cibaTestStore
	}{
		{"MemoryStore", func() cibaTestStore { return NewMemoryStore() }},
		{"HydratingMemoryStore", func() cibaTestStore { return NewHydratingMemoryStore() }},
	}

	for _, sc := range stores {
		t.Run(sc.name, func(t *testing.T) {
			ctx := t.Context()

			t.Run("ShouldRoundTrip", func(t *testing.T) {
				store := sc.new()
				want := newCIBATestRequest()

				require.NoError(t, store.CreateCIBASession(ctx, "sig", want))

				for _, get := range []func() (oauth2.BackChannelAuthenticationRequester, error){
					func() (oauth2.BackChannelAuthenticationRequester, error) {
						return store.GetCIBASession(ctx, "sig", &oauth2.DefaultSession{})
					},
					func() (oauth2.BackChannelAuthenticationRequester, error) {
						return store.GetCIBASessionByRequestID(ctx, "request-id", &oauth2.DefaultSession{})
					},
				} {
					got, err := get()
					require.NoError(t, err)

					assert.Equal(t, want.GetID(), got.GetID())
					assert.Equal(t, "ping", got.GetDeliveryMode())

					kind, value := got.GetHint()
					assert.Equal(t, oauth2.CIBAHintKindLoginHint, kind)
					assert.Equal(t, "john", value)
					assert.Equal(t, "john", got.GetIDTokenHintClaims()["sub"])
					assert.Equal(t, "bm", got.GetBindingMessage())
					assert.Equal(t, "uc", got.GetUserCode())
					assert.Equal(t, time.Minute, got.GetRequestedExpiry())
					assert.JSONEq(t, `{"a":1}`, string(got.GetRequestContext()))
					assert.Equal(t, "tok", oauth2.GetClientNotificationToken(got))
					assert.Equal(t, "raw-id", oauth2.GetAuthRequestID(got))
					assert.Equal(t, "sig", got.GetAuthRequestIDSignature())
					assert.Equal(t, oauth2.CIBAStatusPending, got.GetStatus())
					assert.True(t, want.GetLastPolled().Equal(got.GetLastPolled()))
					assert.Equal(t, 5*time.Second, got.GetPollingInterval())
					assert.Equal(t, 2, got.GetSlowDownCount())
					assert.Equal(t, "cause", got.GetFailureCause())
					assert.Equal(t, "john", got.GetSession().GetSubject())
				}
			})

			t.Run("ShouldNotFind", func(t *testing.T) {
				store := sc.new()

				_, err := store.GetCIBASession(ctx, "nope", &oauth2.DefaultSession{})
				assert.ErrorIs(t, err, oauth2.ErrNotFound)

				_, err = store.GetCIBASessionByRequestID(ctx, "nope", &oauth2.DefaultSession{})
				assert.ErrorIs(t, err, oauth2.ErrNotFound)

				assert.ErrorIs(t, store.DecideCIBASession(ctx, "nope", newCIBATestRequest()), oauth2.ErrNotFound)
				assert.ErrorIs(t, store.InvalidateCIBASession(ctx, "nope"), oauth2.ErrNotFound)
			})

			t.Run("ShouldDecideOnce", func(t *testing.T) {
				store := sc.new()

				require.NoError(t, store.CreateCIBASession(ctx, "sig", newCIBATestRequest()))

				decided := newCIBATestRequest()
				decided.SetStatus(oauth2.CIBAStatusApproved)

				require.NoError(t, store.DecideCIBASession(ctx, "sig", decided))

				got, err := store.GetCIBASession(ctx, "sig", &oauth2.DefaultSession{})
				require.NoError(t, err)
				assert.Equal(t, oauth2.CIBAStatusApproved, got.GetStatus())

				denied := newCIBATestRequest()
				denied.SetStatus(oauth2.CIBAStatusDenied)

				assert.ErrorIs(t, store.DecideCIBASession(ctx, "sig", denied), oauth2.ErrCIBADecided)

				got, err = store.GetCIBASession(ctx, "sig", &oauth2.DefaultSession{})
				require.NoError(t, err)
				assert.Equal(t, oauth2.CIBAStatusApproved, got.GetStatus())
			})

			t.Run("ShouldNotDecideAnInvalidatedRequest", func(t *testing.T) {
				store := sc.new()

				require.NoError(t, store.CreateCIBASession(ctx, "sig", newCIBATestRequest()))
				require.NoError(t, store.InvalidateCIBASession(ctx, "sig"))

				decided := newCIBATestRequest()
				decided.SetStatus(oauth2.CIBAStatusApproved)

				assert.ErrorIs(t, store.DecideCIBASession(ctx, "sig", decided), oauth2.ErrCIBADecided)

				got, err := store.GetCIBASession(ctx, "sig", &oauth2.DefaultSession{})
				assert.ErrorIs(t, err, oauth2.ErrInvalidatedCIBASession)
				require.NotNil(t, got)
				assert.Equal(t, oauth2.CIBAStatusPending, got.GetStatus())
			})

			t.Run("ShouldUpdate", func(t *testing.T) {
				store := sc.new()

				require.NoError(t, store.CreateCIBASession(ctx, "sig", newCIBATestRequest()))

				updated := newCIBATestRequest()
				updated.SetSlowDownCount(9)

				require.NoError(t, store.UpdateCIBASession(ctx, "sig", updated))

				got, err := store.GetCIBASession(ctx, "sig", &oauth2.DefaultSession{})
				require.NoError(t, err)
				assert.Equal(t, 9, got.GetSlowDownCount())

				require.NoError(t, store.UpdateCIBASession(ctx, "missing", updated))

				_, err = store.GetCIBASession(ctx, "missing", &oauth2.DefaultSession{})
				assert.ErrorIs(t, err, oauth2.ErrNotFound)
			})

			t.Run("ShouldUpdateOnlyThePollingState", func(t *testing.T) {
				store := sc.new()

				require.NoError(t, store.CreateCIBASession(ctx, "sig", newCIBATestRequest()))

				stale, err := store.GetCIBASession(ctx, "sig", &oauth2.DefaultSession{})
				require.NoError(t, err)

				decided := newCIBATestRequest()
				decided.Session = &oauth2.DefaultSession{Subject: "john", Username: "approved"}
				decided.SetStatus(oauth2.CIBAStatusApproved)
				decided.SetFailureCause("")

				require.NoError(t, store.DecideCIBASession(ctx, "sig", decided))

				polled := time.Now().UTC().Add(time.Minute).Truncate(time.Second)

				stale.SetLastPolled(polled)
				stale.SetPollingInterval(15 * time.Second)
				stale.SetSlowDownCount(7)
				stale.SetFailureCause("stale")

				require.NoError(t, store.UpdateCIBASession(ctx, "sig", stale))

				got, err := store.GetCIBASession(ctx, "sig", &oauth2.DefaultSession{})
				require.NoError(t, err)

				assert.Equal(t, oauth2.CIBAStatusApproved, got.GetStatus())
				assert.Equal(t, "", got.GetFailureCause())
				assert.Equal(t, "approved", got.GetSession().GetUsername())
				assert.True(t, polled.Equal(got.GetLastPolled()))
				assert.Equal(t, 15*time.Second, got.GetPollingInterval())
				assert.Equal(t, 7, got.GetSlowDownCount())
			})

			t.Run("ShouldInvalidate", func(t *testing.T) {
				store := sc.new()

				require.NoError(t, store.CreateCIBASession(ctx, "sig", newCIBATestRequest()))
				require.NoError(t, store.InvalidateCIBASession(ctx, "sig"))

				got, err := store.GetCIBASession(ctx, "sig", &oauth2.DefaultSession{})
				assert.ErrorIs(t, err, oauth2.ErrInvalidatedCIBASession)
				assert.NotNil(t, got)

				got, err = store.GetCIBASessionByRequestID(ctx, "request-id", &oauth2.DefaultSession{})
				assert.ErrorIs(t, err, oauth2.ErrInvalidatedCIBASession)
				assert.NotNil(t, got)
			})

			t.Run("ShouldNotAlias", func(t *testing.T) {
				store := sc.new()
				want := newCIBATestRequest()

				require.NoError(t, store.CreateCIBASession(ctx, "sig", want))

				want.SetStatus(oauth2.CIBAStatusFailed)
				want.SetSlowDownCount(99)
				want.SetFailureCause("mutated")

				got, err := store.GetCIBASession(ctx, "sig", &oauth2.DefaultSession{})
				require.NoError(t, err)

				assert.Equal(t, oauth2.CIBAStatusPending, got.GetStatus())
				assert.Equal(t, 2, got.GetSlowDownCount())
				assert.Equal(t, "cause", got.GetFailureCause())

				got.SetStatus(oauth2.CIBAStatusDenied)

				again, err := store.GetCIBASession(ctx, "sig", &oauth2.DefaultSession{})
				require.NoError(t, err)
				assert.Equal(t, oauth2.CIBAStatusPending, again.GetStatus())
			})
		})
	}
}

func TestHydratingMemoryStoreCIBADecideConcurrently(t *testing.T) {
	ctx := t.Context()
	store := NewHydratingMemoryStore()

	require.NoError(t, store.CreateCIBASession(ctx, "sig", newCIBATestRequest()))

	const n = 32

	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		winners []string
		losers  int
	)

	for i := range n {
		wg.Add(1)

		go func() {
			defer wg.Done()

			subject := "subject-" + strconv.Itoa(i)

			r := newCIBATestRequest()
			r.Session = &oauth2.DefaultSession{Subject: subject}
			r.SetStatus(oauth2.CIBAStatusApproved)

			err := store.DecideCIBASession(ctx, "sig", r)

			mu.Lock()
			defer mu.Unlock()

			if err == nil {
				winners = append(winners, subject)

				return
			}

			assert.ErrorIs(t, err, oauth2.ErrCIBADecided)

			losers++
		}()
	}

	wg.Wait()

	require.Len(t, winners, 1)
	assert.Equal(t, n-1, losers)

	got, err := store.GetCIBASession(ctx, "sig", &oauth2.DefaultSession{})
	require.NoError(t, err)
	assert.Equal(t, oauth2.CIBAStatusApproved, got.GetStatus())
	assert.Equal(t, winners[0], got.GetSession().GetSubject())
}
