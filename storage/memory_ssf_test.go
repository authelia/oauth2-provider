// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package storage

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
)

func newSSFTestStream(id, client string) *oauth2.SSFStream {
	return &oauth2.SSFStream{
		StreamID:        id,
		ClientID:        client,
		Issuer:          "https://tx.example.com",
		Audience:        []string{"rx"},
		EventsDelivered: []string{"a"},
		Status:          oauth2.SSFStreamStatusEnabled,
		Delivery:        oauth2.SSFDelivery{Method: oauth2.SSFDeliveryMethodPush, EndpointURL: "https://rx.example.com", AuthorizationHeader: "Bearer s"},
	}
}

func TestMemoryStoreSSFStream(t *testing.T) {
	ctx := t.Context()

	t.Run("ShouldCreateGetListUpdateDelete", func(t *testing.T) {
		s := NewMemoryStore()

		require.NoError(t, s.CreateSSFStream(ctx, newSSFTestStream("s1", "c1")))

		got, err := s.GetSSFStream(ctx, "c1", "s1")
		require.NoError(t, err)
		assert.Equal(t, "Bearer s", got.Delivery.AuthorizationHeader)

		list, err := s.ListSSFStreams(ctx, "c1")
		require.NoError(t, err)
		require.Len(t, list, 1)
		assert.Equal(t, "s1", list[0].StreamID)

		list, err = s.ListSSFStreams(ctx, "c2")
		require.NoError(t, err)
		assert.Empty(t, list)

		updated := newSSFTestStream("s1", "c1")
		updated.Description = "new"

		require.NoError(t, s.UpdateSSFStream(ctx, updated))

		got, err = s.GetSSFStream(ctx, "c1", "s1")
		require.NoError(t, err)
		assert.Equal(t, "new", got.Description)

		require.NoError(t, s.DeleteSSFStream(ctx, "c1", "s1"))

		_, err = s.GetSSFStream(ctx, "c1", "s1")
		assert.ErrorIs(t, err, oauth2.ErrNotFound)

		require.NoError(t, s.CreateSSFStream(ctx, newSSFTestStream("s2", "c1")))
	})

	t.Run("ShouldConflictOnSecondCreate", func(t *testing.T) {
		s := NewMemoryStore()

		require.NoError(t, s.CreateSSFStream(ctx, newSSFTestStream("s1", "c1")))

		err := s.CreateSSFStream(ctx, newSSFTestStream("s2", "c1"))
		assert.ErrorIs(t, err, oauth2.ErrSSFStreamConflict)

		err = s.CreateSSFStream(ctx, newSSFTestStream("s1", "c2"))
		assert.ErrorIs(t, err, oauth2.ErrSSFStreamConflict)

		require.NoError(t, s.CreateSSFStream(ctx, newSSFTestStream("s3", "c3")))
	})

	t.Run("ShouldWriteOnlyTheNamedFields", func(t *testing.T) {
		at := time.Unix(1700000000, 0).UTC()

		s := NewMemoryStore()

		seeded := newSSFTestStream("s1", "c1")
		seeded.Status, seeded.StatusReason, seeded.LastVerificationAt = oauth2.SSFStreamStatusPaused, "held", at
		seeded.Description = "original"

		require.NoError(t, s.CreateSSFStream(ctx, seeded))

		// Configuration updates keep the status, reason and verification time.
		updated := newSSFTestStream("s1", "c1")
		updated.Description = "new"
		updated.Status, updated.StatusReason, updated.LastVerificationAt = oauth2.SSFStreamStatusEnabled, "other", at.Add(time.Hour)

		require.NoError(t, s.UpdateSSFStream(ctx, updated))

		want := seeded.Clone()
		want.Description = "new"

		got, err := s.GetSSFStream(ctx, "c1", "s1")
		require.NoError(t, err)
		assert.Equal(t, want, got)

		// The status write changes only the status and reason.
		require.NoError(t, s.UpdateSSFStreamStatus(ctx, "c1", "s1", oauth2.SSFStreamStatusDisabled, "stopped"))

		want.Status, want.StatusReason = oauth2.SSFStreamStatusDisabled, "stopped"

		got, err = s.GetSSFStream(ctx, "c1", "s1")
		require.NoError(t, err)
		assert.Equal(t, want, got)

		// The verification write changes only the verification time.
		require.NoError(t, s.UpdateSSFStreamLastVerification(ctx, "c1", "s1", at.Add(2*time.Hour)))

		want.LastVerificationAt = at.Add(2 * time.Hour)

		got, err = s.GetSSFStream(ctx, "c1", "s1")
		require.NoError(t, err)
		assert.Equal(t, want, got)
	})

	t.Run("ShouldScopeNarrowWritesToOwner", func(t *testing.T) {
		s := NewMemoryStore()

		seeded := newSSFTestStream("s1", "c1")
		seeded.Status = oauth2.SSFStreamStatusEnabled

		require.NoError(t, s.CreateSSFStream(ctx, seeded))

		assert.ErrorIs(t, s.UpdateSSFStreamStatus(ctx, "c2", "s1", oauth2.SSFStreamStatusPaused, "x"), oauth2.ErrNotFound)
		assert.ErrorIs(t, s.UpdateSSFStreamStatus(ctx, "c1", "nope", oauth2.SSFStreamStatusPaused, "x"), oauth2.ErrNotFound)
		assert.ErrorIs(t, s.UpdateSSFStreamLastVerification(ctx, "c2", "s1", time.Now()), oauth2.ErrNotFound)
		assert.ErrorIs(t, s.UpdateSSFStreamLastVerification(ctx, "c1", "nope", time.Now()), oauth2.ErrNotFound)

		got, err := s.GetSSFStream(ctx, "c1", "s1")
		require.NoError(t, err)
		assert.Equal(t, seeded, got)
	})

	t.Run("ShouldNotFindForWrongClient", func(t *testing.T) {
		s := NewMemoryStore()

		require.NoError(t, s.CreateSSFStream(ctx, newSSFTestStream("s1", "c1")))

		_, errWrong := s.GetSSFStream(ctx, "c2", "s1")
		_, errUnknown := s.GetSSFStream(ctx, "c1", "nope")

		assert.ErrorIs(t, errWrong, oauth2.ErrNotFound)
		assert.ErrorIs(t, errUnknown, oauth2.ErrNotFound)
		assert.Equal(t, errUnknown.Error(), errWrong.Error())

		wrong := newSSFTestStream("s1", "c2")
		wrong.Description = "hijack"

		assert.ErrorIs(t, s.UpdateSSFStream(ctx, wrong), oauth2.ErrNotFound)
		assert.ErrorIs(t, s.UpdateSSFStream(ctx, newSSFTestStream("nope", "c1")), oauth2.ErrNotFound)
		assert.ErrorIs(t, s.DeleteSSFStream(ctx, "c2", "s1"), oauth2.ErrNotFound)
		assert.ErrorIs(t, s.DeleteSSFStream(ctx, "c1", "nope"), oauth2.ErrNotFound)

		got, err := s.GetSSFStream(ctx, "c1", "s1")
		require.NoError(t, err)
		assert.Empty(t, got.Description)
	})

	t.Run("ShouldRejectInvalidStream", func(t *testing.T) {
		s := NewMemoryStore()

		assert.ErrorIs(t, s.CreateSSFStream(ctx, nil), oauth2.ErrServerError)
		assert.ErrorIs(t, s.CreateSSFStream(ctx, newSSFTestStream("", "c1")), oauth2.ErrServerError)
		assert.ErrorIs(t, s.CreateSSFStream(ctx, newSSFTestStream("s1", "")), oauth2.ErrServerError)
		assert.ErrorIs(t, s.UpdateSSFStream(ctx, nil), oauth2.ErrServerError)
	})

	t.Run("ShouldReturnCopies", func(t *testing.T) {
		s := NewMemoryStore()

		in := newSSFTestStream("s1", "c1")

		require.NoError(t, s.CreateSSFStream(ctx, in))

		in.Audience[0], in.EventsDelivered[0], in.Description = "mutated", "mutated", "mutated"

		got, err := s.GetSSFStream(ctx, "c1", "s1")
		require.NoError(t, err)
		assert.Equal(t, []string{"rx"}, got.Audience)
		assert.Equal(t, []string{"a"}, got.EventsDelivered)
		assert.Empty(t, got.Description)

		got.Audience[0], got.EventsDelivered[0], got.Description = "mutated", "mutated", "mutated"

		list, err := s.ListSSFStreams(ctx, "c1")
		require.NoError(t, err)
		require.Len(t, list, 1)
		list[0].Audience[0], list[0].Description = "mutated", "mutated"

		again, err := s.GetSSFStream(ctx, "c1", "s1")
		require.NoError(t, err)
		assert.Equal(t, []string{"rx"}, again.Audience)
		assert.Equal(t, []string{"a"}, again.EventsDelivered)
		assert.Empty(t, again.Description)

		up := newSSFTestStream("s1", "c1")

		require.NoError(t, s.UpdateSSFStream(ctx, up))

		up.EventsDelivered[0] = "mutated"

		again, err = s.GetSSFStream(ctx, "c1", "s1")
		require.NoError(t, err)
		assert.Equal(t, []string{"a"}, again.EventsDelivered)
	})

	t.Run("ShouldAllowExactlyOneConcurrentCreate", func(t *testing.T) {
		s := NewMemoryStore()

		const workers = 32

		var (
			wg        sync.WaitGroup
			successes atomic.Int32
			conflicts atomic.Int32
		)

		start := make(chan struct{})

		for i := range workers {
			wg.Add(1)

			go func() {
				defer wg.Done()

				<-start

				err := s.CreateSSFStream(ctx, newSSFTestStream("s"+string(rune('A'+i)), "c1"))

				switch {
				case err == nil:
					successes.Add(1)
				case assert.ErrorIs(t, err, oauth2.ErrSSFStreamConflict):
					conflicts.Add(1)
				}
			}()
		}

		close(start)
		wg.Wait()

		assert.Equal(t, int32(1), successes.Load())
		assert.Equal(t, int32(workers-1), conflicts.Load())
	})
}
