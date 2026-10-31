// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	. "authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
)

const ssfVerifyURL = "https://ssf.example.com/ssf/verify"

type ssfVerifyRecorder struct {
	calls   int
	stream  *SSFStream
	state   string
	failure error
	onCall  func()
}

func (v *ssfVerifyRecorder) HandleSSFVerification(_ context.Context, stream *SSFStream, state string) (err error) {
	v.calls++
	v.stream = stream
	v.state = state

	if v.onCall != nil {
		v.onCall()
	}

	return v.failure
}

type ssfFailUpdateStore struct {
	*ssfCountingStore
}

func (s *ssfFailUpdateStore) UpdateSSFStreamLastVerification(context.Context, string, string, time.Time) error {
	return errors.New("update failed")
}

type ssfReadCountingStore struct {
	*ssfCountingStore
	gets int
}

func (s *ssfReadCountingStore) GetSSFStream(ctx context.Context, clientID, streamID string) (*SSFStream, error) {
	s.gets++

	return s.ssfCountingStore.GetSSFStream(ctx, clientID, streamID)
}

func (h *ssfHandlerHarness) doVerify(t *testing.T, client, method, contentType, body string) (rw *httptest.ResponseRecorder, err error) {
	t.Helper()

	r := httptest.NewRequest(method, ssfVerifyURL, strings.NewReader(body))
	r.Header.Set(consts.HeaderAuthorization, "Bearer tok-"+client)

	if contentType != "" {
		r.Header.Set(consts.HeaderContentType, contentType)
	}

	rw = httptest.NewRecorder()

	if err = h.provider.HandleSSFVerificationRequest(context.Background(), r, &DefaultSession{}); err != nil {
		h.provider.WriteSSFError(context.Background(), rw, r, err)
	}

	return rw, err
}

func TestSSFVerification(t *testing.T) {
	newHarness := func(t *testing.T, interval time.Duration) (*ssfHandlerHarness, *ssfVerifyRecorder, string) {
		t.Helper()

		rec := &ssfVerifyRecorder{}
		h := newSSFHandlerHarness(t, func(c *SSFConfig) {
			c.VerificationHandler = rec
			c.MinVerificationInterval = interval
		})

		return h, rec, h.createStream(t, "a", `{}`)
	}

	t.Run("ShouldPassStreamAndState", func(t *testing.T) {
		h, rec, id := newHarness(t, 0)

		_, err := h.doVerify(t, "a", http.MethodPost, "application/json", `{"stream_id":"`+id+`","state":"s-1"}`)
		require.NoError(t, err)

		require.Equal(t, 1, rec.calls)
		assert.Equal(t, id, rec.stream.StreamID)
		assert.Equal(t, "s-1", rec.state)
		assert.False(t, h.stored(t, "a", id).LastVerificationAt.IsZero())
	})

	t.Run("ShouldAllowMissingState", func(t *testing.T) {
		h, rec, id := newHarness(t, 0)

		_, err := h.doVerify(t, "a", http.MethodPost, "application/json", `{"stream_id":"`+id+`"}`)
		require.NoError(t, err)

		assert.Equal(t, 1, rec.calls)
		assert.Equal(t, "", rec.state)
	})

	t.Run("ShouldAllowPausedStream", func(t *testing.T) {
		h, rec, id := newHarness(t, 0)

		require.NoError(t, h.store.UpdateSSFStreamStatus(context.Background(), "a", id, SSFStreamStatusPaused, ""))

		_, err := h.doVerify(t, "a", http.MethodPost, "application/json", `{"stream_id":"`+id+`"}`)
		require.NoError(t, err)

		assert.Equal(t, 1, rec.calls)
	})

	t.Run("ShouldRejectMissingStreamID", func(t *testing.T) {
		h, rec, _ := newHarness(t, 0)

		rw, err := h.doVerify(t, "a", http.MethodPost, "application/json", `{"state":"x"}`)
		require.Error(t, err)

		assert.Equal(t, http.StatusBadRequest, rw.Code)
		assert.Contains(t, rw.Body.String(), ErrInvalidRequest.ErrorField)
		assert.Equal(t, 0, rec.calls)
	})

	t.Run("ShouldRejectWrongMethod", func(t *testing.T) {
		h, rec, _ := newHarness(t, 0)

		rw, err := h.doVerify(t, "a", http.MethodGet, "", "")
		require.Error(t, err)

		assert.Equal(t, http.StatusMethodNotAllowed, rw.Code)
		assert.Equal(t, http.MethodPost, rw.Header().Get(consts.HeaderAllow))
		assert.Contains(t, rw.Body.String(), ErrInvalidRequest.ErrorField)
		assert.Equal(t, 0, rec.calls)
	})

	t.Run("ShouldRejectReadOnlyToken", func(t *testing.T) {
		h, rec, id := newHarness(t, 0)

		rw, err := h.doVerify(t, "a-ro", http.MethodPost, "application/json", `{"stream_id":"`+id+`"}`)
		require.Error(t, err)

		assert.Equal(t, http.StatusForbidden, rw.Code)
		assert.Equal(t, 0, rec.calls)
	})

	t.Run("ShouldThrottleWithinInterval", func(t *testing.T) {
		h, rec, id := newHarness(t, time.Minute)

		_, err := h.doVerify(t, "a", http.MethodPost, "application/json", `{"stream_id":"`+id+`"}`)
		require.NoError(t, err)

		rw, err := h.doVerify(t, "a", http.MethodPost, "application/json", `{"stream_id":"`+id+`"}`)
		require.Error(t, err)

		assert.Equal(t, http.StatusTooManyRequests, rw.Code)
		assert.Contains(t, rw.Body.String(), ErrSSFVerificationThrottled.ErrorField)
		assert.Equal(t, 1, rec.calls)
	})

	t.Run("ShouldThrottleExistingStreamAfterConfigurationChange", func(t *testing.T) {
		h, rec, id := newHarness(t, 0)

		h.config.MinVerificationInterval = time.Hour

		_, err := h.doVerify(t, "a", http.MethodPost, "application/json", `{"stream_id":"`+id+`"}`)
		require.NoError(t, err)

		rw, err := h.doVerify(t, "a", http.MethodPost, "application/json", `{"stream_id":"`+id+`"}`)
		require.Error(t, err)

		assert.Equal(t, http.StatusTooManyRequests, rw.Code)
		assert.Equal(t, 1, rec.calls)
		assert.Equal(t, 3600, rec.stream.MinVerificationInterval)
	})

	t.Run("ShouldPassAfterInterval", func(t *testing.T) {
		h, rec, id := newHarness(t, time.Minute)

		_, err := h.doVerify(t, "a", http.MethodPost, "application/json", `{"stream_id":"`+id+`"}`)
		require.NoError(t, err)

		require.NoError(t, h.store.UpdateSSFStreamLastVerification(context.Background(), "a", id, time.Now().UTC().Add(-2*time.Minute)))

		_, err = h.doVerify(t, "a", http.MethodPost, "application/json", `{"stream_id":"`+id+`"}`)
		require.NoError(t, err)

		assert.Equal(t, 2, rec.calls)
		assert.WithinDuration(t, time.Now().UTC(), h.stored(t, "a", id).LastVerificationAt, time.Minute)
	})

	t.Run("ShouldThrottleAfterFailedHandler", func(t *testing.T) {
		h, rec, id := newHarness(t, time.Minute)
		rec.failure = errors.New("boom")

		_, err := h.doVerify(t, "a", http.MethodPost, "application/json", `{"stream_id":"`+id+`"}`)
		require.ErrorIs(t, err, rec.failure)

		assert.False(t, h.stored(t, "a", id).LastVerificationAt.IsZero())

		rw, err := h.doVerify(t, "a", http.MethodPost, "application/json", `{"stream_id":"`+id+`"}`)
		require.Error(t, err)

		assert.Equal(t, http.StatusTooManyRequests, rw.Code)
		assert.Equal(t, 1, rec.calls)
	})

	t.Run("ShouldDenyOnPolicyError", func(t *testing.T) {
		h, rec, id := newHarness(t, 0)
		h.config.Policy = ssfHandlerPolicy{err: errors.New("operator disabled")}

		rw, err := h.doVerify(t, "a", http.MethodPost, "application/json", `{"stream_id":"`+id+`"}`)
		require.Error(t, err)

		assert.Equal(t, http.StatusForbidden, rw.Code)
		assert.Equal(t, 0, rec.calls)
		assert.True(t, h.stored(t, "a", id).LastVerificationAt.IsZero())
	})

	t.Run("ShouldRejectStoredPushEndpointNoLongerPermitted", func(t *testing.T) {
		h, rec, _ := newHarness(t, 0)
		id := h.createStream(t, "b", `{"delivery":{"method":"`+SSFDeliveryMethodPush+`","endpoint_url":"https://rx.example.com/events"}}`)

		h.config.EndpointValidator = ssfHandlerValidator{err: errors.New("private address")}

		rw, err := h.doVerify(t, "b", http.MethodPost, "application/json", `{"stream_id":"`+id+`"}`)
		require.Error(t, err)

		assert.Equal(t, http.StatusBadRequest, rw.Code)
		assert.NotContains(t, rw.Body.String(), "private address")
		assert.Equal(t, 0, rec.calls)
		assert.True(t, h.stored(t, "b", id).LastVerificationAt.IsZero())
	})

	t.Run("ShouldKeepChangeMadeByHandler", func(t *testing.T) {
		h, rec, id := newHarness(t, time.Minute)

		rec.onCall = func() {
			require.NoError(t, h.store.UpdateSSFStreamStatus(context.Background(), "a", id, SSFStreamStatusDisabled, "stopped"))
		}

		_, err := h.doVerify(t, "a", http.MethodPost, "application/json", `{"stream_id":"`+id+`"}`)
		require.NoError(t, err)

		stored := h.stored(t, "a", id)
		assert.Equal(t, SSFStreamStatusDisabled, stored.Status)
		assert.Equal(t, "stopped", stored.StatusReason)
		assert.False(t, stored.LastVerificationAt.IsZero())
	})

	t.Run("ShouldNotReadTheStreamAgain", func(t *testing.T) {
		h, _, id := newHarness(t, time.Minute)

		reads := &ssfReadCountingStore{ssfCountingStore: h.store}
		h.provider.Store = reads

		_, err := h.doVerify(t, "a", http.MethodPost, "application/json", `{"stream_id":"`+id+`"}`)
		require.NoError(t, err)

		assert.Equal(t, 1, reads.gets)
		assert.False(t, h.stored(t, "a", id).LastVerificationAt.IsZero())
	})

	t.Run("ShouldNotCallHandlerWhenSaveFails", func(t *testing.T) {
		h, rec, id := newHarness(t, time.Minute)
		h.provider.Store = &ssfFailUpdateStore{ssfCountingStore: h.store}

		_, err := h.doVerify(t, "a", http.MethodPost, "application/json", `{"stream_id":"`+id+`"}`)
		require.Error(t, err)

		assert.Equal(t, 0, rec.calls)
		assert.True(t, h.stored(t, "a", id).LastVerificationAt.IsZero())
	})

	t.Run("ShouldRejectMissingToken", func(t *testing.T) {
		h, rec, id := newHarness(t, 0)

		r := httptest.NewRequest(http.MethodPost, ssfVerifyURL, strings.NewReader(`{"stream_id":"`+id+`"}`))
		r.Header.Set(consts.HeaderContentType, "application/json")

		rw := httptest.NewRecorder()

		err := h.provider.HandleSSFVerificationRequest(context.Background(), r, &DefaultSession{})
		require.Error(t, err)
		h.provider.WriteSSFError(context.Background(), rw, r, err)

		assert.Equal(t, http.StatusUnauthorized, rw.Code)
		assert.Contains(t, rw.Body.String(), ErrInvalidToken.ErrorField)
		assert.Equal(t, 0, rec.calls)
	})

	t.Run("ShouldFailWithoutHandler", func(t *testing.T) {
		h := newSSFHandlerHarness(t, nil)
		id := h.createStream(t, "a", `{}`)

		rw, err := h.doVerify(t, "a", http.MethodPost, "application/json", `{"stream_id":"`+id+`"}`)
		require.Error(t, err)

		assert.Equal(t, http.StatusInternalServerError, rw.Code)
		assert.Contains(t, rw.Body.String(), ErrServerError.ErrorField)
	})

	t.Run("ShouldHideOtherClientsStream", func(t *testing.T) {
		h, rec, id := newHarness(t, 0)

		other, err := h.doVerify(t, "b", http.MethodPost, "application/json", `{"stream_id":"`+id+`"}`)
		require.Error(t, err)

		unknown, err := h.doVerify(t, "b", http.MethodPost, "application/json", `{"stream_id":"nope"}`)
		require.Error(t, err)

		assert.Equal(t, http.StatusNotFound, other.Code)
		assert.Contains(t, other.Body.String(), ErrNotFound.ErrorField)
		assert.Equal(t, unknown.Code, other.Code)
		assert.Equal(t, unknown.Body.String(), other.Body.String())
		assert.Equal(t, 0, rec.calls)
	})
}

func TestNewSSFVerificationSubject(t *testing.T) {
	subject, err := NewSSFVerificationSubject("stream-1")
	require.NoError(t, err)

	data, err := json.Marshal(subject)
	require.NoError(t, err)

	assert.JSONEq(t, `{"format":"opaque","id":"stream-1"}`, string(data))

	_, err = NewSSFVerificationSubject("")
	assert.Error(t, err)
}
