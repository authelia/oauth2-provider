// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	. "authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
)

const ssfPollURL = "https://ssf.example.com/ssf/poll"

func (h *ssfHandlerHarness) newPollRequest(client, method, contentType, body string) *http.Request {
	r := httptest.NewRequest(method, ssfPollURL, strings.NewReader(body))

	if client != "" {
		r.Header.Set(consts.HeaderAuthorization, "Bearer tok-"+client)
	}

	if contentType != "" {
		r.Header.Set(consts.HeaderContentType, contentType)
	}

	return r
}

func (h *ssfHandlerHarness) parsePoll(contentType, body, streamID string) (*SSFPollRequest, error) {
	return h.provider.NewSSFPollRequest(context.Background(), h.newPollRequest("a", http.MethodPost, contentType, body), &DefaultSession{}, streamID)
}

func (h *ssfHandlerHarness) doPoll(client, method, contentType, body, streamID string) *httptest.ResponseRecorder {
	r := h.newPollRequest(client, method, contentType, body)
	ctx := context.Background()
	rw := httptest.NewRecorder()

	if _, err := h.provider.NewSSFPollRequest(ctx, r, &DefaultSession{}, streamID); err != nil {
		h.provider.WriteSSFPollError(ctx, rw, r, err)

		return rw
	}

	h.provider.WriteSSFPollResponse(ctx, rw, nil, false)

	return rw
}

func TestSSFPoll(t *testing.T) {
	h := newSSFHandlerHarness(t, nil)
	id := h.createStream(t, "a", `{}`)
	pushID := h.createStream(t, "p", `{"delivery":{"method":"`+SSFDeliveryMethodPush+`","endpoint_url":"https://rx.example.com/events"}}`)

	// RFC 8936 Figure 5 and Figure 3.
	const ack = `{"ack":["3d0c3cf797584bd193bd0fb1bd4e7d30"],"setErrs":{"4d3559ec67504aaba65d40b0363faad8":{"err":"authentication_failed","description":"The SET could not be authenticated"}},"returnImmediately":true}`

	t.Run("AckAndSetErrs", func(t *testing.T) {
		request, err := h.parsePoll("application/json", ack, id)
		require.NoError(t, err)

		assert.Equal(t, id, request.Stream.StreamID)
		assert.Nil(t, request.MaxEvents)
		assert.True(t, request.ReturnImmediately)
		assert.Equal(t, []string{"3d0c3cf797584bd193bd0fb1bd4e7d30"}, request.Ack)
		assert.Equal(t, map[string]SSFPollSetError{"4d3559ec67504aaba65d40b0363faad8": {Err: "authentication_failed", Description: "The SET could not be authenticated"}}, request.SetErrs)
	})

	t.Run("AcknowledgeOnlyMaxEventsZero", func(t *testing.T) {
		request, err := h.parsePoll("application/json", `{"ack":["4d3559ec67504aaba65d40b0363faad8","3d0c3cf797584bd193bd0fb1bd4e7d30"],"maxEvents":0,"returnImmediately":true}`, id)
		require.NoError(t, err)

		require.NotNil(t, request.MaxEvents)
		assert.Equal(t, 0, *request.MaxEvents)
		assert.Len(t, request.Ack, 2)
	})

	t.Run("MaxEventsAbsent", func(t *testing.T) {
		request, err := h.parsePoll("application/json", `{}`, id)
		require.NoError(t, err)

		assert.Nil(t, request.MaxEvents)
		assert.False(t, request.ReturnImmediately)
		assert.Empty(t, request.Ack)
		assert.Empty(t, request.SetErrs)
	})

	t.Run("EmptyObject", func(t *testing.T) {
		_, err := h.parsePoll("application/json", `{}`, id)
		require.NoError(t, err)
	})

	t.Run("EmptyBodyJSON", func(t *testing.T) {
		request, err := h.parsePoll("application/json", ``, id)
		require.NoError(t, err)

		assert.Nil(t, request.MaxEvents)
	})

	t.Run("ShouldReadBodyAtTheLargestLimit", func(t *testing.T) {
		large := newSSFHandlerHarness(t, func(c *SSFConfig) { c.MaxRequestBytes = math.MaxInt64 })
		largeID := large.createStream(t, "a", `{}`)

		request, err := large.parsePoll("application/json", ack, largeID)
		require.NoError(t, err)

		assert.Equal(t, []string{"3d0c3cf797584bd193bd0fb1bd4e7d30"}, request.Ack)
		assert.Len(t, request.SetErrs, 1)

		_, err = large.parsePoll("application/json", `this is not json`, largeID)
		assert.ErrorIs(t, err, ErrInvalidRequest)
	})

	t.Run("EmptyBodyNoContentType", func(t *testing.T) {
		request, err := h.parsePoll("", ``, id)
		require.NoError(t, err)

		assert.Equal(t, id, request.Stream.StreamID)
	})

	t.Run("PausedAndDisabledAccepted", func(t *testing.T) {
		for _, status := range []string{SSFStreamStatusPaused, SSFStreamStatusDisabled} {
			require.NoError(t, h.store.UpdateSSFStreamStatus(context.Background(), "a", id, status, ""))
			require.Equal(t, status, h.stored(t, "a", id).Status)

			_, err := h.parsePoll("application/json", `{}`, id)
			assert.NoError(t, err, status)
		}

		require.NoError(t, h.store.UpdateSSFStreamStatus(context.Background(), "a", id, SSFStreamStatusEnabled, ""))
	})

	t.Run("ShouldParse", func(t *testing.T) {
		accepted := []struct {
			name     string
			body     string
			expected SSFPollRequest
		}{
			{name: "ShouldMatchMemberNamesExactly", body: `{"maxEvents":1,"MAXEVENTS":5,"MaxEvents":7,"ACK":[null],"SetErrs":7,"ReturnImmediately":true}`, expected: SSFPollRequest{MaxEvents: new(1)}},
			{name: "ShouldTreatNullMembersAsAbsent", body: `{"maxEvents":null,"returnImmediately":null,"ack":null,"setErrs":null}`},
			{name: "ShouldIgnoreUnknownMembers", body: `{"other":{"a":[1,2]},"returnImmediately":false}`},
			{name: "ShouldAcceptEmptyAckAndSetErrs", body: `{"ack":[],"setErrs":{}}`, expected: SSFPollRequest{Ack: []string{}, SetErrs: map[string]SSFPollSetError{}}},
			{name: "ShouldAcceptSetErrWithoutDescription", body: `{"setErrs":{"x":{"err":"invalid_key"},"y":{"err":"invalid_state","description":null,"other":1}}}`, expected: SSFPollRequest{SetErrs: map[string]SSFPollSetError{"x": {Err: "invalid_key"}, "y": {Err: "invalid_state"}}}},
			{name: "ShouldAcceptEmptyDescription", body: `{"setErrs":{"x":{"err":"invalid_key","description":""}}}`, expected: SSFPollRequest{SetErrs: map[string]SSFPollSetError{"x": {Err: "invalid_key"}}}},
			{name: "ShouldAcceptSurroundingWhitespace", body: " \n{ \"maxEvents\" : 2 , \"ack\" : [ \"a\" ] }\n ", expected: SSFPollRequest{MaxEvents: new(2), Ack: []string{"a"}}},
		}

		for _, tc := range accepted {
			t.Run(tc.name, func(t *testing.T) {
				request, err := h.parsePoll("application/json", tc.body, id)
				require.NoError(t, err)

				assert.Equal(t, tc.expected.MaxEvents, request.MaxEvents)
				assert.Equal(t, tc.expected.ReturnImmediately, request.ReturnImmediately)
				assert.Equal(t, tc.expected.Ack, request.Ack)
				assert.Equal(t, tc.expected.SetErrs, request.SetErrs)
			})
		}
	})

	testCases := []struct {
		name        string
		client      string
		method      string
		contentType string
		body        string
		streamID    string
		status      int
		err         string
		allow       string
	}{
		{"NegativeMaxEvents", "a", http.MethodPost, "application/json", `{"maxEvents":-1}`, id, http.StatusBadRequest, "invalid_request", ""},
		{"FractionalMaxEvents", "a", http.MethodPost, "application/json", `{"maxEvents":1.5}`, id, http.StatusBadRequest, "invalid_request", ""},
		{"StringMaxEvents", "a", http.MethodPost, "application/json", `{"maxEvents":"1"}`, id, http.StatusBadRequest, "invalid_request", ""},
		{"OverflowingMaxEvents", "a", http.MethodPost, "application/json", `{"maxEvents":99999999999999999999}`, id, http.StatusBadRequest, "invalid_request", ""},
		{"StringReturnImmediately", "a", http.MethodPost, "application/json", `{"returnImmediately":"true"}`, id, http.StatusBadRequest, "invalid_request", ""},
		{"NumberReturnImmediately", "a", http.MethodPost, "application/json", `{"returnImmediately":1}`, id, http.StatusBadRequest, "invalid_request", ""},
		{"NullAck", "a", http.MethodPost, "application/json", `{"ack":[null]}`, id, http.StatusBadRequest, "invalid_request", ""},
		{"EmptyAck", "a", http.MethodPost, "application/json", `{"ack":[""]}`, id, http.StatusBadRequest, "invalid_request", ""},
		{"NumberAck", "a", http.MethodPost, "application/json", `{"ack":["a",1]}`, id, http.StatusBadRequest, "invalid_request", ""},
		{"ObjectAck", "a", http.MethodPost, "application/json", `{"ack":{"a":"b"}}`, id, http.StatusBadRequest, "invalid_request", ""},
		{"ArraySetErrs", "a", http.MethodPost, "application/json", `{"setErrs":[]}`, id, http.StatusBadRequest, "invalid_request", ""},
		{"EmptySetErr", "a", http.MethodPost, "application/json", `{"setErrs":{"x":{}}}`, id, http.StatusBadRequest, "invalid_request", ""},
		{"NullSetErr", "a", http.MethodPost, "application/json", `{"setErrs":{"x":null}}`, id, http.StatusBadRequest, "invalid_request", ""},
		{"StringSetErr", "a", http.MethodPost, "application/json", `{"setErrs":{"x":"invalid_key"}}`, id, http.StatusBadRequest, "invalid_request", ""},
		{"EmptySetErrCode", "a", http.MethodPost, "application/json", `{"setErrs":{"x":{"err":"","description":"d"}}}`, id, http.StatusBadRequest, "invalid_request", ""},
		{"NullSetErrCode", "a", http.MethodPost, "application/json", `{"setErrs":{"x":{"err":null,"description":"d"}}}`, id, http.StatusBadRequest, "invalid_request", ""},
		{"NumberSetErrCode", "a", http.MethodPost, "application/json", `{"setErrs":{"x":{"err":5}}}`, id, http.StatusBadRequest, "invalid_request", ""},
		{"NumberSetErrDescription", "a", http.MethodPost, "application/json", `{"setErrs":{"x":{"err":"invalid_key","description":5}}}`, id, http.StatusBadRequest, "invalid_request", ""},
		{"CaseFoldedSetErrCode", "a", http.MethodPost, "application/json", `{"setErrs":{"x":{"ERR":"invalid_key"}}}`, id, http.StatusBadRequest, "invalid_request", ""},
		{"EmptySetErrKey", "a", http.MethodPost, "application/json", `{"setErrs":{"":{"err":"invalid_key","description":"d"}}}`, id, http.StatusBadRequest, "invalid_request", ""},
		{"RepeatedSetErrKey", "a", http.MethodPost, "application/json", `{"setErrs":{"x":{"err":"invalid_key"},"x":{"err":"invalid_issuer"}}}`, id, http.StatusBadRequest, "invalid_request", ""},
		{"RepeatedMember", "a", http.MethodPost, "application/json", `{"maxEvents":1,"maxEvents":5}`, id, http.StatusBadRequest, "invalid_request", ""},
		{"RepeatedUnknownMember", "a", http.MethodPost, "application/json", `{"x":1,"x":2}`, id, http.StatusBadRequest, "invalid_request", ""},
		{"NullBody", "a", http.MethodPost, "application/json", `null`, id, http.StatusBadRequest, "invalid_request", ""},
		{"StringBody", "a", http.MethodPost, "application/json", `"x"`, id, http.StatusBadRequest, "invalid_request", ""},
		{"UnterminatedBody", "a", http.MethodPost, "application/json", `{"maxEvents":1`, id, http.StatusBadRequest, "invalid_request", ""},
		{"PushStream", "p", http.MethodPost, "application/json", `{}`, pushID, http.StatusBadRequest, "invalid_request", ""},
		{"Malformed", "a", http.MethodPost, "application/json", `{"ack":`, id, http.StatusBadRequest, "invalid_request", ""},
		{"NotAnObject", "a", http.MethodPost, "application/json", `[]`, id, http.StatusBadRequest, "invalid_request", ""},
		{"WrongTypes", "a", http.MethodPost, "application/json", `{"ack":"x"}`, id, http.StatusBadRequest, "invalid_request", ""},
		{"WrongContentType", "a", http.MethodPost, "text/plain", `{}`, id, http.StatusBadRequest, "invalid_request", ""},
		{"FormContentType", "a", http.MethodPost, "application/x-www-form-urlencoded", `maxEvents=1`, id, http.StatusBadRequest, "invalid_request", ""},
		{"BodyWithoutContentType", "a", http.MethodPost, "", `{}`, id, http.StatusBadRequest, "invalid_request", ""},
		{"Oversized", "a", http.MethodPost, "application/json", `{"ack":["` + strings.Repeat("a", 600) + `"]}`, id, http.StatusBadRequest, "invalid_request", ""},
		{"Trailing", "a", http.MethodPost, "application/json", `{} {}`, id, http.StatusBadRequest, "invalid_request", ""},
		{"OtherClientStream", "b", http.MethodPost, "application/json", `{}`, id, http.StatusNotFound, "invalid_request", ""},
		{"UnknownStream", "b", http.MethodPost, "application/json", `{}`, "nope", http.StatusNotFound, "invalid_request", ""},
		{"ReadScopeOnly", "a-ro", http.MethodPost, "application/json", `{}`, id, http.StatusForbidden, "access_denied", ""},
		{"NoCredential", "", http.MethodPost, "application/json", `{}`, id, http.StatusUnauthorized, "", ""},
		{"MethodGet", "a", http.MethodGet, "", ``, id, http.StatusMethodNotAllowed, "invalid_request", http.MethodPost},
		{"MethodPut", "a", http.MethodPut, "application/json", `{}`, id, http.StatusMethodNotAllowed, "invalid_request", http.MethodPost},
	}

	for _, tc := range testCases {
		t.Run("Reject"+tc.name, func(t *testing.T) {
			rw := h.doPoll(tc.client, tc.method, tc.contentType, tc.body, tc.streamID)

			assert.Equal(t, tc.status, rw.Code, rw.Body.String())
			assert.Equal(t, "no-store", rw.Header().Get("Cache-Control"))

			// RFC 6750 Section 3.1.
			if tc.err == "" {
				assert.Equal(t, "Bearer", rw.Header().Get("WWW-Authenticate"))
				assert.Empty(t, rw.Header().Get("Content-Type"))
				assert.Empty(t, rw.Body.Bytes())

				return
			}

			var got map[string]string

			require.NoError(t, json.Unmarshal(rw.Body.Bytes(), &got))
			assert.Equal(t, tc.err, got["err"])
			assert.NotEmpty(t, got["description"])
			assert.Equal(t, tc.allow, rw.Header().Get("Allow"))

			if tc.status == http.StatusUnauthorized || tc.status == http.StatusForbidden {
				assert.NotEmpty(t, rw.Header().Get("WWW-Authenticate"))
			}
		})
	}

	t.Run("OtherClientIdenticalToUnknown", func(t *testing.T) {
		other := h.doPoll("b", http.MethodPost, "application/json", `{}`, id)
		unknown := h.doPoll("b", http.MethodPost, "application/json", `{}`, "nope")

		assert.Equal(t, http.StatusNotFound, other.Code)
		assert.Equal(t, unknown.Code, other.Code)
		assert.Equal(t, unknown.Body.String(), other.Body.String())
	})
}

func TestSSFPollPolicy(t *testing.T) {
	h := newSSFHandlerHarness(t, nil)
	id := h.createStream(t, "a", `{}`)

	h.config.Policy = ssfHandlerPolicy{err: errors.New("operator disabled")}

	rw := h.doPoll("a", http.MethodPost, "application/json", `{"ack":["x"]}`, id)

	assert.Equal(t, http.StatusForbidden, rw.Code)
	assert.Contains(t, rw.Body.String(), `"err":"access_denied"`)
	assert.NotContains(t, rw.Body.String(), "operator disabled")
}

func TestSSFPollResponse(t *testing.T) {
	h := newSSFHandlerHarness(t, nil)

	testCases := []struct {
		name string
		sets map[string]string
		more bool
		want string
	}{
		{"Sets", map[string]string{"4d3559ec67504aaba65d40b0363faad8": "eyJhbGciOiJub25lIn0.e30."}, true, `{"sets":{"4d3559ec67504aaba65d40b0363faad8":"eyJhbGciOiJub25lIn0.e30."},"moreAvailable":true}`},
		{"SetsNoMore", map[string]string{"a": "b"}, false, `{"sets":{"a":"b"}}`},
		{"Empty", map[string]string{}, false, `{"sets":{}}`},
		{"Nil", nil, false, `{"sets":{}}`},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rw := httptest.NewRecorder()

			h.provider.WriteSSFPollResponse(context.Background(), rw, tc.sets, tc.more)

			assert.Equal(t, http.StatusOK, rw.Code)
			assert.JSONEq(t, tc.want, rw.Body.String())
			assert.Equal(t, "no-store", rw.Header().Get("Cache-Control"))
			assert.Equal(t, "no-cache", rw.Header().Get("Pragma"))
			assert.Equal(t, "application/json; charset=utf-8", rw.Header().Get("Content-Type"))
		})
	}
}
