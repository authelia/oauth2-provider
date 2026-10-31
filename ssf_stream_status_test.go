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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	. "authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/token/jwt"
)

const ssfStatusURL = "https://ssf.example.com/ssf/status"

func (h *ssfHandlerHarness) doStatus(t *testing.T, client, method, target, contentType, body string) *httptest.ResponseRecorder {
	t.Helper()

	r := httptest.NewRequest(method, target, strings.NewReader(body))
	r.Header.Set(consts.HeaderAuthorization, "Bearer tok-"+client)

	if contentType != "" {
		r.Header.Set(consts.HeaderContentType, contentType)
	}

	ctx := context.Background()
	rw := httptest.NewRecorder()

	requester, err := h.provider.NewSSFStreamStatusRequest(ctx, r, &DefaultSession{})
	if err != nil {
		h.provider.WriteSSFError(ctx, rw, r, err)

		return rw
	}

	responder, err := h.provider.NewSSFStreamStatusResponse(ctx, requester)
	if err != nil {
		h.provider.WriteSSFError(ctx, rw, r, err)

		return rw
	}

	h.provider.WriteSSFStreamStatusResponse(ctx, rw, requester, responder)

	return rw
}

func TestSSFStreamStatus(t *testing.T) {
	h := newSSFHandlerHarness(t, nil)
	id := h.createStream(t, "a", `{"events_requested":["`+ssfEventSessionRev+`"]}`)

	// A read-only token resolves to the client 'r-ro', so its stream is stored directly.
	roID := "ro-stream"
	require.NoError(t, h.store.CreateSSFStream(context.Background(), &SSFStream{StreamID: roID, ClientID: "r-ro", Status: SSFStreamStatusPaused, StatusReason: "held"}))

	notFound := h.doStatus(t, "b", http.MethodGet, ssfStatusURL+"?stream_id="+id, "", "")
	unknown := h.doStatus(t, "b", http.MethodGet, ssfStatusURL+"?stream_id=nope", "", "")

	assert.Equal(t, http.StatusNotFound, notFound.Code)
	assert.Equal(t, unknown.Code, notFound.Code)
	assert.Equal(t, unknown.Body.String(), notFound.Body.String())

	t.Run("ReadMissingStreamID", func(t *testing.T) {
		rw := h.doStatus(t, "r-ro", http.MethodGet, ssfStatusURL, "", "")
		assert.Equal(t, http.StatusBadRequest, rw.Code)
		assert.Contains(t, rw.Body.String(), "invalid_request")
		assert.Equal(t, "no-store", rw.Header().Get("Cache-Control"))
	})

	t.Run("ReadDefaultsEnabled", func(t *testing.T) {
		rw := h.doStatus(t, "a", http.MethodGet, ssfStatusURL+"?stream_id="+id, "", "")
		require.Equal(t, http.StatusOK, rw.Code, rw.Body.String())
		assert.JSONEq(t, `{"stream_id":"`+id+`","status":"enabled"}`, rw.Body.String())
		assert.Equal(t, "no-store", rw.Header().Get("Cache-Control"))
		assert.Equal(t, "application/json; charset=utf-8", rw.Header().Get("Content-Type"))
	})

	t.Run("ReadNeedsOnlyRead", func(t *testing.T) {
		rw := h.doStatus(t, "r-ro", http.MethodGet, ssfStatusURL+"?stream_id="+roID, "", "")
		require.Equal(t, http.StatusOK, rw.Code, rw.Body.String())
		assert.JSONEq(t, `{"stream_id":"`+roID+`","status":"paused","reason":"held"}`, rw.Body.String())
	})

	t.Run("UpdateNeedsManage", func(t *testing.T) {
		rw := h.doStatus(t, "a-ro", http.MethodPost, ssfStatusURL, "application/json", `{"stream_id":"`+id+`","status":"paused"}`)
		assert.Equal(t, http.StatusForbidden, rw.Code)
		assert.Contains(t, rw.Body.String(), "insufficient_scope")
		assert.Equal(t, "enabled", h.stored(t, "a", id).Status)
	})

	t.Run("UpdatePersistsAndPauses", func(t *testing.T) {
		assert.True(t, h.stored(t, "a", id).Accepts(ssfEventSessionRev))

		rw := h.doStatus(t, "a", http.MethodPost, ssfStatusURL, "application/json", `{"stream_id":"`+id+`","status":"paused","reason":"maintenance"}`)
		require.Equal(t, http.StatusOK, rw.Code, rw.Body.String())
		assert.JSONEq(t, `{"stream_id":"`+id+`","status":"paused","reason":"maintenance"}`, rw.Body.String())

		stored := h.stored(t, "a", id)
		assert.Equal(t, "paused", stored.Status)
		assert.Equal(t, "maintenance", stored.StatusReason)
		assert.False(t, stored.Accepts(ssfEventSessionRev))

		rw = h.doStatus(t, "a", http.MethodGet, ssfStatusURL+"?stream_id="+id, "", "")
		assert.JSONEq(t, `{"stream_id":"`+id+`","status":"paused","reason":"maintenance"}`, rw.Body.String())
	})

	t.Run("UpdateWithoutReasonClearsIt", func(t *testing.T) {
		rw := h.doStatus(t, "a", http.MethodPost, ssfStatusURL, "application/json", `{"stream_id":"`+id+`","status":"enabled"}`)
		require.Equal(t, http.StatusOK, rw.Code, rw.Body.String())
		assert.JSONEq(t, `{"stream_id":"`+id+`","status":"enabled"}`, rw.Body.String())
		assert.Empty(t, h.stored(t, "a", id).StatusReason)
	})

	t.Run("UpdateKeepsConfiguration", func(t *testing.T) {
		before := h.stored(t, "a", id)

		rw := h.doStatus(t, "a", http.MethodPost, ssfStatusURL, "application/json", `{"stream_id":"`+id+`","status":"disabled"}`)
		require.Equal(t, http.StatusOK, rw.Code)

		after := h.stored(t, "a", id)
		assert.Equal(t, before.Delivery, after.Delivery)
		assert.Equal(t, before.EventsDelivered, after.EventsDelivered)
		assert.Equal(t, "disabled", after.Status)
	})
}

func TestSSFStreamStatusPolicy(t *testing.T) {
	h := newSSFHandlerHarness(t, nil)
	id := h.createStream(t, "a", `{"description":"d"}`)

	h.config.Policy = ssfHandlerPolicy{err: errors.New("operator disabled")}

	t.Run("ShouldDenyUpdateOnPolicyError", func(t *testing.T) {
		rw := h.doStatus(t, "a", http.MethodPost, ssfStatusURL, "application/json", `{"stream_id":"`+id+`","status":"paused"}`)
		assert.Equal(t, http.StatusForbidden, rw.Code)
		assert.Contains(t, rw.Body.String(), `"error":"access_denied"`)
		assert.NotContains(t, rw.Body.String(), "operator disabled")
		assert.Equal(t, SSFStreamStatusEnabled, h.stored(t, "a", id).Status)
	})

	t.Run("ShouldNotRevealAnotherClientsStream", func(t *testing.T) {
		rw := h.doStatus(t, "b", http.MethodPost, ssfStatusURL, "application/json", `{"stream_id":"`+id+`","status":"paused"}`)
		assert.Equal(t, http.StatusNotFound, rw.Code)
	})

	t.Run("ShouldReadDespitePolicyError", func(t *testing.T) {
		rw := h.doStatus(t, "a", http.MethodGet, ssfStatusURL+"?stream_id="+id, "", "")
		assert.Equal(t, http.StatusOK, rw.Code)
	})

	t.Run("ShouldFailOnMissingPolicy", func(t *testing.T) {
		h.config.Policy = nil

		rw := h.doStatus(t, "a", http.MethodPost, ssfStatusURL, "application/json", `{"stream_id":"`+id+`","status":"paused"}`)
		assert.Equal(t, http.StatusInternalServerError, rw.Code)
		assert.Equal(t, SSFStreamStatusEnabled, h.stored(t, "a", id).Status)
	})
}

func TestSSFStreamStatusRejects(t *testing.T) {
	h := newSSFHandlerHarness(t, nil)
	id := h.createStream(t, "a", `{}`)

	testCases := []struct {
		name        string
		client      string
		method      string
		target      string
		contentType string
		body        string
		code        int
		err         string
	}{
		{"UnknownStatus", "a", http.MethodPost, ssfStatusURL, "application/json", `{"stream_id":"` + id + `","status":"gone"}`, http.StatusBadRequest, "invalid_request"},
		{"MissingStatus", "a", http.MethodPost, ssfStatusURL, "application/json", `{"stream_id":"` + id + `"}`, http.StatusBadRequest, "invalid_request"},
		{"MissingStreamID", "a", http.MethodPost, ssfStatusURL, "application/json", `{"status":"paused"}`, http.StatusBadRequest, "invalid_request"},
		{"WrongContentType", "a", http.MethodPost, ssfStatusURL, "text/plain", `{"stream_id":"` + id + `","status":"paused"}`, http.StatusBadRequest, "invalid_request"},
		{"MalformedBody", "a", http.MethodPost, ssfStatusURL, "application/json", `{`, http.StatusBadRequest, "invalid_request"},
		{"OversizeBody", "a", http.MethodPost, ssfStatusURL, "application/json", `{"stream_id":"` + id + `","status":"paused","reason":"` + strings.Repeat("x", 600) + `"}`, http.StatusBadRequest, "invalid_request"},
		{"ForeignStream", "b", http.MethodPost, ssfStatusURL, "application/json", `{"stream_id":"` + id + `","status":"paused"}`, http.StatusNotFound, "not_found"},
		{"UnknownStream", "b", http.MethodPost, ssfStatusURL, "application/json", `{"stream_id":"nope","status":"paused"}`, http.StatusNotFound, "not_found"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rw := h.doStatus(t, tc.client, tc.method, tc.target, tc.contentType, tc.body)

			assert.Equal(t, tc.code, rw.Code, rw.Body.String())
			assert.Contains(t, rw.Body.String(), `"error":"`+tc.err+`"`)
			assert.Equal(t, "no-store", rw.Header().Get("Cache-Control"))
			assert.Equal(t, "enabled", h.stored(t, "a", id).Status)
		})
	}

	foreign := h.doStatus(t, "b", http.MethodPost, ssfStatusURL, "application/json", `{"stream_id":"`+id+`","status":"paused"}`)
	unknown := h.doStatus(t, "b", http.MethodPost, ssfStatusURL, "application/json", `{"stream_id":"nope","status":"paused"}`)
	assert.Equal(t, unknown.Body.String(), foreign.Body.String())
}

func TestSSFStreamStatusMethods(t *testing.T) {
	for _, method := range []string{http.MethodHead, http.MethodOptions, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		t.Run(method, func(t *testing.T) {
			h := newSSFHandlerHarness(t, nil)

			rw := h.doStatus(t, "a", method, ssfStatusURL, "application/json", `{}`)
			assert.Equal(t, http.StatusMethodNotAllowed, rw.Code)
			assert.Equal(t, "GET, POST", rw.Header().Get("Allow"))
			assert.Equal(t, "no-store", rw.Header().Get("Cache-Control"))
			assert.Contains(t, rw.Body.String(), `"error":"invalid_request"`)
		})
	}

	t.Run("ConfigurationEndpointKeepsItsMethods", func(t *testing.T) {
		h := newSSFHandlerHarness(t, nil)

		rw := h.do(t, "a", http.MethodHead, ssfHandlerURL, "", "")
		assert.Equal(t, http.StatusMethodNotAllowed, rw.Code)
		assert.Equal(t, "GET, POST, PUT, PATCH, DELETE", rw.Header().Get("Allow"))
	})
}

func TestSSFStreamStatusUnauthorized(t *testing.T) {
	h := newSSFHandlerHarness(t, nil)

	r := httptest.NewRequest(http.MethodGet, ssfStatusURL+"?stream_id=x", nil)

	_, err := h.provider.NewSSFStreamStatusRequest(context.Background(), r, &DefaultSession{})
	require.Error(t, err)

	rw := httptest.NewRecorder()
	h.provider.WriteSSFError(context.Background(), rw, r, err)

	assert.Equal(t, http.StatusUnauthorized, rw.Code)
	assert.NotEmpty(t, rw.Header().Get("WWW-Authenticate"))
}

func TestSSFStreamStatusMisbehavingStore(t *testing.T) {
	h := newSSFHandlerHarness(t, nil)
	h.provider.Store = ssfMisbehavingStore{h.store.MemoryStore}

	for _, tc := range []struct{ name, method, target, body string }{
		{"Read", http.MethodGet, ssfStatusURL + "?stream_id=x", ""},
		{"ReadNil", http.MethodGet, ssfStatusURL + "?stream_id=nil", ""},
		{"Update", http.MethodPost, ssfStatusURL, `{"stream_id":"x","status":"paused"}`},
		{"UpdateNil", http.MethodPost, ssfStatusURL, `{"stream_id":"nil","status":"paused"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rw := h.doStatus(t, "a", tc.method, tc.target, "application/json", tc.body)
			assert.Equal(t, http.StatusNotFound, rw.Code)
			assert.Contains(t, rw.Body.String(), `"error":"not_found"`)
		})
	}
}

func TestNewSSFStreamUpdatedEvent(t *testing.T) {
	event := NewSSFStreamUpdatedEvent("paused", "maintenance")
	require.NotNil(t, event)
	assert.Equal(t, &jwt.SSFStreamUpdated{Status: "paused", Reason: "maintenance"}, event)
	assert.NoError(t, event.Validate())

	data, err := json.Marshal(NewSSFStreamUpdatedEvent("disabled", ""))
	require.NoError(t, err)
	assert.JSONEq(t, `{"status":"disabled"}`, string(data))
}
