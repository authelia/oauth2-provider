// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	. "authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/handler/rfc9449"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/testing/mock"
)

func TestWriteAccessResponse(t *testing.T) {
	testCases := []struct {
		name     string
		toMap    map[string]any
		expected map[string]any
		headers  http.Header
	}{
		{
			name:     "ShouldWriteEmptyResponse",
			toMap:    map[string]any{},
			expected: map[string]any{},
			headers: http.Header{
				consts.HeaderContentType:  []string{consts.ContentTypeApplicationJSON},
				consts.HeaderCacheControl: []string{consts.CacheControlNoStore},
				consts.HeaderPragma:       []string{consts.PragmaNoCache},
			},
		},
		{
			name: "ShouldWriteResponseWithStandardClaims",
			toMap: map[string]any{
				consts.AccessResponseAccessToken: "access-token-value",
				consts.AccessResponseTokenType:   "bearer",
				consts.AccessResponseExpiresIn:   3600,
			},
			expected: map[string]any{
				consts.AccessResponseAccessToken: "access-token-value",
				consts.AccessResponseTokenType:   "bearer",
				consts.AccessResponseExpiresIn:   float64(3600),
			},
			headers: http.Header{
				consts.HeaderContentType:  []string{consts.ContentTypeApplicationJSON},
				consts.HeaderCacheControl: []string{consts.CacheControlNoStore},
				consts.HeaderPragma:       []string{consts.PragmaNoCache},
			},
		},
		{
			name: "ShouldWriteResponseWithExtraFields",
			toMap: map[string]any{
				consts.AccessResponseAccessToken: "tok",
				"custom_field":                   "custom_value",
			},
			expected: map[string]any{
				consts.AccessResponseAccessToken: "tok",
				"custom_field":                   "custom_value",
			},
			headers: http.Header{
				consts.HeaderContentType:  []string{consts.ContentTypeApplicationJSON},
				consts.HeaderCacheControl: []string{consts.CacheControlNoStore},
				consts.HeaderPragma:       []string{consts.PragmaNoCache},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			provider := &Fosite{Config: new(Config)}
			requester := mock.NewMockAccessRequester(ctrl)
			responder := mock.NewMockAccessResponder(ctrl)

			responder.EXPECT().ToMap().Return(tc.toMap)

			rw := httptest.NewRecorder()
			provider.WriteAccessResponse(t.Context(), rw, requester, responder)

			assert.Equal(t, http.StatusOK, rw.Code)
			assert.Equal(t, tc.headers, rw.Header())

			actual := map[string]any{}
			require.NoError(t, json.NewDecoder(rw.Body).Decode(&actual))
			assert.Equal(t, tc.expected, actual)
		})
	}
}

func TestWriteAccessResponseMarshalError(t *testing.T) {
	testCases := []struct {
		name     string
		toMap    map[string]any
		contains string
	}{
		{
			name: "ShouldRespondInternalServerErrorWhenToMapNotMarshalable",
			toMap: map[string]any{
				// channels cannot be marshaled to JSON
				"bad": make(chan int),
			},
			contains: "json: unsupported type",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			provider := &Fosite{Config: &Config{SendDebugMessagesToClients: true}}
			requester := mock.NewMockAccessRequester(ctrl)
			responder := mock.NewMockAccessResponder(ctrl)

			responder.EXPECT().ToMap().Return(tc.toMap)

			rw := httptest.NewRecorder()
			provider.WriteAccessResponse(t.Context(), rw, requester, responder)

			assert.Equal(t, http.StatusInternalServerError, rw.Code)
			assert.Contains(t, rw.Body.String(), tc.contains)
		})
	}
}

func TestWriteAccessResponseRotatesDPoPNonce(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	store := storage.NewMemoryStore()
	strategy := rfc9449.NewDefaultStrategy(&Config{DPoPEnabled: true}, store)

	provider := &Fosite{Config: &Config{DPoPEnabled: true, DPoPStrategy: strategy}}

	session := &DefaultSession{}
	session.SetDPoPJWKThumbprint("some-thumbprint")

	requester := mock.NewMockAccessRequester(ctrl)
	requester.EXPECT().GetSession().AnyTimes().Return(session)

	responder := mock.NewMockAccessResponder(ctrl)
	responder.EXPECT().ToMap().Return(map[string]any{})

	rw := httptest.NewRecorder()
	provider.WriteAccessResponse(t.Context(), rw, requester, responder)

	assert.NotEmpty(t, rw.Header().Get(consts.HeaderDPoPNonce))
}

func TestWriteAccessResponseDoesNotRotateDPoPNonceWhenSessionNotBound(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	store := storage.NewMemoryStore()
	strategy := rfc9449.NewDefaultStrategy(&Config{DPoPEnabled: true}, store)

	provider := &Fosite{Config: &Config{DPoPEnabled: true, DPoPStrategy: strategy}}

	requester := mock.NewMockAccessRequester(ctrl)
	requester.EXPECT().GetSession().AnyTimes().Return(&DefaultSession{})

	responder := mock.NewMockAccessResponder(ctrl)
	responder.EXPECT().ToMap().Return(map[string]any{})

	rw := httptest.NewRecorder()
	provider.WriteAccessResponse(t.Context(), rw, requester, responder)

	assert.Empty(t, rw.Header().Get(consts.HeaderDPoPNonce))
}

func TestWriteAccessResponseDoesNotRotateDPoPNonceWhenDisabled(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	store := storage.NewMemoryStore()
	strategy := rfc9449.NewDefaultStrategy(&Config{DPoPEnabled: true}, store)

	provider := &Fosite{Config: &Config{DPoPEnabled: false, DPoPStrategy: strategy}}

	session := &DefaultSession{}
	session.SetDPoPJWKThumbprint("some-thumbprint")

	requester := mock.NewMockAccessRequester(ctrl)
	requester.EXPECT().GetSession().AnyTimes().Return(session)

	responder := mock.NewMockAccessResponder(ctrl)
	responder.EXPECT().ToMap().Return(map[string]any{})

	rw := httptest.NewRecorder()
	provider.WriteAccessResponse(t.Context(), rw, requester, responder)

	assert.Empty(t, rw.Header().Get(consts.HeaderDPoPNonce))
}
