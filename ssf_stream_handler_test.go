// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	. "authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/testing/mock"
)

const (
	ssfHandlerAudience = "https://ssf.example.com/ssf"
	ssfHandlerURL      = "https://ssf.example.com/ssf/stream"
	ssfHandlerSecret   = "Bearer rx-secret-value"
	ssfEventSessionRev = "https://schemas.openid.net/secevent/caep/event-type/session-revoked"
	ssfEventCredChange = "https://schemas.openid.net/secevent/caep/event-type/credential-change"
	ssfEventOther      = "https://schemas.openid.net/secevent/caep/event-type/other"
)

type ssfHandlerPolicy struct {
	policy *SSFClientPolicy
	err    error
}

func (p ssfHandlerPolicy) SSFStreamPolicy(ctx context.Context, client Client) (*SSFClientPolicy, error) {
	return p.policy, p.err
}

type ssfHandlerValidator struct{ err error }

func (v ssfHandlerValidator) ValidateSSFEndpoint(ctx context.Context, client Client, endpoint *url.URL) error {
	return v.err
}

type ssfCountingStore struct {
	*storage.MemoryStore
	creates atomic.Int32
}

func (s *ssfCountingStore) CreateSSFStream(ctx context.Context, stream *SSFStream) error {
	s.creates.Add(1)

	return s.MemoryStore.CreateSSFStream(ctx, stream)
}

type ssfHandlerHarness struct {
	provider *Fosite
	store    *ssfCountingStore
	config   *SSFConfig
}

func newSSFHandlerHarness(t *testing.T, mutate func(c *SSFConfig)) *ssfHandlerHarness {
	t.Helper()

	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	introspector := mock.NewMockTokenIntrospector(ctrl)
	introspector.EXPECT().IntrospectToken(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
		Do(func(_ context.Context, token string, _ TokenUse, requester AccessRequester, _ []string) {
			ar := requester.(*AccessRequest)
			ar.GrantedScope = []string{consts.ScopeSSFManage}

			if strings.HasSuffix(token, "-ro") {
				ar.GrantedScope = []string{consts.ScopeSSFRead}
			}

			ar.GrantedAudience = []string{ssfHandlerAudience}
			ar.Client = &DefaultClient{ID: strings.TrimPrefix(token, "tok-")}
		}).Return(AccessToken, nil).AnyTimes()

	config := &SSFConfig{
		Issuer:   "https://ssf.example.com",
		Audience: ssfHandlerAudience,
		Policy: ssfHandlerPolicy{policy: &SSFClientPolicy{
			Audience:        []string{"https://rx.example.com"},
			EventsSupported: []string{ssfEventSessionRev, ssfEventCredChange},
			DeliveryMethods: []string{SSFDeliveryMethodPush, SSFDeliveryMethodPoll},
		}},
		EndpointValidator: ssfHandlerValidator{},
		PollEndpointURL: func(ctx context.Context, streamID string) (string, error) {
			return "https://ssf.example.com/ssf/poll/" + streamID, nil
		},
		MinVerificationInterval: 0,
		MaxRequestBytes:         512,
	}

	if mutate != nil {
		mutate(config)
	}

	store := &ssfCountingStore{MemoryStore: storage.NewMemoryStore()}

	return &ssfHandlerHarness{
		provider: &Fosite{Store: store, Config: &Config{SSF: config, TokenIntrospectionHandlers: TokenIntrospectionHandlers{introspector}}},
		store:    store,
		config:   config,
	}
}

func (h *ssfHandlerHarness) do(t *testing.T, client, method, target, contentType, body string) *httptest.ResponseRecorder {
	t.Helper()

	r := httptest.NewRequest(method, target, strings.NewReader(body))
	r.Header.Set(consts.HeaderAuthorization, "Bearer tok-"+client)

	if contentType != "" {
		r.Header.Set(consts.HeaderContentType, contentType)
	}

	ctx := context.Background()
	rw := httptest.NewRecorder()

	requester, err := h.provider.NewSSFStreamRequest(ctx, r, &DefaultSession{})
	if err != nil {
		h.provider.WriteSSFError(ctx, rw, r, err)

		return rw
	}

	responder, err := h.provider.NewSSFStreamResponse(ctx, requester)
	if err != nil {
		h.provider.WriteSSFError(ctx, rw, r, err)

		return rw
	}

	h.provider.WriteSSFStreamResponse(ctx, rw, requester, responder)

	return rw
}

func TestSSFStreamHandlerCreate(t *testing.T) {
	t.Run("ShouldCreatePollStreamByDefault", func(t *testing.T) {
		h := newSSFHandlerHarness(t, nil)

		rw := h.do(t, "a", http.MethodPost, ssfHandlerURL, "application/json",
			`{"events_requested":["`+ssfEventSessionRev+`","`+ssfEventOther+`"],"description":"d"}`)

		require.Equal(t, http.StatusCreated, rw.Code, rw.Body.String())
		assert.Equal(t, "no-store", rw.Header().Get("Cache-Control"))

		var got map[string]any
		require.NoError(t, json.Unmarshal(rw.Body.Bytes(), &got))

		id, _ := got["stream_id"].(string)
		assert.NotEmpty(t, id)
		assert.Equal(t, "https://ssf.example.com", got["iss"])
		assert.Equal(t, []any{"https://rx.example.com"}, got["aud"])
		assert.Equal(t, []any{ssfEventSessionRev}, got["events_delivered"])
		assert.Equal(t, []any{ssfEventSessionRev, ssfEventCredChange}, got["events_supported"])
		assert.Equal(t, map[string]any{"method": SSFDeliveryMethodPoll, "endpoint_url": "https://ssf.example.com/ssf/poll/" + id}, got["delivery"])
		assert.Equal(t, "d", got["description"])

		stored, err := h.store.GetSSFStream(context.Background(), "a", id)
		require.NoError(t, err)
		assert.Equal(t, SSFStreamStatusEnabled, stored.Status)
		assert.Equal(t, "a", stored.ClientID)
	})

	t.Run("ShouldIgnoreTransmitterSuppliedProperties", func(t *testing.T) {
		h := newSSFHandlerHarness(t, nil)

		rw := h.do(t, "a", http.MethodPost, ssfHandlerURL, "application/json",
			`{"iss":"https://evil.example.com","aud":["x"],"stream_id":"chosen","events_delivered":["`+ssfEventOther+`"],"events_supported":["`+ssfEventOther+`"],"events_requested":["`+ssfEventCredChange+`"]}`)

		require.Equal(t, http.StatusCreated, rw.Code, rw.Body.String())

		var got map[string]any
		require.NoError(t, json.Unmarshal(rw.Body.Bytes(), &got))

		assert.NotEqual(t, "chosen", got["stream_id"])
		assert.Equal(t, "https://ssf.example.com", got["iss"])
		assert.Equal(t, []any{"https://rx.example.com"}, got["aud"])
		assert.Equal(t, []any{ssfEventCredChange}, got["events_delivered"])
	})

	t.Run("ShouldDefaultAudienceToClientID", func(t *testing.T) {
		h := newSSFHandlerHarness(t, func(c *SSFConfig) {
			c.Policy = ssfHandlerPolicy{policy: &SSFClientPolicy{DeliveryMethods: []string{SSFDeliveryMethodPoll}}}
		})

		rw := h.do(t, "a", http.MethodPost, ssfHandlerURL, "application/json", `{}`)
		require.Equal(t, http.StatusCreated, rw.Code, rw.Body.String())
		assert.Contains(t, rw.Body.String(), `"aud":["a"]`)
		assert.Contains(t, rw.Body.String(), `"events_delivered":[]`)
	})

	t.Run("ShouldCreatePushStreamWithoutLeakingSecret", func(t *testing.T) {
		h := newSSFHandlerHarness(t, nil)

		rw := h.do(t, "a", http.MethodPost, ssfHandlerURL, "application/json",
			`{"delivery":{"method":"`+SSFDeliveryMethodPush+`","endpoint_url":"https://rx.example.com/push","authorization_header":"`+ssfHandlerSecret+`"}}`)

		require.Equal(t, http.StatusCreated, rw.Code, rw.Body.String())
		assert.NotContains(t, rw.Body.String(), ssfHandlerSecret)
		assert.NotContains(t, rw.Body.String(), "authorization_header")

		list, err := h.store.ListSSFStreams(context.Background(), "a")
		require.NoError(t, err)
		require.Len(t, list, 1)
		assert.Equal(t, ssfHandlerSecret, list[0].Delivery.AuthorizationHeader)
		assert.Equal(t, "https://rx.example.com/push", list[0].Delivery.EndpointURL)
	})

	t.Run("ShouldIgnoreReceiverSuppliedPollEndpoint", func(t *testing.T) {
		h := newSSFHandlerHarness(t, nil)

		rw := h.do(t, "a", http.MethodPost, ssfHandlerURL, "application/json",
			`{"delivery":{"method":"`+SSFDeliveryMethodPoll+`","endpoint_url":"https://evil.example.com/x","authorization_header":"`+ssfHandlerSecret+`"}}`)

		require.Equal(t, http.StatusCreated, rw.Code, rw.Body.String())
		assert.NotContains(t, rw.Body.String(), "evil.example.com")

		list, err := h.store.ListSSFStreams(context.Background(), "a")
		require.NoError(t, err)
		require.Len(t, list, 1)
		assert.Empty(t, list[0].Delivery.AuthorizationHeader)
	})

	t.Run("ShouldConflictOnSecondCreate", func(t *testing.T) {
		h := newSSFHandlerHarness(t, nil)

		require.Equal(t, http.StatusCreated, h.do(t, "a", http.MethodPost, ssfHandlerURL, "application/json", `{}`).Code)

		rw := h.do(t, "a", http.MethodPost, ssfHandlerURL, "application/json", `{}`)
		assert.Equal(t, http.StatusConflict, rw.Code)
		assert.Contains(t, rw.Body.String(), ErrSSFStreamConflict.ErrorField)

		assert.Equal(t, http.StatusCreated, h.do(t, "b", http.MethodPost, ssfHandlerURL, "application/json", `{}`).Code)
	})
}

func TestSSFStreamHandlerCreateRequiresIssuer(t *testing.T) {
	h := newSSFHandlerHarness(t, func(c *SSFConfig) { c.Issuer = "" })

	rw := h.do(t, "a", http.MethodPost, ssfHandlerURL, "application/json", `{}`)
	assert.Equal(t, http.StatusInternalServerError, rw.Code)
	assert.Contains(t, rw.Body.String(), `"error":"server_error"`)
	assert.Zero(t, h.store.creates.Load())
}

func TestSSFStreamHandlerCreateRejectsInvalidIssuer(t *testing.T) {
	for _, issuer := range []string{"http://ssf.example.com", "https://ssf.example.com?x=1", "https://ssf.example.com#x"} {
		t.Run(issuer, func(t *testing.T) {
			h := newSSFHandlerHarness(t, func(c *SSFConfig) { c.Issuer = issuer })

			rw := h.do(t, "a", http.MethodPost, ssfHandlerURL, "application/json", `{}`)
			assert.Equal(t, http.StatusInternalServerError, rw.Code)
			assert.Contains(t, rw.Body.String(), `"error":"server_error"`)
			assert.Zero(t, h.store.creates.Load())
		})
	}
}

type ssfFailingStore struct{ *storage.MemoryStore }

var errSSFDriver = errors.New("driver failure with secret dsn")

func (ssfFailingStore) CreateSSFStream(context.Context, *SSFStream) error { return errSSFDriver }

func (ssfFailingStore) ListSSFStreams(context.Context, string) ([]*SSFStream, error) {
	return nil, errSSFDriver
}

func (ssfFailingStore) GetSSFStream(context.Context, string, string) (*SSFStream, error) {
	return nil, errSSFDriver
}

func (ssfFailingStore) DeleteSSFStream(context.Context, string, string) error { return errSSFDriver }

func TestSSFStreamInvalidStoredIssuer(t *testing.T) {
	const bad = "http://old.example.com?x=1"

	newStream := func(t *testing.T, h *ssfHandlerHarness) string {
		t.Helper()

		id := h.createStream(t, "a", `{"description":"d"}`)

		stream := h.stored(t, "a", id).Clone()
		stream.Issuer = bad

		require.NoError(t, h.store.UpdateSSFStream(context.Background(), stream))

		return id
	}

	t.Run("ShouldReportConfiguredIssuer", func(t *testing.T) {
		h := newSSFHandlerHarness(t, nil)
		id := newStream(t, h)

		rw := h.do(t, "a", http.MethodGet, ssfHandlerURL+"?stream_id="+id, "", "")
		require.Equal(t, http.StatusOK, rw.Code)
		assert.Contains(t, rw.Body.String(), `"iss":"https://ssf.example.com"`)
		assert.Equal(t, bad, h.stored(t, "a", id).Issuer)
	})

	t.Run("ShouldPersistConfiguredIssuerOnUpdate", func(t *testing.T) {
		h := newSSFHandlerHarness(t, nil)
		id := newStream(t, h)

		rw := h.do(t, "a", http.MethodPatch, ssfHandlerURL, "application/json", `{"stream_id":"`+id+`","iss":"https://ssf.example.com","description":"new"}`)
		require.Equal(t, http.StatusOK, rw.Code)
		assert.Equal(t, "https://ssf.example.com", h.stored(t, "a", id).Issuer)
	})

	t.Run("ShouldKeepValidStoredIssuer", func(t *testing.T) {
		h := newSSFHandlerHarness(t, nil)
		id := h.createStream(t, "a", `{}`)

		h.config.Issuer = "https://new.example.com"

		rw := h.do(t, "a", http.MethodGet, ssfHandlerURL+"?stream_id="+id, "", "")
		require.Equal(t, http.StatusOK, rw.Code)
		assert.Contains(t, rw.Body.String(), `"iss":"https://ssf.example.com"`)
	})
}

func TestSSFStreamHandlerStorageFailure(t *testing.T) {
	h := newSSFHandlerHarness(t, nil)
	h.provider.Store = ssfFailingStore{h.store.MemoryStore}

	testCases := []struct {
		name, method, target, contentType, body string
	}{
		{"Create", http.MethodPost, ssfHandlerURL, "application/json", `{}`},
		{"List", http.MethodGet, ssfHandlerURL, "", ""},
		{"Get", http.MethodGet, ssfHandlerURL + "?stream_id=x", "", ""},
		{"Delete", http.MethodDelete, ssfHandlerURL + "?stream_id=x", "", ""},
		{"Update", http.MethodPatch, ssfHandlerURL, "application/json", `{"stream_id":"x"}`},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rw := h.do(t, "a", tc.method, tc.target, tc.contentType, tc.body)
			assert.Equal(t, http.StatusInternalServerError, rw.Code)
			assert.Contains(t, rw.Body.String(), `"error":"server_error"`)
			assert.NotContains(t, rw.Body.String(), "secret dsn")
		})
	}
}

func TestSSFMinVerificationInterval(t *testing.T) {
	testCases := []struct {
		name     string
		interval time.Duration
		expected float64
	}{
		{"ShouldKeepWholeSeconds", time.Minute, 60},
		{"ShouldRoundUpSubSecond", 500 * time.Millisecond, 1},
		{"ShouldRoundUpFraction", 1500 * time.Millisecond, 2},
		{"ShouldTreatNegativeAsDisabled", -time.Minute, 0},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			h := newSSFHandlerHarness(t, func(c *SSFConfig) { c.MinVerificationInterval = tc.interval })

			rw := h.do(t, "a", http.MethodPost, ssfHandlerURL, "application/json", `{}`)
			require.Equal(t, http.StatusCreated, rw.Code)

			var body map[string]any

			require.NoError(t, json.Unmarshal(rw.Body.Bytes(), &body))

			if tc.expected == 0 {
				assert.NotContains(t, body, "min_verification_interval")
			} else {
				assert.Equal(t, tc.expected, body["min_verification_interval"])
			}
		})
	}

	t.Run("ShouldReportAndAcceptChangedConfiguration", func(t *testing.T) {
		h := newSSFHandlerHarness(t, nil)
		id := h.createStream(t, "a", `{}`)

		h.config.MinVerificationInterval = time.Hour

		rw := h.do(t, "a", http.MethodGet, ssfHandlerURL+"?stream_id="+id, "", "")
		require.Equal(t, http.StatusOK, rw.Code)
		assert.Contains(t, rw.Body.String(), `"min_verification_interval":3600`)

		rw = h.do(t, "a", http.MethodPatch, ssfHandlerURL, "application/json", `{"stream_id":"`+id+`","min_verification_interval":3600}`)
		require.Equal(t, http.StatusOK, rw.Code)
		assert.Equal(t, 3600, h.stored(t, "a", id).MinVerificationInterval)
	})
}

func TestSSFStreamHandlerCreateRejects(t *testing.T) {
	push := `{"delivery":{"method":"` + SSFDeliveryMethodPush + `","endpoint_url":"https://rx.example.com/push"}}`

	testCases := []struct {
		name        string
		mutate      func(c *SSFConfig)
		contentType string
		body        string
		code        int
		errCode     string
		creates     int32
	}{
		{name: "ShouldRejectPushWithoutValidator", mutate: func(c *SSFConfig) { c.EndpointValidator = nil }, contentType: "application/json", body: push, code: http.StatusInternalServerError, errCode: "server_error"},
		{name: "ShouldRejectHTTPEndpoint", contentType: "application/json", body: `{"delivery":{"method":"` + SSFDeliveryMethodPush + `","endpoint_url":"http://rx.example.com/push"}}`, code: http.StatusBadRequest, errCode: "invalid_request"},
		{name: "ShouldRejectMissingEndpoint", contentType: "application/json", body: `{"delivery":{"method":"` + SSFDeliveryMethodPush + `"}}`, code: http.StatusBadRequest, errCode: "invalid_request"},
		{name: "ShouldRejectFragmentEndpoint", contentType: "application/json", body: `{"delivery":{"method":"` + SSFDeliveryMethodPush + `","endpoint_url":"https://rx.example.com/push#frag"}}`, code: http.StatusBadRequest, errCode: "invalid_request"},
		{name: "ShouldRejectCRLFAuthorizationHeader", contentType: "application/json", body: `{"delivery":{"method":"` + SSFDeliveryMethodPush + `","endpoint_url":"https://rx.example.com/push","authorization_header":"Bearer a\r\nX-Evil: 1"}}`, code: http.StatusBadRequest, errCode: "invalid_request"},
		{name: "ShouldRejectNULAuthorizationHeader", contentType: "application/json", body: `{"delivery":{"method":"` + SSFDeliveryMethodPush + `","endpoint_url":"https://rx.example.com/push","authorization_header":"Bearer a\u0000b"}}`, code: http.StatusBadRequest, errCode: "invalid_request"},
		{name: "ShouldRejectEmptyPollEndpoint", mutate: func(c *SSFConfig) {
			c.PollEndpointURL = func(ctx context.Context, streamID string) (string, error) { return "", nil }
		}, contentType: "application/json", body: `{}`, code: http.StatusInternalServerError, errCode: "server_error"},
		{name: "ShouldRejectEmptyAudienceElement", mutate: func(c *SSFConfig) {
			c.Policy = ssfHandlerPolicy{policy: &SSFClientPolicy{Audience: []string{"a", ""}, DeliveryMethods: []string{SSFDeliveryMethodPoll}}}
		}, contentType: "application/json", body: `{}`, code: http.StatusInternalServerError, errCode: "server_error"},
		{name: "ShouldRejectUserinfoEndpoint", contentType: "application/json", body: `{"delivery":{"method":"` + SSFDeliveryMethodPush + `","endpoint_url":"https://u:p@rx.example.com/push"}}`, code: http.StatusBadRequest, errCode: "invalid_request"},
		{name: "ShouldRejectValidatorError", mutate: func(c *SSFConfig) { c.EndpointValidator = ssfHandlerValidator{err: errors.New("private address")} }, contentType: "application/json", body: push, code: http.StatusBadRequest, errCode: "invalid_request"},
		{name: "ShouldRejectMethodOutsidePolicy", mutate: func(c *SSFConfig) {
			c.Policy = ssfHandlerPolicy{policy: &SSFClientPolicy{DeliveryMethods: []string{SSFDeliveryMethodPoll}}}
		}, contentType: "application/json", body: push, code: http.StatusBadRequest, errCode: "invalid_request"},
		{name: "ShouldRejectUnknownMethod", contentType: "application/json", body: `{"delivery":{"method":"urn:example:other"}}`, code: http.StatusBadRequest, errCode: "invalid_request"},
		{name: "ShouldRejectEmptyMethod", contentType: "application/json", body: `{"delivery":{}}`, code: http.StatusBadRequest, errCode: "invalid_request"},
		{name: "ShouldDenyOnPolicyError", mutate: func(c *SSFConfig) { c.Policy = ssfHandlerPolicy{err: errors.New("denied")} }, contentType: "application/json", body: `{}`, code: http.StatusForbidden, errCode: "access_denied"},
		{name: "ShouldFailWithoutPolicy", mutate: func(c *SSFConfig) { c.Policy = nil }, contentType: "application/json", body: `{}`, code: http.StatusInternalServerError, errCode: "server_error"},
		{name: "ShouldFailWithoutPollEndpointFunc", mutate: func(c *SSFConfig) { c.PollEndpointURL = nil }, contentType: "application/json", body: `{}`, code: http.StatusInternalServerError, errCode: "server_error"},
		{name: "ShouldRejectWrongContentType", contentType: "text/plain", body: `{}`, code: http.StatusBadRequest, errCode: "invalid_request"},
		{name: "ShouldRejectMissingContentType", body: `{}`, code: http.StatusBadRequest, errCode: "invalid_request"},
		{name: "ShouldRejectMalformedJSON", contentType: "application/json", body: `{"description":`, code: http.StatusBadRequest, errCode: "invalid_request"},
		{name: "ShouldRejectNullBody", contentType: "application/json", body: `null`, code: http.StatusBadRequest, errCode: "invalid_request"},
		{name: "ShouldRejectTrailingData", contentType: "application/json", body: `{} {}`, code: http.StatusBadRequest, errCode: "invalid_request"},
		{name: "ShouldRejectOversizeBody", contentType: "application/json", body: `{"description":"` + strings.Repeat("a", 600) + `"}`, code: http.StatusBadRequest, errCode: "invalid_request"},
		{name: "ShouldNotTruncateOversizeIntoValidJSON", mutate: func(c *SSFConfig) { c.MaxRequestBytes = 2 }, contentType: "application/json", body: "{}    ", code: http.StatusBadRequest, errCode: "invalid_request"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			h := newSSFHandlerHarness(t, tc.mutate)

			rw := h.do(t, "a", http.MethodPost, ssfHandlerURL, tc.contentType, tc.body)

			assert.Equal(t, tc.code, rw.Code, rw.Body.String())
			assert.Equal(t, "no-store", rw.Header().Get("Cache-Control"))

			var got map[string]any
			require.NoError(t, json.Unmarshal(rw.Body.Bytes(), &got))
			assert.Equal(t, tc.errCode, got["error"])
			assert.NotContains(t, rw.Body.String(), "private address")

			assert.EqualValues(t, tc.creates, h.store.creates.Load())

			list, err := h.store.ListSSFStreams(context.Background(), "a")
			require.NoError(t, err)
			assert.Empty(t, list)
		})
	}
}

func TestSSFStreamHandlerReadAndDelete(t *testing.T) {
	h := newSSFHandlerHarness(t, nil)

	t.Run("ShouldListEmpty", func(t *testing.T) {
		rw := h.do(t, "a", http.MethodGet, ssfHandlerURL, "", "")
		assert.Equal(t, http.StatusOK, rw.Code)
		assert.Equal(t, "no-store", rw.Header().Get("Cache-Control"))
		assert.JSONEq(t, `[]`, rw.Body.String())
	})

	created := h.do(t, "a", http.MethodPost, ssfHandlerURL, "application/json",
		`{"delivery":{"method":"`+SSFDeliveryMethodPush+`","endpoint_url":"https://rx.example.com/push","authorization_header":"`+ssfHandlerSecret+`"}}`)
	require.Equal(t, http.StatusCreated, created.Code, created.Body.String())

	var stream map[string]any
	require.NoError(t, json.Unmarshal(created.Body.Bytes(), &stream))

	id := stream["stream_id"].(string)

	t.Run("ShouldReadOne", func(t *testing.T) {
		rw := h.do(t, "a", http.MethodGet, ssfHandlerURL+"?stream_id="+id, "", "")
		assert.Equal(t, http.StatusOK, rw.Code)
		assert.JSONEq(t, created.Body.String(), rw.Body.String())
		assert.NotContains(t, rw.Body.String(), ssfHandlerSecret)
	})

	t.Run("ShouldList", func(t *testing.T) {
		rw := h.do(t, "a", http.MethodGet, ssfHandlerURL, "", "")
		assert.Equal(t, http.StatusOK, rw.Code)
		assert.JSONEq(t, "["+created.Body.String()+"]", rw.Body.String())
		assert.NotContains(t, rw.Body.String(), ssfHandlerSecret)
	})

	t.Run("ShouldNotListOtherClients", func(t *testing.T) {
		rw := h.do(t, "b", http.MethodGet, ssfHandlerURL, "", "")
		assert.Equal(t, http.StatusOK, rw.Code)
		assert.JSONEq(t, `[]`, rw.Body.String())
	})

	t.Run("ShouldGiveIdenticalResponseForUnownedAndUnknown", func(t *testing.T) {
		for _, method := range []string{http.MethodGet, http.MethodDelete} {
			owned := h.do(t, "b", method, ssfHandlerURL+"?stream_id="+id, "", "")
			unknown := h.do(t, "b", method, ssfHandlerURL+"?stream_id=nope", "", "")

			assert.Equal(t, http.StatusNotFound, owned.Code, method)
			assert.Equal(t, unknown.Code, owned.Code, method)
			assert.Equal(t, unknown.Body.Bytes(), owned.Body.Bytes(), method)
			assert.Equal(t, unknown.Header(), owned.Header(), method)
			assert.Contains(t, owned.Body.String(), "not_found")
		}

		_, err := h.store.GetSSFStream(context.Background(), "a", id)
		require.NoError(t, err)
	})

	t.Run("ShouldRejectDeleteWithoutStreamID", func(t *testing.T) {
		rw := h.do(t, "a", http.MethodDelete, ssfHandlerURL, "", "")
		assert.Equal(t, http.StatusBadRequest, rw.Code)
		assert.Contains(t, rw.Body.String(), "invalid_request")
	})

	t.Run("ShouldDelete", func(t *testing.T) {
		rw := h.do(t, "a", http.MethodDelete, ssfHandlerURL+"?stream_id="+id, "", "")
		assert.Equal(t, http.StatusNoContent, rw.Code)
		assert.Equal(t, "no-store", rw.Header().Get("Cache-Control"))
		assert.Empty(t, rw.Body.String())

		_, err := h.store.GetSSFStream(context.Background(), "a", id)
		assert.Error(t, err)
	})
}

func TestSSFStreamHandlerMethods(t *testing.T) {
	for _, method := range []string{http.MethodHead, http.MethodOptions} {
		t.Run(method, func(t *testing.T) {
			h := newSSFHandlerHarness(t, nil)

			rw := h.do(t, "a", method, ssfHandlerURL, "application/json", `{}`)
			assert.Equal(t, http.StatusMethodNotAllowed, rw.Code)
			assert.Equal(t, "GET, POST, PUT, PATCH, DELETE", rw.Header().Get("Allow"))
			assert.Equal(t, "no-store", rw.Header().Get("Cache-Control"))
		})
	}
}

func TestSSFStreamHandlerUnauthorized(t *testing.T) {
	h := newSSFHandlerHarness(t, nil)

	r := httptest.NewRequest(http.MethodGet, ssfHandlerURL, nil)

	_, err := h.provider.NewSSFStreamRequest(context.Background(), r, &DefaultSession{})
	require.Error(t, err)

	rw := httptest.NewRecorder()
	h.provider.WriteSSFError(context.Background(), rw, r, err)

	assert.Equal(t, http.StatusUnauthorized, rw.Code)
	assert.NotEmpty(t, rw.Header().Get("WWW-Authenticate"))
	assert.Equal(t, "no-store", rw.Header().Get("Cache-Control"))
}

type ssfNonceStrategy struct{ DPoPStrategy }

func (ssfNonceStrategy) NewDPoPNonce(ctx context.Context) (string, error) { return "n-1", nil }

func TestWriteSSFErrorDPoP(t *testing.T) {
	provider := &Fosite{Config: &Config{DPoPEnabled: true, DPoPStrategy: ssfNonceStrategy{}, DPoPAllowedJWSAlgorithms: []string{"ES256"}}}

	for _, tc := range []struct {
		name  string
		err   *RFC6749Error
		code  string
		nonce string
	}{
		{name: "ShouldChallengeInvalidProof", err: ErrInvalidDPoPProof, code: "invalid_dpop_proof"},
		{name: "ShouldChallengeNonce", err: ErrUseDPoPNonce, code: "use_dpop_nonce", nonce: "n-1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, ssfHandlerURL, nil)
			r.Header.Set(consts.HeaderAuthorization, "DPoP abc")

			rw := httptest.NewRecorder()
			provider.WriteSSFError(context.Background(), rw, r, tc.err.WithHint("x"))

			assert.Equal(t, http.StatusUnauthorized, rw.Code)
			assert.Contains(t, rw.Header().Get("WWW-Authenticate"), tc.code)
			assert.Equal(t, tc.nonce, rw.Header().Get("DPoP-Nonce"))
			assert.Equal(t, "no-store", rw.Header().Get("Cache-Control"))
			assert.Contains(t, rw.Body.String(), tc.code)
		})
	}

	t.Run("ShouldWriteStatusForOtherErrors", func(t *testing.T) {
		rw := httptest.NewRecorder()
		provider.WriteSSFError(context.Background(), rw, httptest.NewRequest(http.MethodGet, ssfHandlerURL, nil), ErrNotFound)

		assert.Equal(t, http.StatusNotFound, rw.Code)
		assert.Empty(t, rw.Header().Get("WWW-Authenticate"))
	})
}

type ssfMisbehavingStore struct{ *storage.MemoryStore }

func (ssfMisbehavingStore) GetSSFStream(ctx context.Context, clientID, streamID string) (*SSFStream, error) {
	if streamID == "nil" {
		return nil, nil
	}

	return &SSFStream{StreamID: streamID, ClientID: "someone-else"}, nil
}

func (ssfMisbehavingStore) ListSSFStreams(ctx context.Context, clientID string) ([]*SSFStream, error) {
	return []*SSFStream{nil, {StreamID: "x", ClientID: "someone-else"}, {StreamID: "mine", ClientID: clientID, Status: SSFStreamStatusEnabled}}, nil
}

func TestSSFStreamHandlerMisbehavingStore(t *testing.T) {
	h := newSSFHandlerHarness(t, nil)
	h.provider.Store = ssfMisbehavingStore{h.store.MemoryStore}

	unknown := h.do(t, "a", http.MethodGet, ssfHandlerURL+"?stream_id=x", "", "")
	nilStream := h.do(t, "a", http.MethodGet, ssfHandlerURL+"?stream_id=nil", "", "")

	assert.Equal(t, http.StatusNotFound, unknown.Code)
	assert.Equal(t, unknown.Body.String(), nilStream.Body.String())
	assert.Contains(t, unknown.Body.String(), "not_found")

	list := h.do(t, "a", http.MethodGet, ssfHandlerURL, "", "")
	require.Equal(t, http.StatusOK, list.Code)
	assert.Contains(t, list.Body.String(), `"stream_id":"mine"`)
	assert.NotContains(t, list.Body.String(), `"stream_id":"x"`)
}

func TestSSFStreamHandlerReadOnlyScope(t *testing.T) {
	h := newSSFHandlerHarness(t, nil)

	assert.Equal(t, http.StatusCreated, h.do(t, "a", http.MethodPost, ssfHandlerURL, "application/json", `{}`).Code)

	for _, tc := range []struct{ method, body string }{{http.MethodPost, `{}`}, {http.MethodDelete, ""}} {
		rw := h.do(t, "a-ro", tc.method, ssfHandlerURL+"?stream_id=x", "application/json", tc.body)
		assert.Equal(t, http.StatusForbidden, rw.Code, tc.method)
		assert.Contains(t, rw.Body.String(), "insufficient_scope", tc.method)
	}

	// The token 'tok-a-ro' resolves to the client 'a-ro', which owns this stream.
	require.NoError(t, h.store.CreateSSFStream(context.Background(), &SSFStream{StreamID: "ro-stream", ClientID: "a-ro", Issuer: "https://ssf.example.com"}))

	rw := h.do(t, "a-ro", http.MethodGet, ssfHandlerURL+"?stream_id=ro-stream", "", "")
	require.Equal(t, http.StatusOK, rw.Code, rw.Body.String())

	var got map[string]any

	require.NoError(t, json.Unmarshal(rw.Body.Bytes(), &got))
	assert.Equal(t, "ro-stream", got["stream_id"])
}

func TestSSFStreamRequestDeliveryRedaction(t *testing.T) {
	secret := ssfHandlerSecret
	d := SSFStreamRequestDelivery{Method: SSFDeliveryMethodPush, EndpointURL: "https://rx.example.com", AuthorizationHeader: &secret}

	data, err := json.Marshal(d)
	require.NoError(t, err)

	assert.NotContains(t, string(data), ssfHandlerSecret)

	for _, format := range []string{"%v", "%+v", "%#v"} {
		out := fmt.Sprintf(format, d)

		assert.NotContains(t, out, ssfHandlerSecret, format)
		assert.Contains(t, out, "[redacted]", format)
	}
}

func (h *ssfHandlerHarness) createStream(t *testing.T, client, body string) (id string) {
	t.Helper()

	rw := h.do(t, client, http.MethodPost, ssfHandlerURL, "application/json", body)
	require.Equal(t, http.StatusCreated, rw.Code, rw.Body.String())

	var got struct {
		StreamID string `json:"stream_id"`
	}

	require.NoError(t, json.Unmarshal(rw.Body.Bytes(), &got))

	return got.StreamID
}

func (h *ssfHandlerHarness) stored(t *testing.T, client, id string) *SSFStream {
	t.Helper()

	stream, err := h.store.GetSSFStream(context.Background(), client, id)
	require.NoError(t, err)

	return stream
}

const (
	ssfHeaderEmpty = "<empty>"
	ssfHeaderNull  = "<null>"
)

func ssfPushBody(endpoint, header string) string {
	body := `"delivery":{"method":"` + SSFDeliveryMethodPush + `","endpoint_url":"` + endpoint + `"`

	switch header {
	case "":
	case ssfHeaderEmpty:
		body += `,"authorization_header":""`
	case ssfHeaderNull:
		body += `,"authorization_header":null`
	default:
		body += `,"authorization_header":"` + header + `"`
	}

	return body + `}`
}

func TestSSFStreamUpdate(t *testing.T) {
	const (
		pushURL  = "https://rx.example.com/push"
		otherURL = "https://rx.example.com/other"
		oldAuth  = "Bearer old"
		newAuth  = "Bearer new"
	)

	methods := []string{http.MethodPatch, http.MethodPut}

	t.Run("ShouldRequireStreamID", func(t *testing.T) {
		for _, method := range methods {
			h := newSSFHandlerHarness(t, nil)
			h.createStream(t, "a", `{"description":"d"}`)

			rw := h.do(t, "a", method, ssfHandlerURL, "application/json", `{"description":"x"}`)
			assert.Equal(t, http.StatusBadRequest, rw.Code, method)
			assert.Contains(t, rw.Body.String(), `"error":"invalid_request"`, method)
		}
	})

	t.Run("ShouldIgnoreStreamIDInQuery", func(t *testing.T) {
		for _, method := range methods {
			h := newSSFHandlerHarness(t, nil)
			id := h.createStream(t, "a", `{"description":"d"}`)

			rw := h.do(t, "a", method, ssfHandlerURL+"?stream_id="+id, "application/json", `{"description":"q"}`)
			assert.Equal(t, http.StatusBadRequest, rw.Code, method)
			assert.Contains(t, rw.Body.String(), `"error":"invalid_request"`, method)
			assert.Equal(t, "d", h.stored(t, "a", id).Description)
		}
	})

	t.Run("ShouldPatchOnlyPresentPropertiesAndRecompute", func(t *testing.T) {
		h := newSSFHandlerHarness(t, nil)
		id := h.createStream(t, "a", `{"description":"d","events_requested":["`+ssfEventSessionRev+`","`+ssfEventCredChange+`"],`+ssfPushBody(pushURL, oldAuth)+`}`)

		before := h.stored(t, "a", id)
		before.Status, before.StatusReason = SSFStreamStatusPaused, "maintenance"
		before.LastVerificationAt = time.Unix(1700000000, 0).UTC()
		require.NoError(t, h.store.UpdateSSFStreamStatus(context.Background(), "a", id, before.Status, before.StatusReason))
		require.NoError(t, h.store.UpdateSSFStreamLastVerification(context.Background(), "a", id, before.LastVerificationAt))

		h.config.Policy = ssfHandlerPolicy{policy: &SSFClientPolicy{
			Audience:        []string{"https://rx.example.com"},
			EventsSupported: []string{ssfEventCredChange, ssfEventOther},
			DeliveryMethods: []string{SSFDeliveryMethodPush, SSFDeliveryMethodPoll},
		}}

		rw := h.do(t, "a", http.MethodPatch, ssfHandlerURL, "application/json", `{"stream_id":"`+id+`","events_requested":["`+ssfEventCredChange+`","`+ssfEventOther+`"]}`)
		require.Equal(t, http.StatusOK, rw.Code, rw.Body.String())
		assert.Equal(t, "no-store", rw.Header().Get("Cache-Control"))
		assert.NotContains(t, rw.Body.String(), oldAuth)

		got := h.stored(t, "a", id)
		assert.Equal(t, "d", got.Description)
		assert.Equal(t, []string{ssfEventCredChange, ssfEventOther}, got.EventsRequested)
		assert.Equal(t, []string{ssfEventCredChange, ssfEventOther}, got.EventsSupported)
		assert.Equal(t, []string{ssfEventCredChange, ssfEventOther}, got.EventsDelivered)
		assert.Equal(t, SSFDelivery{Method: SSFDeliveryMethodPush, EndpointURL: pushURL, AuthorizationHeader: oldAuth}, got.Delivery)
		assert.Equal(t, SSFStreamStatusPaused, got.Status)
		assert.Equal(t, "maintenance", got.StatusReason)
		assert.Equal(t, before.LastVerificationAt, got.LastVerificationAt)
		assert.Equal(t, "a", got.ClientID)
		assert.Equal(t, []string{"https://rx.example.com"}, got.Audience)
		assert.Equal(t, before.MinVerificationInterval, got.MinVerificationInterval)
	})

	t.Run("ShouldPutClearMissingReceiverProperties", func(t *testing.T) {
		h := newSSFHandlerHarness(t, nil)
		id := h.createStream(t, "a", `{"description":"d","events_requested":["`+ssfEventSessionRev+`"]}`)

		rw := h.do(t, "a", http.MethodPut, ssfHandlerURL, "application/json", `{"stream_id":"`+id+`","delivery":{"method":"`+SSFDeliveryMethodPoll+`"}}`)
		require.Equal(t, http.StatusOK, rw.Code, rw.Body.String())

		got := h.stored(t, "a", id)
		assert.Empty(t, got.Description)
		assert.Empty(t, got.EventsRequested)
		assert.Equal(t, []string{}, got.EventsDelivered)
		assert.Equal(t, SSFDeliveryMethodPoll, got.Delivery.Method)
		assert.NotContains(t, rw.Body.String(), `"description"`)
	})

	t.Run("ShouldPatchKeepDeliveryWhenAbsent", func(t *testing.T) {
		h := newSSFHandlerHarness(t, nil)
		id := h.createStream(t, "a", `{`+ssfPushBody(pushURL, oldAuth)+`}`)

		rw := h.do(t, "a", http.MethodPatch, ssfHandlerURL, "application/json", `{"stream_id":"`+id+`","description":"x"}`)
		require.Equal(t, http.StatusOK, rw.Code, rw.Body.String())

		assert.Equal(t, SSFDelivery{Method: SSFDeliveryMethodPush, EndpointURL: pushURL, AuthorizationHeader: oldAuth}, h.stored(t, "a", id).Delivery)
	})

	t.Run("ShouldRejectPutWithoutDelivery", func(t *testing.T) {
		h := newSSFHandlerHarness(t, nil)
		id := h.createStream(t, "a", `{"description":"d",`+ssfPushBody(pushURL, oldAuth)+`}`)

		rw := h.do(t, "a", http.MethodPut, ssfHandlerURL, "application/json", `{"stream_id":"`+id+`","description":"x"}`)
		assert.Equal(t, http.StatusBadRequest, rw.Code)
		assert.Contains(t, rw.Body.String(), `"error":"invalid_request"`)

		got := h.stored(t, "a", id)
		assert.Equal(t, "d", got.Description)
		assert.Equal(t, SSFDelivery{Method: SSFDeliveryMethodPush, EndpointURL: pushURL, AuthorizationHeader: oldAuth}, got.Delivery)
	})

	t.Run("ShouldCheckPollEndpointURLWhileStayingPoll", func(t *testing.T) {
		testCases := []struct {
			name     string
			delivery func(id string) string
			status   int
		}{
			{name: "ShouldRejectDifferent", delivery: func(string) string { return `"endpoint_url":"https://evil.example.com/x"` }, status: http.StatusBadRequest},
			{name: "ShouldAcceptSame", delivery: func(id string) string { return `"endpoint_url":"https://ssf.example.com/ssf/poll/` + id + `"` }, status: http.StatusOK},
			{name: "ShouldAcceptAbsent", delivery: func(string) string { return `"authorization_header":"ignored"` }, status: http.StatusOK},
		}

		for _, method := range methods {
			for _, tc := range testCases {
				t.Run(method+tc.name, func(t *testing.T) {
					h := newSSFHandlerHarness(t, nil)
					id := h.createStream(t, "a", `{"description":"d"}`)

					rw := h.do(t, "a", method, ssfHandlerURL, "application/json", `{"stream_id":"`+id+`","description":"x","delivery":{"method":"`+SSFDeliveryMethodPoll+`",`+tc.delivery(id)+`}}`)
					require.Equal(t, tc.status, rw.Code, rw.Body.String())

					got := h.stored(t, "a", id)
					assert.Equal(t, SSFDelivery{Method: SSFDeliveryMethodPoll, EndpointURL: "https://ssf.example.com/ssf/poll/" + id}, got.Delivery)

					if tc.status == http.StatusOK {
						assert.Equal(t, "x", got.Description)
					} else {
						assert.Equal(t, "d", got.Description)
					}
				})
			}
		}
	})

	t.Run("ShouldIgnorePollEndpointURLOnCreate", func(t *testing.T) {
		h := newSSFHandlerHarness(t, nil)
		id := h.createStream(t, "a", `{"delivery":{"method":"`+SSFDeliveryMethodPoll+`","endpoint_url":"https://evil.example.com/x"}}`)

		assert.Equal(t, "https://ssf.example.com/ssf/poll/"+id, h.stored(t, "a", id).Delivery.EndpointURL)
	})

	t.Run("ShouldLeaveStatusAndVerificationToNarrowWrites", func(t *testing.T) {
		for _, method := range methods {
			h := newSSFHandlerHarness(t, nil)
			id := h.createStream(t, "a", `{}`)
			at := time.Unix(1700000000, 0).UTC()

			require.NoError(t, h.store.UpdateSSFStreamStatus(context.Background(), "a", id, SSFStreamStatusDisabled, "stopped"))
			require.NoError(t, h.store.UpdateSSFStreamLastVerification(context.Background(), "a", id, at))

			rw := h.do(t, "a", method, ssfHandlerURL, "application/json", `{"stream_id":"`+id+`","description":"x","delivery":{"method":"`+SSFDeliveryMethodPoll+`"}}`)
			require.Equal(t, http.StatusOK, rw.Code, rw.Body.String())

			got := h.stored(t, "a", id)
			assert.Equal(t, "x", got.Description)
			assert.Equal(t, SSFStreamStatusDisabled, got.Status)
			assert.Equal(t, "stopped", got.StatusReason)
			assert.Equal(t, at, got.LastVerificationAt)
		}
	})

	t.Run("ShouldMergeAuthorizationHeader", func(t *testing.T) {
		testCases := []struct {
			name     string
			endpoint string
			header   string
			expected string
		}{
			{name: "ShouldKeepHeaderWhenURLSameAndHeaderAbsent", endpoint: pushURL, expected: oldAuth},
			{name: "ShouldKeepHeaderWhenURLSameAndHeaderNull", endpoint: pushURL, header: ssfHeaderNull, expected: oldAuth},
			{name: "ShouldClearHeaderWhenURLSameAndHeaderEmpty", endpoint: pushURL, header: ssfHeaderEmpty, expected: ""},
			{name: "ShouldUseNewHeaderWhenURLSame", endpoint: pushURL, header: newAuth, expected: newAuth},
			{name: "ShouldClearHeaderWhenURLChangedAndHeaderAbsent", endpoint: otherURL, expected: ""},
			{name: "ShouldUseNewHeaderWhenURLChanged", endpoint: otherURL, header: newAuth, expected: newAuth},
			{name: "ShouldTreatDifferentStringAsChanged", endpoint: pushURL + "/", expected: ""},
		}

		for _, method := range methods {
			for _, tc := range testCases {
				t.Run(method+tc.name, func(t *testing.T) {
					h := newSSFHandlerHarness(t, nil)
					id := h.createStream(t, "a", `{`+ssfPushBody(pushURL, oldAuth)+`}`)

					rw := h.do(t, "a", method, ssfHandlerURL, "application/json", `{"stream_id":"`+id+`",`+ssfPushBody(tc.endpoint, tc.header)+`}`)
					require.Equal(t, http.StatusOK, rw.Code, rw.Body.String())
					assert.NotContains(t, rw.Body.String(), "authorization_header")

					got := h.stored(t, "a", id)
					assert.Equal(t, SSFDeliveryMethodPush, got.Delivery.Method)
					assert.Equal(t, tc.endpoint, got.Delivery.EndpointURL)
					assert.Equal(t, tc.expected, got.Delivery.AuthorizationHeader)
				})
			}
		}
	})

	t.Run("ShouldSwitchBetweenPushAndPoll", func(t *testing.T) {
		for _, method := range methods {
			t.Run(method, func(t *testing.T) {
				h := newSSFHandlerHarness(t, nil)
				id := h.createStream(t, "a", `{}`)
				poll := SSFDelivery{Method: SSFDeliveryMethodPoll, EndpointURL: "https://ssf.example.com/ssf/poll/" + id}

				rw := h.do(t, "a", method, ssfHandlerURL, "application/json", `{"stream_id":"`+id+`",`+ssfPushBody(pushURL, "")+`}`)
				require.Equal(t, http.StatusOK, rw.Code, rw.Body.String())
				assert.Equal(t, SSFDelivery{Method: SSFDeliveryMethodPush, EndpointURL: pushURL}, h.stored(t, "a", id).Delivery)

				rw = h.do(t, "a", method, ssfHandlerURL, "application/json", `{"stream_id":"`+id+`",`+ssfPushBody(pushURL, newAuth)+`}`)
				require.Equal(t, http.StatusOK, rw.Code, rw.Body.String())
				assert.Equal(t, newAuth, h.stored(t, "a", id).Delivery.AuthorizationHeader)

				rw = h.do(t, "a", method, ssfHandlerURL, "application/json", `{"stream_id":"`+id+`","delivery":{"method":"`+SSFDeliveryMethodPoll+`","endpoint_url":"https://evil.example.com/x","authorization_header":"`+newAuth+`"}}`)
				require.Equal(t, http.StatusOK, rw.Code, rw.Body.String())
				assert.Equal(t, poll, h.stored(t, "a", id).Delivery)

				rw = h.do(t, "a", method, ssfHandlerURL, "application/json", `{"stream_id":"`+id+`",`+ssfPushBody(pushURL, "")+`}`)
				require.Equal(t, http.StatusOK, rw.Code, rw.Body.String())
				assert.Empty(t, h.stored(t, "a", id).Delivery.AuthorizationHeader)
			})
		}
	})

	t.Run("ShouldValidateChangedPushURLAgain", func(t *testing.T) {
		for _, method := range methods {
			h := newSSFHandlerHarness(t, nil)
			id := h.createStream(t, "a", `{`+ssfPushBody(pushURL, oldAuth)+`}`)

			h.config.EndpointValidator = ssfHandlerValidator{err: errors.New("private address")}

			rw := h.do(t, "a", method, ssfHandlerURL, "application/json", `{"stream_id":"`+id+`",`+ssfPushBody(otherURL, newAuth)+`}`)
			assert.Equal(t, http.StatusBadRequest, rw.Code, method)
			assert.Contains(t, rw.Body.String(), `"error":"invalid_request"`, method)
			assert.NotContains(t, rw.Body.String(), "private address", method)
			assert.Equal(t, SSFDelivery{Method: SSFDeliveryMethodPush, EndpointURL: pushURL, AuthorizationHeader: oldAuth}, h.stored(t, "a", id).Delivery, method)
		}
	})

	t.Run("ShouldValidateStoredPushURLWithoutDelivery", func(t *testing.T) {
		h := newSSFHandlerHarness(t, nil)
		id := h.createStream(t, "a", `{`+ssfPushBody(pushURL, oldAuth)+`,"description":"old"}`)

		h.config.EndpointValidator = ssfHandlerValidator{err: errors.New("private address")}

		rw := h.do(t, "a", http.MethodPatch, ssfHandlerURL, "application/json", `{"stream_id":"`+id+`","description":"new"}`)
		assert.Equal(t, http.StatusBadRequest, rw.Code)
		assert.NotContains(t, rw.Body.String(), "private address")
		assert.Equal(t, "old", h.stored(t, "a", id).Description)
	})

	t.Run("ShouldRejectInvalidDelivery", func(t *testing.T) {
		for _, method := range methods {
			for _, delivery := range []string{
				`"delivery":{"method":"urn:example:other"}`,
				`"delivery":{"method":"` + SSFDeliveryMethodPush + `","endpoint_url":"http://rx.example.com/push"}`,
				`"delivery":{"method":"` + SSFDeliveryMethodPush + `","endpoint_url":"https://rx.example.com/push","authorization_header":"a\r\nb"}`,
			} {
				h := newSSFHandlerHarness(t, nil)
				id := h.createStream(t, "a", `{"description":"d"}`)

				rw := h.do(t, "a", method, ssfHandlerURL, "application/json", `{"stream_id":"`+id+`",`+delivery+`}`)
				assert.Equal(t, http.StatusBadRequest, rw.Code, method+delivery)
				assert.Contains(t, rw.Body.String(), `"error":"invalid_request"`, method+delivery)
				assert.Equal(t, "d", h.stored(t, "a", id).Description)
			}
		}
	})

	t.Run("ShouldCheckTransmitterSuppliedProperties", func(t *testing.T) {
		testCases := []struct {
			name   string
			prop   string
			status int
		}{
			{name: "ShouldAcceptMatchingIssuer", prop: `"iss":"https://ssf.example.com"`, status: http.StatusOK},
			{name: "ShouldAcceptMatchingAudienceString", prop: `"aud":"https://rx.example.com"`, status: http.StatusOK},
			{name: "ShouldAcceptMatchingAudienceArray", prop: `"aud":["https://rx.example.com"]`, status: http.StatusOK},
			{name: "ShouldAcceptMatchingEventsSupportedAnyOrder", prop: `"events_supported":["` + ssfEventCredChange + `","` + ssfEventSessionRev + `"]`, status: http.StatusOK},
			{name: "ShouldAcceptMatchingEventsDelivered", prop: `"events_delivered":["` + ssfEventSessionRev + `"]`, status: http.StatusOK},
			{name: "ShouldIgnoreNullProperties", prop: `"iss":null,"aud":null,"events_supported":null,"events_delivered":null,"min_verification_interval":null,"inactivity_timeout":null`, status: http.StatusOK},
			{name: "ShouldAcceptMatchingMinVerificationInterval", prop: `"min_verification_interval":0`, status: http.StatusOK},
			{name: "ShouldRejectDifferentMinVerificationInterval", prop: `"min_verification_interval":60`, status: http.StatusBadRequest},
			{name: "ShouldRejectInactivityTimeout", prop: `"inactivity_timeout":0`, status: http.StatusBadRequest},
			{name: "ShouldRejectDifferentIssuer", prop: `"iss":"https://evil.example.com"`, status: http.StatusBadRequest},
			{name: "ShouldRejectDifferentAudienceString", prop: `"aud":"https://evil.example.com"`, status: http.StatusBadRequest},
			{name: "ShouldRejectDifferentAudienceArray", prop: `"aud":["https://rx.example.com","https://evil.example.com"]`, status: http.StatusBadRequest},
			{name: "ShouldRejectEmptyAudience", prop: `"aud":[]`, status: http.StatusBadRequest},
			{name: "ShouldRejectMalformedAudience", prop: `"aud":7`, status: http.StatusBadRequest},
			{name: "ShouldRejectDifferentEventsSupported", prop: `"events_supported":["` + ssfEventOther + `"]`, status: http.StatusBadRequest},
			{name: "ShouldRejectDifferentEventsDelivered", prop: `"events_delivered":["` + ssfEventCredChange + `"]`, status: http.StatusBadRequest},
			{name: "ShouldRejectEmptyEventsDelivered", prop: `"events_delivered":[]`, status: http.StatusBadRequest},
		}

		for _, method := range methods {
			for _, tc := range testCases {
				t.Run(method+tc.name, func(t *testing.T) {
					h := newSSFHandlerHarness(t, nil)
					id := h.createStream(t, "a", `{"description":"d","events_requested":["`+ssfEventSessionRev+`"]}`)

					rw := h.do(t, "a", method, ssfHandlerURL, "application/json", `{"stream_id":"`+id+`","description":"changed","delivery":{"method":"`+SSFDeliveryMethodPoll+`"},`+tc.prop+`}`)
					assert.Equal(t, tc.status, rw.Code, rw.Body.String())

					if tc.status == http.StatusOK {
						assert.Equal(t, "changed", h.stored(t, "a", id).Description)

						return
					}

					assert.Contains(t, rw.Body.String(), `"error":"invalid_request"`)
					assert.Equal(t, "d", h.stored(t, "a", id).Description)
				})
			}
		}
	})

	t.Run("ShouldMatchEventsDeliveredBeforeUpdate", func(t *testing.T) {
		h := newSSFHandlerHarness(t, nil)
		id := h.createStream(t, "a", `{"events_requested":["`+ssfEventSessionRev+`"]}`)

		rw := h.do(t, "a", http.MethodPatch, ssfHandlerURL, "application/json", `{"stream_id":"`+id+`","events_requested":["`+ssfEventCredChange+`"],"events_delivered":["`+ssfEventCredChange+`"]}`)
		assert.Equal(t, http.StatusBadRequest, rw.Code)
		assert.Equal(t, []string{ssfEventSessionRev}, h.stored(t, "a", id).EventsDelivered)
	})

	t.Run("ShouldDenyOnPolicyError", func(t *testing.T) {
		for _, method := range methods {
			h := newSSFHandlerHarness(t, nil)
			id := h.createStream(t, "a", `{"description":"d"}`)

			h.config.Policy = ssfHandlerPolicy{err: errors.New("denied")}

			rw := h.do(t, "a", method, ssfHandlerURL, "application/json", `{"stream_id":"`+id+`","description":"x"}`)
			assert.Equal(t, http.StatusForbidden, rw.Code, method)
			assert.Contains(t, rw.Body.String(), `"error":"access_denied"`, method)
			assert.Equal(t, "d", h.stored(t, "a", id).Description)
		}
	})

	t.Run("ShouldRejectPatchWhenStoredMethodNoLongerPermitted", func(t *testing.T) {
		h := newSSFHandlerHarness(t, nil)
		id := h.createStream(t, "a", `{`+ssfPushBody(pushURL, oldAuth)+`,"description":"d"}`)

		h.config.Policy = ssfHandlerPolicy{policy: &SSFClientPolicy{DeliveryMethods: []string{SSFDeliveryMethodPoll}}}

		rw := h.do(t, "a", http.MethodPatch, ssfHandlerURL, "application/json", `{"stream_id":"`+id+`","description":"x"}`)
		assert.Equal(t, http.StatusBadRequest, rw.Code)
		assert.Contains(t, rw.Body.String(), `"error":"invalid_request"`)
		assert.Equal(t, "d", h.stored(t, "a", id).Description)
	})

	t.Run("ShouldRequireManageScope", func(t *testing.T) {
		for _, method := range methods {
			h := newSSFHandlerHarness(t, nil)
			id := h.createStream(t, "a", `{}`)

			rw := h.do(t, "a-ro", method, ssfHandlerURL, "application/json", `{"stream_id":"`+id+`"}`)
			assert.Equal(t, http.StatusForbidden, rw.Code, method)
		}
	})

	t.Run("ShouldNotRevealAnotherClientsStream", func(t *testing.T) {
		for _, method := range methods {
			h := newSSFHandlerHarness(t, nil)
			id := h.createStream(t, "a", `{"description":"d"}`)

			foreign := h.do(t, "b", method, ssfHandlerURL, "application/json", `{"stream_id":"`+id+`","description":"hijack"}`)
			unknown := h.do(t, "b", method, ssfHandlerURL, "application/json", `{"stream_id":"unknown","description":"hijack"}`)

			assert.Equal(t, http.StatusNotFound, foreign.Code, method)
			assert.Contains(t, foreign.Body.String(), `"error":"not_found"`, method)
			assert.Equal(t, unknown.Code, foreign.Code, method)
			assert.Equal(t, unknown.Body.String(), foreign.Body.String(), method)
			assert.Equal(t, unknown.Header(), foreign.Header(), method)
			assert.Equal(t, "d", h.stored(t, "a", id).Description)
		}
	})
}
