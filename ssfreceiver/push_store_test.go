// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package ssfreceiver_test

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/jose"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/gen"
	"authelia.com/provider/oauth2/ssfreceiver"
	"authelia.com/provider/oauth2/token/jwt"
)

const (
	testStreamID   = "stream-1"
	testPushSecret = "Bearer cHVzaC1zZWNyZXQ"
)

// testLoopbackGuard keeps the special-use address guard enabled and permits the loopback network of the test server.
type testLoopbackGuard struct{}

func (testLoopbackGuard) GetDisableSpecialUseAddressGuard(context.Context) bool {
	return false
}

func (testLoopbackGuard) GetSpecialUseAddressGuardAllowedNetworks(context.Context) []*net.IPNet {
	_, network, _ := net.ParseCIDR("127.0.0.0/8")

	return []*net.IPNet{network}
}

// testStoreHandler is an EventHandler and a SubjectResolver which change what they are handed.
type testStoreHandler struct {
	events   []*ssfreceiver.ReceivedEvent
	resolved []*ssfreceiver.StreamRecord
}

func (h *testStoreHandler) HandleSecurityEvent(_ context.Context, event *ssfreceiver.ReceivedEvent) (err error) {
	h.events = append(h.events, event)

	mutateTestRecord(event.Stream)

	return nil
}

func (h *testStoreHandler) ResolveSubject(_ context.Context, record *ssfreceiver.StreamRecord, _ *jwt.SubjectIdentifier) (principal any, err error) {
	h.resolved = append(h.resolved, record.Clone())

	mutateTestRecord(record)

	return "principal-1", nil
}

// testStorePush is a Transmitter with one ES256 signing key, and a Receiver over a store with the record of one push
// stream of it.
type testStorePush struct {
	server   *httptest.Server
	key      *ecdsa.PrivateKey
	receiver *ssfreceiver.Receiver
	store    ssfreceiver.Storage
	handler  *testStoreHandler
}

func newTestStorePush(t *testing.T, st testStore) *testStorePush {
	p := &testStorePush{key: gen.MustES256Key(), store: st.new(time.Now), handler: &testStoreHandler{}}

	p.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var data []byte

		switch r.URL.Path {
		case "/.well-known/ssf-configuration":
			data, _ = json.Marshal(map[string]any{
				"spec_version":           "1_0",
				"issuer":                 p.server.URL,
				"jwks_uri":               p.server.URL + "/jwks.json",
				"configuration_endpoint": p.server.URL + "/streams",
				"status_endpoint":        p.server.URL + "/status",
				"verification_endpoint":  p.server.URL + "/verify",
			})
		case "/jwks.json":
			data, _ = json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &p.key.PublicKey, KeyID: "sig-1", Use: "sig", Algorithm: string(jose.ES256)}}})
		default:
			http.NotFound(w, r)

			return
		}

		w.Header().Set("Content-Type", "application/json")

		_, _ = w.Write(data)
	}))

	t.Cleanup(p.server.Close)

	client := &retryablehttp.Client{HTTPClient: p.server.Client(), CheckRetry: retryablehttp.DefaultRetryPolicy, Backoff: retryablehttp.DefaultBackoff}

	p.receiver = &ssfreceiver.Receiver{
		Store: p.store,
		Config: ssfreceiver.Config{
			Strategy: &jwt.DefaultStrategy{Issuer: jwt.NewDefaultIssuerUnverifiedFromJWKS(&jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
				{Key: gen.MustES256Key(), KeyID: "enc-1", Use: "enc", Algorithm: string(jose.ECDH_ES)},
			}})},
			JWKSFetcher:            oauth2.NewDefaultJWKSFetcherStrategy(oauth2.JWKSFetcherWithHTTPClient(client)),
			HTTPClient:             client,
			SpecialUseAddressGuard: testLoopbackGuard{},
			Handler:                p.handler,
			Subjects:               p.handler,
		},
	}

	record := newTestRecord(p.server.URL, testStreamID, testPushURL)

	record.Delivery.AuthorizationHeader = testPushSecret
	record.EventsDelivered = []string{jwt.SecurityEventTypeCAEPSessionRevoked}

	require.NoError(t, p.store.CreateSSFReceiverStream(t.Context(), record))

	return p
}

func (p *testStorePush) stored(t *testing.T) *ssfreceiver.StreamRecord {
	t.Helper()

	record, err := p.store.GetSSFReceiverStream(t.Context(), p.server.URL, testStreamID)
	require.NoError(t, err)

	return record
}

// deliver pushes a SET of the event to the endpoint of the stream, as the application routes it: the record is
// looked up from the request URL.
func (p *testStorePush) deliver(t *testing.T, jti string, subject map[string]any, eventType string, payload map[string]any) (rw *httptest.ResponseRecorder, err error) {
	t.Helper()

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: p.key}, (&jose.SignerOptions{}).WithType("secevent+jwt").WithHeader("kid", "sig-1"))
	require.NoError(t, err)

	claims, err := json.Marshal(map[string]any{
		"iss":    p.server.URL,
		"aud":    "https://rx.example.com",
		"iat":    time.Now().Unix(),
		"jti":    jti,
		"sub_id": subject,
		"events": map[string]any{eventType: payload},
	})
	require.NoError(t, err)

	signature, err := signer.Sign(claims)
	require.NoError(t, err)

	token, err := signature.CompactSerialize()
	require.NoError(t, err)

	r := httptest.NewRequest(http.MethodPost, testPushURL, strings.NewReader(token))

	r.Header.Set("Content-Type", "application/secevent+jwt")
	r.Header.Set("Authorization", testPushSecret)

	record, err := p.store.GetSSFReceiverStreamByPushEndpoint(t.Context(), testPushURL)
	require.NoError(t, err)

	rw = httptest.NewRecorder()

	err = p.receiver.HandlePush(t.Context(), rw, r, record)

	return rw, err
}

func (p *testStorePush) deliverSessionRevoked(t *testing.T, jti string) (rw *httptest.ResponseRecorder, err error) {
	t.Helper()

	return p.deliver(t, jti, map[string]any{"format": "email", "email": "user@example.com"}, jwt.SecurityEventTypeCAEPSessionRevoked, map[string]any{"event_timestamp": time.Now().Unix()})
}

func TestReceiverHandlePushOverStore(t *testing.T) {
	for _, st := range testStores() {
		t.Run(st.name, func(t *testing.T) {
			t.Run("ShouldAcknowledgeKnownJTIWithoutSecondDispatch", func(t *testing.T) {
				p := newTestStorePush(t, st)

				for range 2 {
					rw, err := p.deliverSessionRevoked(t, "jti-1")

					require.NoError(t, err)
					assert.Equal(t, http.StatusAccepted, rw.Code)
					assert.Empty(t, rw.Body.Bytes())
				}

				require.Len(t, p.handler.events, 1)
				assert.Equal(t, "principal-1", p.handler.events[0].Principal)
				assert.IsType(t, &jwt.CAEPSessionRevoked{}, p.handler.events[0].Event)

				known, err := p.store.IsSSFReceiverTokenKnown(t.Context(), p.server.URL, testStreamID, "jti-1")

				require.NoError(t, err)
				assert.True(t, known)

				// Another SET of the stream is dispatched.
				rw, err := p.deliverSessionRevoked(t, "jti-2")

				require.NoError(t, err)
				assert.Equal(t, http.StatusAccepted, rw.Code)
				assert.Len(t, p.handler.events, 2)
			})

			t.Run("ShouldHandResolverTheCloneNotTheStoredRecord", func(t *testing.T) {
				p := newTestStorePush(t, st)

				expected := p.stored(t)

				rw, err := p.deliverSessionRevoked(t, "jti-1")

				require.NoError(t, err)
				assert.Equal(t, http.StatusAccepted, rw.Code)

				require.Len(t, p.handler.resolved, 1)
				require.Len(t, p.handler.events, 1)

				// The secret of the stream is not handed to the application.
				assert.Empty(t, p.handler.resolved[0].Delivery.AuthorizationHeader)
				assert.Equal(t, expected.EventsDelivered, p.handler.resolved[0].EventsDelivered)

				// The resolver and the handler changed what they were handed.
				assert.Equal(t, "mutated", p.handler.events[0].Stream.Delivery.AuthorizationHeader)
				assert.Equal(t, expected, p.stored(t))
				assert.Equal(t, testPushSecret, p.stored(t).Delivery.AuthorizationHeader)
			})
		})
	}
}

func TestReceiverStreamEventsOverStore(t *testing.T) {
	subject := map[string]any{"format": "opaque", "id": testStreamID}

	for _, st := range testStores() {
		t.Run(st.name, func(t *testing.T) {
			t.Run("ShouldConsumeStateOnce", func(t *testing.T) {
				p := newTestStorePush(t, st)

				require.NoError(t, p.store.SetSSFReceiverStreamVerificationState(t.Context(), p.server.URL, testStreamID, "expected", time.Now()))

				rw, err := p.deliver(t, "jti-1", subject, jwt.SecurityEventTypeSSFVerification, map[string]any{"state": "other"})

				require.NoError(t, err)
				assert.Equal(t, http.StatusBadRequest, rw.Code)
				assert.JSONEq(t, `{"err":"invalid_state","description":"The state of the verification event is not the requested one."}`, rw.Body.String())
				assert.True(t, p.stored(t).VerifiedAt.IsZero())
				assert.Equal(t, "expected", p.stored(t).VerificationState)

				rw, err = p.deliver(t, "jti-2", subject, jwt.SecurityEventTypeSSFVerification, map[string]any{"state": "expected"})

				require.NoError(t, err)
				assert.Equal(t, http.StatusAccepted, rw.Code)

				stored := p.stored(t)

				assert.WithinDuration(t, time.Now(), stored.VerifiedAt, time.Minute)
				assert.Empty(t, stored.VerificationState)
				assert.True(t, stored.VerificationRequestedAt.IsZero())

				// No verification is requested now, so the 'state' verifies nothing and is not a failure to verify.
				rw, err = p.deliver(t, "jti-3", subject, jwt.SecurityEventTypeSSFVerification, map[string]any{"state": "expected"})

				require.NoError(t, err)
				assert.Equal(t, http.StatusAccepted, rw.Code)
				assert.Empty(t, rw.Body.Bytes())
				assert.Equal(t, stored, p.stored(t))
				assert.Empty(t, p.handler.events)
			})

			t.Run("ShouldAcceptVerificationWithoutState", func(t *testing.T) {
				p := newTestStorePush(t, st)

				require.NoError(t, p.store.SetSSFReceiverStreamVerificationState(t.Context(), p.server.URL, testStreamID, "expected", time.Now()))

				rw, err := p.deliver(t, "jti-1", subject, jwt.SecurityEventTypeSSFVerification, map[string]any{})

				require.NoError(t, err)
				assert.Equal(t, http.StatusAccepted, rw.Code)

				stored := p.stored(t)

				assert.WithinDuration(t, time.Now(), stored.VerifiedAt, time.Minute)
				assert.Equal(t, "expected", stored.VerificationState)
				assert.False(t, stored.VerificationRequestedAt.IsZero())
			})

			t.Run("ShouldStoreStatusAndReason", func(t *testing.T) {
				p := newTestStorePush(t, st)

				before := p.stored(t)

				rw, err := p.deliver(t, "jti-1", subject, jwt.SecurityEventTypeSSFStreamUpdated, map[string]any{"status": oauth2.SSFStreamStatusPaused, "reason": "License is not valid"})

				require.NoError(t, err)
				assert.Equal(t, http.StatusAccepted, rw.Code)

				before.Status, before.StatusReason = oauth2.SSFStreamStatusPaused, "License is not valid"

				assert.Equal(t, before, p.stored(t))
				assert.Empty(t, p.handler.events)
			})
		})
	}
}
