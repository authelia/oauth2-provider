// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package ssfreceiver_test

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
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
	testPollPath  = "/poll"
	testPollToken = "cG9sbC1hY2Nlc3MtdG9rZW4"
)

type testPollCall struct {
	method        string
	authorization string
	contentType   string
	language      string
	body          string
}

// testPollHandler is an EventHandler and a SubjectResolver which fail as told for a 'jti', and change what they are
// handed.
type testPollHandler struct {
	events []*ssfreceiver.ReceivedEvent

	handle  map[string]error
	resolve map[string]error
}

func (h *testPollHandler) HandleSecurityEvent(_ context.Context, event *ssfreceiver.ReceivedEvent) (err error) {
	if err = h.handle[event.Claims.JTI]; err != nil {
		return err
	}

	h.events = append(h.events, event)

	mutateTestRecord(event.Stream)

	return nil
}

func (h *testPollHandler) ResolveSubject(_ context.Context, record *ssfreceiver.StreamRecord, subject *jwt.SubjectIdentifier) (principal any, err error) {
	mutateTestRecord(record)

	if subject != nil && subject.Email != "" {
		if err = h.resolve[subject.Email]; err != nil {
			return nil, err
		}
	}

	return "principal-1", nil
}

func (h *testPollHandler) handled() (jtis []string) {
	for _, event := range h.events {
		jtis = append(jtis, event.Claims.JTI)
	}

	return jtis
}

// testStorePoll is a Transmitter with one ES256 signing key and a poll endpoint, and a Receiver over a store with the
// record of one poll stream of it.
type testStorePoll struct {
	server   *httptest.Server
	key      *ecdsa.PrivateKey
	receiver *ssfreceiver.Receiver
	store    ssfreceiver.Storage
	handler  *testPollHandler

	mu        sync.Mutex
	calls     []testPollCall
	scopes    []string
	responses []string
	status    int
	critical  []string

	// hook answers the poll request with the number, counted from one, when it returns true.
	hook func(w http.ResponseWriter, r *http.Request, n int) (handled bool)
}

func newTestStorePoll(t *testing.T, st testStore) *testStorePoll {
	t.Helper()

	p := &testStorePoll{key: gen.MustES256Key(), store: st.new(time.Now), handler: &testPollHandler{}}

	p.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var data []byte

		switch r.URL.Path {
		case "/.well-known/ssf-configuration":
			p.mu.Lock()

			members := map[string]any{
				"spec_version":           "1_0",
				"issuer":                 p.server.URL,
				"jwks_uri":               p.server.URL + "/jwks.json",
				"configuration_endpoint": p.server.URL + "/streams",
				"status_endpoint":        p.server.URL + "/status",
				"verification_endpoint":  p.server.URL + "/verify",
			}

			if p.critical != nil {
				members["critical_subject_members"] = p.critical
			}

			p.mu.Unlock()

			data, _ = json.Marshal(members)
		case "/jwks.json":
			data, _ = json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &p.key.PublicKey, KeyID: "sig-1", Use: "sig", Algorithm: string(jose.ES256)}}})
		case testPollPath:
			body, _ := io.ReadAll(r.Body)

			p.mu.Lock()

			p.calls = append(p.calls, testPollCall{
				method:        r.Method,
				authorization: r.Header.Get("Authorization"),
				contentType:   r.Header.Get("Content-Type"),
				language:      r.Header.Get("Content-Language"),
				body:          string(body),
			})

			status, response, hook, n := p.status, `{"sets":{}}`, p.hook, len(p.calls)

			p.mu.Unlock()

			if hook != nil && hook(w, r, n) {
				return
			}

			p.mu.Lock()

			if len(p.responses) != 0 {
				response, p.responses = p.responses[0], p.responses[1:]
			}

			p.mu.Unlock()

			if status != 0 {
				w.WriteHeader(status)

				return
			}

			data = []byte(response)
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
			Authorizer: &ssfreceiver.BearerAuthorizer{Token: func(_ context.Context, _, scope string) (token string, err error) {
				p.mu.Lock()
				defer p.mu.Unlock()

				p.scopes = append(p.scopes, scope)

				return testPollToken, nil
			}},
		},
	}

	record := newTestRecord(p.server.URL, testStreamID, "")

	record.Delivery = oauth2.SSFDelivery{Method: oauth2.SSFDeliveryMethodPoll, EndpointURL: p.server.URL + testPollPath}
	record.EventsDelivered = []string{jwt.SecurityEventTypeCAEPSessionRevoked}

	require.NoError(t, p.store.CreateSSFReceiverStream(t.Context(), record))

	return p
}

func (p *testStorePoll) stored(t *testing.T) *ssfreceiver.StreamRecord {
	t.Helper()

	record, err := p.store.GetSSFReceiverStream(t.Context(), p.server.URL, testStreamID)
	require.NoError(t, err)

	return record
}

func (p *testStorePoll) received() []testPollCall {
	p.mu.Lock()
	defer p.mu.Unlock()

	return append([]testPollCall(nil), p.calls...)
}

// respond queues the poll response with the SETs, each a member name and a SET, in the order given.
func (p *testStorePoll) respond(more bool, sets ...string) {
	body := `{"sets":{`

	for i := 0; i < len(sets); i += 2 {
		if i != 0 {
			body += ","
		}

		name, _ := json.Marshal(sets[i])
		token, _ := json.Marshal(sets[i+1])

		body += string(name) + ":" + string(token)
	}

	body += `}`

	if more {
		body += `,"moreAvailable":true`
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	p.responses = append(p.responses, body+`}`)
}

// set returns a SET of the stream with the claims changed by the overrides, where a nil value removes a claim.
func (p *testStorePoll) set(t *testing.T, key *ecdsa.PrivateKey, jti string, overrides map[string]any) (token string) {
	t.Helper()

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, (&jose.SignerOptions{}).WithType("secevent+jwt").WithHeader("kid", "sig-1"))
	require.NoError(t, err)

	members := map[string]any{
		"iss":    p.server.URL,
		"aud":    "https://rx.example.com",
		"iat":    time.Now().Unix(),
		"jti":    jti,
		"sub_id": map[string]any{"format": "email", "email": "user@example.com"},
		"events": map[string]any{jwt.SecurityEventTypeCAEPSessionRevoked: map[string]any{"event_timestamp": time.Now().Unix()}},
	}

	for name, value := range overrides {
		if value == nil {
			delete(members, name)
		} else {
			members[name] = value
		}
	}

	claims, err := json.Marshal(members)
	require.NoError(t, err)

	signature, err := signer.Sign(claims)
	require.NoError(t, err)

	token, err = signature.CompactSerialize()
	require.NoError(t, err)

	return token
}

func (p *testStorePoll) sessionRevoked(t *testing.T, jti string) (token string) {
	t.Helper()

	return p.set(t, p.key, jti, nil)
}

func (p *testStorePoll) poll(t *testing.T, request ssfreceiver.PollRequest) (result *ssfreceiver.PollResult) {
	t.Helper()

	result, err := p.receiver.Poll(t.Context(), p.server.URL, testStreamID, request)

	require.NoError(t, err)
	require.NotNil(t, result)

	return result
}

func (p *testStorePoll) known(t *testing.T, jti string) (known bool) {
	t.Helper()

	known, err := p.store.IsSSFReceiverTokenKnown(t.Context(), p.server.URL, testStreamID, jti)
	require.NoError(t, err)

	return known
}

// testPollMarkFailStore fails to remember a received SET.
type testPollMarkFailStore struct {
	ssfreceiver.Storage
}

func (testPollMarkFailStore) MarkSSFReceiverTokenReceived(context.Context, string, string, string, time.Time) (err error) {
	return errors.New("the store is unavailable")
}

func TestReceiverPollOverStore(t *testing.T) {
	for _, st := range testStores() {
		t.Run(st.name, func(t *testing.T) {
			t.Run("ShouldAckValidSET", func(t *testing.T) {
				p := newTestStorePoll(t, st)

				expected := p.stored(t)

				p.respond(true, "jti-1", p.sessionRevoked(t, "jti-1"), "jti-2", p.sessionRevoked(t, "jti-2"))

				result := p.poll(t, ssfreceiver.PollRequest{ReturnImmediately: true})

				assert.Equal(t, []string{"jti-1", "jti-2"}, result.Ack)
				assert.Empty(t, result.SetErrs)
				assert.Empty(t, result.Unacknowledged)
				assert.True(t, result.MoreAvailable)

				require.Len(t, result.Received, 2)
				assert.Equal(t, "jti-1", result.Received[0].Claims.JTI)
				assert.Equal(t, jwt.SecurityEventTypeCAEPSessionRevoked, result.Received[0].Type)
				assert.IsType(t, &jwt.CAEPSessionRevoked{}, result.Received[0].Event)

				// The handler was handed its own copy, and changed it.
				assert.Equal(t, []string{"jti-1", "jti-2"}, p.handler.handled())
				assert.Equal(t, "mutated", p.handler.events[0].Stream.Audience[0])
				assert.Equal(t, expected, p.stored(t))

				// The events received are the ones the handler was handed, with the resolved principal.
				assert.Same(t, p.handler.events[0], result.Received[0])
				assert.Same(t, p.handler.events[1], result.Received[1])
				assert.Equal(t, "principal-1", result.Received[0].Principal)
				assert.Equal(t, "principal-1", result.Received[1].Principal)
				assert.NotEqual(t, testPushSecret, result.Received[0].Stream.Delivery.AuthorizationHeader)

				assert.True(t, p.known(t, "jti-1"))
				assert.True(t, p.known(t, "jti-2"))

				// RFC 8936 Section 2.4.3: the result is the acknowledgement of the next request.
				result = p.poll(t, ssfreceiver.PollRequest{Ack: result.Ack, SetErrs: result.SetErrs})

				assert.Empty(t, result.Ack)
				assert.Empty(t, result.SetErrs)
				assert.Empty(t, result.Received)
				assert.False(t, result.MoreAvailable)

				calls := p.received()

				require.Len(t, calls, 2)
				assert.Equal(t, http.MethodPost, calls[0].method)
				assert.Equal(t, "Bearer "+testPollToken, calls[0].authorization)
				assert.Equal(t, "application/json", calls[0].contentType)
				assert.Equal(t, `{"returnImmediately":true}`, calls[0].body)
				assert.Equal(t, `{"ack":["jti-1","jti-2"]}`, calls[1].body)
				assert.Empty(t, calls[1].language)

				assert.Equal(t, []string{oauth2.ScopeSSFManage, oauth2.ScopeSSFManage}, p.scopes)
			})

			t.Run("ShouldUseTheRecordStoredWhileTheRequestWasHeld", func(t *testing.T) {
				p := newTestStorePoll(t, st)

				record := p.stored(t)
				record.EventsDelivered = []string{jwt.SecurityEventTypeRISCAccountDisabled}

				require.NoError(t, p.store.UpdateSSFReceiverStream(t.Context(), p.server.URL, testStreamID, record))

				p.respond(false, "jti-1", p.sessionRevoked(t, "jti-1"))

				// The hook runs on the goroutine of the server, so it does not stop the test.
				p.hook = func(_ http.ResponseWriter, _ *http.Request, _ int) bool {
					record, err := p.store.GetSSFReceiverStream(context.Background(), p.server.URL, testStreamID)
					if assert.NoError(t, err) {
						record.EventsDelivered = []string{jwt.SecurityEventTypeCAEPSessionRevoked}

						assert.NoError(t, p.store.UpdateSSFReceiverStream(context.Background(), p.server.URL, testStreamID, record))
					}

					return false
				}

				result := p.poll(t, ssfreceiver.PollRequest{})

				assert.Equal(t, []string{"jti-1"}, result.Ack)
				assert.Empty(t, result.Unacknowledged)
				assert.Equal(t, []string{"jti-1"}, p.handler.handled())
				require.Len(t, result.Received, 1)
			})

			t.Run("ShouldLeaveTheSETsUnacknowledgedWhenTheRecordIsGone", func(t *testing.T) {
				p := newTestStorePoll(t, st)

				p.respond(false, "jti-1", p.sessionRevoked(t, "jti-1"))

				// The hook runs on the goroutine of the server, so it does not stop the test.
				p.hook = func(_ http.ResponseWriter, _ *http.Request, _ int) bool {
					assert.NoError(t, p.store.DeleteSSFReceiverStream(context.Background(), p.server.URL, testStreamID))

					return false
				}

				result := p.poll(t, ssfreceiver.PollRequest{Ack: []string{"jti-0"}})

				assert.Empty(t, result.Ack)
				assert.Empty(t, result.SetErrs)
				require.Contains(t, result.Unacknowledged, "jti-1")
				assert.ErrorIs(t, result.Unacknowledged["jti-1"], oauth2.ErrNotFound)
				assert.Empty(t, p.handler.handled())
				assert.False(t, p.known(t, "jti-1"))
			})

			t.Run("ShouldListTheAcceptedEventWhoseSETCouldNotBeRemembered", func(t *testing.T) {
				p := newTestStorePoll(t, st)

				p.receiver.Store = testPollMarkFailStore{Storage: p.store}

				p.respond(false, "jti-1", p.sessionRevoked(t, "jti-1"))

				result := p.poll(t, ssfreceiver.PollRequest{})

				assert.Empty(t, result.Ack)
				assert.Contains(t, result.Unacknowledged, "jti-1")
				require.Len(t, result.Received, 1)
				assert.Same(t, p.handler.events[0], result.Received[0])
			})

			t.Run("ShouldAckKnownJTI", func(t *testing.T) {
				p := newTestStorePoll(t, st)

				token := p.sessionRevoked(t, "jti-1")

				p.respond(false, "jti-1", token)
				p.respond(false, "jti-1", token)

				result := p.poll(t, ssfreceiver.PollRequest{})

				assert.Equal(t, []string{"jti-1"}, result.Ack)
				assert.Len(t, result.Received, 1)

				// RFC 8936 Section 2.4: a repeat SET is acknowledged, and is not dispatched again.
				result = p.poll(t, ssfreceiver.PollRequest{})

				assert.Equal(t, []string{"jti-1"}, result.Ack)
				assert.Empty(t, result.SetErrs)
				assert.Empty(t, result.Unacknowledged)
				assert.Empty(t, result.Received)

				assert.Equal(t, []string{"jti-1"}, p.handler.handled())
			})

			t.Run("ShouldReportInvalidSETInSetErrs", func(t *testing.T) {
				p := newTestStorePoll(t, st)

				p.respond(false,
					"jti-1", p.sessionRevoked(t, "jti-1"),
					"jti-2", p.set(t, p.key, "jti-2", map[string]any{"iss": "https://other.example.com"}),
					"jti-3", p.set(t, gen.MustES256Key(), "jti-3", nil),
					"jti-4", "not a SET",
					"jti-5", p.set(t, p.key, "jti-5", map[string]any{"aud": "https://other.example.com"}),
					"jti-6", p.set(t, p.key, "jti-6", map[string]any{"sub": "user"}),
				)

				result := p.poll(t, ssfreceiver.PollRequest{})

				assert.Equal(t, []string{"jti-1"}, result.Ack)
				assert.Empty(t, result.Unacknowledged)
				assert.Len(t, result.Received, 1)

				// RFC 8936 Section 2.4.4, Section 2.6, RFC 8935 Section 2.4.
				assert.Equal(t, map[string]oauth2.SSFPollSetError{
					"jti-2": {Err: ssfreceiver.SetErrorInvalidIssuer, Description: "The issuer of the SET is not the Transmitter of the stream."},
					"jti-3": {Err: ssfreceiver.SetErrorAuthenticationFailed, Description: "The signature of the SET is not valid."},
					"jti-4": {Err: ssfreceiver.SetErrorInvalidRequest, Description: "The SET is not a compact serialized JWS or JWE."},
					"jti-5": {Err: ssfreceiver.SetErrorInvalidAudience, Description: "The audience of the SET has no value of the audience of the stream."},
					"jti-6": {Err: ssfreceiver.SetErrorInvalidRequest, Description: "The claims of the SET are not valid."},
				}, result.SetErrs)

				assert.Equal(t, []string{"jti-1"}, p.handler.handled())

				for _, jti := range []string{"jti-2", "jti-3", "jti-4", "jti-5", "jti-6"} {
					assert.False(t, p.known(t, jti))
				}

				// RFC 8936 Section 2.6: the errors are sent with the language of their descriptions.
				p.poll(t, ssfreceiver.PollRequest{Ack: result.Ack, SetErrs: result.SetErrs})

				calls := p.received()

				require.Len(t, calls, 2)
				assert.Empty(t, calls[0].language)
				assert.Equal(t, "en", calls[1].language)

				var sent struct {
					Ack     []string                          `json:"ack"`
					SetErrs map[string]oauth2.SSFPollSetError `json:"setErrs"`
				}

				require.NoError(t, json.Unmarshal([]byte(calls[1].body), &sent))
				assert.Equal(t, result.Ack, sent.Ack)
				assert.Equal(t, result.SetErrs, sent.SetErrs)
			})

			t.Run("ShouldReportKeyMismatchWithJTI", func(t *testing.T) {
				p := newTestStorePoll(t, st)

				p.respond(false, "jti-other", p.sessionRevoked(t, "jti-1"), "jti-2", p.sessionRevoked(t, "jti-2"))

				result := p.poll(t, ssfreceiver.PollRequest{})

				assert.Equal(t, []string{"jti-2"}, result.Ack)
				assert.Equal(t, map[string]oauth2.SSFPollSetError{
					"jti-other": {Err: ssfreceiver.SetErrorInvalidRequest, Description: "The 'jti' of the SET is not the name of its member in the 'sets'."},
				}, result.SetErrs)
				assert.Empty(t, result.Unacknowledged)

				// The SET is not dispatched or remembered under either name.
				assert.Equal(t, []string{"jti-2"}, p.handler.handled())
				assert.False(t, p.known(t, "jti-1"))
				assert.False(t, p.known(t, "jti-other"))
			})

			t.Run("ShouldLeaveUnnamedSETUnacknowledged", func(t *testing.T) {
				p := newTestStorePoll(t, st)

				p.respond(false, "", p.sessionRevoked(t, "jti-1"), "jti-2", p.sessionRevoked(t, "jti-2"))

				result := p.poll(t, ssfreceiver.PollRequest{})

				// A name which is empty is not one the next request can acknowledge or report.
				assert.Equal(t, []string{"jti-2"}, result.Ack)
				assert.Empty(t, result.SetErrs)
				require.Len(t, result.Unacknowledged, 1)
				require.Error(t, result.Unacknowledged[""])

				assert.Equal(t, []string{"jti-2"}, p.handler.handled())
				assert.False(t, p.known(t, "jti-1"))
			})

			t.Run("ShouldLeaveSETUnacknowledgedWhenIssuedAheadOfTheClockSkew", func(t *testing.T) {
				p := newTestStorePoll(t, st)

				ahead := p.set(t, p.key, "jti-2", map[string]any{"iat": time.Now().Add(2 * time.Minute).Unix()})
				beyond := p.set(t, p.key, "jti-3", map[string]any{"iat": time.Now().Add(time.Hour).Unix()})

				p.respond(false, "jti-1", p.sessionRevoked(t, "jti-1"), "jti-2", ahead, "jti-3", beyond)

				result := p.poll(t, ssfreceiver.PollRequest{})

				// RFC 8936 Section 2.4: a SET which is not acknowledged is delivered again.
				assert.Equal(t, []string{"jti-1"}, result.Ack)
				require.Len(t, result.Unacknowledged, 1)
				require.ErrorIs(t, result.Unacknowledged["jti-2"], ssfreceiver.ErrIssuedAtAhead)

				require.Len(t, result.SetErrs, 1)
				assert.Equal(t, ssfreceiver.SetErrorInvalidRequest, result.SetErrs["jti-3"].Err)

				assert.Equal(t, []string{"jti-1"}, p.handler.handled())
				assert.False(t, p.known(t, "jti-2"))
			})

			t.Run("ShouldReportKeyMismatchWithJTIWhenIssuedAheadOfTheClockSkew", func(t *testing.T) {
				p := newTestStorePoll(t, st)

				iat := map[string]any{"iat": time.Now().Add(2 * time.Minute).Unix()}

				p.respond(false, "jti-other", p.set(t, p.key, "jti-1", iat), "jti-2", p.set(t, p.key, "jti-2", iat))

				result := p.poll(t, ssfreceiver.PollRequest{})

				// RFC 8936 Section 2.3: the name is not the 'jti' on a redelivery either, so the SET is reported.
				assert.Empty(t, result.Ack)
				assert.Equal(t, map[string]oauth2.SSFPollSetError{
					"jti-other": {Err: ssfreceiver.SetErrorInvalidRequest, Description: "The 'jti' of the SET is not the name of its member in the 'sets'."},
				}, result.SetErrs)

				require.Len(t, result.Unacknowledged, 1)
				require.ErrorIs(t, result.Unacknowledged["jti-2"], ssfreceiver.ErrIssuedAtAhead)

				assert.Empty(t, p.handler.handled())
				assert.False(t, p.known(t, "jti-1"))
				assert.False(t, p.known(t, "jti-other"))
				assert.False(t, p.known(t, "jti-2"))
			})

			t.Run("ShouldLeaveSETUnacknowledgedWhenHandlerFails", func(t *testing.T) {
				p := newTestStorePoll(t, st)

				failure := errors.New("the queue is full")

				p.handler.handle = map[string]error{"jti-2": failure}

				sets := []string{"jti-1", p.sessionRevoked(t, "jti-1"), "jti-2", p.sessionRevoked(t, "jti-2"), "jti-3", p.sessionRevoked(t, "jti-3")}

				p.respond(false, sets...)

				result := p.poll(t, ssfreceiver.PollRequest{})

				// Decision G, RFC 8936 Section 2.3: the SET is neither acknowledged nor reported, so it is delivered again.
				assert.Equal(t, []string{"jti-1", "jti-3"}, result.Ack)
				assert.Empty(t, result.SetErrs)
				assert.Len(t, result.Received, 2)

				require.Len(t, result.Unacknowledged, 1)
				require.ErrorIs(t, result.Unacknowledged["jti-2"], failure)

				assert.False(t, p.known(t, "jti-2"))

				// The SET is delivered again, with the ones the lost acknowledgement was of.
				p.handler.handle = nil

				p.respond(false, sets...)

				result = p.poll(t, ssfreceiver.PollRequest{})

				assert.Equal(t, []string{"jti-1", "jti-2", "jti-3"}, result.Ack)
				assert.Empty(t, result.Unacknowledged)
				require.Len(t, result.Received, 1)
				assert.Equal(t, "jti-2", result.Received[0].Claims.JTI)

				assert.Equal(t, []string{"jti-1", "jti-3", "jti-2"}, p.handler.handled())
				assert.True(t, p.known(t, "jti-2"))
			})

			t.Run("ShouldNotReportHandlerFailureInSetErrs", func(t *testing.T) {
				testCases := []struct {
					name    string
					handle  error
					resolve error
					strip   func(p *testStorePoll)
				}{
					{name: "ShouldNotReportHandlerError", handle: errors.New("the queue is full")},
					{name: "ShouldNotReportSetErrorWithoutCode", handle: &ssfreceiver.SetError{Description: "no code"}},
					{name: "ShouldNotReportResolverError", resolve: errors.New("the directory is down")},
					{name: "ShouldNotReportResolverSetError", resolve: &ssfreceiver.SetError{Code: ssfreceiver.SetErrorAccessDenied}},
					{name: "ShouldNotReportMissingHandler", strip: func(p *testStorePoll) { p.receiver.Config.Handler = nil }},
					{name: "ShouldNotReportUnreachableKeys", strip: func(p *testStorePoll) { p.receiver.Config.JWKSFetcher = testFailingFetcher{} }},
				}

				for _, tc := range testCases {
					t.Run(tc.name, func(t *testing.T) {
						p := newTestStorePoll(t, st)

						if tc.handle != nil {
							p.handler.handle = map[string]error{"jti-1": tc.handle}
						}

						if tc.resolve != nil {
							p.handler.resolve = map[string]error{"user@example.com": tc.resolve}
						}

						if tc.strip != nil {
							tc.strip(p)
						}

						p.respond(false, "jti-1", p.sessionRevoked(t, "jti-1"))

						result := p.poll(t, ssfreceiver.PollRequest{})

						// RFC 8936 Section 2: only an error of the parsing or the validation of a SET is reported.
						assert.Empty(t, result.SetErrs)
						assert.Empty(t, result.Ack)
						assert.Empty(t, result.Received)
						require.Len(t, result.Unacknowledged, 1)
						require.Error(t, result.Unacknowledged["jti-1"])

						assert.Empty(t, p.handler.events)
						assert.False(t, p.known(t, "jti-1"))
					})
				}
			})

			t.Run("ShouldReportSetErrorOfHandler", func(t *testing.T) {
				p := newTestStorePoll(t, st)

				p.handler.handle = map[string]error{"jti-1": &ssfreceiver.SetError{Code: ssfreceiver.SetErrorAccessDenied, Description: "The event is refused."}}

				p.respond(false, "jti-1", p.sessionRevoked(t, "jti-1"))

				result := p.poll(t, ssfreceiver.PollRequest{})

				// Decision G: a *SetError of the handler with a code is reported.
				assert.Equal(t, map[string]oauth2.SSFPollSetError{"jti-1": {Err: ssfreceiver.SetErrorAccessDenied, Description: "The event is refused."}}, result.SetErrs)
				assert.Empty(t, result.Ack)
				assert.Empty(t, result.Unacknowledged)
				assert.False(t, p.known(t, "jti-1"))
			})

			t.Run("ShouldAckDiscardedAndUnknownSubjectEvents", func(t *testing.T) {
				p := newTestStorePoll(t, st)

				p.critical = []string{"tenant"}
				p.receiver.Config.ProcessedSubjectMembers = []string{"user"}
				p.handler.resolve = map[string]error{"unknown@example.com": ssfreceiver.ErrSubjectUnknown}

				p.respond(false,
					// SSF Section 8.1.1: the type is not in the 'events_delivered'.
					"jti-1", p.set(t, p.key, "jti-1", map[string]any{"events": map[string]any{jwt.SecurityEventTypeCAEPCredentialChange: map[string]any{"credential_type": "password", "change_type": "update"}}}),
					// SSF Section 3.6: the subject has a critical member which is not processed.
					"jti-2", p.set(t, p.key, "jti-2", map[string]any{"sub_id": map[string]any{
						"format": "complex",
						"user":   map[string]any{"format": "email", "email": "user@example.com"},
						"tenant": map[string]any{"format": "opaque", "id": "tenant-1"},
					}}),
					// SSF Section 9.3: the subject is not known.
					"jti-3", p.set(t, p.key, "jti-3", map[string]any{"sub_id": map[string]any{"format": "email", "email": "unknown@example.com"}}),
				)

				result := p.poll(t, ssfreceiver.PollRequest{})

				assert.Equal(t, []string{"jti-1", "jti-2", "jti-3"}, result.Ack)
				assert.Empty(t, result.SetErrs)
				assert.Empty(t, result.Unacknowledged)

				// An event the handler was not handed is not one that was received.
				assert.Empty(t, result.Received)
				assert.Empty(t, p.handler.events)

				// The SETs are remembered, so a repeat is acknowledged the same.
				for _, jti := range result.Ack {
					assert.True(t, p.known(t, jti))
				}
			})

			t.Run("ShouldStopAtTheConfiguredSetLimit", func(t *testing.T) {
				p := newTestStorePoll(t, st)

				p.receiver.Config.MaxPollSets = 2

				p.respond(false,
					"jti-3", p.sessionRevoked(t, "jti-3"),
					"jti-1", p.sessionRevoked(t, "jti-1"),
					"jti-2", p.sessionRevoked(t, "jti-2"),
					"jti-4", "not a SET",
				)

				result := p.poll(t, ssfreceiver.PollRequest{})

				// The first SETs of the response are processed. The others are neither acknowledged nor reported, so
				// they are delivered again, and there are more to poll for.
				assert.Equal(t, []string{"jti-3", "jti-1"}, result.Ack)
				assert.Empty(t, result.SetErrs)
				assert.Empty(t, result.Unacknowledged)
				assert.Len(t, result.Received, 2)
				assert.True(t, result.MoreAvailable)

				assert.Equal(t, []string{"jti-3", "jti-1"}, p.handler.handled())
				assert.False(t, p.known(t, "jti-2"))

				// A response within the limit is processed whole.
				p.respond(false, "jti-2", p.sessionRevoked(t, "jti-2"), "jti-4", "not a SET")

				result = p.poll(t, ssfreceiver.PollRequest{Ack: result.Ack})

				assert.Equal(t, []string{"jti-2"}, result.Ack)
				assert.Len(t, result.SetErrs, 1)
				assert.False(t, result.MoreAvailable)
			})

			t.Run("ShouldHandleStreamEvents", func(t *testing.T) {
				p := newTestStorePoll(t, st)

				subject := map[string]any{"format": "opaque", "id": testStreamID}

				require.NoError(t, p.store.SetSSFReceiverStreamVerificationState(t.Context(), p.server.URL, testStreamID, "expected", time.Now()))

				p.respond(false,
					"jti-1", p.set(t, p.key, "jti-1", map[string]any{"sub_id": subject, "events": map[string]any{jwt.SecurityEventTypeSSFVerification: map[string]any{"state": "other"}}}),
					"jti-2", p.set(t, p.key, "jti-2", map[string]any{"sub_id": subject, "events": map[string]any{jwt.SecurityEventTypeSSFVerification: map[string]any{"state": "expected"}}}),
					"jti-3", p.set(t, p.key, "jti-3", map[string]any{"sub_id": subject, "events": map[string]any{jwt.SecurityEventTypeSSFStreamUpdated: map[string]any{"status": oauth2.SSFStreamStatusPaused, "reason": "License is not valid"}}}),
				)

				result := p.poll(t, ssfreceiver.PollRequest{})

				// SSF Section 8.1.4.1, Section 8.1.5.
				assert.Equal(t, []string{"jti-2", "jti-3"}, result.Ack)
				assert.Equal(t, map[string]oauth2.SSFPollSetError{
					"jti-1": {Err: ssfreceiver.SetErrorInvalidState, Description: "The state of the verification event is not the requested one."},
				}, result.SetErrs)
				assert.Empty(t, result.Received)
				assert.Empty(t, result.Unacknowledged)
				assert.Empty(t, p.handler.events)

				stored := p.stored(t)

				assert.WithinDuration(t, time.Now(), stored.VerifiedAt, time.Minute)
				assert.Empty(t, stored.VerificationState)
				assert.Equal(t, oauth2.SSFStreamStatusPaused, stored.Status)
				assert.Equal(t, "License is not valid", stored.StatusReason)
			})

			t.Run("ShouldRefuseStreamThatIsNotPolled", func(t *testing.T) {
				p := newTestStorePoll(t, st)

				push := newTestRecord(p.server.URL, "stream-push", testPushURL)

				require.NoError(t, p.store.CreateSSFReceiverStream(t.Context(), push))

				result, err := p.receiver.Poll(t.Context(), p.server.URL, "stream-push", ssfreceiver.PollRequest{})

				require.ErrorIs(t, err, ssfreceiver.ErrStreamRequest)
				assert.Nil(t, result)

				result, err = p.receiver.Poll(t.Context(), p.server.URL, "stream-unknown", ssfreceiver.PollRequest{})

				require.ErrorIs(t, err, oauth2.ErrNotFound)
				assert.Nil(t, result)

				result, err = p.receiver.Poll(t.Context(), p.server.URL, "", ssfreceiver.PollRequest{})

				require.ErrorIs(t, err, ssfreceiver.ErrStreamRequest)
				assert.Nil(t, result)

				assert.Empty(t, p.received())
			})

			t.Run("ShouldReturnTheErrorOfTheRequest", func(t *testing.T) {
				p := newTestStorePoll(t, st)

				p.status = http.StatusUnauthorized

				result, err := p.receiver.Poll(t.Context(), p.server.URL, testStreamID, ssfreceiver.PollRequest{Ack: []string{"jti-1"}})

				require.ErrorIs(t, err, ssfreceiver.ErrTransmitterUnauthorized)
				assert.Nil(t, result)

				p.status = 0

				p.mu.Lock()
				p.responses = []string{`{"sets":{"jti-1":1}}`}
				p.mu.Unlock()

				result, err = p.receiver.Poll(t.Context(), p.server.URL, testStreamID, ssfreceiver.PollRequest{})

				require.ErrorIs(t, err, ssfreceiver.ErrPollResponse)
				assert.Nil(t, result)
			})

			t.Run("ShouldStopWhenTheContextIsDone", func(t *testing.T) {
				p := newTestStorePoll(t, st)

				ctx, cancel := context.WithCancel(t.Context())

				t.Cleanup(cancel)

				// The handler of the first SET ends the context.
				p.receiver.Config.Handler = testHandlerFunc(func(c context.Context, event *ssfreceiver.ReceivedEvent) error {
					cancel()

					return p.handler.HandleSecurityEvent(c, event)
				})

				p.respond(false, "jti-1", p.sessionRevoked(t, "jti-1"), "jti-2", p.sessionRevoked(t, "jti-2"))

				result, err := p.receiver.Poll(ctx, p.server.URL, testStreamID, ssfreceiver.PollRequest{})

				// The SET which was handled is acknowledged, as these stores mark it though the context is done. The
				// other is delivered again.
				require.NoError(t, err)
				require.NotNil(t, result)
				assert.Equal(t, []string{"jti-1"}, result.Ack)
				assert.Empty(t, result.SetErrs)
				assert.Empty(t, result.Unacknowledged)
				assert.True(t, result.MoreAvailable)

				require.Len(t, result.Received, 1)
				assert.Equal(t, "jti-1", result.Received[0].Claims.JTI)

				assert.Equal(t, []string{"jti-1"}, p.handler.handled())
				assert.True(t, p.known(t, "jti-1"))
				assert.False(t, p.known(t, "jti-2"))
			})
		})
	}
}

type testHandlerFunc func(ctx context.Context, event *ssfreceiver.ReceivedEvent) error

func (f testHandlerFunc) HandleSecurityEvent(ctx context.Context, event *ssfreceiver.ReceivedEvent) (err error) {
	return f(ctx, event)
}

// testFailingFetcher is a JWKSFetcherStrategy which reaches no Transmitter.
type testFailingFetcher struct{}

func (testFailingFetcher) Resolve(context.Context, string, bool) (*jose.JSONWebKeySet, error) {
	return nil, errors.New("the keys are unreachable")
}
