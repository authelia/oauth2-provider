// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package integration_test

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
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
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/token/jwt"
)

const (
	// ssfTestServerClient is the client of the authorization server at the upstream Transmitter, and
	// ssfTestDownstreamClient the client of the downstream Receiver at the authorization server.
	ssfTestServerClient     = "authorization-server"
	ssfTestDownstreamClient = "downstream"

	ssfTestTokenPrefix = "tok-"
	ssfTestPushSecret  = "Bearer cHVzaC1zZWNyZXQ"
	ssfTestPushRotated = "Bearer cm90YXRlZC1zZWNyZXQ"
	ssfTestPushPath    = "/ssf/push/"
	ssfTestPollPath    = "/ssf/poll/"

	ssfTestUpstreamEmail = "user@upstream.example.com"
	ssfTestPrincipal     = "user-1"
	ssfTestPairwise      = "pairwise-user-1"

	// ssfTestLongPoll is how long the Transmitter holds a poll request which has no SET.
	ssfTestLongPoll = 200 * time.Millisecond
)

// ssfTestStore is the storage of a Transmitter, of a Receiver and of a Relay, which one authorization server has in
// one store.
type ssfTestStore interface {
	oauth2.Storage
	oauth2.SSFStreamStorage
	ssfreceiver.Storage
	ssfreceiver.RelayStorage
}

type ssfTestStoreType struct {
	name string
	new  func() (store ssfTestStore, clients map[string]oauth2.Client)
}

func ssfTestStoreTypes() []ssfTestStoreType {
	return []ssfTestStoreType{
		{
			name: "MemoryStore",
			new: func() (ssfTestStore, map[string]oauth2.Client) {
				s := storage.NewMemoryStore()

				return s, s.Clients
			},
		},
		{
			name: "HydratingMemoryStore",
			new: func() (ssfTestStore, map[string]oauth2.Client) {
				s := storage.NewHydratingMemoryStore()

				return s, s.Clients
			},
		},
	}
}

// ssfTestLoopbackGuard keeps the special-use address guard enabled and permits the loopback network of the test
// servers.
type ssfTestLoopbackGuard struct{}

func (ssfTestLoopbackGuard) GetDisableSpecialUseAddressGuard(context.Context) bool {
	return false
}

func (ssfTestLoopbackGuard) GetSpecialUseAddressGuardAllowedNetworks(context.Context) []*net.IPNet {
	return []*net.IPNet{ssfTestLoopback()}
}

func ssfTestLoopback() *net.IPNet {
	_, network, _ := net.ParseCIDR("127.0.0.0/8")

	return network
}

func ssfTestAudience(clientID string) string {
	return "https://" + clientID + ".example.com"
}

// ssfTestIntrospector resolves the access token 'tok-<client id>' to the registered client, with the 'ssf.manage'
// scope and the audience of the Transmitter.
type ssfTestIntrospector struct {
	tx *ssfTestTransmitter
}

func (i ssfTestIntrospector) IntrospectToken(ctx context.Context, token string, _ oauth2.TokenUse, request oauth2.AccessRequester, _ []string) (use oauth2.TokenUse, err error) {
	id, ok := strings.CutPrefix(token, ssfTestTokenPrefix)
	if !ok {
		return "", oauth2.ErrUnknownRequest
	}

	client, err := i.tx.store.GetClient(ctx, id)
	if err != nil {
		return "", oauth2.ErrUnknownRequest
	}

	ar, ok := request.(*oauth2.AccessRequest)
	if !ok {
		return "", oauth2.ErrUnknownRequest
	}

	ar.Client = client
	ar.GrantedScope = oauth2.Arguments{oauth2.ScopeSSFManage}
	ar.GrantedAudience = oauth2.Arguments{i.tx.server.URL}

	return oauth2.AccessToken, nil
}

// ssfTestSent is a SET the Transmitter issued, and the outcome of the push when its stream is a push stream.
type ssfTestSent struct {
	token, jti string
	result     oauth2.SSFPushResult
}

// ssfTestTransmitter is this library's Transmitter with the routes, the queue of the poll streams and the delivery of
// the verification event an application adds to it.
type ssfTestTransmitter struct {
	server   *httptest.Server
	provider *oauth2.Fosite
	store    ssfTestStore

	mu      sync.Mutex
	queue   map[string]map[string]string
	acked   []string
	setErrs map[string]oauth2.SSFPollSetError
	wake    chan struct{}
}

func newSSFTestTransmitter(t *testing.T, store ssfTestStore, key *rsa.PrivateKey) *ssfTestTransmitter {
	t.Helper()

	tx := &ssfTestTransmitter{
		store:   store,
		queue:   map[string]map[string]string{},
		setErrs: map[string]oauth2.SSFPollSetError{},
		wake:    make(chan struct{}, 1),
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/.well-known/ssf-configuration", tx.serveConfiguration)
	mux.HandleFunc("/jwks.json", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "sig-1", Use: jwt.JSONWebTokenUseSignature, Algorithm: string(jose.RS256)}}})
	})
	mux.HandleFunc("/ssf/streams", tx.serveStreams)
	mux.HandleFunc("/ssf/status", tx.serveStatus)
	mux.HandleFunc("/ssf/verify", tx.serveVerification)
	mux.HandleFunc(ssfTestPollPath+"{id}", tx.servePoll)

	tx.server = httptest.NewTLSServer(mux)

	t.Cleanup(tx.server.Close)

	config := &oauth2.Config{
		Issuer:                                tx.server.URL,
		SpecialUseAddressGuardAllowedNetworks: []*net.IPNet{ssfTestLoopback()},
		TokenIntrospectionHandlers:            oauth2.TokenIntrospectionHandlers{ssfTestIntrospector{tx: tx}},
	}

	config.SSF = &oauth2.SSFConfig{
		TokenStrategy: &oauth2.DefaultSecurityEventTokenStrategy{Strategy: &jwt.DefaultStrategy{
			Config: config,
			Issuer: jwt.NewDefaultIssuerUnverifiedFromJWKS(&jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
				{Key: key, KeyID: "sig-1", Use: jwt.JSONWebTokenUseSignature, Algorithm: string(jose.RS256)},
			}}),
		}},
		Policy:            tx,
		EndpointValidator: tx,
		HTTPClient:        &retryablehttp.Client{HTTPClient: tx.server.Client(), CheckRetry: retryablehttp.DefaultRetryPolicy, Backoff: retryablehttp.DefaultBackoff},
		PollEndpointURL: func(_ context.Context, streamID string) (endpoint string, err error) {
			return tx.server.URL + ssfTestPollPath + streamID, nil
		},
		VerificationHandler: tx,
	}

	tx.provider = &oauth2.Fosite{Store: store, Config: config}

	return tx
}

// SSFStreamPolicy implements oauth2.SSFStreamPolicy.
func (tx *ssfTestTransmitter) SSFStreamPolicy(_ context.Context, client oauth2.Client) (policy *oauth2.SSFClientPolicy, err error) {
	return &oauth2.SSFClientPolicy{
		Audience:        []string{ssfTestAudience(client.GetID())},
		EventsSupported: []string{jwt.SecurityEventTypeCAEPSessionRevoked, jwt.SecurityEventTypeCAEPCredentialChange},
		DeliveryMethods: []string{oauth2.SSFDeliveryMethodPush, oauth2.SSFDeliveryMethodPoll},
	}, nil
}

// ValidateSSFEndpoint implements oauth2.SSFEndpointValidator.
func (tx *ssfTestTransmitter) ValidateSSFEndpoint(_ context.Context, _ oauth2.Client, endpoint *url.URL) (err error) {
	if !ssfTestLoopback().Contains(net.ParseIP(endpoint.Hostname())) {
		return errors.New("the endpoint is not a test server")
	}

	return nil
}

// HandleSSFVerification implements oauth2.SSFVerificationHandler: the event is pushed before the request is answered,
// or queued for the next poll.
func (tx *ssfTestTransmitter) HandleSSFVerification(ctx context.Context, stream *oauth2.SSFStream, state *string) (err error) {
	var (
		subject *jwt.SubjectIdentifier
		sent    ssfTestSent
	)

	if subject, err = oauth2.NewSSFVerificationSubject(stream.StreamID); err != nil {
		return err
	}

	if sent, err = tx.send(ctx, stream, subject, &jwt.SSFVerification{State: state}, ""); err != nil {
		return err
	}

	if stream.Delivery.Method == oauth2.SSFDeliveryMethodPush && sent.result.Outcome != oauth2.SSFPushDelivered {
		return sent.result.Err
	}

	return nil
}

// send issues the SET of the event for the stream and delivers it as the stream is delivered: a push stream with one
// push attempt, a poll stream by the queue its poll endpoint answers from.
func (tx *ssfTestTransmitter) send(ctx context.Context, stream *oauth2.SSFStream, subject *jwt.SubjectIdentifier, event jwt.SecurityEvent, txn string) (sent ssfTestSent, err error) {
	if sent.token, sent.jti, err = tx.provider.GenerateSecurityEventToken(ctx, stream, subject, event, "", txn); err != nil {
		return sent, err
	}

	if stream.Delivery.Method == oauth2.SSFDeliveryMethodPoll {
		tx.enqueue(stream.StreamID, sent.jti, sent.token)

		return sent, nil
	}

	sent.result, err = tx.push(ctx, stream, event.SecurityEventType(), sent.token)

	return sent, err
}

func (tx *ssfTestTransmitter) push(ctx context.Context, stream *oauth2.SSFStream, eventType, token string) (result oauth2.SSFPushResult, err error) {
	var client oauth2.Client

	if client, err = tx.store.GetClient(ctx, stream.ClientID); err != nil {
		return result, err
	}

	return tx.provider.PushSecurityEventTokenToStream(ctx, client, stream.StreamID, eventType, token), nil
}

// stream returns the stored stream of the client, which has at most one.
func (tx *ssfTestTransmitter) stream(t *testing.T, clientID string) *oauth2.SSFStream {
	t.Helper()

	streams, err := tx.store.ListSSFStreams(t.Context(), clientID)

	require.NoError(t, err)
	require.Len(t, streams, 1)

	return streams[0]
}

// emit sends the event on the stream of the authorization server.
func (tx *ssfTestTransmitter) emit(t *testing.T, subject *jwt.SubjectIdentifier, event jwt.SecurityEvent, txn string) ssfTestSent {
	t.Helper()

	sent, err := tx.send(t.Context(), tx.stream(t, ssfTestServerClient), subject, event, txn)

	require.NoError(t, err)

	return sent
}

func (tx *ssfTestTransmitter) enqueue(streamID, jti, token string) {
	tx.mu.Lock()

	if tx.queue[streamID] == nil {
		tx.queue[streamID] = map[string]string{}
	}

	tx.queue[streamID][jti] = token

	tx.mu.Unlock()

	select {
	case tx.wake <- struct{}{}:
	default:
	}
}

// settle removes the SETs of the stream the Receiver acknowledged or reported.
//
// See: https://www.rfc-editor.org/rfc/rfc8936#section-2.4
func (tx *ssfTestTransmitter) settle(streamID string, ack []string, setErrs map[string]oauth2.SSFPollSetError) {
	tx.mu.Lock()
	defer tx.mu.Unlock()

	for _, jti := range ack {
		if _, ok := tx.queue[streamID][jti]; ok {
			delete(tx.queue[streamID], jti)

			tx.acked = append(tx.acked, jti)
		}
	}

	for jti, serr := range setErrs {
		if _, ok := tx.queue[streamID][jti]; ok {
			delete(tx.queue[streamID], jti)

			tx.setErrs[jti] = serr
		}
	}
}

// take returns up to limit SETs of the stream, which stay queued until they are settled.
func (tx *ssfTestTransmitter) take(streamID string, limit int) (sets map[string]string, more bool) {
	tx.mu.Lock()
	defer tx.mu.Unlock()

	sets = map[string]string{}

	for jti, token := range tx.queue[streamID] {
		if len(sets) == limit {
			return sets, true
		}

		sets[jti] = token
	}

	return sets, false
}

func (tx *ssfTestTransmitter) queued(streamID string) (n int) {
	tx.mu.Lock()
	defer tx.mu.Unlock()

	return len(tx.queue[streamID])
}

func (tx *ssfTestTransmitter) acknowledged() []string {
	tx.mu.Lock()
	defer tx.mu.Unlock()

	return slices.Clone(tx.acked)
}

func (tx *ssfTestTransmitter) reported() (n int) {
	tx.mu.Lock()
	defer tx.mu.Unlock()

	return len(tx.setErrs)
}

func (tx *ssfTestTransmitter) serveConfiguration(w http.ResponseWriter, r *http.Request) {
	tx.provider.WriteSSFConfiguration(r.Context(), w, &oauth2.SSFConfiguration{
		SpecVersion:              oauth2.SSFSpecVersion,
		Issuer:                   tx.server.URL,
		JWKSURI:                  tx.server.URL + "/jwks.json",
		DeliveryMethodsSupported: []string{oauth2.SSFDeliveryMethodPush, oauth2.SSFDeliveryMethodPoll},
		ConfigurationEndpoint:    tx.server.URL + "/ssf/streams",
		StatusEndpoint:           tx.server.URL + "/ssf/status",
		VerificationEndpoint:     tx.server.URL + "/ssf/verify",
		AuthorizationSchemes:     []oauth2.SSFAuthorizationScheme{{SpecURN: oauth2.SSFAuthorizationSchemeOAuth2}},
	})
}

func (tx *ssfTestTransmitter) serveStreams(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	requester, err := tx.provider.NewSSFStreamRequest(ctx, r, &oauth2.DefaultSession{})
	if err != nil {
		tx.provider.WriteSSFError(ctx, w, r, err)

		return
	}

	responder, err := tx.provider.NewSSFStreamResponse(ctx, requester)
	if err != nil {
		tx.provider.WriteSSFError(ctx, w, r, err)

		return
	}

	tx.provider.WriteSSFStreamResponse(ctx, w, requester, responder)
}

func (tx *ssfTestTransmitter) serveStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	requester, err := tx.provider.NewSSFStreamStatusRequest(ctx, r, &oauth2.DefaultSession{})
	if err != nil {
		tx.provider.WriteSSFError(ctx, w, r, err)

		return
	}

	responder, err := tx.provider.NewSSFStreamStatusResponse(ctx, requester)
	if err != nil {
		tx.provider.WriteSSFError(ctx, w, r, err)

		return
	}

	tx.provider.WriteSSFStreamStatusResponse(ctx, w, requester, responder)
}

func (tx *ssfTestTransmitter) serveVerification(w http.ResponseWriter, r *http.Request) {
	if err := tx.provider.HandleSSFVerificationRequest(r.Context(), r, &oauth2.DefaultSession{}); err != nil {
		tx.provider.WriteSSFError(r.Context(), w, r, err)

		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// servePoll answers a poll request from the queue of the stream, and holds one which asks to wait until a SET is
// queued or ssfTestLongPoll has passed.
//
// See: https://www.rfc-editor.org/rfc/rfc8936#section-2.5
func (tx *ssfTestTransmitter) servePoll(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	request, err := tx.provider.NewSSFPollRequest(ctx, r, &oauth2.DefaultSession{}, r.PathValue("id"))
	if err != nil {
		tx.provider.WriteSSFPollError(ctx, w, r, err)

		return
	}

	id, limit := request.Stream.StreamID, 10

	if request.MaxEvents != nil {
		limit = min(limit, *request.MaxEvents)
	}

	tx.settle(id, request.Ack, request.SetErrs)

	sets, more := tx.take(id, limit)

	if len(sets) == 0 && limit != 0 && !request.ReturnImmediately {
		select {
		case <-tx.wake:
		case <-time.After(ssfTestLongPoll):
		case <-ctx.Done():
			return
		}

		sets, more = tx.take(id, limit)
	}

	tx.provider.WriteSSFPollResponse(ctx, w, sets, more)
}

// ssfTestReceiver is a Receiver with the route of its push endpoints, an EventHandler which only records, and a
// SubjectResolver.
type ssfTestReceiver struct {
	server   *httptest.Server
	receiver *ssfreceiver.Receiver
	store    ssfTestStore

	// principals is the principal of each 'email' or opaque 'id' the application knows.
	principals map[string]string

	mu           sync.Mutex
	events       []*ssfreceiver.ReceivedEvent
	streamEvents []*ssfreceiver.ReceivedEvent
	failures     []error
}

func newSSFTestReceiver(t *testing.T, store ssfTestStore, clientID string, decryption jose.JSONWebKey, principals map[string]string) *ssfTestReceiver {
	t.Helper()

	rx := &ssfTestReceiver{store: store, principals: principals}

	rx.server = httptest.NewTLSServer(http.HandlerFunc(rx.servePush))

	t.Cleanup(rx.server.Close)

	rx.receiver = &ssfreceiver.Receiver{
		Store: store,
		Config: ssfreceiver.Config{
			Strategy:               &jwt.DefaultStrategy{Issuer: jwt.NewDefaultIssuerUnverifiedFromJWKS(&jose.JSONWebKeySet{Keys: []jose.JSONWebKey{decryption}})},
			HTTPClient:             &retryablehttp.Client{HTTPClient: rx.server.Client(), CheckRetry: retryablehttp.DefaultRetryPolicy, Backoff: retryablehttp.DefaultBackoff},
			SpecialUseAddressGuard: ssfTestLoopbackGuard{},
			Authorizer: &ssfreceiver.BearerAuthorizer{Token: func(context.Context, string, string) (token string, err error) {
				return ssfTestTokenPrefix + clientID, nil
			}},
			Handler:       rx,
			StreamHandler: rx,
			Subjects:      rx,
		},
	}

	return rx
}

// servePush routes a push delivery request: the record is looked up from the request URL, one per stream.
//
// See: https://www.rfc-editor.org/rfc/rfc8935#section-2
func (rx *ssfTestReceiver) servePush(w http.ResponseWriter, r *http.Request) {
	record, err := rx.store.GetSSFReceiverStreamByPushEndpoint(r.Context(), rx.server.URL+r.URL.Path)
	if err != nil {
		http.NotFound(w, r)

		return
	}

	if err = rx.receiver.HandlePush(r.Context(), w, r, record); err != nil {
		rx.mu.Lock()
		rx.failures = append(rx.failures, err)
		rx.mu.Unlock()
	}
}

// HandleSecurityEvent implements ssfreceiver.EventHandler. It persists the event and does not act on it.
func (rx *ssfTestReceiver) HandleSecurityEvent(_ context.Context, event *ssfreceiver.ReceivedEvent) (err error) {
	rx.mu.Lock()
	defer rx.mu.Unlock()

	rx.events = append(rx.events, event)

	return nil
}

// HandleStreamEvent implements ssfreceiver.StreamEventHandler.
func (rx *ssfTestReceiver) HandleStreamEvent(_ context.Context, event *ssfreceiver.ReceivedEvent) (err error) {
	rx.mu.Lock()
	defer rx.mu.Unlock()

	rx.streamEvents = append(rx.streamEvents, event)

	return nil
}

// ResolveSubject implements ssfreceiver.SubjectResolver.
func (rx *ssfTestReceiver) ResolveSubject(_ context.Context, _ *ssfreceiver.StreamRecord, subject *jwt.SubjectIdentifier) (principal any, err error) {
	if name, ok := rx.principals[subject.Email+subject.ID]; ok {
		return name, nil
	}

	return nil, ssfreceiver.ErrSubjectUnknown
}

func (rx *ssfTestReceiver) received() []*ssfreceiver.ReceivedEvent {
	rx.mu.Lock()
	defer rx.mu.Unlock()

	return slices.Clone(rx.events)
}

func (rx *ssfTestReceiver) receivedStreamEvents() []*ssfreceiver.ReceivedEvent {
	rx.mu.Lock()
	defer rx.mu.Unlock()

	return slices.Clone(rx.streamEvents)
}

func (rx *ssfTestReceiver) pushFailures() []error {
	rx.mu.Lock()
	defer rx.mu.Unlock()

	return slices.Clone(rx.failures)
}

func (rx *ssfTestReceiver) stored(t *testing.T, issuer, streamID string) *ssfreceiver.StreamRecord {
	t.Helper()

	record, err := rx.store.GetSSFReceiverStream(t.Context(), issuer, streamID)

	require.NoError(t, err)

	return record
}

// create creates a stream of the delivery method at the Transmitter, which is a push stream to a new endpoint URL of
// the Receiver or a poll stream.
func (rx *ssfTestReceiver) create(t *testing.T, tx *ssfTestTransmitter, clientID, method string) *ssfreceiver.StreamRecord {
	t.Helper()

	delivery := oauth2.SSFDelivery{Method: method}

	if method == oauth2.SSFDeliveryMethodPush {
		delivery.EndpointURL, delivery.AuthorizationHeader = rx.server.URL+ssfTestPushPath+clientID, ssfTestPushSecret
	}

	record, err := rx.receiver.CreateStream(t.Context(), ssfreceiver.CreateStreamRequest{
		Issuer:          tx.server.URL,
		Audience:        []string{ssfTestAudience(clientID)},
		Delivery:        delivery,
		EventsRequested: []string{jwt.SecurityEventTypeCAEPSessionRevoked},
	})

	require.NoError(t, err)
	require.NotEmpty(t, record.StreamID)

	assert.Equal(t, ssfreceiver.StreamRecordActive, record.State)
	assert.Equal(t, []string{ssfTestAudience(clientID)}, record.Audience)
	assert.Equal(t, []string{jwt.SecurityEventTypeCAEPSessionRevoked}, record.EventsDelivered)
	assert.Equal(t, record, rx.stored(t, tx.server.URL, record.StreamID))
	assert.Equal(t, record.StreamID, tx.stream(t, clientID).StreamID)

	return record
}

// ssfTestKeys are the RSA signing keys of the two Transmitters, which every subtest shares.
type ssfTestKeys struct {
	upstream, server *rsa.PrivateKey
}

// ssfTestEnvironment is an upstream Transmitter, the authorization server which is a Receiver of it and a Transmitter
// over the same store, and a downstream Receiver of the authorization server.
type ssfTestEnvironment struct {
	upstream    *ssfTestTransmitter
	server      *ssfTestReceiver
	transmitter *ssfTestTransmitter
	downstream  *ssfTestReceiver
}

// newSSFTestEnvironment returns the environment over new stores. When encrypted the upstream Transmitter encrypts
// each SET to the key of the authorization server.
func newSSFTestEnvironment(t *testing.T, st ssfTestStoreType, keys ssfTestKeys, encrypted bool) *ssfTestEnvironment {
	t.Helper()

	env := &ssfTestEnvironment{}

	decryption := gen.MustES256Key()

	upstream, clients := st.new()

	clients[ssfTestServerClient] = &oauth2.DefaultClient{ID: ssfTestServerClient}

	if encrypted {
		clients[ssfTestServerClient] = &oauth2.DefaultRegisteredClient{
			DefaultClient: &oauth2.DefaultClient{ID: ssfTestServerClient},
			JSONWebKeys: &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
				{Key: &decryption.PublicKey, KeyID: "enc-1", Use: jwt.JSONWebTokenUseEncryption, Algorithm: string(jose.ECDH_ES)},
			}},
			SecurityEventTokenEncryptedResponseAlg: string(jose.ECDH_ES),
			SecurityEventTokenEncryptedResponseEnc: string(jose.A256GCM),
		}
	}

	env.upstream = newSSFTestTransmitter(t, upstream, keys.upstream)

	server, clients := st.new()

	clients[ssfTestDownstreamClient] = &oauth2.DefaultClient{ID: ssfTestDownstreamClient}

	env.server = newSSFTestReceiver(t, server, ssfTestServerClient,
		jose.JSONWebKey{Key: decryption, KeyID: "enc-1", Use: jwt.JSONWebTokenUseEncryption, Algorithm: string(jose.ECDH_ES)},
		map[string]string{ssfTestUpstreamEmail: ssfTestPrincipal})

	env.transmitter = newSSFTestTransmitter(t, server, keys.server)

	downstream, _ := st.new()

	env.downstream = newSSFTestReceiver(t, downstream, ssfTestDownstreamClient,
		jose.JSONWebKey{Key: gen.MustES256Key(), KeyID: "enc-1", Use: jwt.JSONWebTokenUseEncryption, Algorithm: string(jose.ECDH_ES)},
		map[string]string{ssfTestPairwise: "downstream-user-1"})

	return env
}

func ssfTestEmailSubject(t *testing.T, email string) *jwt.SubjectIdentifier {
	t.Helper()

	subject, err := jwt.NewSubjectIdentifierEmail(email)

	require.NoError(t, err)

	return subject
}

func ssfTestSessionRevoked() *jwt.CAEPSessionRevoked {
	return &jwt.CAEPSessionRevoked{SecurityEventCommon: jwt.SecurityEventCommon{
		EventTimestamp:   time.Now().Unix(),
		InitiatingEntity: jwt.SecurityEventInitiatingEntityPolicy,
		ReasonAdmin:      map[string]string{"en": "A reason of the upstream Transmitter."},
	}}
}

type ssfTestRelayStreams func(ctx context.Context, eventType string) (streams []*oauth2.SSFStream, err error)

func (f ssfTestRelayStreams) RelayStreams(ctx context.Context, eventType string) (streams []*oauth2.SSFStream, err error) {
	return f(ctx, eventType)
}

type ssfTestRelaySubjects func(ctx context.Context, stream *oauth2.SSFStream, event *ssfreceiver.RelayEvent) (subject *jwt.SubjectIdentifier, err error)

func (f ssfTestRelaySubjects) MapRelaySubject(ctx context.Context, stream *oauth2.SSFStream, event *ssfreceiver.RelayEvent) (subject *jwt.SubjectIdentifier, err error) {
	return f(ctx, stream, event)
}

// TestSSFTransmitterAgainstReceiver runs this library's Transmitter against its Receiver in one process: the streams
// are created, verified, updated and deleted through the stream management endpoints, the SETs are delivered by push
// and by poll, signed and encrypted, and a received event is relayed to a stream of the authorization server.
func TestSSFTransmitterAgainstReceiver(t *testing.T) {
	keys := ssfTestKeys{upstream: gen.MustRSAKey(), server: gen.MustRSAKey()}

	for _, st := range ssfTestStoreTypes() {
		t.Run(st.name, func(t *testing.T) {
			t.Run("ShouldReceivePushedEvents", func(t *testing.T) {
				testSSFPushDelivery(t, newSSFTestEnvironment(t, st, keys, false))
			})

			t.Run("ShouldReceiveEncryptedPushedEvents", func(t *testing.T) {
				env := newSSFTestEnvironment(t, st, keys, true)

				env.server.create(t, env.upstream, ssfTestServerClient, oauth2.SSFDeliveryMethodPush)

				sent := env.upstream.emit(t, ssfTestEmailSubject(t, ssfTestUpstreamEmail), ssfTestSessionRevoked(), "txn-1")

				require.True(t, jwt.IsEncryptedJWT(sent.token))
				require.Equal(t, oauth2.SSFPushDelivered, sent.result.Outcome, "%+v", sent.result)

				events := env.server.received()

				require.Len(t, events, 1)
				assert.True(t, events[0].Encrypted)
				assert.True(t, jwt.IsSignedJWT(events[0].Token))
				assert.Equal(t, sent.jti, events[0].Claims.JTI)
				assert.Equal(t, ssfTestPrincipal, events[0].Principal)
				assert.Empty(t, env.server.pushFailures())
			})

			t.Run("ShouldReceivePolledEvents", func(t *testing.T) {
				testSSFPollDelivery(t, newSSFTestEnvironment(t, st, keys, true))
			})

			t.Run("ShouldReceivePolledEventsWithPoller", func(t *testing.T) {
				testSSFPoller(t, newSSFTestEnvironment(t, st, keys, false))
			})

			t.Run("ShouldRelayReceivedEvent", func(t *testing.T) {
				testSSFRelay(t, newSSFTestEnvironment(t, st, keys, false))
			})
		})
	}
}

// testSSFPushDelivery covers a push stream: create, verification, delivery, a repeated delivery, an unknown subject,
// a status change of each party, a rotated secret and delete.
func testSSFPushDelivery(t *testing.T, env *ssfTestEnvironment) {
	ctx, issuer := t.Context(), env.upstream.server.URL

	record := env.server.create(t, env.upstream, ssfTestServerClient, oauth2.SSFDeliveryMethodPush)

	assert.Equal(t, ssfTestPushSecret, record.Delivery.AuthorizationHeader)
	assert.Equal(t, ssfTestPushSecret, env.upstream.stream(t, ssfTestServerClient).Delivery.AuthorizationHeader)

	status, err := env.server.receiver.ReadStreamStatus(ctx, issuer, record.StreamID)

	require.NoError(t, err)
	assert.Equal(t, oauth2.SSFStreamStatusEnabled, status.Status)

	// SSF Section 8.1.4.2: the event is pushed before the verification request is answered.
	require.NoError(t, env.server.receiver.RequestStreamVerification(ctx, issuer, record.StreamID))

	stored := env.server.stored(t, issuer, record.StreamID)

	assert.WithinDuration(t, time.Now(), stored.VerifiedAt, time.Minute)
	assert.Empty(t, stored.VerificationState)
	assert.True(t, stored.VerificationRequestedAt.IsZero())

	streamEvents := env.server.receivedStreamEvents()

	require.Len(t, streamEvents, 1)
	assert.Equal(t, jwt.SecurityEventTypeSSFVerification, streamEvents[0].Type)

	sent := env.upstream.emit(t, ssfTestEmailSubject(t, ssfTestUpstreamEmail), ssfTestSessionRevoked(), "txn-1")

	require.Equal(t, oauth2.SSFPushDelivered, sent.result.Outcome, "%+v", sent.result)
	assert.Equal(t, http.StatusAccepted, sent.result.Status)
	assert.True(t, jwt.IsSignedJWT(sent.token))

	events := env.server.received()

	require.Len(t, events, 1)
	assert.Equal(t, jwt.SecurityEventTypeCAEPSessionRevoked, events[0].Type)
	assert.IsType(t, &jwt.CAEPSessionRevoked{}, events[0].Event)
	assert.Equal(t, issuer, events[0].Claims.Issuer)
	assert.Equal(t, sent.jti, events[0].Claims.JTI)
	assert.Equal(t, "txn-1", events[0].Claims.Transaction)
	assert.Equal(t, ssfTestUpstreamEmail, events[0].Claims.SubjectIdentifier.Email)
	assert.Equal(t, ssfTestPrincipal, events[0].Principal)
	assert.Equal(t, sent.token, events[0].Token)
	assert.False(t, events[0].Encrypted)
	assert.Empty(t, events[0].Stream.Delivery.AuthorizationHeader)

	// RFC 8935 Section 2: a SET delivered again is acknowledged and not handled again.
	result, err := env.upstream.push(ctx, env.upstream.stream(t, ssfTestServerClient), jwt.SecurityEventTypeCAEPSessionRevoked, sent.token)

	require.NoError(t, err)
	assert.Equal(t, oauth2.SSFPushDelivered, result.Outcome)
	assert.Len(t, env.server.received(), 1)

	// SSF Section 9.3: a subject the Receiver does not know is acknowledged and not handled.
	sent = env.upstream.emit(t, ssfTestEmailSubject(t, "unknown@upstream.example.com"), ssfTestSessionRevoked(), "txn-2")

	assert.Equal(t, oauth2.SSFPushDelivered, sent.result.Outcome)
	assert.Len(t, env.server.received(), 1)

	// SSF Section 8.1.5: the Transmitter pauses the stream and tells the Receiver.
	subject, err := oauth2.NewSSFVerificationSubject(record.StreamID)

	require.NoError(t, err)
	require.NoError(t, env.upstream.store.UpdateSSFStreamStatus(ctx, ssfTestServerClient, record.StreamID, oauth2.SSFStreamStatusPaused, "Maintenance"))

	sent = env.upstream.emit(t, subject, oauth2.NewSSFStreamUpdatedEvent(oauth2.SSFStreamStatusPaused, "Maintenance"), "")

	require.Equal(t, oauth2.SSFPushDelivered, sent.result.Outcome, "%+v", sent.result)

	stored = env.server.stored(t, issuer, record.StreamID)

	assert.Equal(t, oauth2.SSFStreamStatusPaused, stored.Status)
	assert.Equal(t, "Maintenance", stored.StatusReason)

	streamEvents = env.server.receivedStreamEvents()

	require.Len(t, streamEvents, 2)
	assert.Equal(t, jwt.SecurityEventTypeSSFStreamUpdated, streamEvents[1].Type)
	assert.Equal(t, oauth2.SSFStreamStatusPaused, streamEvents[1].Stream.Status)

	// SSF Section 8.1.2.1: the Transmitter holds the events of a paused stream.
	sent = env.upstream.emit(t, ssfTestEmailSubject(t, ssfTestUpstreamEmail), ssfTestSessionRevoked(), "txn-3")

	assert.Equal(t, oauth2.SSFPushRetryable, sent.result.Outcome)
	require.ErrorIs(t, sent.result.Err, oauth2.ErrSSFStreamPaused)
	assert.Len(t, env.server.received(), 1)

	// SSF Section 8.1.2.2: the Receiver enables the stream, and the held SET is delivered.
	updated, err := env.server.receiver.UpdateStreamStatus(ctx, issuer, record.StreamID, oauth2.SSFStreamStatusEnabled, "")

	require.NoError(t, err)
	assert.Equal(t, oauth2.SSFStreamStatusEnabled, updated.Status)
	assert.Equal(t, oauth2.SSFStreamStatusEnabled, env.server.stored(t, issuer, record.StreamID).Status)
	assert.Equal(t, oauth2.SSFStreamStatusEnabled, env.upstream.stream(t, ssfTestServerClient).Status)

	result, err = env.upstream.push(ctx, env.upstream.stream(t, ssfTestServerClient), jwt.SecurityEventTypeCAEPSessionRevoked, sent.token)

	require.NoError(t, err)
	assert.Equal(t, oauth2.SSFPushDelivered, result.Outcome)

	events = env.server.received()

	require.Len(t, events, 2)
	assert.Equal(t, "txn-3", events[1].Claims.Transaction)

	// SSF Section 8.1.1.4: the secret is rotated by replacing the stream, and the next push has the new one.
	replaced, err := env.server.receiver.ReplaceStream(ctx, issuer, record.StreamID, ssfreceiver.StreamReplacement{
		Delivery:        oauth2.SSFDelivery{Method: oauth2.SSFDeliveryMethodPush, EndpointURL: record.Delivery.EndpointURL, AuthorizationHeader: ssfTestPushRotated},
		EventsRequested: []string{jwt.SecurityEventTypeCAEPSessionRevoked},
	})

	require.NoError(t, err)
	assert.Equal(t, ssfTestPushRotated, replaced.Delivery.AuthorizationHeader)
	assert.Equal(t, ssfTestPushRotated, env.server.stored(t, issuer, record.StreamID).Delivery.AuthorizationHeader)
	assert.Equal(t, ssfTestPushRotated, env.upstream.stream(t, ssfTestServerClient).Delivery.AuthorizationHeader)

	sent = env.upstream.emit(t, ssfTestEmailSubject(t, ssfTestUpstreamEmail), ssfTestSessionRevoked(), "txn-4")

	require.Equal(t, oauth2.SSFPushDelivered, sent.result.Outcome, "%+v", sent.result)
	assert.Len(t, env.server.received(), 3)

	// The activity which restarts the inactivity timeout of a push stream.
	require.NoError(t, env.server.receiver.Touch(ctx, issuer, record.StreamID))

	configurations, err := env.server.receiver.ListStreams(ctx, issuer)

	require.NoError(t, err)
	require.Len(t, configurations, 1)
	assert.Equal(t, record.StreamID, configurations[0].StreamID)

	require.NoError(t, env.server.receiver.DeleteStream(ctx, issuer, record.StreamID))

	streams, err := env.upstream.store.ListSSFStreams(ctx, ssfTestServerClient)

	require.NoError(t, err)
	assert.Empty(t, streams)

	_, err = env.server.store.GetSSFReceiverStream(ctx, issuer, record.StreamID)

	require.ErrorIs(t, err, oauth2.ErrNotFound)
	assert.Empty(t, env.server.pushFailures())
}

// testSSFPollDelivery covers a poll stream with Receiver.Poll: create, verification, an encrypted SET, a SET the
// Transmitter delivers again, and the acknowledgement.
func testSSFPollDelivery(t *testing.T, env *ssfTestEnvironment) {
	ctx, issuer := t.Context(), env.upstream.server.URL

	record := env.server.create(t, env.upstream, ssfTestServerClient, oauth2.SSFDeliveryMethodPoll)

	assert.Equal(t, oauth2.SSFDeliveryMethodPoll, record.Delivery.Method)
	assert.Equal(t, issuer+ssfTestPollPath+record.StreamID, record.Delivery.EndpointURL)

	result, err := env.server.receiver.Poll(ctx, issuer, record.StreamID, ssfreceiver.PollRequest{ReturnImmediately: true})

	require.NoError(t, err)
	assert.Empty(t, result.Ack)
	assert.Empty(t, result.Received)
	assert.False(t, result.MoreAvailable)

	require.NoError(t, env.server.receiver.RequestStreamVerification(ctx, issuer, record.StreamID))

	// SSF Section 8.1.4.2: the verification event is queued, so the request is still pending.
	assert.NotEmpty(t, env.server.stored(t, issuer, record.StreamID).VerificationState)
	assert.True(t, env.server.stored(t, issuer, record.StreamID).VerifiedAt.IsZero())

	sent := env.upstream.emit(t, ssfTestEmailSubject(t, ssfTestUpstreamEmail), ssfTestSessionRevoked(), "txn-1")

	require.True(t, jwt.IsEncryptedJWT(sent.token))
	require.Equal(t, 2, env.upstream.queued(record.StreamID))

	result, err = env.server.receiver.Poll(ctx, issuer, record.StreamID, ssfreceiver.PollRequest{ReturnImmediately: true})

	require.NoError(t, err)
	require.Len(t, result.Ack, 2)
	assert.Contains(t, result.Ack, sent.jti)
	assert.Empty(t, result.SetErrs)
	assert.Empty(t, result.Unacknowledged)

	require.Len(t, result.Received, 1)
	assert.Equal(t, sent.jti, result.Received[0].Claims.JTI)
	assert.Equal(t, ssfTestPrincipal, result.Received[0].Principal)
	assert.True(t, result.Received[0].Encrypted)
	assert.True(t, jwt.IsSignedJWT(result.Received[0].Token))
	assert.Len(t, env.server.received(), 1)

	stored := env.server.stored(t, issuer, record.StreamID)

	assert.WithinDuration(t, time.Now(), stored.VerifiedAt, time.Minute)
	assert.Empty(t, stored.VerificationState)
	require.Len(t, env.server.receivedStreamEvents(), 1)

	// RFC 8936 Section 2.4: the SETs are not acknowledged yet, so the Transmitter delivers them again, and they are
	// acknowledged and not handled again.
	again, err := env.server.receiver.Poll(ctx, issuer, record.StreamID, ssfreceiver.PollRequest{ReturnImmediately: true})

	require.NoError(t, err)
	assert.ElementsMatch(t, result.Ack, again.Ack)
	assert.Empty(t, again.Received)
	assert.Len(t, env.server.received(), 1)
	assert.Len(t, env.server.receivedStreamEvents(), 1)

	none := 0

	// RFC 8936 Section 2.4.2: an acknowledge-only request.
	last, err := env.server.receiver.Poll(ctx, issuer, record.StreamID, ssfreceiver.PollRequest{MaxEvents: &none, ReturnImmediately: true, Ack: again.Ack})

	require.NoError(t, err)
	assert.Empty(t, last.Ack)
	assert.Zero(t, env.upstream.queued(record.StreamID))
	assert.ElementsMatch(t, result.Ack, env.upstream.acknowledged())
	assert.Zero(t, env.upstream.reported())
}

// testSSFPoller covers a poll stream with a Poller, which long polls, hands each event to the EventHandler and
// acknowledges it in the next request, and in a last request when its context is done.
func testSSFPoller(t *testing.T, env *ssfTestEnvironment) {
	issuer := env.upstream.server.URL

	record := env.server.create(t, env.upstream, ssfTestServerClient, oauth2.SSFDeliveryMethodPoll)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	var (
		mu       sync.Mutex
		failures []error
	)

	poller := &ssfreceiver.Poller{
		Receiver: env.server.receiver,
		Issuer:   issuer,
		StreamID: record.StreamID,
		Interval: 10 * time.Millisecond,
		Backoff:  ssfreceiver.PollBackoff{Min: 10 * time.Millisecond, Max: 50 * time.Millisecond},
		Failure: func(err error, _ time.Duration) {
			mu.Lock()
			defer mu.Unlock()

			failures = append(failures, err)
		},
	}

	done := make(chan error, 1)

	go func() {
		done <- poller.Run(ctx)
	}()

	first := env.upstream.emit(t, ssfTestEmailSubject(t, ssfTestUpstreamEmail), ssfTestSessionRevoked(), "txn-1")

	require.Eventually(t, func() bool { return len(env.server.received()) == 1 }, 10*time.Second, 5*time.Millisecond)

	// The Poller acknowledged the first SET or is about to, and its next long poll returns the second.
	second := env.upstream.emit(t, ssfTestEmailSubject(t, ssfTestUpstreamEmail), ssfTestSessionRevoked(), "txn-2")

	require.Eventually(t, func() bool { return len(env.server.received()) == 2 }, 10*time.Second, 5*time.Millisecond)

	cancel()

	select {
	case err := <-done:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(10 * time.Second):
		require.Fail(t, "the poller did not return")
	}

	events := env.server.received()

	require.Len(t, events, 2)
	assert.ElementsMatch(t, []string{first.jti, second.jti}, []string{events[0].Claims.JTI, events[1].Claims.JTI})

	// Each SET is acknowledged by the request after it, or by the last request of the Poller.
	assert.ElementsMatch(t, []string{first.jti, second.jti}, env.upstream.acknowledged())
	assert.Zero(t, env.upstream.queued(record.StreamID))
	assert.Zero(t, env.upstream.reported())

	mu.Lock()
	defer mu.Unlock()

	assert.Empty(t, failures)
}

// testSSFRelay covers one event from the upstream Transmitter to the downstream Receiver: the authorization server
// receives it, prepares the SET of its own stream after its handler returned, and pushes it as it pushes its own.
func testSSFRelay(t *testing.T, env *ssfTestEnvironment) {
	ctx := t.Context()

	env.server.create(t, env.upstream, ssfTestServerClient, oauth2.SSFDeliveryMethodPush)
	env.downstream.create(t, env.transmitter, ssfTestDownstreamClient, oauth2.SSFDeliveryMethodPush)

	relay := &ssfreceiver.Relay{
		Provider: env.transmitter.provider,
		Streams: ssfTestRelayStreams(func(ctx context.Context, _ string) ([]*oauth2.SSFStream, error) {
			return env.transmitter.store.ListSSFStreams(ctx, ssfTestDownstreamClient)
		}),
		Subjects: ssfTestRelaySubjects(func(_ context.Context, _ *oauth2.SSFStream, event *ssfreceiver.RelayEvent) (*jwt.SubjectIdentifier, error) {
			if event.Principal != ssfTestPrincipal {
				return nil, ssfreceiver.ErrRelaySubjectNotCovered
			}

			return jwt.NewSubjectIdentifierOpaque(ssfTestPairwise)
		}),
		Policy:         ssfreceiver.RelayEventTypes(jwt.SecurityEventTypeCAEPSessionRevoked),
		Store:          env.server.store,
		TransactionKey: []byte("0123456789abcdef0123456789abcdef"),
	}

	sent := env.upstream.emit(t, ssfTestEmailSubject(t, ssfTestUpstreamEmail), ssfTestSessionRevoked(), "txn-1")

	require.Equal(t, oauth2.SSFPushDelivered, sent.result.Outcome, "%+v", sent.result)

	received := env.server.received()

	require.Len(t, received, 1)

	event, err := ssfreceiver.NewRelayEvent(received[0])

	require.NoError(t, err)

	tokens, skipped, err := relay.Prepare(ctx, event)

	require.NoError(t, err)
	require.Empty(t, skipped)
	require.Len(t, tokens, 1)
	assert.Equal(t, jwt.SecurityEventTypeCAEPSessionRevoked, tokens[0].EventType)
	assert.False(t, tokens[0].Held)
	assert.NotEqual(t, sent.token, tokens[0].Token)
	assert.NotEqual(t, sent.jti, tokens[0].JTI)

	// Prepare delivers nothing.
	assert.Empty(t, env.downstream.received())

	stream := env.transmitter.stream(t, ssfTestDownstreamClient)

	assert.Equal(t, stream.StreamID, tokens[0].Stream.StreamID)

	result, err := env.transmitter.push(ctx, stream, tokens[0].EventType, tokens[0].Token)

	require.NoError(t, err)
	require.Equal(t, oauth2.SSFPushDelivered, result.Outcome, "%+v", result)

	relayed := env.downstream.received()

	require.Len(t, relayed, 1)

	// SSF Section 10.1: a new SET of the authorization server, with the subject and the 'txn' of the stream.
	assert.Equal(t, env.transmitter.server.URL, relayed[0].Claims.Issuer)
	assert.Equal(t, []string{ssfTestAudience(ssfTestDownstreamClient)}, relayed[0].Claims.Audience)
	assert.Equal(t, tokens[0].JTI, relayed[0].Claims.JTI)
	assert.Equal(t, jwt.SubjectIdentifierFormatOpaque, relayed[0].Claims.SubjectIdentifier.Format)
	assert.Equal(t, ssfTestPairwise, relayed[0].Claims.SubjectIdentifier.ID)
	assert.Empty(t, relayed[0].Claims.SubjectIdentifier.Email)
	assert.NotEmpty(t, relayed[0].Claims.Transaction)
	assert.NotEqual(t, "txn-1", relayed[0].Claims.Transaction)
	assert.Equal(t, "downstream-user-1", relayed[0].Principal)

	revoked, ok := relayed[0].Event.(*jwt.CAEPSessionRevoked)

	require.True(t, ok)
	assert.Equal(t, received[0].Event.(*jwt.CAEPSessionRevoked).EventTimestamp, revoked.EventTimestamp)
	assert.Equal(t, jwt.SecurityEventInitiatingEntityPolicy, revoked.InitiatingEntity)
	assert.Empty(t, revoked.ReasonAdmin)

	// The same event is prepared again with the same identifiers, so the SET is acknowledged and not handled again.
	again, skipped, err := relay.Prepare(ctx, event)

	require.NoError(t, err)
	require.Empty(t, skipped)
	require.Len(t, again, 1)
	assert.Equal(t, tokens[0].JTI, again[0].JTI)

	result, err = env.transmitter.push(ctx, stream, again[0].EventType, again[0].Token)

	require.NoError(t, err)
	assert.Equal(t, oauth2.SSFPushDelivered, result.Outcome)
	assert.Len(t, env.downstream.received(), 1)

	// SSF Section 4.1.9: the copy of the event in another SET, which has its 'txn', is not relayed.
	copied := *event
	copied.OriginJTI = "another-jti"

	tokens, skipped, err = relay.Prepare(ctx, &copied)

	require.NoError(t, err)
	assert.Empty(t, tokens)
	assert.Empty(t, skipped)

	assert.Empty(t, env.server.pushFailures())
	assert.Empty(t, env.downstream.pushFailures())
}
