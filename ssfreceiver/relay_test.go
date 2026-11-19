// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package ssfreceiver_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"hash"
	"strings"
	"sync"
	"testing"

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
	testRelayIssuerURL    = "https://as.example.com"
	testRelayOriginIssuer = "https://idp.example.com"
	testRelayOriginJTI    = "origin-jti-1"
	testRelayTxn          = "txn-upstream-1"
	testRelayPrincipal    = "user-1"
	testRelayStreamA      = "stream-a"
	testRelayStreamB      = "stream-b"
	testRelayClientA      = "rx-a"
	testRelayClientB      = "rx-b"
	testRelayClientEnc    = "rx-enc"
	testRelayKeyID        = "as-sig-1"
	testRelayReceived     = "eyJ.received.token"
)

var (
	testRelayIssuerKey = sync.OnceValue(gen.MustRSAKey)
	testRelayClientKey = sync.OnceValue(gen.MustRSAKey)
)

var errTestRelay = errors.New("test relay failure")

type testRelayStreams struct {
	streams []*oauth2.SSFStream
	types   []string
	err     error
}

func (s *testRelayStreams) RelayStreams(_ context.Context, eventType string) (streams []*oauth2.SSFStream, err error) {
	s.types = append(s.types, eventType)

	return s.streams, s.err
}

// testRelaySubjects maps the principal to an opaque subject which is pairwise to the stream.
type testRelaySubjects struct {
	uncovered map[string]bool
	failing   map[string]bool
	mapped    []string
}

func (m *testRelaySubjects) MapRelaySubject(_ context.Context, stream *oauth2.SSFStream, event *ssfreceiver.RelayEvent) (subject *jwt.SubjectIdentifier, err error) {
	m.mapped = append(m.mapped, stream.StreamID)

	switch {
	case m.uncovered[stream.StreamID]:
		return nil, ssfreceiver.ErrRelaySubjectNotCovered
	case m.failing[stream.StreamID]:
		return nil, errTestRelay
	}

	// The mapper is handed a copy of the stream.
	stream.Audience = append(stream.Audience, "https://changed.example.com")

	return jwt.NewSubjectIdentifierOpaque(testRelaySubject(stream.StreamID, event.Principal))
}

func testRelaySubject(streamID string, principal any) string {
	return streamID + "|" + principal.(string)
}

type testRelayIssuer struct {
	ssfreceiver.RelayIssuer

	calls int
}

func (i *testRelayIssuer) GenerateSecurityEventToken(ctx context.Context, stream *oauth2.SSFStream, subject *jwt.SubjectIdentifier, event jwt.SecurityEvent, jti, txn string) (token, usedJTI string, err error) {
	i.calls++

	return i.RelayIssuer.GenerateSecurityEventToken(ctx, stream, subject, event, jti, txn)
}

type testRelay struct {
	relay    *ssfreceiver.Relay
	store    *storage.MemoryStore
	streams  *testRelayStreams
	subjects *testRelaySubjects
	issuer   *testRelayIssuer
	a, b     *oauth2.SSFStream
}

func newTestRelay(t *testing.T) *testRelay {
	t.Helper()

	x := &testRelay{store: storage.NewMemoryStore(), subjects: &testRelaySubjects{}}

	x.store.Clients[testRelayClientA] = &oauth2.DefaultClient{ID: testRelayClientA}
	x.store.Clients[testRelayClientB] = &oauth2.DefaultClient{ID: testRelayClientB}
	x.store.Clients[testRelayClientEnc] = &oauth2.DefaultRegisteredClient{
		DefaultClient: &oauth2.DefaultClient{ID: testRelayClientEnc},
		JSONWebKeys: &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
			{Key: &testRelayClientKey().PublicKey, KeyID: "rx-enc-1", Algorithm: string(jose.RSA_OAEP_256), Use: jwt.JSONWebTokenUseEncryption},
		}},
		SecurityEventTokenEncryptedResponseAlg: string(jose.RSA_OAEP_256),
		SecurityEventTokenEncryptedResponseEnc: string(jose.A256GCM),
	}

	config := &oauth2.Config{Issuer: testRelayIssuerURL}

	config.SSF = &oauth2.SSFConfig{TokenStrategy: &oauth2.DefaultSecurityEventTokenStrategy{Strategy: &jwt.DefaultStrategy{
		Config: config,
		Issuer: jwt.NewDefaultIssuerUnverifiedFromJWKS(&jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
			{Key: testRelayIssuerKey(), KeyID: testRelayKeyID, Algorithm: string(jose.RS256), Use: jwt.JSONWebTokenUseSignature},
		}}),
	}}}

	x.issuer = &testRelayIssuer{RelayIssuer: &oauth2.Fosite{Store: x.store, Config: config}}

	x.a = testRelayStream(testRelayStreamA, testRelayClientA, "https://rp-a.example.com")
	x.b = testRelayStream(testRelayStreamB, testRelayClientB, "https://rp-b.example.com")
	x.streams = &testRelayStreams{streams: []*oauth2.SSFStream{x.a, x.b}}

	x.relay = &ssfreceiver.Relay{
		Provider:       x.issuer,
		Streams:        x.streams,
		Subjects:       x.subjects,
		Policy:         ssfreceiver.RelayEventTypes(jwt.SecurityEventTypeCAEPSessionRevoked, jwt.SecurityEventTypeCAEPCredentialChange),
		Store:          x.store,
		TransactionKey: []byte(strings.Repeat("k", 32)),
	}

	return x
}

func testRelayStream(streamID, clientID, audience string) *oauth2.SSFStream {
	return &oauth2.SSFStream{
		StreamID:        streamID,
		ClientID:        clientID,
		Audience:        []string{audience},
		EventsDelivered: []string{jwt.SecurityEventTypeCAEPSessionRevoked, jwt.SecurityEventTypeCAEPCredentialChange},
		Status:          oauth2.SSFStreamStatusEnabled,
	}
}

func testRelayEvent() *ssfreceiver.RelayEvent {
	return &ssfreceiver.RelayEvent{
		Event: &jwt.CAEPSessionRevoked{SecurityEventCommon: jwt.SecurityEventCommon{
			EventTimestamp: 1700000000,
			ReasonAdmin:    map[string]string{"en": "Upstream policy 7 of the upstream staff"},
			ReasonUser:     map[string]string{"en": "Upstream text"},
		}},
		Transaction:  testRelayTxn,
		Principal:    testRelayPrincipal,
		OriginIssuer: testRelayOriginIssuer,
		OriginJTI:    testRelayOriginJTI,
	}
}

// testRelayDigest is the SHA-256 of the parts, each preceded by its length as 8 bytes, big endian.
func testRelayDigest(parts ...string) string {
	return testRelayHash(sha256.New(), parts...)
}

func testRelayMAC(key []byte, parts ...string) string {
	return testRelayHash(hmac.New(sha256.New, key), parts...)
}

func testRelayHash(h hash.Hash, parts ...string) string {
	for _, part := range parts {
		var size [8]byte

		binary.BigEndian.PutUint64(size[:], uint64(len(part)))

		_, _ = h.Write(size[:])
		_, _ = h.Write([]byte(part))
	}

	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

// testRelayDecode verifies the token with the key of the issuer and returns its header and claims. An encrypted token
// is first decrypted with the key of the client.
func testRelayDecode(t *testing.T, token string) (header jose.Header, claims map[string]any) {
	t.Helper()

	if strings.Count(token, ".") == 4 {
		jwe, err := jose.ParseEncryptedCompact(token, []jose.KeyAlgorithm{jose.RSA_OAEP_256}, []jose.ContentEncryption{jose.A256GCM})
		require.NoError(t, err)

		plaintext, err := jwe.Decrypt(testRelayClientKey())
		require.NoError(t, err)

		token = string(plaintext)
	}

	jws, err := jose.ParseSignedCompact(token, []jose.SignatureAlgorithm{jose.RS256})
	require.NoError(t, err)
	require.Len(t, jws.Signatures, 1)

	payload, err := jws.Verify(&testRelayIssuerKey().PublicKey)
	require.NoError(t, err)

	require.NoError(t, json.Unmarshal(payload, &claims))

	return jws.Signatures[0].Protected, claims
}

func testRelayTokens(t *testing.T, tokens []ssfreceiver.RelayToken) (byStream map[string]ssfreceiver.RelayToken) {
	t.Helper()

	byStream = map[string]ssfreceiver.RelayToken{}

	for _, token := range tokens {
		require.NotNil(t, token.Stream)

		byStream[token.Stream.StreamID] = token
	}

	require.Len(t, byStream, len(tokens))

	return byStream
}

func testRelaySkips(t *testing.T, skipped []ssfreceiver.RelaySkip) (byStream map[string]error) {
	t.Helper()

	byStream = map[string]error{}

	for _, skip := range skipped {
		require.NotNil(t, skip.Stream)
		require.Error(t, skip.Reason)

		byStream[skip.Stream.StreamID] = skip.Reason
	}

	require.Len(t, byStream, len(skipped))

	return byStream
}

func TestRelayPrepare(t *testing.T) {
	t.Run("ShouldIssueWithProviderIssuerAndStreamAudience", func(t *testing.T) {
		x := newTestRelay(t)
		x.relay.ReasonAdmin = map[string]string{"en": "Relayed by the authorization server"}

		tokens, skipped, err := x.relay.Prepare(t.Context(), testRelayEvent())

		require.NoError(t, err)
		assert.Empty(t, skipped)
		require.Len(t, tokens, 2)
		assert.Equal(t, []string{jwt.SecurityEventTypeCAEPSessionRevoked}, x.streams.types)

		byStream := testRelayTokens(t, tokens)

		for streamID, audience := range map[string]string{testRelayStreamA: "https://rp-a.example.com", testRelayStreamB: "https://rp-b.example.com"} {
			token := byStream[streamID]

			header, claims := testRelayDecode(t, token.Token)

			assert.Equal(t, testRelayKeyID, header.KeyID)
			assert.Equal(t, jwt.JSONWebTokenTypeSecurityEventToken, header.ExtraHeaders[jose.HeaderType])
			assert.Equal(t, testRelayIssuerURL, claims["iss"])
			assert.Equal(t, []any{audience}, claims["aud"])
			assert.Equal(t, token.JTI, claims["jti"])
			assert.Equal(t, jwt.SecurityEventTypeCAEPSessionRevoked, token.EventType)
			assert.False(t, token.Held)
			assert.Equal(t, []string{audience}, token.Stream.Audience)

			// CAEP Section 2, SSF Section 9.2: the event is the sanitized one.
			assert.Equal(t, map[string]any{jwt.SecurityEventTypeCAEPSessionRevoked: map[string]any{
				"event_timestamp": float64(1700000000),
				"reason_admin":    map[string]any{"en": "Relayed by the authorization server"},
			}}, claims["events"])
		}
	})

	t.Run("ShouldNeverReturnTheReceivedToken", func(t *testing.T) {
		x := newTestRelay(t)

		event, err := ssfreceiver.NewRelayEvent(testRelayReceivedEvent())
		require.NoError(t, err)

		tokens, _, err := x.relay.Prepare(t.Context(), event)

		require.NoError(t, err)
		require.Len(t, tokens, 2)

		for _, token := range tokens {
			assert.NotEqual(t, testRelayReceived, token.Token)
			assert.NotEqual(t, testRelayOriginJTI, token.JTI)

			_, claims := testRelayDecode(t, token.Token)

			assert.Equal(t, testRelayIssuerURL, claims["iss"])
			assert.NotEqual(t, testRelayOriginJTI, claims["jti"])
			assert.NotEqual(t, []any{testAudienceUpstream}, claims["aud"])
			assert.NotContains(t, token.Token, testRelayReceived)
		}
	})

	t.Run("ShouldRemapSubjectPerStream", func(t *testing.T) {
		x := newTestRelay(t)

		tokens, _, err := x.relay.Prepare(t.Context(), testRelayEvent())

		require.NoError(t, err)
		require.Len(t, tokens, 2)

		for streamID, token := range testRelayTokens(t, tokens) {
			_, claims := testRelayDecode(t, token.Token)

			assert.Equal(t, map[string]any{"format": "opaque", "id": testRelaySubject(streamID, testRelayPrincipal)}, claims["sub_id"])
			assert.NotContains(t, claims, "sub")
		}

		assert.Equal(t, []string{testRelayStreamA, testRelayStreamB}, x.subjects.mapped)
		assert.Equal(t, []string{"https://rp-a.example.com"}, x.a.Audience, "the mapper must be handed a copy of the stream")
	})

	t.Run("ShouldSkipStreamWithoutEventType", func(t *testing.T) {
		x := newTestRelay(t)
		x.b.EventsDelivered = []string{jwt.SecurityEventTypeCAEPCredentialChange}

		tokens, skipped, err := x.relay.Prepare(t.Context(), testRelayEvent())

		require.NoError(t, err)
		require.Len(t, tokens, 1)
		assert.Equal(t, testRelayStreamA, tokens[0].Stream.StreamID)
		require.ErrorIs(t, testRelaySkips(t, skipped)[testRelayStreamB], ssfreceiver.ErrRelayStreamEventType)
		assert.Equal(t, []string{testRelayStreamA}, x.subjects.mapped)
	})

	t.Run("ShouldSkipDisabledStream", func(t *testing.T) {
		for _, status := range []string{oauth2.SSFStreamStatusDisabled, "", "unknown"} {
			x := newTestRelay(t)
			x.b.Status = status

			tokens, skipped, err := x.relay.Prepare(t.Context(), testRelayEvent())

			require.NoError(t, err)
			require.Len(t, tokens, 1)
			assert.Equal(t, testRelayStreamA, tokens[0].Stream.StreamID)
			require.ErrorIs(t, testRelaySkips(t, skipped)[testRelayStreamB], ssfreceiver.ErrRelayStreamDisabled)
			assert.Equal(t, []string{testRelayStreamA}, x.subjects.mapped)
		}
	})

	t.Run("ShouldFlagPausedStreamAsHeld", func(t *testing.T) {
		x := newTestRelay(t)
		x.b.Status = oauth2.SSFStreamStatusPaused

		tokens, skipped, err := x.relay.Prepare(t.Context(), testRelayEvent())

		require.NoError(t, err)
		assert.Empty(t, skipped)
		require.Len(t, tokens, 2)

		byStream := testRelayTokens(t, tokens)

		assert.False(t, byStream[testRelayStreamA].Held)
		assert.True(t, byStream[testRelayStreamB].Held)
		assert.Equal(t, oauth2.SSFStreamStatusPaused, byStream[testRelayStreamB].Stream.Status)

		_, claims := testRelayDecode(t, byStream[testRelayStreamB].Token)

		assert.Equal(t, []any{"https://rp-b.example.com"}, claims["aud"])
	})

	t.Run("ShouldSkipUncoveredSubject", func(t *testing.T) {
		x := newTestRelay(t)
		x.subjects.uncovered = map[string]bool{testRelayStreamA: true}

		tokens, skipped, err := x.relay.Prepare(t.Context(), testRelayEvent())

		require.NoError(t, err)
		require.Len(t, tokens, 1)
		assert.Equal(t, testRelayStreamB, tokens[0].Stream.StreamID)
		require.ErrorIs(t, testRelaySkips(t, skipped)[testRelayStreamA], ssfreceiver.ErrRelaySubjectNotCovered)
		assert.Equal(t, 1, x.issuer.calls)
	})
}

func TestRelayPrepareIdentifiers(t *testing.T) {
	t.Run("ShouldDeriveDistinctTxnPerStreamByDefault", func(t *testing.T) {
		x := newTestRelay(t)

		assert.Equal(t, ssfreceiver.RelayTransactionPerStream, x.relay.TransactionMode)
		assert.Equal(t, ssfreceiver.RelayTransactionPerStream, ssfreceiver.RelayTransactionMode(0))

		tokens, _, err := x.relay.Prepare(t.Context(), testRelayEvent())

		require.NoError(t, err)
		require.Len(t, tokens, 2)

		seen := map[any]bool{}

		for streamID, token := range testRelayTokens(t, tokens) {
			_, claims := testRelayDecode(t, token.Token)

			// SSF Section 10.1: a keyed digest of the incoming 'txn' and the stream ID.
			assert.Equal(t, testRelayMAC(x.relay.TransactionKey, testRelayTxn, streamID), claims["txn"])
			assert.NotEqual(t, testRelayTxn, claims["txn"])

			seen[claims["txn"]] = true
		}

		assert.Len(t, seen, 2)

		// Another key gives other values.
		y := newTestRelay(t)
		y.relay.TransactionKey = []byte(strings.Repeat("o", 32))

		others, _, err := y.relay.Prepare(t.Context(), testRelayEvent())

		require.NoError(t, err)
		require.Len(t, others, 2)

		for _, token := range others {
			_, claims := testRelayDecode(t, token.Token)

			assert.NotContains(t, seen, claims["txn"])
		}
	})

	t.Run("ShouldRefusePerStreamModeWithoutTransactionKey", func(t *testing.T) {
		for _, key := range [][]byte{nil, {}, []byte(strings.Repeat("k", 31))} {
			x := newTestRelay(t)
			x.relay.TransactionKey = key

			tokens, skipped, err := x.relay.Prepare(t.Context(), testRelayEvent())

			require.ErrorIs(t, err, ssfreceiver.ErrRelayConfiguration)
			assert.Empty(t, tokens)
			assert.Empty(t, skipped)
			assert.Zero(t, x.issuer.calls)
			assert.Empty(t, x.streams.types)
		}

		// The function may choose the per-stream mode, so it requires the key whatever the mode of the relay.
		for _, key := range [][]byte{nil, []byte(strings.Repeat("k", 31))} {
			x := newTestRelay(t)
			x.relay.TransactionMode, x.relay.TransactionKey = ssfreceiver.RelayTransactionPropagate, key
			x.relay.TransactionModeFor = func(*oauth2.SSFStream) ssfreceiver.RelayTransactionMode {
				return ssfreceiver.RelayTransactionPropagate
			}

			tokens, _, err := x.relay.Prepare(t.Context(), testRelayEvent())

			require.ErrorIs(t, err, ssfreceiver.ErrRelayConfiguration)
			assert.Empty(t, tokens)
			assert.Zero(t, x.issuer.calls)
		}

		// The key is not required to propagate.
		x := newTestRelay(t)
		x.relay.TransactionMode, x.relay.TransactionKey = ssfreceiver.RelayTransactionPropagate, nil

		tokens, _, err := x.relay.Prepare(t.Context(), testRelayEvent())

		require.NoError(t, err)
		assert.Len(t, tokens, 2)
	})

	t.Run("ShouldRefuseUnknownTransactionMode", func(t *testing.T) {
		x := newTestRelay(t)
		x.relay.TransactionMode = ssfreceiver.RelayTransactionMode(7)

		tokens, _, err := x.relay.Prepare(t.Context(), testRelayEvent())

		require.ErrorIs(t, err, ssfreceiver.ErrRelayConfiguration)
		assert.Empty(t, tokens)
		assert.Zero(t, x.issuer.calls)
	})

	t.Run("ShouldRefuseIncompleteRelay", func(t *testing.T) {
		for _, incomplete := range []func(r *ssfreceiver.Relay){
			func(r *ssfreceiver.Relay) { r.Provider = nil },
			func(r *ssfreceiver.Relay) { r.Streams = nil },
			func(r *ssfreceiver.Relay) { r.Subjects = nil },
		} {
			x := newTestRelay(t)
			incomplete(x.relay)

			tokens, _, err := x.relay.Prepare(t.Context(), testRelayEvent())

			require.ErrorIs(t, err, ssfreceiver.ErrRelayConfiguration)
			assert.Empty(t, tokens)
		}

		var relay *ssfreceiver.Relay

		_, _, err := relay.Prepare(t.Context(), testRelayEvent())

		require.ErrorIs(t, err, ssfreceiver.ErrRelayConfiguration)
	})

	t.Run("ShouldCarryIncomingTxnInPropagateMode", func(t *testing.T) {
		x := newTestRelay(t)
		x.relay.TransactionMode = ssfreceiver.RelayTransactionPropagate

		tokens, _, err := x.relay.Prepare(t.Context(), testRelayEvent())

		require.NoError(t, err)
		require.Len(t, tokens, 2)

		for _, token := range tokens {
			_, claims := testRelayDecode(t, token.Token)

			assert.Equal(t, testRelayTxn, claims["txn"])
		}
	})

	t.Run("ShouldDeriveTxnWhenAbsent", func(t *testing.T) {
		derived := testRelayDigest(testRelayOriginIssuer, testRelayOriginJTI)

		x := newTestRelay(t)
		x.relay.TransactionMode = ssfreceiver.RelayTransactionPropagate

		event := testRelayEvent()
		event.Transaction = ""

		tokens, _, err := x.relay.Prepare(t.Context(), event)

		require.NoError(t, err)
		require.Len(t, tokens, 2)

		for _, token := range tokens {
			_, claims := testRelayDecode(t, token.Token)

			assert.Equal(t, derived, claims["txn"])
		}

		// The per-stream value is of the derived one.
		y := newTestRelay(t)

		tokens, _, err = y.relay.Prepare(t.Context(), event)

		require.NoError(t, err)
		require.Len(t, tokens, 2)

		for streamID, token := range testRelayTokens(t, tokens) {
			_, claims := testRelayDecode(t, token.Token)

			assert.Equal(t, testRelayMAC(y.relay.TransactionKey, derived, streamID), claims["txn"])
		}
	})
}

func TestRelayPrepareTransactionModes(t *testing.T) {
	t.Run("ShouldDeriveStableJTI", func(t *testing.T) {
		for _, mode := range []ssfreceiver.RelayTransactionMode{ssfreceiver.RelayTransactionPerStream, ssfreceiver.RelayTransactionPropagate} {
			x := newTestRelay(t)
			x.relay.TransactionMode = mode

			first, _, err := x.relay.Prepare(t.Context(), testRelayEvent())

			require.NoError(t, err)
			require.Len(t, first, 2)

			// The same event prepared again with the same store.
			second, skipped, err := x.relay.Prepare(t.Context(), testRelayEvent())

			require.NoError(t, err)
			assert.Empty(t, skipped)
			require.Len(t, second, 2)

			// The 'txn' is not an input.
			again := testRelayEvent()
			again.Transaction = "another"

			third, _, err := x.relay.Prepare(t.Context(), again)

			require.NoError(t, err)
			require.Len(t, third, 2)

			a, b, c := testRelayTokens(t, first), testRelayTokens(t, second), testRelayTokens(t, third)

			for _, streamID := range []string{testRelayStreamA, testRelayStreamB} {
				unkeyed := testRelayDigest(testRelayOriginIssuer, testRelayOriginJTI, streamID, testRelayPrincipal)
				want := unkeyed

				// SSF Section 10.1: the 'jti' of a stream can not be computed for another stream without the key.
				if mode == ssfreceiver.RelayTransactionPerStream {
					want = testRelayMAC(x.relay.TransactionKey, "jti", testRelayOriginIssuer, testRelayOriginJTI, streamID, testRelayPrincipal)

					assert.NotEqual(t, unkeyed, a[streamID].JTI)
					assert.NotEqual(t, testRelayMAC([]byte(strings.Repeat("o", 32)), "jti", testRelayOriginIssuer, testRelayOriginJTI, streamID, testRelayPrincipal), a[streamID].JTI)
				}

				assert.Equal(t, want, a[streamID].JTI)
				assert.Equal(t, want, b[streamID].JTI)
				assert.Equal(t, want, c[streamID].JTI)

				_, claims := testRelayDecode(t, a[streamID].Token)
				_, repeat := testRelayDecode(t, b[streamID].Token)

				assert.Equal(t, want, claims["jti"])
				assert.Equal(t, want, repeat["jti"])
				assert.Equal(t, claims["txn"], repeat["txn"])
				assert.NotEqual(t, claims["jti"], claims["txn"])
			}

			assert.NotEqual(t, a[testRelayStreamA].JTI, a[testRelayStreamB].JTI)
		}
	})

	t.Run("ShouldDeriveDistinctJTIPerPrincipal", func(t *testing.T) {
		for _, mode := range []ssfreceiver.RelayTransactionMode{ssfreceiver.RelayTransactionPropagate, ssfreceiver.RelayTransactionPerStream} {
			x := newTestRelay(t)
			x.relay.TransactionMode = mode

			prepare := func(principal string) map[string]ssfreceiver.RelayToken {
				event := testRelayEvent()
				event.Principal = principal

				tokens, _, err := x.relay.Prepare(t.Context(), event)

				require.NoError(t, err)
				require.Len(t, tokens, 2)

				return testRelayTokens(t, tokens)
			}

			// RFC 8417 Section 2.2: the SETs of two principals of one event are distinct SETs.
			first, second, again := prepare("user-1"), prepare("user-2"), prepare("user-1")

			for _, streamID := range []string{testRelayStreamA, testRelayStreamB} {
				assert.NotEqual(t, first[streamID].JTI, second[streamID].JTI)
				assert.Equal(t, first[streamID].JTI, again[streamID].JTI)
			}
		}
	})

	t.Run("ShouldChooseTransactionModePerStream", func(t *testing.T) {
		x := newTestRelay(t)

		// The mode of the relay is not used with the function.
		x.relay.TransactionMode = ssfreceiver.RelayTransactionMode(7)
		x.relay.TransactionModeFor = func(stream *oauth2.SSFStream) ssfreceiver.RelayTransactionMode {
			defer func() { stream.StreamID = "changed" }()

			if stream.StreamID == testRelayStreamA {
				return ssfreceiver.RelayTransactionPropagate
			}

			return ssfreceiver.RelayTransactionPerStream
		}

		tokens, skipped, err := x.relay.Prepare(t.Context(), testRelayEvent())

		require.NoError(t, err)
		assert.Empty(t, skipped)
		require.Len(t, tokens, 2)

		byStream := testRelayTokens(t, tokens)

		_, public := testRelayDecode(t, byStream[testRelayStreamA].Token)
		_, pairwise := testRelayDecode(t, byStream[testRelayStreamB].Token)

		assert.Equal(t, testRelayTxn, public["txn"])
		assert.Equal(t, testRelayDigest(testRelayOriginIssuer, testRelayOriginJTI, testRelayStreamA, testRelayPrincipal), public["jti"])
		assert.Equal(t, testRelayMAC(x.relay.TransactionKey, testRelayTxn, testRelayStreamB), pairwise["txn"])
		assert.Equal(t, testRelayMAC(x.relay.TransactionKey, "jti", testRelayOriginIssuer, testRelayOriginJTI, testRelayStreamB, testRelayPrincipal), pairwise["jti"])
	})

	t.Run("ShouldSkipStreamWithUnknownTransactionMode", func(t *testing.T) {
		x := newTestRelay(t)
		x.relay.TransactionModeFor = func(stream *oauth2.SSFStream) ssfreceiver.RelayTransactionMode {
			if stream.StreamID == testRelayStreamB {
				return ssfreceiver.RelayTransactionMode(7)
			}

			return ssfreceiver.RelayTransactionPropagate
		}

		tokens, skipped, err := x.relay.Prepare(t.Context(), testRelayEvent())

		require.NoError(t, err)
		require.Len(t, tokens, 1)
		assert.Equal(t, testRelayStreamA, tokens[0].Stream.StreamID)
		require.ErrorIs(t, testRelaySkips(t, skipped)[testRelayStreamB], ssfreceiver.ErrRelayConfiguration)
		assert.Equal(t, 1, x.issuer.calls)
	})

	t.Run("ShouldNotConfuseOriginIssuerAndJTI", func(t *testing.T) {
		jtis := map[string]bool{}

		for _, origin := range [][2]string{{"https://idp.example.com/a", "b"}, {"https://idp.example.com/", "ab"}, {"https://idp.example.com/ab", ""}} {
			x := newTestRelay(t)

			event := testRelayEvent()
			event.OriginIssuer, event.OriginJTI = origin[0], origin[1]

			tokens, _, err := x.relay.Prepare(t.Context(), event)

			if origin[1] == "" {
				require.ErrorIs(t, err, ssfreceiver.ErrRelayEventOrigin)
				assert.Empty(t, tokens)
				assert.Zero(t, x.issuer.calls)

				continue
			}

			require.NoError(t, err)
			require.Len(t, tokens, 2)

			jtis[testRelayTokens(t, tokens)[testRelayStreamA].JTI] = true
		}

		assert.Len(t, jtis, 2)
	})
}

func TestRelayPrepareStreams(t *testing.T) {
	t.Run("ShouldEncryptForEncryptionClient", func(t *testing.T) {
		x := newTestRelay(t)
		x.b.ClientID = testRelayClientEnc

		tokens, skipped, err := x.relay.Prepare(t.Context(), testRelayEvent())

		require.NoError(t, err)
		assert.Empty(t, skipped)
		require.Len(t, tokens, 2)

		byStream := testRelayTokens(t, tokens)

		// RFC 8417 Section 5.1.
		assert.Len(t, strings.Split(byStream[testRelayStreamA].Token, "."), 3)
		require.Len(t, strings.Split(byStream[testRelayStreamB].Token, "."), 5)

		header, claims := testRelayDecode(t, byStream[testRelayStreamB].Token)

		assert.Equal(t, jwt.JSONWebTokenTypeSecurityEventToken, header.ExtraHeaders[jose.HeaderType])
		assert.Equal(t, testRelayIssuerURL, claims["iss"])
		assert.Equal(t, []any{"https://rp-b.example.com"}, claims["aud"])
		assert.Equal(t, byStream[testRelayStreamB].JTI, claims["jti"])
		assert.Equal(t, map[string]any{"format": "opaque", "id": testRelaySubject(testRelayStreamB, testRelayPrincipal)}, claims["sub_id"])
	})

	t.Run("ShouldContinueAfterOneStreamFails", func(t *testing.T) {
		x := newTestRelay(t)

		unknown := testRelayStream("stream-unknown", "rx-unknown", "https://rp-unknown.example.com")
		failing := testRelayStream("stream-failing", testRelayClientA, "https://rp-failing.example.com")
		unidentified := testRelayStream("", testRelayClientA, "https://rp-unidentified.example.com")

		x.subjects.failing = map[string]bool{"stream-failing": true}
		x.streams.streams = []*oauth2.SSFStream{unknown, nil, failing, unidentified, x.a, x.b}

		tokens, skipped, err := x.relay.Prepare(t.Context(), testRelayEvent())

		require.NoError(t, err)
		require.Len(t, tokens, 2)
		require.Len(t, skipped, 4)

		byStream := testRelayTokens(t, tokens)

		assert.Contains(t, byStream, testRelayStreamA)
		assert.Contains(t, byStream, testRelayStreamB)

		// The client of the stream does not load.
		assert.Equal(t, "stream-unknown", skipped[0].Stream.StreamID)
		require.ErrorIs(t, skipped[0].Reason, oauth2.ErrServerError)

		assert.Nil(t, skipped[1].Stream)
		require.ErrorIs(t, skipped[1].Reason, ssfreceiver.ErrRelayStream)

		assert.Equal(t, "stream-failing", skipped[2].Stream.StreamID)
		require.ErrorIs(t, skipped[2].Reason, errTestRelay)

		assert.Equal(t, []string{"https://rp-unidentified.example.com"}, skipped[3].Stream.Audience)
		require.ErrorIs(t, skipped[3].Reason, ssfreceiver.ErrRelayStream)
	})

	t.Run("ShouldFailWhenStreamsFail", func(t *testing.T) {
		x := newTestRelay(t)
		x.streams.err = errTestRelay

		tokens, skipped, err := x.relay.Prepare(t.Context(), testRelayEvent())

		require.ErrorIs(t, err, errTestRelay)
		assert.Empty(t, tokens)
		assert.Empty(t, skipped)
	})

	t.Run("ShouldRefuseStreamEvents", func(t *testing.T) {
		for _, have := range []jwt.SecurityEvent{
			&jwt.SSFVerification{},
			jwt.SSFVerification{},
			&jwt.SSFStreamUpdated{Status: jwt.SSFStreamStatusPaused},
			jwt.SSFStreamUpdated{Status: jwt.SSFStreamStatusPaused},
			jwt.RawSecurityEvent{URI: jwt.SecurityEventTypeSSFVerification, Claims: map[string]any{}},
		} {
			x := newTestRelay(t)

			x.a.EventsDelivered = append(x.a.EventsDelivered, jwt.SecurityEventTypeSSFVerification, jwt.SecurityEventTypeSSFStreamUpdated)
			x.relay.Policy = func(_ context.Context, event *ssfreceiver.RelayEvent, _ map[string]string) (jwt.SecurityEvent, bool, error) {
				t.Error("the policy was asked")

				return event.Event, true, nil
			}

			event := testRelayEvent()
			event.Event = have

			tokens, skipped, err := x.relay.Prepare(t.Context(), event)

			// SSF Section 8.1.4: a stream event is of the stream it was received on.
			require.ErrorIs(t, err, ssfreceiver.ErrRelayStreamEvent)
			assert.Empty(t, tokens)
			assert.Empty(t, skipped)
			assert.Zero(t, x.issuer.calls)
			assert.Empty(t, x.streams.types)
		}
	})

	t.Run("ShouldRelayNothingWithoutPolicy", func(t *testing.T) {
		x := newTestRelay(t)
		x.relay.Policy = nil

		tokens, skipped, err := x.relay.Prepare(t.Context(), testRelayEvent())

		require.NoError(t, err)
		assert.Empty(t, tokens)
		assert.Empty(t, skipped)
		assert.Zero(t, x.issuer.calls)
		assert.Empty(t, x.streams.types)
	})

	t.Run("ShouldRelayNothingForUnlistedType", func(t *testing.T) {
		x := newTestRelay(t)

		event := testRelayEvent()
		event.Event = &jwt.RISCAccountDisabled{}

		tokens, skipped, err := x.relay.Prepare(t.Context(), event)

		require.NoError(t, err)
		assert.Empty(t, tokens)
		assert.Empty(t, skipped)
		assert.Empty(t, x.streams.types)
	})

	t.Run("ShouldFailWhenPolicyFails", func(t *testing.T) {
		x := newTestRelay(t)
		x.relay.Policy = func(context.Context, *ssfreceiver.RelayEvent, map[string]string) (jwt.SecurityEvent, bool, error) {
			return nil, false, errTestRelay
		}

		tokens, _, err := x.relay.Prepare(t.Context(), testRelayEvent())

		require.ErrorIs(t, err, errTestRelay)
		assert.Empty(t, tokens)
		assert.Empty(t, x.streams.types)
	})

	t.Run("ShouldSelectStreamsByPolicyEventType", func(t *testing.T) {
		x := newTestRelay(t)
		x.b.EventsDelivered = []string{jwt.SecurityEventTypeRISCAccountDisabled}
		x.relay.Policy = func(context.Context, *ssfreceiver.RelayEvent, map[string]string) (jwt.SecurityEvent, bool, error) {
			return &jwt.RISCAccountDisabled{}, true, nil
		}

		tokens, skipped, err := x.relay.Prepare(t.Context(), testRelayEvent())

		require.NoError(t, err)
		require.Len(t, tokens, 1)
		assert.Equal(t, testRelayStreamB, tokens[0].Stream.StreamID)
		assert.Equal(t, jwt.SecurityEventTypeRISCAccountDisabled, tokens[0].EventType)
		assert.Equal(t, []string{jwt.SecurityEventTypeRISCAccountDisabled}, x.streams.types)
		require.ErrorIs(t, testRelaySkips(t, skipped)[testRelayStreamA], ssfreceiver.ErrRelayStreamEventType)

		_, claims := testRelayDecode(t, tokens[0].Token)

		assert.Contains(t, claims["events"], jwt.SecurityEventTypeRISCAccountDisabled)
	})
}

const testAudienceUpstream = "https://as.example.com/ssf/receiver"

func testRelayReceivedEvent() *ssfreceiver.ReceivedEvent {
	event := &jwt.CAEPSessionRevoked{SecurityEventCommon: jwt.SecurityEventCommon{EventTimestamp: 1700000000}}

	return &ssfreceiver.ReceivedEvent{
		Stream: &ssfreceiver.StreamRecord{Issuer: testRelayOriginIssuer, StreamID: "upstream-1", State: ssfreceiver.StreamRecordActive},
		Claims: &jwt.SecurityEventTokenClaims{
			Issuer:      testRelayOriginIssuer,
			JTI:         testRelayOriginJTI,
			Audience:    []string{testAudienceUpstream},
			Transaction: testRelayTxn,
		},
		Type:      jwt.SecurityEventTypeCAEPSessionRevoked,
		Event:     event,
		Principal: testRelayPrincipal,
		Token:     testRelayReceived,
	}
}

func TestNewRelayEvent(t *testing.T) {
	t.Run("ShouldBuildFromReceivedEvent", func(t *testing.T) {
		received := testRelayReceivedEvent()

		event, err := ssfreceiver.NewRelayEvent(received)

		require.NoError(t, err)
		assert.Same(t, received.Event, event.Event)
		assert.Equal(t, testRelayTxn, event.Transaction)
		assert.Equal(t, testRelayPrincipal, event.Principal)
		assert.Equal(t, testRelayOriginIssuer, event.OriginIssuer)
		assert.Equal(t, testRelayOriginJTI, event.OriginJTI)
		assert.Empty(t, event.ExcludeClientIDs)
	})

	t.Run("ShouldLeaveAbsentTxnEmpty", func(t *testing.T) {
		received := testRelayReceivedEvent()
		received.Claims.Transaction = ""

		event, err := ssfreceiver.NewRelayEvent(received)

		require.NoError(t, err)
		assert.Empty(t, event.Transaction)
	})

	t.Run("ShouldRefuseStreamEvents", func(t *testing.T) {
		for _, have := range []jwt.SecurityEvent{&jwt.SSFVerification{}, &jwt.SSFStreamUpdated{Status: jwt.SSFStreamStatusPaused}} {
			received := testRelayReceivedEvent()
			received.Type, received.Event = have.SecurityEventType(), have

			event, err := ssfreceiver.NewRelayEvent(received)

			require.ErrorIs(t, err, ssfreceiver.ErrRelayStreamEvent)
			assert.Nil(t, event)
		}

		// The type of the event decides, whatever the Type says.
		received := testRelayReceivedEvent()
		received.Type = jwt.SecurityEventTypeSSFVerification

		event, err := ssfreceiver.NewRelayEvent(received)

		require.ErrorIs(t, err, ssfreceiver.ErrRelayStreamEvent)
		assert.Nil(t, event)
	})

	t.Run("ShouldRefuseIncompleteReceivedEvent", func(t *testing.T) {
		for _, incomplete := range []func(e *ssfreceiver.ReceivedEvent) *ssfreceiver.ReceivedEvent{
			func(*ssfreceiver.ReceivedEvent) *ssfreceiver.ReceivedEvent { return nil },
			func(e *ssfreceiver.ReceivedEvent) *ssfreceiver.ReceivedEvent { e.Claims = nil; return e },
			func(e *ssfreceiver.ReceivedEvent) *ssfreceiver.ReceivedEvent { e.Event = nil; return e },
			func(e *ssfreceiver.ReceivedEvent) *ssfreceiver.ReceivedEvent {
				e.Event = (*jwt.CAEPSessionRevoked)(nil)

				return e
			},
			func(e *ssfreceiver.ReceivedEvent) *ssfreceiver.ReceivedEvent { e.Claims.Issuer = ""; return e },
			func(e *ssfreceiver.ReceivedEvent) *ssfreceiver.ReceivedEvent { e.Claims.JTI = ""; return e },
		} {
			event, err := ssfreceiver.NewRelayEvent(incomplete(testRelayReceivedEvent()))

			require.ErrorIs(t, err, ssfreceiver.ErrRelayEventOrigin)
			assert.Nil(t, event)
		}
	})
}
