// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/handler/openid"
	"authelia.com/provider/oauth2/internal/gen"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestSendBackChannelLogout_RequiresSubjectOrSessionID(t *testing.T) {
	f, _ := newBCLProvider(t)

	client := bclClient("rp-1", "https://rp.example/logout", false)

	_, err := f.SendBackChannelLogout(t.Context(), oauth2.NewBackChannelLogoutRequest("", "", []oauth2.Client{client}))

	require.Error(t, err)
	assert.ErrorIs(t, err, oauth2.ErrInvalidRequest)
}

func TestSendBackChannelLogout_RequiresStrategy(t *testing.T) {
	f, config := newBCLProvider(t)

	config.BackChannelLogoutTokenStrategy = nil

	client := bclClient("rp-1", "https://rp.example/logout", false)

	_, err := f.SendBackChannelLogout(t.Context(), oauth2.NewBackChannelLogoutRequest("alice", "", []oauth2.Client{client}))

	require.Error(t, err)
	assert.ErrorIs(t, err, oauth2.ErrServerError)
}

func TestSendBackChannelLogout_EmptyClientsIsNotAnError(t *testing.T) {
	f, _ := newBCLProvider(t)

	results, err := f.SendBackChannelLogout(t.Context(), oauth2.NewBackChannelLogoutRequest("alice", "", nil))

	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestSendBackChannelLogout_DeliversAndAcceptsOKAndNoContent(t *testing.T) {
	for name, status := range map[string]int{"OK": http.StatusOK, "NoContent": http.StatusNoContent} {
		t.Run(name, func(t *testing.T) {
			f, _ := newBCLProvider(t)

			server, tokens := bclServer(t, status)

			client := bclClient("rp-1", server.URL, false)

			results, err := f.SendBackChannelLogout(t.Context(), oauth2.NewBackChannelLogoutRequest("alice", "session-1", []oauth2.Client{client}))

			require.NoError(t, err)
			require.Len(t, results, 1)

			assert.Equal(t, "rp-1", results[0].ClientID)
			assert.True(t, results[0].Success())
			assert.Equal(t, status, results[0].Status)
			assert.NoError(t, results[0].Err)

			require.Len(t, *tokens, 1)

			header := decodeLogoutTokenHeader(t, (*tokens)[0])
			assert.Equal(t, "logout+jwt", header["typ"])

			claims := decodeLogoutToken(t, (*tokens)[0])

			assert.Equal(t, "alice", claims["sub"])
			assert.Equal(t, "session-1", claims["sid"])
			assert.Equal(t, bclTestIssuer, claims["iss"])
			assert.Equal(t, []any{"rp-1"}, claims["aud"])
			assert.NotEmpty(t, claims["jti"])
			assert.NotContains(t, claims, "nonce")

			events, ok := claims["events"].(map[string]any)
			require.True(t, ok)
			assert.Contains(t, events, "http://schemas.openid.net/event/backchannel-logout")
			assert.Empty(t, events["http://schemas.openid.net/event/backchannel-logout"])
		})
	}
}

func TestSendBackChannelLogout_ReportsNonSuccessStatus(t *testing.T) {
	for name, status := range map[string]int{"BadRequest": http.StatusBadRequest, "ServerError": http.StatusInternalServerError, "Accepted": http.StatusAccepted} {
		t.Run(name, func(t *testing.T) {
			f, _ := newBCLProvider(t)

			server, _ := bclServer(t, status)

			client := bclClient("rp-1", server.URL, false)

			results, err := f.SendBackChannelLogout(t.Context(), oauth2.NewBackChannelLogoutRequest("alice", "", []oauth2.Client{client}))

			require.NoError(t, err)
			require.Len(t, results, 1)

			assert.False(t, results[0].Success())
			assert.Equal(t, status, results[0].Status)
			assert.Error(t, results[0].Err)
		})
	}
}

func TestSendBackChannelLogout_ReportsUnreachableRelyingParty(t *testing.T) {
	f, _ := newBCLProvider(t)

	server, _ := bclServer(t, http.StatusOK)

	uri := server.URL

	server.Close()

	client := bclClient("rp-1", uri, false)

	results, err := f.SendBackChannelLogout(t.Context(), oauth2.NewBackChannelLogoutRequest("alice", "", []oauth2.Client{client}))

	require.NoError(t, err)
	require.Len(t, results, 1)

	assert.False(t, results[0].Success())
	assert.Zero(t, results[0].Status)
	assert.Error(t, results[0].Err)
}

func TestSendBackChannelLogout_SkipsIneligibleClients(t *testing.T) {
	f, _ := newBCLProvider(t)

	server, tokens := bclServer(t, http.StatusOK)

	clients := []oauth2.Client{
		bclClient("rp-eligible", server.URL, false),
		bclClient("rp-no-uri", "", false),
		bclClient("rp-needs-sid", server.URL, true),
		&oauth2.DefaultClient{ID: "rp-not-a-bcl-client"},
	}

	results, err := f.SendBackChannelLogout(t.Context(), oauth2.NewBackChannelLogoutRequest("alice", "", clients))

	require.NoError(t, err)
	require.Len(t, results, 4)

	assert.True(t, results[0].Success())
	assert.False(t, results[0].Skipped)

	for _, i := range []int{1, 2, 3} {
		assert.True(t, results[i].Skipped, "index %d", i)
		assert.NotEmpty(t, results[i].Reason, "index %d", i)
		assert.Zero(t, results[i].Status, "index %d", i)
		assert.False(t, results[i].Success(), "index %d", i)
	}

	assert.Equal(t, "rp-no-uri", results[1].ClientID)
	assert.Contains(t, results[2].Reason, "sid")

	assert.Len(t, *tokens, 1)
}

func TestSendBackChannelLogout_SessionRequiredSatisfiedBySessionID(t *testing.T) {
	f, _ := newBCLProvider(t)

	server, _ := bclServer(t, http.StatusOK)

	client := bclClient("rp-1", server.URL, true)

	results, err := f.SendBackChannelLogout(t.Context(), oauth2.NewBackChannelLogoutRequest("alice", "session-1", []oauth2.Client{client}))

	require.NoError(t, err)
	require.Len(t, results, 1)

	assert.True(t, results[0].Success())
}

func TestSendBackChannelLogout_MintsDistinctJTIPerClient(t *testing.T) {
	f, _ := newBCLProvider(t)

	server, tokens := bclServer(t, http.StatusOK)

	clients := []oauth2.Client{
		bclClient("rp-1", server.URL, false),
		bclClient("rp-2", server.URL, false),
	}

	results, err := f.SendBackChannelLogout(t.Context(), oauth2.NewBackChannelLogoutRequest("alice", "", clients))

	require.NoError(t, err)
	require.Len(t, results, 2)
	require.Len(t, *tokens, 2)

	first, second := decodeLogoutToken(t, (*tokens)[0]), decodeLogoutToken(t, (*tokens)[1])

	assert.NotEqual(t, first["jti"], second["jti"])

	auds := []any{first["aud"], second["aud"]}

	assert.Contains(t, auds, []any{"rp-1"})
	assert.Contains(t, auds, []any{"rp-2"})
}

func TestSendBackChannelLogout_ResultsFollowInputOrder(t *testing.T) {
	f, _ := newBCLProvider(t)

	var counter int64

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt64(&counter, 1) == 1 {
			time.Sleep(100 * time.Millisecond)
		}

		w.WriteHeader(http.StatusOK)
	}))

	t.Cleanup(server.Close)

	clients := []oauth2.Client{
		bclClient("rp-1", server.URL, false),
		bclClient("rp-2", server.URL, false),
		bclClient("rp-3", "", false),
		bclClient("rp-4", server.URL, false),
	}

	results, err := f.SendBackChannelLogout(t.Context(), oauth2.NewBackChannelLogoutRequest("alice", "", clients))

	require.NoError(t, err)
	require.Len(t, results, 4)

	for i, client := range clients {
		assert.Equal(t, client.GetID(), results[i].ClientID, "index %d", i)
	}

	assert.True(t, results[2].Skipped)
}

func TestSendBackChannelLogout_RespectsConcurrencyLimit(t *testing.T) {
	f, config := newBCLProvider(t)

	config.BackChannelLogoutConcurrency = 2

	var (
		mu       sync.Mutex
		current  int
		observed int
	)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		current++

		if current > observed {
			observed = current
		}
		mu.Unlock()

		time.Sleep(50 * time.Millisecond)

		mu.Lock()
		current--
		mu.Unlock()

		w.WriteHeader(http.StatusOK)
	}))

	t.Cleanup(server.Close)

	clients := make([]oauth2.Client, 0, 10)

	for i := 0; i < 10; i++ {
		clients = append(clients, bclClient("rp-"+strconv.Itoa(i), server.URL, false))
	}

	results, err := f.SendBackChannelLogout(t.Context(), oauth2.NewBackChannelLogoutRequest("alice", "", clients))

	require.NoError(t, err)
	require.Len(t, results, 10)

	for i := range results {
		assert.True(t, results[i].Success(), "index %d", i)
	}

	mu.Lock()
	defer mu.Unlock()

	assert.Positive(t, observed)
	assert.LessOrEqual(t, observed, 2)
}

func TestSendBackChannelLogout_HonoursContextCancellation(t *testing.T) {
	f, _ := newBCLProvider(t)

	release := make(chan struct{})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))

	t.Cleanup(server.Close)
	t.Cleanup(func() { close(release) })

	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()

	client := bclClient("rp-1", server.URL, false)

	results, err := f.SendBackChannelLogout(ctx, oauth2.NewBackChannelLogoutRequest("alice", "", []oauth2.Client{client}))

	require.NoError(t, err)
	require.Len(t, results, 1)

	assert.False(t, results[0].Success())
	assert.Error(t, results[0].Err)
}

func TestSendBackChannelLogout_ReportsSigningFailure(t *testing.T) {
	f, config := newBCLProvider(t)

	config.BackChannelLogoutTokenStrategy = stubFailingBackChannelLogoutTokenStrategy{}

	client := bclClient("rp-1", "https://rp.example/logout", false)

	results, err := f.SendBackChannelLogout(t.Context(), oauth2.NewBackChannelLogoutRequest("alice", "", []oauth2.Client{client}))

	require.NoError(t, err)
	require.Len(t, results, 1)

	assert.Error(t, results[0].Err)
	assert.Zero(t, results[0].Status)
	assert.False(t, results[0].Skipped)
	assert.False(t, results[0].Success())
}

func TestSendBackChannelLogout_DoesNotFollowRedirects(t *testing.T) {
	f, _ := newBCLProvider(t)

	var secondContacted int32

	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&secondContacted, 1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(second.Close)

	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, second.URL, http.StatusTemporaryRedirect)
	}))
	t.Cleanup(first.Close)

	client := bclClient("rp-1", first.URL, false)

	results, err := f.SendBackChannelLogout(t.Context(), oauth2.NewBackChannelLogoutRequest("alice", "", []oauth2.Client{client}))

	require.NoError(t, err)
	require.Len(t, results, 1)

	assert.False(t, results[0].Success())
	assert.Equal(t, http.StatusTemporaryRedirect, results[0].Status)
	assert.Error(t, results[0].Err)

	assert.Zero(t, atomic.LoadInt32(&secondContacted))
}

func TestRetryableHTTPClientFieldCount(t *testing.T) {
	assert.Equal(t, 13, reflect.TypeOf(retryablehttp.Client{}).NumField(),
		"retryablehttp.Client's field count changed: review backChannelLogoutHTTPClient in backchannel_logout_request_handler.go")
}

func newBCLProvider(t *testing.T) (*oauth2.Fosite, *oauth2.Config) {
	t.Helper()

	config := &oauth2.Config{IDTokenIssuer: bclTestIssuer, MinParameterEntropy: 8}

	jwtStrategy := &jwt.DefaultStrategy{Config: config, Issuer: jwt.NewDefaultIssuerRS256Unverified(bclTestKey)}

	config.BackChannelLogoutTokenStrategy = &openid.DefaultStrategy{Strategy: jwtStrategy, Config: config}

	client := retryablehttp.NewClient()
	client.RetryMax = 0
	client.Logger = nil

	config.HTTPClient = client

	return &oauth2.Fosite{Store: storage.NewMemoryStore(), Config: config}, config
}

func bclClient(id, uri string, sessionRequired bool) *oauth2.DefaultBackChannelLogoutClient {
	return &oauth2.DefaultBackChannelLogoutClient{
		DefaultClient:                    &oauth2.DefaultClient{ID: id},
		BackChannelLogoutURI:             uri,
		BackChannelLogoutSessionRequired: sessionRequired,
	}
}

func bclServer(t *testing.T, status int) (server *httptest.Server, tokens *[]string) {
	t.Helper()

	var (
		mu        sync.Mutex
		collected []string
	)

	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "application/x-www-form-urlencoded", r.Header.Get("Content-Type"))

		require.NoError(t, r.ParseForm())

		mu.Lock()
		collected = append(collected, r.PostForm.Get("logout_token"))
		mu.Unlock()

		w.WriteHeader(status)
	}))

	t.Cleanup(server.Close)

	return server, &collected
}

func decodeLogoutToken(t *testing.T, token string) map[string]any {
	t.Helper()

	parts := strings.Split(token, ".")
	require.Len(t, parts, 3)

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)

	claims := map[string]any{}
	require.NoError(t, json.Unmarshal(payload, &claims))

	return claims
}

func decodeLogoutTokenHeader(t *testing.T, token string) map[string]any {
	t.Helper()

	parts := strings.Split(token, ".")
	require.Len(t, parts, 3)

	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	require.NoError(t, err)

	claims := map[string]any{}
	require.NoError(t, json.Unmarshal(header, &claims))

	return claims
}

type stubFailingBackChannelLogoutTokenStrategy struct{}

func (stubFailingBackChannelLogoutTokenStrategy) GenerateBackChannelLogoutToken(ctx context.Context, client oauth2.Client, lifespan time.Duration, subject, sid string, audience []string, extra map[string]any) (token string, err error) {
	return "", errors.New("signing failed")
}

const bclTestIssuer = "https://op.example/"

var bclTestKey = gen.MustRSAKey()
