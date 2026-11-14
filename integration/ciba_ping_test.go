// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package integration_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/storage"
)

const (
	cibaPingClientID          = "ciba-ping-client"
	cibaPingNotificationToken = "ping-notification-token"
)

func TestCIBAPingFlow(t *testing.T) {
	stores := []struct {
		name string
		new  func() (any, map[string]oauth2.Client)
	}{
		{name: idjagStoreMemory, new: func() (any, map[string]oauth2.Client) {
			s := storage.NewMemoryStore()
			return s, s.Clients
		}},
		{name: idjagStoreHydrate, new: func() (any, map[string]oauth2.Client) {
			s := storage.NewHydratingMemoryStore()
			return s, s.Clients
		}},
	}

	for _, st := range stores {
		t.Run(st.name, func(t *testing.T) {
			type ping struct {
				authorization string
				contentType   string
				body          map[string]string
			}

			var (
				mu    sync.Mutex
				pings []ping
			)

			notification := httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
				data, _ := io.ReadAll(r.Body)

				p := ping{authorization: r.Header.Get(consts.HeaderAuthorization), contentType: r.Header.Get(consts.HeaderContentType), body: map[string]string{}}
				_ = json.Unmarshal(data, &p.body)

				mu.Lock()
				pings = append(pings, p)
				mu.Unlock()

				rw.WriteHeader(http.StatusNoContent)
			}))

			t.Cleanup(notification.Close)

			newStore := func() (any, map[string]oauth2.Client) {
				store, clients := st.new()

				clients[cibaPingClientID] = &oauth2.DefaultCIBAClient{
					BackChannelTokenDeliveryMode:          consts.CIBAModePing,
					BackChannelClientNotificationEndpoint: notification.URL,
					DefaultClient: &oauth2.DefaultClient{
						ID:           cibaPingClientID,
						ClientSecret: oauth2.NewBCryptClientSecret(`$2a$04$6i/O2OM9CcEVTRLq9uFDtOze4AtISH79iYkZeEUsos4WzWtCnJ52y`),
						GrantTypes:   []string{consts.GrantTypeOpenIDCIBA, consts.GrantTypeRefreshToken},
						Scopes:       []string{consts.ScopeOpenID, consts.ScopeOffline},
					},
				}

				return store, clients
			}

			flow := newCIBAFlow(t, newStore, func(config *oauth2.Config) {
				config.BackChannelNotifier = oauth2.NewHTTPBackChannelNotifier(notification.Client())
			})

			status, body := flow.post(t, "/bc-authorize", cibaPingClientID, url.Values{
				consts.FormParameterScope:                   {cibaScope},
				consts.FormParameterLoginHint:               {testSubject},
				consts.FormParameterClientNotificationToken: {cibaPingNotificationToken},
			}, nil)
			require.Equal(t, http.StatusOK, status, "backchannel authentication error: %+v", body)

			id, _ := body[consts.FormParameterAuthReqID].(string)
			require.NotEmpty(t, id)

			status, body = flow.poll(t, cibaPingClientID, id, nil)
			assert.Equal(t, http.StatusBadRequest, status)
			assert.Equal(t, "authorization_pending", body["error"])

			mu.Lock()
			assert.Empty(t, pings)
			mu.Unlock()

			flow.approve(t)

			mu.Lock()
			require.Len(t, pings, 1)
			assert.Equal(t, "Bearer "+cibaPingNotificationToken, pings[0].authorization)
			assert.Equal(t, "application/json", pings[0].contentType)
			assert.Equal(t, map[string]string{consts.FormParameterAuthReqID: id}, pings[0].body)
			mu.Unlock()

			status, body = flow.poll(t, cibaPingClientID, id, nil)
			require.Equal(t, http.StatusOK, status, "token error: %+v", body)
			assert.NotEmpty(t, body["access_token"])
			assert.NotEmpty(t, body["id_token"])
		})
	}
}

func TestCIBAPingDeliveryFailureStillIssuesTokens(t *testing.T) {
	stores := []struct {
		name string
		new  func() (any, map[string]oauth2.Client)
	}{
		{name: idjagStoreMemory, new: func() (any, map[string]oauth2.Client) {
			s := storage.NewMemoryStore()
			return s, s.Clients
		}},
		{name: idjagStoreHydrate, new: func() (any, map[string]oauth2.Client) {
			s := storage.NewHydratingMemoryStore()
			return s, s.Clients
		}},
	}

	for _, st := range stores {
		t.Run(st.name, func(t *testing.T) {
			var calls int

			var mu sync.Mutex

			notification := httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
				mu.Lock()
				calls++
				mu.Unlock()

				rw.WriteHeader(http.StatusInternalServerError)
			}))

			t.Cleanup(notification.Close)

			newStore := func() (any, map[string]oauth2.Client) {
				store, clients := st.new()

				clients[cibaPingClientID] = &oauth2.DefaultCIBAClient{
					BackChannelTokenDeliveryMode:          consts.CIBAModePing,
					BackChannelClientNotificationEndpoint: notification.URL,
					DefaultClient: &oauth2.DefaultClient{
						ID:           cibaPingClientID,
						ClientSecret: oauth2.NewBCryptClientSecret(`$2a$04$6i/O2OM9CcEVTRLq9uFDtOze4AtISH79iYkZeEUsos4WzWtCnJ52y`),
						GrantTypes:   []string{consts.GrantTypeOpenIDCIBA, consts.GrantTypeRefreshToken},
						Scopes:       []string{consts.ScopeOpenID, consts.ScopeOffline},
					},
				}

				return store, clients
			}

			flow := newCIBAFlow(t, newStore, func(config *oauth2.Config) {
				config.BackChannelNotifier = oauth2.NewHTTPBackChannelNotifier(notification.Client())
			})

			status, body := flow.post(t, "/bc-authorize", cibaPingClientID, url.Values{
				consts.FormParameterScope:                   {cibaScope},
				consts.FormParameterLoginHint:               {testSubject},
				consts.FormParameterClientNotificationToken: {cibaPingNotificationToken},
			}, nil)
			require.Equal(t, http.StatusOK, status, "backchannel authentication error: %+v", body)

			id, _ := body[consts.FormParameterAuthReqID].(string)
			require.NotEmpty(t, id)

			flow.approve(t)

			mu.Lock()
			assert.Equal(t, 1, calls)
			mu.Unlock()

			status, body = flow.poll(t, cibaPingClientID, id, nil)
			require.Equal(t, http.StatusOK, status, "token error: %+v", body)
			assert.NotEmpty(t, body["access_token"])
		})
	}
}
