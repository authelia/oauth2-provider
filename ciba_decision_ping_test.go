// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/handler/openid"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/token/jwt"
)

type recordingBackChannelNotifier struct {
	mu            sync.Mutex
	notifications []*oauth2.BackChannelNotification
	err           error
}

func (n *recordingBackChannelNotifier) NotifyBackChannelClient(_ context.Context, notification *oauth2.BackChannelNotification) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	n.notifications = append(n.notifications, notification)

	return n.err
}

func newCIBAPingTestProvider(store cibaDecisionTestStore, notifier oauth2.BackChannelNotifier) (provider *oauth2.Fosite) {
	provider = newCIBADecisionTestProvider(store)
	provider.Config.(*oauth2.Config).BackChannelNotifier = notifier

	return provider
}

func newCIBAPingTestRequest(mode, token string) (request *oauth2.BackChannelAuthenticationRequest) {
	request = newCIBADecisionTestRequest(newCIBADecisionTestSession("john"))
	request.DeliveryMode = mode
	request.ClientNotificationToken = token
	request.Client = &oauth2.DefaultCIBAClient{
		BackChannelTokenDeliveryMode:          mode,
		BackChannelClientNotificationEndpoint: "https://client.example.com/notify",
		DefaultClient:                         &oauth2.DefaultClient{ID: "client"},
	}

	return request
}

func decideCIBAPingTest(t *testing.T, provider *oauth2.Fosite, outcome string) (result *oauth2.BackChannelAuthenticationDecisionResult, err error) {
	t.Helper()

	loaded, err := provider.NewBackChannelAuthenticationDecisionRequest(t.Context(), cibaDecisionTestRequestID, openid.NewDefaultSession())
	require.NoError(t, err)

	switch outcome {
	case "approve":
		loaded.GrantScope(consts.ScopeOpenID)

		approval := newCIBADecisionTestSession("john")
		approval.Claims.AuthTime = jwt.NewNumericDate(time.Now().UTC())

		return provider.ApproveBackChannelAuthentication(t.Context(), loaded, approval)
	case "deny":
		return provider.DenyBackChannelAuthentication(t.Context(), loaded)
	default:
		return provider.FailBackChannelAuthentication(t.Context(), loaded, "unreachable")
	}
}

func TestPingOnApproveDenyFail(t *testing.T) {
	for _, sc := range cibaDecisionTestStores {
		for _, outcome := range []string{"approve", "deny", "fail"} {
			t.Run(sc.name+"/"+outcome, func(t *testing.T) {
				store := sc.new()
				notifier := &recordingBackChannelNotifier{}
				provider := newCIBAPingTestProvider(store, notifier)

				createCIBADecisionTestRequest(t, provider, newCIBAPingTestRequest(consts.CIBAModePing, "notification-token"))

				stored, err := store.GetCIBASessionByRequestID(t.Context(), cibaDecisionTestRequestID, openid.NewDefaultSession())
				require.NoError(t, err)

				authReqID := oauth2.GetAuthRequestID(stored)
				require.NotEmpty(t, authReqID)

				result, err := decideCIBAPingTest(t, provider, outcome)
				require.NoError(t, err)

				require.Len(t, notifier.notifications, 1)
				assert.Same(t, notifier.notifications[0], result.Notification)
				assert.NoError(t, result.DeliveryError)

				notification := notifier.notifications[0]

				assert.Equal(t, consts.CIBAModePing, notification.Mode)
				assert.Equal(t, "client", notification.ClientID)
				assert.Equal(t, cibaDecisionTestRequestID, notification.RequestID)
				assert.Equal(t, "https://client.example.com/notify", notification.Endpoint)
				assert.Equal(t, "notification-token", notification.BearerToken)

				body := map[string]string{}
				require.NoError(t, json.Unmarshal(notification.Body, &body))
				assert.Equal(t, map[string]string{consts.FormParameterAuthReqID: authReqID}, body)
			})
		}
	}
}

func TestPingDeliveryFailureKeepsDecision(t *testing.T) {
	for _, sc := range cibaDecisionTestStores {
		t.Run(sc.name, func(t *testing.T) {
			store := sc.new()
			notifier := &recordingBackChannelNotifier{err: errors.New("unreachable")}
			provider := newCIBAPingTestProvider(store, notifier)

			createCIBADecisionTestRequest(t, provider, newCIBAPingTestRequest(consts.CIBAModePing, "notification-token"))

			result, err := decideCIBAPingTest(t, provider, "approve")
			require.NoError(t, err)

			assert.EqualError(t, result.DeliveryError, "unreachable")
			assert.NotNil(t, result.Notification)
			assert.Equal(t, oauth2.CIBAStatusApproved, result.Status)

			stored, err := store.GetCIBASessionByRequestID(t.Context(), cibaDecisionTestRequestID, openid.NewDefaultSession())
			require.NoError(t, err)
			assert.Equal(t, oauth2.CIBAStatusApproved, stored.GetStatus())
		})
	}
}

func TestPingBuildFailureIsDeliveryError(t *testing.T) {
	for _, sc := range cibaDecisionTestStores {
		t.Run(sc.name, func(t *testing.T) {
			store := sc.new()
			notifier := &recordingBackChannelNotifier{}
			provider := newCIBAPingTestProvider(store, notifier)

			createCIBADecisionTestRequest(t, provider, newCIBAPingTestRequest(consts.CIBAModePing, ""))

			result, err := decideCIBAPingTest(t, provider, "deny")
			require.NoError(t, err)

			assert.Error(t, result.DeliveryError)
			assert.Nil(t, result.Notification)
			assert.Empty(t, notifier.notifications)
			assert.Equal(t, oauth2.CIBAStatusDenied, result.Status)

			stored, err := store.GetCIBASessionByRequestID(t.Context(), cibaDecisionTestRequestID, openid.NewDefaultSession())
			require.NoError(t, err)
			assert.Equal(t, oauth2.CIBAStatusDenied, stored.GetStatus())
		})
	}
}

func TestPollClientNoNotification(t *testing.T) {
	for _, sc := range cibaDecisionTestStores {
		t.Run(sc.name, func(t *testing.T) {
			store := sc.new()
			notifier := &recordingBackChannelNotifier{}
			provider := newCIBAPingTestProvider(store, notifier)

			createCIBADecisionTestRequest(t, provider, newCIBAPingTestRequest(consts.CIBAModePoll, ""))

			result, err := decideCIBAPingTest(t, provider, "approve")
			require.NoError(t, err)

			assert.Nil(t, result.Notification)
			assert.NoError(t, result.DeliveryError)
			assert.Empty(t, notifier.notifications)
		})
	}
}

func TestPingLosingConcurrentDecisionSendsNoPing(t *testing.T) {
	for _, sc := range cibaDecisionTestStores {
		t.Run(sc.name, func(t *testing.T) {
			store := sc.new()
			notifier := &recordingBackChannelNotifier{}
			provider := newCIBAPingTestProvider(store, notifier)

			createCIBADecisionTestRequest(t, provider, newCIBAPingTestRequest(consts.CIBAModePing, "notification-token"))

			const n = 2

			requests := make([]oauth2.BackChannelAuthenticationRequester, n)

			for i := range requests {
				loaded, err := provider.NewBackChannelAuthenticationDecisionRequest(t.Context(), cibaDecisionTestRequestID, openid.NewDefaultSession())
				require.NoError(t, err)

				loaded.GrantScope(consts.ScopeOpenID)

				requests[i] = loaded
			}

			errs := make([]error, n)

			var wg sync.WaitGroup

			start := make(chan struct{})

			for i := range requests {
				wg.Add(1)

				go func() {
					defer wg.Done()

					<-start

					approval := newCIBADecisionTestSession("john")
					approval.Claims.AuthTime = jwt.NewNumericDate(time.Now().UTC())

					_, errs[i] = provider.ApproveBackChannelAuthentication(t.Context(), requests[i], approval)
				}()
			}

			close(start)
			wg.Wait()

			failures := 0

			for _, err := range errs {
				if err != nil {
					failures++
				}
			}

			assert.Equal(t, 1, failures)
			assert.Len(t, notifier.notifications, 1)
		})
	}
}

func TestPingInvalidatedRequestIsDecided(t *testing.T) {
	for _, sc := range cibaDecisionTestStores {
		t.Run(sc.name, func(t *testing.T) {
			store := sc.new()
			notifier := &recordingBackChannelNotifier{}
			provider := newCIBAPingTestProvider(store, notifier)

			request := newCIBAPingTestRequest(consts.CIBAModePing, "notification-token")
			createCIBADecisionTestRequest(t, provider, request)

			loaded, err := provider.NewBackChannelAuthenticationDecisionRequest(t.Context(), cibaDecisionTestRequestID, openid.NewDefaultSession())
			require.NoError(t, err)

			// The token endpoint invalidates the request once the client exceeds the slow down limit.
			require.NoError(t, store.InvalidateCIBASession(t.Context(), request.GetAuthRequestIDSignature()))

			loaded.GrantScope(consts.ScopeOpenID)

			approval := newCIBADecisionTestSession("john")
			approval.Claims.AuthTime = jwt.NewNumericDate(time.Now().UTC())

			_, err = provider.ApproveBackChannelAuthentication(t.Context(), loaded, approval)
			require.Error(t, err)
			assert.Contains(t, oauth2.ErrorToRFC6749Error(err).GetDescription(), "already decided")
			assert.Empty(t, notifier.notifications)
		})
	}
}
