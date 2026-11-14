// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"maps"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/compose"
	"authelia.com/provider/oauth2/handler/openid"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/gen"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/testing/mock"
	"authelia.com/provider/oauth2/token/jwt"
)

const (
	cibaPushTestClientID  = "push-client"
	cibaPushTestRequestID = "push-request-id"
	cibaPushTestToken     = "push-notification-token"
	cibaPushTestEndpoint  = "https://client.example.com/cb"
)

// cibaPushTestStores builds each store with the memory store it is backed by, so a test can register clients and
// inspect what was persisted.
var cibaPushTestStores = []struct {
	name string
	new  func() (any, *storage.MemoryStore)
}{
	{"MemoryStore", func() (any, *storage.MemoryStore) {
		s := storage.NewMemoryStore()

		return s, s
	}},
	{"HydratingMemoryStore", func() (any, *storage.MemoryStore) {
		s := storage.NewHydratingMemoryStore()

		return s, s.MemoryStore
	}},
}

func newCIBAPushTestProvider(t *testing.T, store any, memory *storage.MemoryStore, notifier oauth2.BackChannelNotifier) (provider *oauth2.Fosite) {
	t.Helper()

	memory.Clients[cibaPushTestClientID] = &oauth2.DefaultCIBAClient{
		BackChannelTokenDeliveryMode:          consts.CIBAModePush,
		BackChannelClientNotificationEndpoint: cibaPushTestEndpoint,
		DefaultClient: &oauth2.DefaultClient{
			ID:         cibaPushTestClientID,
			GrantTypes: oauth2.Arguments{consts.GrantTypeRefreshToken},
			Scopes:     oauth2.Arguments{consts.ScopeOpenID, consts.ScopeOffline},
		},
	}

	config := &oauth2.Config{
		GlobalSecret:        []byte("foobarfoobarfoobarfoobarfoobarfoobarfoobarfoobar"),
		Issuer:              "https://op.example.com",
		AccessTokenLifespan: time.Hour,
		IDTokenLifespan:     time.Hour,
		BackChannelNotifier: notifier,
	}

	strategy := &jwt.DefaultStrategy{Config: config, Issuer: jwt.NewDefaultIssuerRS256Unverified(gen.MustRSAKey())}

	composed := compose.Compose(
		config,
		store,
		&compose.CommonStrategy{
			CoreStrategy:               compose.NewOAuth2HMACStrategy(config),
			OpenIDConnectTokenStrategy: compose.NewOpenIDConnectStrategy(nil, strategy, config),
			Strategy:                   strategy,
		},
		compose.OAuth2RefreshTokenGrantFactory,
		compose.OAuth2TokenIntrospectionFactory,
		compose.CIBADecisionFactory,
		compose.CIBATokenFactory,
		compose.OpenIDConnectCIBAFactory,
		compose.CIBAEndpointFactory,
		compose.OpenIDConnectRefreshFactory,
	)

	provider, ok := composed.(*oauth2.Fosite)
	require.True(t, ok)

	return provider
}

// newCIBAPushTestRequest stores a pending push request for the scopes and returns its raw 'auth_req_id'.
func newCIBAPushTestRequest(t *testing.T, provider *oauth2.Fosite, scopes oauth2.Arguments) (authReqID string) {
	t.Helper()

	client, err := provider.Store.GetClient(t.Context(), cibaPushTestClientID)
	require.NoError(t, err)

	session := openid.NewDefaultSession()
	session.Subject = "john"
	session.Claims.Subject = "john"

	request := oauth2.NewBackChannelAuthenticationRequest()
	request.SetID(cibaPushTestRequestID)
	request.Client = client
	request.DeliveryMode = consts.CIBAModePush
	request.ClientNotificationToken = cibaPushTestToken
	request.RequestedAt = time.Now().UTC()
	request.RequestedScope = scopes
	request.Session = session

	response, err := provider.NewBackChannelAuthenticationResponse(t.Context(), request)
	require.NoError(t, err)

	require.NotEmpty(t, response.GetAuthRequestID())

	return response.GetAuthRequestID()
}

func loadCIBAPushTestRequest(t *testing.T, provider *oauth2.Fosite, scopes oauth2.Arguments) oauth2.BackChannelAuthenticationRequester {
	t.Helper()

	loaded, err := provider.NewBackChannelAuthenticationDecisionRequest(t.Context(), cibaPushTestRequestID, openid.NewDefaultSession())
	require.NoError(t, err)

	for _, scope := range scopes {
		loaded.GrantScope(scope)
	}

	return loaded
}

func newCIBAPushTestApproval() *openid.DefaultSession {
	approval := openid.NewDefaultSession()
	approval.Subject = "john"
	approval.Claims.Subject = "john"
	approval.Claims.AuthTime = jwt.NewNumericDate(time.Now().Add(-time.Minute))

	return approval
}

func decodeCIBAPushTestBody(t *testing.T, notification *oauth2.BackChannelNotification) (body map[string]any) {
	t.Helper()

	body = map[string]any{}
	require.NoError(t, json.Unmarshal(notification.Body, &body))

	return body
}

func decodeCIBAPushTestClaims(t *testing.T, token string) (claims map[string]any) {
	t.Helper()

	parts := strings.Split(token, ".")
	require.Len(t, parts, 3)

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)

	claims = map[string]any{}
	require.NoError(t, json.Unmarshal(payload, &claims))

	return claims
}

// leftHalfSHA256 is the hash for the RS256 ID Token alg: the left-most half of the SHA-256 digest.
func leftHalfSHA256(value string) string {
	sum := sha256.Sum256([]byte(value))

	return base64.RawURLEncoding.EncodeToString(sum[:len(sum)/2])
}

func TestPushApproveDeliversTokens(t *testing.T) {
	scopes := oauth2.Arguments{consts.ScopeOpenID, consts.ScopeOffline}

	for _, sc := range cibaPushTestStores {
		t.Run(sc.name, func(t *testing.T) {
			store, memory := sc.new()
			notifier := &recordingBackChannelNotifier{}
			provider := newCIBAPushTestProvider(t, store, memory, notifier)

			authReqID := newCIBAPushTestRequest(t, provider, scopes)

			result, err := provider.ApproveBackChannelAuthentication(t.Context(), loadCIBAPushTestRequest(t, provider, scopes), newCIBAPushTestApproval())
			require.NoError(t, err)
			require.NoError(t, result.IssuanceError)
			require.NoError(t, result.DeliveryError)
			assert.Equal(t, oauth2.CIBAStatusApproved, result.Status)

			require.Len(t, notifier.notifications, 1)
			notification := notifier.notifications[0]
			assert.Same(t, notification, result.Notification)

			assert.Equal(t, consts.CIBAModePush, notification.Mode)
			assert.Equal(t, cibaPushTestClientID, notification.ClientID)
			assert.Equal(t, cibaPushTestRequestID, notification.RequestID)
			assert.Equal(t, cibaPushTestEndpoint, notification.Endpoint)
			assert.Equal(t, cibaPushTestToken, notification.BearerToken)

			body := decodeCIBAPushTestBody(t, notification)

			for _, key := range []string{consts.FormParameterAuthReqID, consts.AccessResponseAccessToken, consts.AccessResponseTokenType, consts.AccessResponseRefreshToken, consts.AccessResponseExpiresIn, consts.AccessResponseIDToken} {
				assert.Contains(t, body, key)
			}

			assert.Equal(t, authReqID, body[consts.FormParameterAuthReqID])
			assert.Equal(t, "bearer", strings.ToLower(body[consts.AccessResponseTokenType].(string)))

			access, refresh := body[consts.AccessResponseAccessToken].(string), body[consts.AccessResponseRefreshToken].(string)

			claims := decodeCIBAPushTestClaims(t, body[consts.AccessResponseIDToken].(string))
			assert.Equal(t, body[consts.FormParameterAuthReqID], claims[consts.ClaimCIBAAuthReqID])
			assert.Equal(t, leftHalfSHA256(access), claims[consts.ClaimAccessTokenHash])
			assert.Equal(t, leftHalfSHA256(refresh), claims[consts.ClaimRefreshTokenHash])

			_, requester, err := provider.IntrospectToken(context.Background(), access, oauth2.AccessToken, openid.NewDefaultSession())
			require.NoError(t, err)
			assert.Equal(t, cibaPushTestClientID, requester.GetClient().GetID())

			stored, err := memory.GetCIBASessionByRequestID(t.Context(), cibaPushTestRequestID, openid.NewDefaultSession())
			assert.ErrorIs(t, err, oauth2.ErrInvalidatedCIBASession)
			require.NotNil(t, stored)
			assert.Equal(t, oauth2.CIBAStatusApproved, stored.GetStatus())
		})
	}
}

// cibaPushRollbackStore simulates a transaction over the memory store: BeginTX snapshots the maps push issuance
// writes, and Rollback restores them.
type cibaPushRollbackStore struct {
	*mock.MockTransactional

	memory   *storage.MemoryStore
	snapshot func()
}

func newCIBAPushRollbackStore(ctrl *gomock.Controller, memory *storage.MemoryStore) *cibaPushRollbackStore {
	s := &cibaPushRollbackStore{MockTransactional: mock.NewMockTransactional(ctrl), memory: memory}

	s.MockTransactional.EXPECT().BeginTX(gomock.Any()).DoAndReturn(func(ctx context.Context) (context.Context, error) {
		cibaSessions, invalidated := maps.Clone(memory.CIBASessions), maps.Clone(memory.InvalidatedCIBASessions)
		accessTokens, accessIDs := maps.Clone(memory.AccessTokens), maps.Clone(memory.AccessTokenRequestIDs)
		refreshTokens, refreshIDs := maps.Clone(memory.RefreshTokens), maps.Clone(memory.RefreshTokenRequestIDs)
		idSessions := maps.Clone(memory.IDSessions)

		s.snapshot = func() {
			memory.CIBASessions, memory.InvalidatedCIBASessions = cibaSessions, invalidated
			memory.AccessTokens, memory.AccessTokenRequestIDs = accessTokens, accessIDs
			memory.RefreshTokens, memory.RefreshTokenRequestIDs = refreshTokens, refreshIDs
			memory.IDSessions = idSessions
		}

		return ctx, nil
	}).Times(1)

	s.MockTransactional.EXPECT().Rollback(gomock.Any()).DoAndReturn(func(_ context.Context) error {
		s.snapshot()

		return nil
	}).Times(1)

	s.MockTransactional.EXPECT().Commit(gomock.Any()).Times(0)

	return s
}

var errCIBAPushTestRefresh = errors.New("refresh token storage unavailable")

type cibaPushFailingMemoryStore struct {
	*storage.MemoryStore
	*cibaPushRollbackStore
}

func (s *cibaPushFailingMemoryStore) CreateRefreshTokenSession(_ context.Context, _ string, _ string, _ oauth2.Requester) error {
	return errCIBAPushTestRefresh
}

type cibaPushFailingHydratingStore struct {
	*storage.HydratingMemoryStore
	*cibaPushRollbackStore
}

func (s *cibaPushFailingHydratingStore) CreateRefreshTokenSession(_ context.Context, _ string, _ string, _ oauth2.Requester) error {
	return errCIBAPushTestRefresh
}

func TestPushIssuanceFailureRollsBackAndFails(t *testing.T) {
	scopes := oauth2.Arguments{consts.ScopeOpenID, consts.ScopeOffline}

	stores := []struct {
		name string
		new  func(ctrl *gomock.Controller) (any, *storage.MemoryStore)
	}{
		{"MemoryStore", func(ctrl *gomock.Controller) (any, *storage.MemoryStore) {
			s := storage.NewMemoryStore()

			return &cibaPushFailingMemoryStore{MemoryStore: s, cibaPushRollbackStore: newCIBAPushRollbackStore(ctrl, s)}, s
		}},
		{"HydratingMemoryStore", func(ctrl *gomock.Controller) (any, *storage.MemoryStore) {
			s := storage.NewHydratingMemoryStore()

			return &cibaPushFailingHydratingStore{HydratingMemoryStore: s, cibaPushRollbackStore: newCIBAPushRollbackStore(ctrl, s.MemoryStore)}, s.MemoryStore
		}},
	}

	for _, sc := range stores {
		t.Run(sc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)

			store, memory := sc.new(ctrl)
			notifier := &recordingBackChannelNotifier{}
			provider := newCIBAPushTestProvider(t, store, memory, notifier)

			authReqID := newCIBAPushTestRequest(t, provider, scopes)

			result, err := provider.ApproveBackChannelAuthentication(t.Context(), loadCIBAPushTestRequest(t, provider, scopes), newCIBAPushTestApproval())
			require.NoError(t, err)
			require.NotNil(t, result)

			assert.ErrorIs(t, result.IssuanceError, errCIBAPushTestRefresh)
			assert.NoError(t, result.DeliveryError)
			assert.Equal(t, oauth2.CIBAStatusFailed, result.Status)

			assert.Empty(t, memory.AccessTokens)
			assert.Empty(t, memory.RefreshTokens)

			stored, err := memory.GetCIBASessionByRequestID(t.Context(), cibaPushTestRequestID, openid.NewDefaultSession())
			require.NoError(t, err)
			assert.Equal(t, oauth2.CIBAStatusFailed, stored.GetStatus())
			assert.Contains(t, stored.GetFailureCause(), errCIBAPushTestRefresh.Error())

			require.Len(t, notifier.notifications, 1)
			assert.Same(t, notifier.notifications[0], result.Notification)

			body := map[string]string{}
			require.NoError(t, json.Unmarshal(notifier.notifications[0].Body, &body))

			assert.Equal(t, authReqID, body[consts.FormParameterAuthReqID])
			assert.Equal(t, "transaction_failed", body[consts.FormParameterError])
			assert.NotContains(t, string(notifier.notifications[0].Body), errCIBAPushTestRefresh.Error())
		})
	}
}

func TestPushIssuanceFailureInJoinedTransactionReturnsError(t *testing.T) {
	scopes := oauth2.Arguments{consts.ScopeOpenID, consts.ScopeOffline}

	ctrl := gomock.NewController(t)

	memory := storage.NewMemoryStore()
	store := &cibaPushFailingMemoryStore{MemoryStore: memory, cibaPushRollbackStore: newCIBAPushRollbackStore(ctrl, memory)}
	notifier := &recordingBackChannelNotifier{}
	provider := newCIBAPushTestProvider(t, store, memory, notifier)

	newCIBAPushTestRequest(t, provider, scopes)

	request := loadCIBAPushTestRequest(t, provider, scopes)

	outer, owned, err := storage.JoinOrBeginTx(t.Context(), store)
	require.NoError(t, err)
	require.True(t, owned)

	result, err := provider.ApproveBackChannelAuthentication(outer, request, newCIBAPushTestApproval())
	assert.ErrorIs(t, err, errCIBAPushTestRefresh)
	assert.Nil(t, result)
	assert.Empty(t, notifier.notifications)

	require.NoError(t, storage.MaybeRollbackTx(outer, store))

	stored, err := memory.GetCIBASessionByRequestID(t.Context(), cibaPushTestRequestID, openid.NewDefaultSession())
	require.NoError(t, err)
	assert.Equal(t, oauth2.CIBAStatusPending, stored.GetStatus())
	assert.Empty(t, memory.AccessTokens)
}

type cibaPushJoinedMemoryStore struct {
	*storage.MemoryStore
	*mock.MockTransactional
}

type cibaPushJoinedHydratingStore struct {
	*storage.HydratingMemoryStore
	*mock.MockTransactional
}

func TestPushApproveInJoinedTransactionLeavesDeliveryToTheOwner(t *testing.T) {
	scopes := oauth2.Arguments{consts.ScopeOpenID, consts.ScopeOffline}

	stores := []struct {
		name string
		new  func(tx *mock.MockTransactional) (any, *storage.MemoryStore)
	}{
		{"MemoryStore", func(tx *mock.MockTransactional) (any, *storage.MemoryStore) {
			s := storage.NewMemoryStore()

			return &cibaPushJoinedMemoryStore{MemoryStore: s, MockTransactional: tx}, s
		}},
		{"HydratingMemoryStore", func(tx *mock.MockTransactional) (any, *storage.MemoryStore) {
			s := storage.NewHydratingMemoryStore()

			return &cibaPushJoinedHydratingStore{HydratingMemoryStore: s, MockTransactional: tx}, s.MemoryStore
		}},
	}

	for _, sc := range stores {
		t.Run(sc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)

			tx := mock.NewMockTransactional(ctrl)
			tx.EXPECT().BeginTX(gomock.Any()).DoAndReturn(func(ctx context.Context) (context.Context, error) { return ctx, nil }).Times(1)
			tx.EXPECT().Commit(gomock.Any()).Return(nil).Times(1)
			tx.EXPECT().Rollback(gomock.Any()).Times(0)

			store, memory := sc.new(tx)
			notifier := &recordingBackChannelNotifier{}
			provider := newCIBAPushTestProvider(t, store, memory, notifier)

			authReqID := newCIBAPushTestRequest(t, provider, scopes)

			request := loadCIBAPushTestRequest(t, provider, scopes)

			outer, owned, err := storage.JoinOrBeginTx(t.Context(), store)
			require.NoError(t, err)
			require.True(t, owned)

			result, err := provider.ApproveBackChannelAuthentication(outer, request, newCIBAPushTestApproval())
			require.NoError(t, err)
			require.NotNil(t, result)
			assert.Equal(t, oauth2.CIBAStatusApproved, result.Status)
			assert.NoError(t, result.IssuanceError)
			assert.NoError(t, result.DeliveryError)

			assert.Empty(t, notifier.notifications)

			require.NotNil(t, result.Notification)
			assert.Equal(t, consts.CIBAModePush, result.Notification.Mode)

			body := decodeCIBAPushTestBody(t, result.Notification)
			assert.Equal(t, authReqID, body[consts.FormParameterAuthReqID])
			assert.NotEmpty(t, body[consts.AccessResponseAccessToken])
			assert.NotEmpty(t, body[consts.AccessResponseIDToken])

			require.NoError(t, storage.MaybeCommitTx(outer, store))
		})
	}
}

type cibaPushFailingNonTransactionalStore struct {
	*storage.MemoryStore
}

func (s *cibaPushFailingNonTransactionalStore) CreateRefreshTokenSession(_ context.Context, _ string, _ string, _ oauth2.Requester) error {
	return errCIBAPushTestRefresh
}

func TestPushIssuanceFailureWithoutTransactionNotifiesAndReturnsError(t *testing.T) {
	scopes := oauth2.Arguments{consts.ScopeOpenID, consts.ScopeOffline}

	testCases := []struct {
		name    string
		store   func(memory *storage.MemoryStore) any
		granted oauth2.Arguments
		cause   error
		access  int
		refresh int
	}{
		{
			name: "ShouldNotifyWhenTheRefreshTokenCannotBeStored",
			store: func(memory *storage.MemoryStore) any {
				return &cibaPushFailingNonTransactionalStore{MemoryStore: memory}
			},
			granted: scopes,
			cause:   errCIBAPushTestRefresh,
			access:  1,
			refresh: 0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			memory := storage.NewMemoryStore()
			notifier := &recordingBackChannelNotifier{}
			provider := newCIBAPushTestProvider(t, tc.store(memory), memory, notifier)

			authReqID := newCIBAPushTestRequest(t, provider, scopes)

			result, err := provider.ApproveBackChannelAuthentication(t.Context(), loadCIBAPushTestRequest(t, provider, tc.granted), newCIBAPushTestApproval())
			assert.ErrorIs(t, err, oauth2.ErrServerError)
			assert.ErrorIs(t, err, tc.cause)

			require.NotNil(t, result)
			assert.Equal(t, oauth2.CIBAStatusFailed, result.Status)
			assert.ErrorIs(t, result.IssuanceError, tc.cause)
			assert.NoError(t, result.DeliveryError)

			// The token sessions written before the failure stay persisted, but no token is delivered.
			assert.Len(t, memory.AccessTokens, tc.access)
			assert.Len(t, memory.RefreshTokens, tc.refresh)

			require.Len(t, notifier.notifications, 1)
			assert.Same(t, notifier.notifications[0], result.Notification)

			body := map[string]string{}
			require.NoError(t, json.Unmarshal(result.Notification.Body, &body))

			assert.Equal(t, authReqID, body[consts.FormParameterAuthReqID])
			assert.Equal(t, "transaction_failed", body[consts.FormParameterError])
			assert.NotContains(t, body, consts.AccessResponseAccessToken)

			// The approval and the invalidation written before the failure are not rolled back.
			stored, err := memory.GetCIBASessionByRequestID(t.Context(), cibaPushTestRequestID, openid.NewDefaultSession())
			assert.ErrorIs(t, err, oauth2.ErrInvalidatedCIBASession)
			require.NotNil(t, stored)
			assert.Equal(t, oauth2.CIBAStatusApproved, stored.GetStatus())
		})
	}
}

// cibaPushNilNotifierConfig resolves no notifier, as a Configurator other than *oauth2.Config may.
type cibaPushNilNotifierConfig struct {
	*oauth2.Config
}

func (c *cibaPushNilNotifierConfig) GetBackChannelNotifier(_ context.Context) oauth2.BackChannelNotifier {
	return nil
}

func TestPushApproveWithoutNotifierRecordsNothing(t *testing.T) {
	scopes := oauth2.Arguments{consts.ScopeOpenID, consts.ScopeOffline}

	testCases := []struct {
		name     string
		notifier oauth2.BackChannelNotifier
	}{
		{"ShouldRejectANilNotifier", nil},
		{"ShouldRejectATypedNilNotifier", (*recordingBackChannelNotifier)(nil)},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			for _, sc := range cibaPushTestStores {
				t.Run(sc.name, func(t *testing.T) {
					store, memory := sc.new()
					provider := newCIBAPushTestProvider(t, store, memory, tc.notifier)

					if tc.notifier == nil {
						provider.Config = &cibaPushNilNotifierConfig{Config: provider.Config.(*oauth2.Config)}
					}

					newCIBAPushTestRequest(t, provider, scopes)

					result, err := provider.ApproveBackChannelAuthentication(t.Context(), loadCIBAPushTestRequest(t, provider, scopes), newCIBAPushTestApproval())
					assert.ErrorIs(t, err, oauth2.ErrServerError)
					assert.Nil(t, result)

					stored, err := memory.GetCIBASessionByRequestID(t.Context(), cibaPushTestRequestID, openid.NewDefaultSession())
					require.NoError(t, err)
					assert.Equal(t, oauth2.CIBAStatusPending, stored.GetStatus())
					assert.Empty(t, memory.AccessTokens)
					assert.Empty(t, memory.IDSessions)
				})
			}
		})
	}
}

func TestPushConcurrentApproveIssuesOnce(t *testing.T) {
	scopes := oauth2.Arguments{consts.ScopeOpenID, consts.ScopeOffline}

	for _, sc := range cibaPushTestStores {
		t.Run(sc.name, func(t *testing.T) {
			store, memory := sc.new()
			notifier := &recordingBackChannelNotifier{}
			provider := newCIBAPushTestProvider(t, store, memory, notifier)

			newCIBAPushTestRequest(t, provider, scopes)

			const n = 2

			requests := make([]oauth2.BackChannelAuthenticationRequester, n)

			for i := range requests {
				requests[i] = loadCIBAPushTestRequest(t, provider, scopes)
			}

			var (
				wg      sync.WaitGroup
				start   = make(chan struct{})
				errs    = make([]error, n)
				results = make([]*oauth2.BackChannelAuthenticationDecisionResult, n)
			)

			for i := range requests {
				wg.Add(1)

				go func() {
					defer wg.Done()

					<-start

					results[i], errs[i] = provider.ApproveBackChannelAuthentication(context.Background(), requests[i], newCIBAPushTestApproval())
				}()
			}

			close(start)
			wg.Wait()

			var winners, losers int

			for i := range errs {
				if errs[i] == nil {
					winners++

					assert.Equal(t, oauth2.CIBAStatusApproved, results[i].Status)
					assert.NoError(t, results[i].IssuanceError)

					continue
				}

				losers++

				assert.ErrorIs(t, errs[i], oauth2.ErrInvalidRequest)
				assert.Contains(t, oauth2.ErrorToRFC6749Error(errs[i]).GetDescription(), "already decided")
			}

			assert.Equal(t, 1, winners)
			assert.Equal(t, 1, losers)

			require.Len(t, notifier.notifications, 1)
			assert.Contains(t, decodeCIBAPushTestBody(t, notifier.notifications[0]), consts.AccessResponseAccessToken)
			assert.Len(t, memory.AccessTokens, 1)
		})
	}
}

func TestPushDenyFailExpireBodies(t *testing.T) {
	scopes := oauth2.Arguments{consts.ScopeOpenID}

	testCases := []struct {
		name     string
		decide   func(t *testing.T, provider *oauth2.Fosite, request oauth2.BackChannelAuthenticationRequester) (*oauth2.BackChannelAuthenticationDecisionResult, error)
		status   oauth2.CIBAStatus
		expected string
	}{
		{
			name: "ShouldSendAccessDeniedOnDeny",
			decide: func(t *testing.T, provider *oauth2.Fosite, request oauth2.BackChannelAuthenticationRequester) (*oauth2.BackChannelAuthenticationDecisionResult, error) {
				return provider.DenyBackChannelAuthentication(t.Context(), request)
			},
			status:   oauth2.CIBAStatusDenied,
			expected: "access_denied",
		},
		{
			name: "ShouldSendTransactionFailedOnFail",
			decide: func(t *testing.T, provider *oauth2.Fosite, request oauth2.BackChannelAuthenticationRequester) (*oauth2.BackChannelAuthenticationDecisionResult, error) {
				return provider.FailBackChannelAuthentication(t.Context(), request, "device unreachable")
			},
			status:   oauth2.CIBAStatusFailed,
			expected: "transaction_failed",
		},
		{
			name: "ShouldSendExpiredTokenOnExpire",
			decide: func(t *testing.T, provider *oauth2.Fosite, request oauth2.BackChannelAuthenticationRequester) (*oauth2.BackChannelAuthenticationDecisionResult, error) {
				request.GetSession().SetExpiresAt(oauth2.CIBAAuthRequestID, time.Now().Add(-time.Second))

				return provider.ExpireBackChannelAuthentication(t.Context(), request)
			},
			status:   oauth2.CIBAStatusPending,
			expected: "expired_token",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			for _, sc := range cibaPushTestStores {
				t.Run(sc.name, func(t *testing.T) {
					store, memory := sc.new()
					notifier := &recordingBackChannelNotifier{}
					provider := newCIBAPushTestProvider(t, store, memory, notifier)

					authReqID := newCIBAPushTestRequest(t, provider, scopes)

					result, err := tc.decide(t, provider, loadCIBAPushTestRequest(t, provider, nil))
					require.NoError(t, err)
					require.NoError(t, result.DeliveryError)
					assert.Equal(t, tc.status, result.Status)

					require.Len(t, notifier.notifications, 1)
					assert.Same(t, notifier.notifications[0], result.Notification)
					assert.Equal(t, consts.CIBAModePush, result.Notification.Mode)
					assert.Equal(t, cibaPushTestToken, result.Notification.BearerToken)

					body := map[string]string{}
					require.NoError(t, json.Unmarshal(result.Notification.Body, &body))

					assert.Equal(t, authReqID, body[consts.FormParameterAuthReqID])
					assert.Equal(t, tc.expected, body[consts.FormParameterError])
					assert.Empty(t, memory.AccessTokens)
				})
			}
		})
	}
}

func TestExpireBackChannelAuthenticationRejects(t *testing.T) {
	testCases := []struct {
		name   string
		mode   string
		expire bool
		decide bool
	}{
		{"ShouldRejectAnUnexpiredPushRequest", consts.CIBAModePush, false, false},
		{"ShouldRejectAPollRequest", consts.CIBAModePoll, true, false},
		{"ShouldRejectAPingRequest", consts.CIBAModePing, true, false},
		{"ShouldRejectADecidedPushRequest", consts.CIBAModePush, true, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			for _, sc := range cibaPushTestStores {
				t.Run(sc.name, func(t *testing.T) {
					store, memory := sc.new()
					notifier := &recordingBackChannelNotifier{}
					provider := newCIBAPushTestProvider(t, store, memory, notifier)

					newCIBAPushTestRequest(t, provider, oauth2.Arguments{consts.ScopeOpenID})

					request := loadCIBAPushTestRequest(t, provider, nil)
					request.(*oauth2.BackChannelAuthenticationRequest).DeliveryMode = tc.mode

					if tc.decide {
						request.SetStatus(oauth2.CIBAStatusDenied)
					}

					if tc.expire {
						request.GetSession().SetExpiresAt(oauth2.CIBAAuthRequestID, time.Now().Add(-time.Second))
					}

					result, err := provider.ExpireBackChannelAuthentication(t.Context(), request)
					assert.ErrorIs(t, err, oauth2.ErrInvalidRequest)
					assert.Nil(t, result)
					assert.Empty(t, notifier.notifications)
				})
			}
		})
	}
}

func TestNewBackChannelPushTokenNotification(t *testing.T) {
	client := &oauth2.DefaultCIBAClient{
		BackChannelTokenDeliveryMode:          consts.CIBAModePush,
		BackChannelClientNotificationEndpoint: cibaPushTestEndpoint,
		DefaultClient:                         &oauth2.DefaultClient{ID: cibaPushTestClientID},
	}

	request := oauth2.NewBackChannelAuthenticationRequest()
	request.SetID(cibaPushTestRequestID)
	request.ClientNotificationToken = cibaPushTestToken

	response := oauth2.NewAccessResponse()
	response.SetAccessToken("access")
	response.SetTokenType(oauth2.BearerAccessToken)
	response.SetExpiresIn(time.Hour)
	response.SetExtra(consts.AccessResponseIDToken, "id-token")

	notification, err := oauth2.NewBackChannelPushTokenNotification(client, request, "raw-id", response)
	require.NoError(t, err)

	assert.Equal(t, consts.CIBAModePush, notification.Mode)
	assert.Equal(t, cibaPushTestRequestID, notification.RequestID)
	assert.Equal(t, cibaPushTestEndpoint, notification.Endpoint)
	assert.Equal(t, cibaPushTestToken, notification.BearerToken)

	body := decodeCIBAPushTestBody(t, notification)
	assert.Equal(t, "raw-id", body[consts.FormParameterAuthReqID])
	assert.Equal(t, "access", body[consts.AccessResponseAccessToken])
	assert.Equal(t, "id-token", body[consts.AccessResponseIDToken])
	assert.InDelta(t, 3600, body[consts.AccessResponseExpiresIn], 1)

	_, err = oauth2.NewBackChannelPushTokenNotification(client, request, "raw-id", nil)
	assert.Error(t, err)

	_, err = oauth2.NewBackChannelPushTokenNotification(client, request, "", response)
	assert.Error(t, err)
}

func TestPushApproveWithoutDeliveryRecordsNothing(t *testing.T) {
	scopes := oauth2.Arguments{consts.ScopeOpenID, consts.ScopeOffline}

	testCases := []struct {
		name   string
		mutate func(request *oauth2.BackChannelAuthenticationRequest)
	}{
		{"ShouldRejectAMissingAuthRequestID", func(request *oauth2.BackChannelAuthenticationRequest) { request.AuthRequestID = "" }},
		{"ShouldRejectAMissingClientNotificationToken", func(request *oauth2.BackChannelAuthenticationRequest) { request.ClientNotificationToken = "" }},
		{"ShouldRejectAMissingClientNotificationEndpoint", func(request *oauth2.BackChannelAuthenticationRequest) {
			request.Client = &oauth2.DefaultCIBAClient{
				BackChannelTokenDeliveryMode: consts.CIBAModePush,
				DefaultClient:                request.Client.(*oauth2.DefaultCIBAClient).DefaultClient,
			}
		}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			for _, sc := range cibaPushTestStores {
				t.Run(sc.name, func(t *testing.T) {
					store, memory := sc.new()
					notifier := &recordingBackChannelNotifier{}
					provider := newCIBAPushTestProvider(t, store, memory, notifier)

					newCIBAPushTestRequest(t, provider, scopes)

					loaded := loadCIBAPushTestRequest(t, provider, scopes)

					request, ok := loaded.(*oauth2.BackChannelAuthenticationRequest)
					require.True(t, ok)

					tc.mutate(request)

					result, err := provider.ApproveBackChannelAuthentication(t.Context(), loaded, newCIBAPushTestApproval())
					assert.ErrorIs(t, err, oauth2.ErrServerError)
					assert.Nil(t, result)
					assert.Empty(t, notifier.notifications)

					stored, err := memory.GetCIBASessionByRequestID(t.Context(), cibaPushTestRequestID, openid.NewDefaultSession())
					require.NoError(t, err)
					assert.Equal(t, oauth2.CIBAStatusPending, stored.GetStatus())
					assert.Empty(t, memory.AccessTokens)
					assert.Empty(t, memory.IDSessions)
				})
			}
		})
	}
}

func TestPushApproveWithoutIDTokenFails(t *testing.T) {
	scopes := oauth2.Arguments{consts.ScopeOpenID, consts.ScopeOffline}

	for _, sc := range cibaPushTestStores {
		t.Run(sc.name, func(t *testing.T) {
			store, memory := sc.new()
			notifier := &recordingBackChannelNotifier{}
			provider := newCIBAPushTestProvider(t, store, memory, notifier)

			config := provider.Config.(*oauth2.Config)

			var handlers oauth2.TokenEndpointHandlers

			for _, h := range config.TokenEndpointHandlers {
				if _, ok := h.(*openid.OpenIDConnectCIBAHandler); !ok {
					handlers = append(handlers, h)
				}
			}

			config.TokenEndpointHandlers = handlers

			authReqID := newCIBAPushTestRequest(t, provider, scopes)

			// The memory stores are not transactional, so the recorded approval is not rolled back.
			result, err := provider.ApproveBackChannelAuthentication(t.Context(), loadCIBAPushTestRequest(t, provider, scopes), newCIBAPushTestApproval())
			assert.ErrorIs(t, err, oauth2.ErrServerError)
			require.NotNil(t, result)

			assert.ErrorIs(t, result.IssuanceError, oauth2.ErrServerError)
			assert.Equal(t, oauth2.CIBAStatusFailed, result.Status)

			require.Len(t, notifier.notifications, 1)

			body := decodeCIBAPushTestBody(t, notifier.notifications[0])
			assert.Equal(t, authReqID, body[consts.FormParameterAuthReqID])
			assert.Equal(t, "transaction_failed", body[consts.FormParameterError])
			assert.NotContains(t, body, consts.AccessResponseAccessToken)
		})
	}
}

type cibaDecisionRollbackMemoryStore struct {
	*storage.MemoryStore
	*cibaPushRollbackStore
}

type cibaDecisionRollbackHydratingStore struct {
	*storage.HydratingMemoryStore
	*cibaPushRollbackStore
}

var errCIBADecisionTestHandler = errors.New("openid connect session storage unavailable")

type cibaFailingDecisionHandler struct{}

func (cibaFailingDecisionHandler) HandleBackChannelAuthenticationDecision(_ context.Context, _ oauth2.BackChannelAuthenticationRequester, _ *oauth2.BackChannelAuthenticationDecisionResult) error {
	return errCIBADecisionTestHandler
}

func TestPingDecisionHandlerFailureRollsBack(t *testing.T) {
	stores := []struct {
		name string
		new  func(ctrl *gomock.Controller) (cibaDecisionTestStore, cibaDecisionTestStore)
	}{
		{"MemoryStore", func(ctrl *gomock.Controller) (cibaDecisionTestStore, cibaDecisionTestStore) {
			s := storage.NewMemoryStore()

			return &cibaDecisionRollbackMemoryStore{MemoryStore: s, cibaPushRollbackStore: newCIBAPushRollbackStore(ctrl, s)}, s
		}},
		{"HydratingMemoryStore", func(ctrl *gomock.Controller) (cibaDecisionTestStore, cibaDecisionTestStore) {
			s := storage.NewHydratingMemoryStore()

			return &cibaDecisionRollbackHydratingStore{HydratingMemoryStore: s, cibaPushRollbackStore: newCIBAPushRollbackStore(ctrl, s.MemoryStore)}, s
		}},
	}

	for _, sc := range stores {
		t.Run(sc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)

			store, plain := sc.new(ctrl)
			notifier := &recordingBackChannelNotifier{}
			provider := newCIBAPingTestProvider(store, notifier)

			config := provider.Config.(*oauth2.Config)
			handlers := config.BackChannelAuthenticationDecisionHandlers

			config.BackChannelAuthenticationDecisionHandlers = append(append(oauth2.BackChannelAuthenticationDecisionHandlers{}, handlers...), cibaFailingDecisionHandler{})

			createCIBADecisionTestRequest(t, provider, newCIBAPingTestRequest(consts.CIBAModePing, "notification-token"))

			_, err := decideCIBAPingTest(t, provider, "approve")
			assert.ErrorIs(t, err, errCIBADecisionTestHandler)
			assert.Empty(t, notifier.notifications)

			stored, err := plain.GetCIBASessionByRequestID(t.Context(), cibaDecisionTestRequestID, openid.NewDefaultSession())
			require.NoError(t, err)
			assert.Equal(t, oauth2.CIBAStatusPending, stored.GetStatus())

			provider.Store = plain
			config.BackChannelAuthenticationDecisionHandlers = handlers

			result, err := decideCIBAPingTest(t, provider, "approve")
			require.NoError(t, err)
			assert.Equal(t, oauth2.CIBAStatusApproved, result.Status)
			assert.Len(t, notifier.notifications, 1)
		})
	}
}

func TestPushSweepExpiresALoadedRequest(t *testing.T) {
	scopes := oauth2.Arguments{consts.ScopeOpenID, consts.ScopeOffline}

	for _, sc := range cibaPushTestStores {
		t.Run(sc.name, func(t *testing.T) {
			store, memory := sc.new()
			notifier := &recordingBackChannelNotifier{}
			provider := newCIBAPushTestProvider(t, store, memory, notifier)
			provider.Config.(*oauth2.Config).CIBAAuthRequestLifespan = time.Second

			authReqID := newCIBAPushTestRequest(t, provider, scopes)

			time.Sleep(2 * time.Second)

			loaded, err := provider.NewBackChannelAuthenticationDecisionRequest(t.Context(), cibaPushTestRequestID, openid.NewDefaultSession())
			require.ErrorIs(t, err, oauth2.ErrDeviceExpiredToken)
			require.NotNil(t, loaded)

			result, err := provider.ExpireBackChannelAuthentication(t.Context(), loaded)
			require.NoError(t, err)
			require.NoError(t, result.DeliveryError)

			require.Len(t, notifier.notifications, 1)

			body := decodeCIBAPushTestBody(t, notifier.notifications[0])
			assert.Equal(t, authReqID, body[consts.FormParameterAuthReqID])
			assert.Equal(t, "expired_token", body[consts.FormParameterError])
			assert.Equal(t, cibaPushTestToken, notifier.notifications[0].BearerToken)
		})
	}
}
