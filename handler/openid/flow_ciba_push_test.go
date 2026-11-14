// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package openid_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"maps"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/handler/openid"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/token/jwt"
)

type cibaPushRecordingNotifier struct {
	mu            sync.Mutex
	notifications []*oauth2.BackChannelNotification
}

func (n *cibaPushRecordingNotifier) NotifyBackChannelClient(_ context.Context, notification *oauth2.BackChannelNotification) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	n.notifications = append(n.notifications, notification)

	return nil
}

// usePush makes the fixture client a push client which may be issued refresh tokens, and records its notifications.
func (f *cibaOpenIDFixture) usePush() *cibaPushRecordingNotifier {
	notifier := &cibaPushRecordingNotifier{}

	f.client.BackChannelTokenDeliveryMode = consts.CIBAModePush
	f.client.BackChannelClientNotificationEndpoint = "https://client.example.com/cb"
	f.client.GrantTypes = oauth2.Arguments{consts.GrantTypeRefreshToken}
	f.client.Scopes = oauth2.Arguments{consts.ScopeOpenID, consts.ScopeOffline, cibaTestScopeProfile}
	f.config.BackChannelNotifier = notifier

	return notifier
}

// pushRequest stores a pending push request for the scopes and returns its raw 'auth_req_id'.
func (f *cibaOpenIDFixture) pushRequest(t *testing.T, scopes oauth2.Arguments) (authReqID string) {
	t.Helper()

	session := openid.NewDefaultSession()
	session.Subject = cibaTestSubject
	session.Claims.Subject = cibaTestSubject

	request := oauth2.NewBackChannelAuthenticationRequest()
	request.SetID("request-id")
	request.Client = f.client
	request.DeliveryMode = consts.CIBAModePush
	request.ClientNotificationToken = "push-notification-token"
	request.RequestedAt = time.Now().UTC()
	request.RequestedScope = scopes
	request.Session = session

	response, err := f.provider.NewBackChannelAuthenticationResponse(t.Context(), request)
	require.NoError(t, err)

	return response.GetAuthRequestID()
}

func cibaPushTestHash(value string) string {
	sum := sha256.Sum256([]byte(value))

	return base64.RawURLEncoding.EncodeToString(sum[:len(sum)/2])
}

func TestOpenIDCIBAPushIDTokenClaims(t *testing.T) {
	testCases := []struct {
		name    string
		scopes  oauth2.Arguments
		refresh bool
	}{
		{"ShouldAddTheRefreshTokenHashWhenARefreshTokenIsIssued", oauth2.Arguments{consts.ScopeOpenID, consts.ScopeOffline}, true},
		{"ShouldOmitTheRefreshTokenHashWithoutARefreshToken", oauth2.Arguments{consts.ScopeOpenID, cibaTestScopeProfile}, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			for _, sc := range cibaOpenIDTestStores {
				t.Run(sc.name, func(t *testing.T) {
					f := newCIBAOpenIDFixture(t, sc.new)
					notifier := f.usePush()

					authReqID := f.pushRequest(t, tc.scopes)

					loaded := f.load(t, "request-id", tc.scopes)

					result, err := f.provider.ApproveBackChannelAuthentication(t.Context(), loaded, newCIBAPushApproval())
					require.NoError(t, err)
					require.NoError(t, result.IssuanceError)
					require.Len(t, notifier.notifications, 1)

					body := map[string]any{}
					require.NoError(t, json.Unmarshal(notifier.notifications[0].Body, &body))

					access, _ := body[consts.AccessResponseAccessToken].(string)
					require.NotEmpty(t, access)

					token, _ := body[consts.AccessResponseIDToken].(string)
					require.NotEmpty(t, token)

					claims := decodeCIBATestIDToken(t, token)

					assert.Equal(t, cibaPushTestHash(access), claims[consts.ClaimAccessTokenHash])
					assert.Equal(t, authReqID, claims[consts.ClaimCIBAAuthReqID])

					if tc.refresh {
						refresh, _ := body[consts.AccessResponseRefreshToken].(string)
						require.NotEmpty(t, refresh)

						assert.Equal(t, cibaPushTestHash(refresh), claims[consts.ClaimRefreshTokenHash])
					} else {
						assert.NotContains(t, body, consts.AccessResponseRefreshToken)
						assert.NotContains(t, claims, consts.ClaimRefreshTokenHash)
					}
				})
			}
		})
	}
}

// cibaPushTransactionalStore simulates a transaction over the memory store: BeginTX snapshots the maps push issuance
// writes, and Rollback restores them.
type cibaPushTransactionalStore struct {
	cibaOpenIDTestStore

	memory    *storage.MemoryStore
	restore   func()
	rollbacks int
}

func (s *cibaPushTransactionalStore) BeginTX(ctx context.Context) (context.Context, error) {
	m := s.memory

	cibaSessions, invalidated := maps.Clone(m.CIBASessions), maps.Clone(m.InvalidatedCIBASessions)
	accessTokens, accessIDs := maps.Clone(m.AccessTokens), maps.Clone(m.AccessTokenRequestIDs)
	refreshTokens, refreshIDs := maps.Clone(m.RefreshTokens), maps.Clone(m.RefreshTokenRequestIDs)
	idSessions := maps.Clone(m.IDSessions)

	s.restore = func() {
		m.CIBASessions, m.InvalidatedCIBASessions = cibaSessions, invalidated
		m.AccessTokens, m.AccessTokenRequestIDs = accessTokens, accessIDs
		m.RefreshTokens, m.RefreshTokenRequestIDs = refreshTokens, refreshIDs
		m.IDSessions = idSessions
	}

	return ctx, nil
}

func (s *cibaPushTransactionalStore) Commit(_ context.Context) error {
	return nil
}

func (s *cibaPushTransactionalStore) Rollback(_ context.Context) error {
	s.rollbacks++
	s.restore()

	return nil
}

func TestOpenIDCIBAPushApprovalWithoutOpenIDIsDenied(t *testing.T) {
	for _, sc := range cibaOpenIDTestStores {
		t.Run(sc.name, func(t *testing.T) {
			var transactional *cibaPushTransactionalStore

			f := newCIBAOpenIDFixture(t, func() (cibaOpenIDTestStore, *storage.MemoryStore) {
				store, memory := sc.new()

				transactional = &cibaPushTransactionalStore{cibaOpenIDTestStore: store, memory: memory}

				return transactional, memory
			})
			notifier := f.usePush()

			f.pushRequest(t, oauth2.Arguments{consts.ScopeOpenID, cibaTestScopeProfile})

			loaded := f.load(t, "request-id", oauth2.Arguments{cibaTestScopeProfile})

			result, err := f.provider.ApproveBackChannelAuthentication(t.Context(), loaded, newCIBAPushApproval())
			assert.Nil(t, result)
			assert.ErrorIs(t, err, oauth2.ErrAccessDenied)
			assert.Equal(t, oauth2.CIBAStatusPending, loaded.GetStatus())
			assert.Equal(t, 0, transactional.rollbacks)

			stored, err := f.store.GetCIBASessionByRequestID(t.Context(), "request-id", openid.NewDefaultSession())
			require.NoError(t, err)
			assert.Equal(t, oauth2.CIBAStatusPending, stored.GetStatus())

			assert.Empty(t, notifier.notifications)
		})
	}
}

func TestPollIDTokenHasNoPushClaims(t *testing.T) {
	for _, sc := range cibaOpenIDTestStores {
		t.Run(sc.name, func(t *testing.T) {
			f := newCIBAOpenIDFixture(t, sc.new)

			f.client.GrantTypes = oauth2.Arguments{consts.GrantTypeOpenIDCIBA, consts.GrantTypeRefreshToken}
			f.client.Scopes = oauth2.Arguments{consts.ScopeOpenID, consts.ScopeOffline}

			scopes := oauth2.Arguments{consts.ScopeOpenID, consts.ScopeOffline}

			authReqID, requestID := f.request(t, scopes, nil)
			f.approve(t, requestID, scopes, nil)

			response := f.poll(t, authReqID)

			require.NotEmpty(t, response.GetExtra(consts.AccessResponseRefreshToken))

			token, ok := response.GetExtra(consts.AccessResponseIDToken).(string)
			require.True(t, ok)

			claims := decodeCIBATestIDToken(t, token)

			assert.NotEmpty(t, claims[consts.ClaimAccessTokenHash])
			assert.NotContains(t, claims, consts.ClaimCIBAAuthReqID)
			assert.NotContains(t, claims, consts.ClaimRefreshTokenHash)
		})
	}
}

func newCIBAPushApproval() *openid.DefaultSession {
	approval := openid.NewDefaultSession()
	approval.Subject = cibaTestSubject
	approval.Claims.Subject = cibaTestSubject
	approval.Claims.AuthTime = jwt.NewNumericDate(time.Now().Add(-time.Minute))

	return approval
}
