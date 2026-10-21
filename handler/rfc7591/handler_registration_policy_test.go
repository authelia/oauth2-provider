// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc7591

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/storage"
)

const (
	policyHandlerKey      = "session:example"
	policyHandlerOtherKey = "session:other"
	policyHandlerRedirect = "https://a.apps.example.com/oauth/callback"
	policyHandlerPattern  = "^https://[a-z0-9-]+\\.apps\\.example\\.com/oauth/callback$"

	policyHintLimitReached = "The presented Client Registration Token has reached its registration limit."
)

func TestClientRegistrationHandlerPolicy(t *testing.T) {
	for name, factory := range policyTestStores() {
		t.Run(name, func(t *testing.T) {
			t.Run("ShouldRegisterInPolicyBeyondTheGrantedScope", func(t *testing.T) {
				handler, _, _ := newPolicyRegistrationHandler(t, factory)

				responder := oauth2.NewClientRegistrationResponse()

				require.NoError(t, handler.HandleRFC7591ClientRegistrationEndpointRequest(context.Background(), policyRegistrationRequest(policyHandlerExample(1), policyHandlerKey), responder))
				assert.Equal(t, http.StatusCreated, responder.GetStatusCode())
				assert.NotEmpty(t, responder.ClientID)
			})

			t.Run("ShouldRejectOutOfPolicyGrantType", func(t *testing.T) {
				handler, _, memory := newPolicyRegistrationHandler(t, factory)

				requester := policyRegistrationRequest(policyHandlerExample(1), policyHandlerKey)
				requester.Metadata.GrantTypes = []string{consts.GrantTypeAuthorizationCode, consts.GrantTypeClientCredentials}

				err := handler.HandleRFC7591ClientRegistrationEndpointRequest(context.Background(), requester, oauth2.NewClientRegistrationResponse())

				assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), policyErrorPrefix+"The 'grant_types' value 'client_credentials' is not permitted by the registration policy.")
				assert.Empty(t, memory.Clients)
				assert.Zero(t, memory.ClientRegistrationCounts[policyHandlerKey])
			})

			t.Run("ShouldEnforceMaxRegistrationsPerKey", func(t *testing.T) {
				handler, _, memory := newPolicyRegistrationHandler(t, factory)

				ctx := context.Background()

				require.NoError(t, handler.HandleRFC7591ClientRegistrationEndpointRequest(ctx, policyRegistrationRequest(policyHandlerExample(1), policyHandlerKey), oauth2.NewClientRegistrationResponse()))

				err := handler.HandleRFC7591ClientRegistrationEndpointRequest(ctx, policyRegistrationRequest(policyHandlerExample(1), policyHandlerKey), oauth2.NewClientRegistrationResponse())
				assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), invalidTokenPrefix+policyHintLimitReached)

				require.NoError(t, handler.HandleRFC7591ClientRegistrationEndpointRequest(ctx, policyRegistrationRequest(policyHandlerExample(1), policyHandlerOtherKey), oauth2.NewClientRegistrationResponse()))

				assert.Len(t, memory.Clients, 2)
				assert.Equal(t, int64(1), memory.ClientRegistrationCounts[policyHandlerKey])
				assert.Equal(t, int64(1), memory.ClientRegistrationCounts[policyHandlerOtherKey])
			})

			t.Run("ShouldNeverExceedMaxRegistrationsConcurrently", func(t *testing.T) {
				handler, _, memory := newPolicyRegistrationHandler(t, factory)

				const attempts = 20

				var (
					wg      sync.WaitGroup
					mu      sync.Mutex
					created int
					limited int
				)

				for range attempts {
					wg.Add(1)

					go func() {
						defer wg.Done()

						responder := oauth2.NewClientRegistrationResponse()

						err := handler.HandleRFC7591ClientRegistrationEndpointRequest(context.Background(), policyRegistrationRequest(policyHandlerExample(1), policyHandlerKey), responder)

						mu.Lock()
						defer mu.Unlock()

						switch {
						case err == nil && responder.GetStatusCode() == http.StatusCreated:
							created++
						case err != nil && oauth2.ErrorToDebugRFC6749Error(err).Error() == invalidTokenPrefix+policyHintLimitReached:
							limited++
						}
					}()
				}

				wg.Wait()

				assert.Equal(t, 1, created)
				assert.Equal(t, attempts-1, limited)
				assert.Len(t, memory.Clients, 1)
			})

			t.Run("ShouldRejectRegistrationScopeListedByThePolicy", func(t *testing.T) {
				handler, _, memory := newPolicyRegistrationHandler(t, factory)

				claim := policyHandlerExample(0)
				claim[consts.ClientMetadataScope] = map[string]any{policyRuleSubsetOf: []any{consts.ScopeOpenID, consts.ScopeClientRegistration}}

				requester := policyRegistrationRequest(claim, policyHandlerKey)
				requester.Metadata.Scope = consts.ScopeOpenID + " " + consts.ScopeClientRegistration

				err := handler.HandleRFC7591ClientRegistrationEndpointRequest(context.Background(), requester, oauth2.NewClientRegistrationResponse())

				assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), policyErrorPrefix+"The request requested the scopes 'authelia:oauth2:dynamic-client-registration' which the presented Client Registration Token is not permitted to grant.")
				assert.Empty(t, memory.Clients)
			})

			t.Run("ShouldRejectMalformedPolicyWithoutReserving", func(t *testing.T) {
				handler, _, memory := newPolicyRegistrationHandler(t, factory)

				claim := policyHandlerExample(1)
				claim[consts.ClientMetadataScope] = map[string]any{}

				err := handler.HandleRFC7591ClientRegistrationEndpointRequest(context.Background(), policyRegistrationRequest(claim, policyHandlerKey), oauth2.NewClientRegistrationResponse())

				assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), policyErrorPrefix+policyHintScopeExactlyOne)
				assert.Empty(t, memory.Clients)
				assert.Empty(t, memory.ClientRegistrationCounts)
			})

			t.Run("ShouldMintManagementTokenCarryingThePolicy", func(t *testing.T) {
				handler, store, _ := newPolicyRegistrationHandler(t, factory)

				ctx := context.Background()
				responder := oauth2.NewClientRegistrationResponse()

				require.NoError(t, handler.HandleRFC7591ClientRegistrationEndpointRequest(ctx, policyRegistrationRequest(policyHandlerExample(1), policyHandlerKey), responder))

				session := &oauth2.DefaultSession{}

				stored, err := store.GetClientRegistrationTokenSession(ctx, handler.Strategy.ClientRegistrationTokenSignature(ctx, responder.RegistrationAccessToken), session)
				require.NoError(t, err)

				expected, err := ParseRegistrationPolicy(policyHandlerExample(0), nil, true)
				require.NoError(t, err)

				extra := stored.GetSession().(*oauth2.DefaultSession).Extra
				require.Contains(t, extra, consts.ClientRegistrationPolicyInternalKey)

				actual, err := ParseRegistrationPolicy(extra[consts.ClientRegistrationPolicyInternalKey], nil, true)
				require.NoError(t, err)

				assert.Equal(t, expected.WithoutMaxRegistrations(), actual.WithoutMaxRegistrations())
				assert.Zero(t, actual.MaxRegistrations())
				assert.NotContains(t, extra[consts.ClientRegistrationPolicyInternalKey], policyMemberMaxRegistrations)
				assert.Equal(t, oauth2.Arguments{ClientConfigurationURL(testEndpoint, responder.ClientID)}, stored.GetGrantedAudience())
				assert.Empty(t, stored.GetGrantedScopes())
				assert.Empty(t, stored.GetGrantedResource())
			})

			t.Run("ShouldApplyTheCeilingWithoutAPolicy", func(t *testing.T) {
				handler, _, memory := newPolicyRegistrationHandler(t, factory)

				requester := policyRegistrationRequest(nil, policyHandlerKey)
				requester.Authenticated = &policyRequester{Requester: grantableFixture("", oauth2.Arguments{consts.ScopeClientRegistration}), key: policyHandlerKey}

				err := handler.HandleRFC7591ClientRegistrationEndpointRequest(context.Background(), requester, oauth2.NewClientRegistrationResponse())

				assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), policyErrorPrefix+"The request requested the scopes 'openid', 'email' which the presented Client Registration Token is not permitted to grant.")
				assert.Empty(t, memory.Clients)
			})

			t.Run("ShouldFailWhenStorageCannotCount", func(t *testing.T) {
				handler, _, memory := newPolicyRegistrationHandler(t, factory)
				handler.Store = &uncountedStore{Storage: handler.Store}

				err := handler.HandleRFC7591ClientRegistrationEndpointRequest(context.Background(), policyRegistrationRequest(policyHandlerExample(1), policyHandlerKey), oauth2.NewClientRegistrationResponse())

				require.ErrorIs(t, err, oauth2.ErrServerError)
				assert.Empty(t, memory.Clients)
			})

			for suffix, claim := range map[string]map[string]any{"EmptyPolicy": {}, "CounterOnlyPolicy": {policyMemberMaxRegistrations: 1}} {
				t.Run("ShouldSkipTheCeilingButRejectRegistrationScopeWith"+suffix, func(t *testing.T) {
					handler, _, memory := newPolicyRegistrationHandler(t, factory)

					requester := policyRegistrationRequest(claim, policyHandlerKey)
					requester.Metadata.Scope = consts.ScopeOpenID + " " + policyTestEmail + " " + policyTestProfile

					require.NoError(t, handler.HandleRFC7591ClientRegistrationEndpointRequest(context.Background(), requester, oauth2.NewClientRegistrationResponse()))
					require.Len(t, memory.Clients, 1)

					handler, _, memory = newPolicyRegistrationHandler(t, factory)

					requester = policyRegistrationRequest(claim, policyHandlerKey)
					requester.Metadata.Scope = consts.ScopeOpenID + " " + consts.ScopeClientRegistration

					err := handler.HandleRFC7591ClientRegistrationEndpointRequest(context.Background(), requester, oauth2.NewClientRegistrationResponse())

					assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), policyErrorPrefix+"The request requested the scopes 'authelia:oauth2:dynamic-client-registration' which the presented Client Registration Token is not permitted to grant.")
					assert.Empty(t, memory.Clients)
				})
			}

			t.Run("ShouldFailWithoutACounterKey", func(t *testing.T) {
				handler, _, memory := newPolicyRegistrationHandler(t, factory)

				err := handler.HandleRFC7591ClientRegistrationEndpointRequest(context.Background(), policyRegistrationRequest(policyHandlerExample(1), ""), oauth2.NewClientRegistrationResponse())

				require.ErrorIs(t, err, oauth2.ErrServerError)
				assert.Empty(t, memory.Clients)
				assert.Empty(t, memory.ClientRegistrationCounts)
			})

			t.Run("ShouldRegisterWithoutCountingWhenUnlimited", func(t *testing.T) {
				handler, _, memory := newPolicyRegistrationHandler(t, factory)
				handler.Store = &uncountedStore{Storage: handler.Store}

				require.NoError(t, handler.HandleRFC7591ClientRegistrationEndpointRequest(context.Background(), policyRegistrationRequest(policyHandlerExample(0), policyHandlerKey), oauth2.NewClientRegistrationResponse()))
				assert.Len(t, memory.Clients, 1)
			})

			t.Run("ShouldReleaseTheSlotWhenMintingFails", func(t *testing.T) {
				handler, store, memory := newPolicyRegistrationHandler(t, factory)
				handler.Store = &failingCountedStore{
					failingSessionStore:              &failingSessionStore{Storage: store},
					ClientRegistrationCounterStorage: store.(oauth2.ClientRegistrationCounterStorage),
				}

				err := handler.HandleRFC7591ClientRegistrationEndpointRequest(context.Background(), policyRegistrationRequest(policyHandlerExample(1), policyHandlerKey), oauth2.NewClientRegistrationResponse())

				require.ErrorIs(t, err, oauth2.ErrServerError)
				assert.Empty(t, memory.Clients)
				assert.Zero(t, memory.ClientRegistrationCounts[policyHandlerKey])

				handler.Store = store

				require.NoError(t, handler.HandleRFC7591ClientRegistrationEndpointRequest(context.Background(), policyRegistrationRequest(policyHandlerExample(1), policyHandlerKey), oauth2.NewClientRegistrationResponse()))
			})

			t.Run("ShouldRetainTheSlotWhenDeletionFails", func(t *testing.T) {
				handler, store, memory := newPolicyRegistrationHandler(t, factory)
				handler.Store = &undeletableStore{failingCountedStore: &failingCountedStore{
					failingSessionStore:              &failingSessionStore{Storage: store},
					ClientRegistrationCounterStorage: store.(oauth2.ClientRegistrationCounterStorage),
				}}

				err := handler.HandleRFC7591ClientRegistrationEndpointRequest(context.Background(), policyRegistrationRequest(policyHandlerExample(1), policyHandlerKey), oauth2.NewClientRegistrationResponse())

				require.ErrorIs(t, err, oauth2.ErrServerError)
				assert.Contains(t, oauth2.ErrorToDebugRFC6749Error(err).Error(), "The registration counter slot was retained.")
				assert.Len(t, memory.Clients, 1)
				assert.Equal(t, int64(1), memory.ClientRegistrationCounts[policyHandlerKey])

				handler.Store = store

				err = handler.HandleRFC7591ClientRegistrationEndpointRequest(context.Background(), policyRegistrationRequest(policyHandlerExample(1), policyHandlerKey), oauth2.NewClientRegistrationResponse())

				require.ErrorIs(t, err, oauth2.ErrInvalidToken)
			})

			t.Run("ShouldReleaseTheSlotWhenCreateFailsAfterCancellation", func(t *testing.T) {
				handler, store, memory := newPolicyRegistrationHandler(t, factory)

				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()

				handler.Store = &cancellingStore{Storage: store, cancel: cancel, failCreate: true}

				err := handler.HandleRFC7591ClientRegistrationEndpointRequest(ctx, policyRegistrationRequest(policyHandlerExample(1), policyHandlerKey), oauth2.NewClientRegistrationResponse())

				require.ErrorIs(t, err, oauth2.ErrServerError)
				require.Error(t, ctx.Err())
				assert.NotContains(t, oauth2.ErrorToDebugRFC6749Error(err).Error(), "Releasing the registration counter slot also failed")
				assert.Empty(t, memory.Clients)
				assert.Zero(t, memory.ClientRegistrationCounts[policyHandlerKey])
			})

			t.Run("ShouldCompensateWhenMintingFailsAfterCancellation", func(t *testing.T) {
				handler, store, memory := newPolicyRegistrationHandler(t, factory)

				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()

				handler.Store = &cancellingStore{Storage: store, cancel: cancel}

				err := handler.HandleRFC7591ClientRegistrationEndpointRequest(ctx, policyRegistrationRequest(policyHandlerExample(1), policyHandlerKey), oauth2.NewClientRegistrationResponse())

				require.ErrorIs(t, err, oauth2.ErrServerError)
				require.Error(t, ctx.Err())
				assert.Empty(t, memory.Clients)
				assert.Zero(t, memory.ClientRegistrationCounts[policyHandlerKey])
			})
		})
	}
}

func newPolicyRegistrationHandler(t *testing.T, factory func() Storage) (handler *ClientRegistrationHandler, store Storage, memory *storage.MemoryStore) {
	t.Helper()

	config := &oauth2.Config{
		GlobalSecret:                          []byte("super-duper-secret-that-is-at-least-32-bytes"),
		RFC7591ClientRegistrationGlobalSecret: []byte("a-completely-different-secret-at-least-32b"),
		RFC7591ClientRegistrationEndpointURL:  testEndpoint,
		RFC7591ClientRegistrationStrategy:     NewDefaultClientRegistrationStrategy(),
		ScopeStrategy:                         oauth2.ExactScopeStrategy,
		TokenEntropy:                          32,
	}

	store = factory()

	switch typed := store.(type) {
	case *storage.HydratingMemoryStore:
		memory = typed.MemoryStore
	case *storage.MemoryStore:
		memory = typed
	default:
		t.Fatalf("unexpected store %T", store)
	}

	return &ClientRegistrationHandler{
		Store:    store,
		Strategy: hoauth2.NewHMACCoreStrategy(config, "authelia_%s_"),
		Config:   config,
	}, store, memory
}

func policyHandlerExample(max int) (claim map[string]any) {
	claim = map[string]any{
		policyMemberRedirectURIs:           map[string]any{policyRulePattern: policyHandlerPattern},
		consts.ClientMetadataGrantTypes:    map[string]any{policyRuleSubsetOf: []any{consts.GrantTypeAuthorizationCode, consts.GrantTypeRefreshToken}},
		consts.ClientMetadataResponseTypes: map[string]any{policyRuleOneOf: []any{consts.ResponseTypeAuthorizationCodeFlow}},
		policyMemberAuthMethod:             map[string]any{policyRuleOneOf: []any{consts.ClientAuthMethodPrivateKeyJWT, consts.ClientAuthMethodNone}},
		consts.ClientMetadataScope:         map[string]any{policyRuleSubsetOf: []any{consts.ScopeOpenID, policyTestProfile, policyTestEmail, policyTestTimetable}},
	}

	if max > 0 {
		claim[policyMemberMaxRegistrations] = max
	}

	return claim
}

func policyRegistrationRequest(claim map[string]any, key string) (requester *oauth2.ClientRegistrationRequest) {
	requester = oauth2.NewClientRegistrationRequest()
	requester.Metadata = &oauth2.ClientRegistrationMetadata{
		RedirectURIs:            []string{policyHandlerRedirect},
		GrantTypes:              []string{consts.GrantTypeAuthorizationCode},
		ResponseTypes:           []string{consts.ResponseTypeAuthorizationCodeFlow},
		TokenEndpointAuthMethod: consts.ClientAuthMethodNone,
		Scope:                   consts.ScopeOpenID + " " + policyTestEmail,
	}
	requester.Authenticated = &policyRequester{
		Requester: grantableFixture("", oauth2.Arguments{consts.ScopeClientRegistration}),
		claim:     claim,
		ok:        claim != nil,
		key:       key,
		patterns:  true,
	}

	return requester
}

type uncountedStore struct {
	Storage
}

type failingCountedStore struct {
	*failingSessionStore
	oauth2.ClientRegistrationCounterStorage
}

var errTestCreateClientFailed = errors.New("create client failed")

var errTestDeleteClientFailed = errors.New("delete client failed")

type undeletableStore struct {
	*failingCountedStore
}

func (s *undeletableStore) DeleteClient(ctx context.Context, id string) (err error) {
	return errTestDeleteClientFailed
}

type cancellingStore struct {
	Storage

	cancel     context.CancelFunc
	failCreate bool
}

func (s *cancellingStore) CreateClient(ctx context.Context, client oauth2.Client) (err error) {
	if s.failCreate {
		s.cancel()

		return errTestCreateClientFailed
	}

	return s.Storage.CreateClient(ctx, client)
}

func (s *cancellingStore) CreateClientRegistrationTokenSession(ctx context.Context, signature string, requester oauth2.Requester) (err error) {
	s.cancel()

	return errTestCreateSessionFailed
}

func (s *cancellingStore) DeleteClient(ctx context.Context, id string) (err error) {
	if err = ctx.Err(); err != nil {
		return err
	}

	return s.Storage.DeleteClient(ctx, id)
}

func (s *cancellingStore) ReserveClientRegistration(ctx context.Context, key string, max int64) (err error) {
	return s.Storage.(oauth2.ClientRegistrationCounterStorage).ReserveClientRegistration(ctx, key, max)
}

func (s *cancellingStore) ReleaseClientRegistration(ctx context.Context, key string) (err error) {
	if err = ctx.Err(); err != nil {
		return err
	}

	return s.Storage.(oauth2.ClientRegistrationCounterStorage).ReleaseClientRegistration(ctx, key)
}
