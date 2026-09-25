// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc8628_test

import (
	"context"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	. "authelia.com/provider/oauth2/handler/rfc8628"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/storage"
)

// RFC 8628 Section 3.2 requires a unique end-user code per grant, so the approval found by user code must belong to
// the device code being redeemed.
func TestDeviceCodeTokenHandlerRejectsApprovalOwnedByAnotherDeviceCode(t *testing.T) {
	for name, newStore := range userCodeBindingStores() {
		t.Run(name, func(t *testing.T) {
			strategy := &o2hmacshaStrategy
			store, memory := newStore()

			config := &oauth2.Config{
				ScopeStrategy:       oauth2.HierarchicScopeStrategy,
				AudienceStrategy:    oauth2.DefaultAudienceStrategy,
				AccessTokenLifespan: time.Minute,
			}

			h := hoauth2.GenericCodeTokenEndpointHandler{
				CodeTokenEndpointHandler: &DeviceCodeTokenHandler{
					Strategy: strategy,
					Storage:  store,
					Config:   config,
				},
				AccessTokenStrategy:  strategy,
				RefreshTokenStrategy: strategy,
				Config:               config,
				CoreStorage:          store,
			}

			client := &oauth2.DefaultClient{ID: "device", GrantTypes: oauth2.Arguments{consts.GrantTypeOAuthDeviceCode}}

			_, uSig, err := strategy.GenerateRFC8628UserCode(t.Context())
			require.NoError(t, err)

			newGrant := func(subject string) (code string) {
				var sig string

				code, sig, err = strategy.GenerateRFC8628DeviceCode(t.Context())
				require.NoError(t, err)

				session := &oauth2.DefaultSession{Subject: subject}
				session.SetExpiresAt(oauth2.DeviceCode, time.Now().UTC().Add(time.Hour))
				session.SetExpiresAt(oauth2.UserCode, time.Now().UTC().Add(time.Hour))

				r := oauth2.NewDeviceAuthorizeRequest()
				r.Client = client
				r.SetSession(session)
				r.SetDeviceCodeSignature(sig)
				r.SetUserCodeSignature(uSig)
				r.SetStatus(oauth2.DeviceAuthorizeStatusNew)

				// CreateDeviceCodeSession rejects a shared user code, so seed the collision directly.
				memory.DeviceCodes[sig] = r
				memory.UserCodes[uSig] = r

				return code
			}

			attackerCode := newGrant("")
			victimCode := newGrant("")

			approved, err := store.GetDeviceCodeSessionByUserCode(t.Context(), uSig, &oauth2.DefaultSession{})
			require.NoError(t, err)

			approved.SetStatus(oauth2.DeviceAuthorizeStatusApproved)
			approved.GrantScope("admin")
			approved.SetSession(&oauth2.DefaultSession{Subject: "victim"})
			require.NoError(t, store.UpdateDeviceCodeSession(t.Context(), approved.GetDeviceCodeSignature(), approved))

			newAccessRequest := func(code string) *oauth2.AccessRequest {
				return &oauth2.AccessRequest{
					GrantTypes: oauth2.Arguments{consts.GrantTypeOAuthDeviceCode},
						Client:      client,
						Form:        url.Values{consts.FormParameterDeviceCode: {code}},
						Session:     &oauth2.DefaultSession{},
						RequestedAt: time.Now().UTC(),
				}
			}

			attacker := newAccessRequest(attackerCode)

			err = h.HandleTokenEndpointRequest(t.Context(), attacker)
			require.ErrorIs(t, err, oauth2.ErrInvalidGrant)
			assert.NotEqual(t, "victim", attacker.GetSession().GetSubject())
			assert.NotContains(t, attacker.GetGrantedScopes(), "admin")

			victim := newAccessRequest(victimCode)

			require.NoError(t, h.HandleTokenEndpointRequest(t.Context(), victim))
			assert.Equal(t, "victim", victim.GetSession().GetSubject())
		})
	}
}

func TestDeviceAuthorizeHandlerDoesNotReuseALiveUserCode(t *testing.T) {
	const taken = "BCDFGHJK"

	testCases := []struct {
		name  string
		codes []string
		err   error
		calls int
	}{
		{
			name:  "ShouldRegenerateOnCollision",
			codes: []string{taken},
			calls: 2,
		},
		{
			name:  "ShouldFailWhenEveryAttemptCollides",
			codes: []string{taken, taken, taken, taken, taken},
			err:   oauth2.ErrServerError,
			calls: 3,
		},
	}

	for name, newStore := range userCodeBindingStores() {
		for _, tc := range testCases {
			t.Run(name+"/"+tc.name, func(t *testing.T) {
				store, _ := newStore()
				strategy := &fixedUserCodeStrategy{CodeStrategy: &o2hmacshaStrategy, codes: tc.codes}

				takenSig, err := strategy.RFC8628UserCodeSignature(t.Context(), taken)
				require.NoError(t, err)

				_, ownerSig, err := strategy.GenerateRFC8628DeviceCode(t.Context())
				require.NoError(t, err)

				owner := oauth2.NewDeviceAuthorizeRequest()
				owner.SetSession(&oauth2.DefaultSession{})
				owner.SetDeviceCodeSignature(ownerSig)
				owner.SetUserCodeSignature(takenSig)
				owner.SetStatus(oauth2.DeviceAuthorizeStatusNew)
				require.NoError(t, store.CreateDeviceCodeSession(t.Context(), ownerSig, owner))

				handler := DeviceAuthorizeHandler{
					Storage:  store,
					Strategy: strategy,
					Config: &oauth2.Config{
						RFC8628CodeLifespan:        time.Minute,
						RFC8628UserVerificationURL: "https://www.test.com",
					},
				}

				request := oauth2.NewDeviceAuthorizeRequest()
				request.SetSession(&oauth2.DefaultSession{})

				response := oauth2.NewDeviceAuthorizeResponse()

				err = handler.HandleRFC8628DeviceAuthorizeEndpointRequest(t.Context(), request, response)
				assert.Equal(t, tc.calls, strategy.calls)

				if tc.err != nil {
					require.ErrorIs(t, err, tc.err)
				} else {
					require.NoError(t, err)
					assert.NotEqual(t, taken, response.GetUserCode())
					assert.NotEqual(t, takenSig, request.GetUserCodeSignature())
				}

				found, err := store.GetDeviceCodeSessionByUserCode(t.Context(), takenSig, &oauth2.DefaultSession{})
				require.NoError(t, err)
				assert.Equal(t, ownerSig, found.GetDeviceCodeSignature())
			})
		}
	}
}

func TestDeviceAuthorizeHandlerRegeneratesUserCodeClaimedConcurrently(t *testing.T) {
	const taken = "BCDFGHJK"

	for name, newStore := range userCodeBindingStores() {
		t.Run(name, func(t *testing.T) {
			store, _ := newStore()
			strategy := &fixedUserCodeStrategy{CodeStrategy: &o2hmacshaStrategy, codes: []string{taken}}

			takenSig, err := strategy.RFC8628UserCodeSignature(t.Context(), taken)
			require.NoError(t, err)

			_, ownerSig, err := strategy.GenerateRFC8628DeviceCode(t.Context())
			require.NoError(t, err)

			owner := oauth2.NewDeviceAuthorizeRequest()
			owner.SetSession(&oauth2.DefaultSession{})
			owner.SetDeviceCodeSignature(ownerSig)
			owner.SetUserCodeSignature(takenSig)
			owner.SetStatus(oauth2.DeviceAuthorizeStatusNew)

			handler := DeviceAuthorizeHandler{
				Storage:  &racingUserCodeStore{userCodeBindingStore: store, owner: owner},
				Strategy: strategy,
				Config: &oauth2.Config{
					RFC8628CodeLifespan:        time.Minute,
					RFC8628UserVerificationURL: "https://www.test.com",
				},
			}

			request := oauth2.NewDeviceAuthorizeRequest()
			request.SetSession(&oauth2.DefaultSession{})

			response := oauth2.NewDeviceAuthorizeResponse()

			require.NoError(t, handler.HandleRFC8628DeviceAuthorizeEndpointRequest(t.Context(), request, response))
			assert.Equal(t, 2, strategy.calls)
			assert.NotEqual(t, taken, response.GetUserCode())
			assert.NotEqual(t, takenSig, request.GetUserCodeSignature())

			found, err := store.GetDeviceCodeSessionByUserCode(t.Context(), takenSig, &oauth2.DefaultSession{})
			require.NoError(t, err)
			assert.Equal(t, ownerSig, found.GetDeviceCodeSignature())

			found, err = store.GetDeviceCodeSessionByUserCode(t.Context(), request.GetUserCodeSignature(), &oauth2.DefaultSession{})
			require.NoError(t, err)
			assert.Equal(t, request.GetDeviceCodeSignature(), found.GetDeviceCodeSignature())
		})
	}
}

type racingUserCodeStore struct {
	userCodeBindingStore

	owner oauth2.DeviceAuthorizeRequester
	raced bool
}

func (s *racingUserCodeStore) GetDeviceCodeSessionByUserCode(ctx context.Context, signature string, session oauth2.Session) (oauth2.DeviceAuthorizeRequester, error) {
	request, err := s.userCodeBindingStore.GetDeviceCodeSessionByUserCode(ctx, signature, session)

	if !s.raced {
		s.raced = true

		if cerr := s.CreateDeviceCodeSession(ctx, s.owner.GetDeviceCodeSignature(), s.owner); cerr != nil {
			return nil, cerr
		}
	}

	return request, err
}

type fixedUserCodeStrategy struct {
	CodeStrategy

	codes []string
	calls int
}

func (s *fixedUserCodeStrategy) GenerateRFC8628UserCode(ctx context.Context) (code string, signature string, err error) {
	if s.calls < len(s.codes) {
		code = s.codes[s.calls]
		s.calls++

		signature, err = s.RFC8628UserCodeSignature(ctx, code)

		return code, signature, err
	}

	s.calls++

	return s.CodeStrategy.GenerateRFC8628UserCode(ctx)
}

type userCodeBindingStore interface {
	Storage
	hoauth2.CoreStorage
}

func userCodeBindingStores() map[string]func() (userCodeBindingStore, *storage.MemoryStore) {
	return map[string]func() (userCodeBindingStore, *storage.MemoryStore){
		"MemoryStore": func() (userCodeBindingStore, *storage.MemoryStore) {
			store := storage.NewMemoryStore()

			return store, store
		},
		"HydratingMemoryStore": func() (userCodeBindingStore, *storage.MemoryStore) {
			store := storage.NewHydratingMemoryStore()

			return store, store.MemoryStore
		},
	}
}
