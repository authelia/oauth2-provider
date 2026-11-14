// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"encoding/json"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/handler/ciba"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/handler/openid"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/token/jwt"
)

type cibaDecisionTestStore interface {
	ciba.Storage
	oauth2.Storage
}

var cibaDecisionTestStores = []struct {
	name string
	new  func() cibaDecisionTestStore
}{
	{"MemoryStore", func() cibaDecisionTestStore { return storage.NewMemoryStore() }},
	{"HydratingMemoryStore", func() cibaDecisionTestStore { return storage.NewHydratingMemoryStore() }},
}

const cibaDecisionTestRequestID = "request-id"

func newCIBADecisionTestProvider(store cibaDecisionTestStore) (provider *oauth2.Fosite) {
	config := &oauth2.Config{GlobalSecret: []byte("foobarfoobarfoobarfoobarfoobarfoobarfoobarfoobar")}

	strategy := hoauth2.NewHMACCoreStrategy(config, "authelia_%s_")

	config.BackChannelAuthenticationEndpointHandlers.Append(&ciba.EndpointHandler{Strategy: strategy, Storage: store, Config: config})
	config.BackChannelAuthenticationDecisionHandlers.Append(&ciba.DecisionHandler{Strategy: strategy, Storage: store, Config: config})

	return &oauth2.Fosite{Store: store, Config: config}
}

func newCIBADecisionTestRequest(session oauth2.Session) (request *oauth2.BackChannelAuthenticationRequest) {
	request = oauth2.NewBackChannelAuthenticationRequest()
	request.SetID(cibaDecisionTestRequestID)
	request.DeliveryMode = consts.CIBAModePoll
	request.Client = &oauth2.DefaultClient{ID: "client"}
	request.Session = session
	request.RequestedScope = oauth2.Arguments{consts.ScopeOpenID, "profile", "email"}
	request.RequestedAudience = oauth2.Arguments{"https://api.example.com", "https://other.example.com"}
	request.SetRequestedAuthorizationDetails(oauth2.AuthorizationDetails{{Type: "payment", Actions: []string{"read", "write"}}})

	return request
}

func newCIBADecisionTestSession(subject string) (session *openid.DefaultSession) {
	session = openid.NewDefaultSession()
	session.Subject = subject
	session.Claims.Subject = subject

	return session
}

func createCIBADecisionTestRequest(t *testing.T, provider *oauth2.Fosite, request *oauth2.BackChannelAuthenticationRequest) {
	t.Helper()

	_, err := provider.NewBackChannelAuthenticationResponse(t.Context(), request)
	require.NoError(t, err)
}

func TestApproveCarriesBackchannelState(t *testing.T) {
	const (
		jkt       = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"
		requested = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
		x5t       = "A4DtL2JmUMhAsvJj5tAtEqYFn7uHnaMbNKmoNcE7dnE"
	)

	jwk := []byte(`{"kty":"EC","crv":"P-256","x":"x","y":"y"}`)

	for _, sc := range cibaDecisionTestStores {
		t.Run(sc.name, func(t *testing.T) {
			store := sc.new()
			provider := newCIBADecisionTestProvider(store)

			original := newCIBADecisionTestSession("john")
			original.SetDPoPJWKThumbprint(jkt)
			original.SetRequestedDPoPJWKThumbprint(requested)
			original.SetDPoPPublicKeyJWK(jwk)
			original.SetOIDCKeyBindingGranted(true)
			original.SetClientCertificateSHA256Thumbprint(x5t)

			request := newCIBADecisionTestRequest(original)
			request.RequestedScope = append(request.RequestedScope, consts.ScopeBoundKey)
			request.Form = url.Values{consts.FormParameterAuthenticationContextClassReferenceValues: {"phr"}, consts.FormParameterMaximumAge: {"60"}}
			request.BindingMessage = "W4SCT"
			request.RequestContext = json.RawMessage(`{"device":"kiosk"}`)
			request.RequestedExpiry = 120 * time.Second

			createCIBADecisionTestRequest(t, provider, request)

			pending, err := store.GetCIBASessionByRequestID(t.Context(), cibaDecisionTestRequestID, openid.NewDefaultSession())
			require.NoError(t, err)

			expiresAt := pending.GetSession().GetExpiresAt(oauth2.CIBAAuthRequestID)
			require.False(t, expiresAt.IsZero())

			loaded, err := provider.NewBackChannelAuthenticationDecisionRequest(t.Context(), cibaDecisionTestRequestID, openid.NewDefaultSession())
			require.NoError(t, err)

			assert.Equal(t, "W4SCT", loaded.GetBindingMessage())

			loaded.GrantScope(consts.ScopeOpenID)
			loaded.GrantScope(consts.ScopeBoundKey)

			authTime := time.Now().Add(-time.Minute).UTC().Truncate(time.Second)

			approval := newCIBADecisionTestSession("john")
			approval.Claims.AuthTime = jwt.NewNumericDate(authTime)
			approval.Claims.AuthenticationMethodsReferences = []string{"pwd", "otp"}

			result, err := provider.ApproveBackChannelAuthentication(t.Context(), loaded, approval)
			require.NoError(t, err)
			require.NotNil(t, result)

			assert.Equal(t, oauth2.CIBAStatusApproved, result.Status)
			assert.Nil(t, result.Notification)
			assert.NoError(t, result.DeliveryError)
			assert.NoError(t, result.IssuanceError)

			stored, err := store.GetCIBASessionByRequestID(t.Context(), cibaDecisionTestRequestID, openid.NewDefaultSession())
			require.NoError(t, err)

			assert.Equal(t, oauth2.CIBAStatusApproved, stored.GetStatus())
			assert.Equal(t, oauth2.Arguments{consts.ScopeOpenID, consts.ScopeBoundKey}, stored.GetGrantedScopes())
			assert.Equal(t, "W4SCT", stored.GetBindingMessage())
			assert.JSONEq(t, `{"device":"kiosk"}`, string(stored.GetRequestContext()))
			assert.Equal(t, 120*time.Second, stored.GetRequestedExpiry())
			assert.Equal(t, "phr", stored.GetRequestForm().Get(consts.FormParameterAuthenticationContextClassReferenceValues))
			assert.Equal(t, "60", stored.GetRequestForm().Get(consts.FormParameterMaximumAge))

			session, ok := stored.GetSession().(*openid.DefaultSession)
			require.True(t, ok)

			assert.Equal(t, "john", session.GetSubject())
			assert.Equal(t, jkt, session.GetDPoPJWKThumbprint())
			assert.Equal(t, requested, session.GetRequestedDPoPJWKThumbprint())
			assert.Equal(t, jwk, session.GetDPoPPublicKeyJWK())
			assert.True(t, session.GetOIDCKeyBindingGranted())
			assert.Equal(t, x5t, session.GetClientCertificateSHA256Thumbprint())
			assert.Equal(t, expiresAt, session.GetExpiresAt(oauth2.CIBAAuthRequestID))
			assert.ElementsMatch(t, []string{consts.ClaimAuthenticationContextClassReference, consts.ClaimAuthenticationTime}, session.GetRequestedAuthenticationContextClaims())

			require.NotNil(t, session.Claims.AuthTime)
			assert.Equal(t, authTime, session.Claims.AuthTime.UTC())
			assert.Equal(t, []string{"pwd", "otp"}, session.Claims.AuthenticationMethodsReferences)
		})
	}
}

func TestApproveClearsKeyBindingWhenBoundKeyIsNotGranted(t *testing.T) {
	testCases := []struct {
		name     string
		grant    oauth2.Arguments
		expected bool
	}{
		{name: "ShouldKeepKeyBindingWhenGranted", grant: oauth2.Arguments{consts.ScopeOpenID, consts.ScopeBoundKey}, expected: true},
		{name: "ShouldClearKeyBindingWhenNarrowedAway", grant: oauth2.Arguments{consts.ScopeOpenID}, expected: false},
	}

	for _, sc := range cibaDecisionTestStores {
		t.Run(sc.name, func(t *testing.T) {
			for _, tc := range testCases {
				t.Run(tc.name, func(t *testing.T) {
					store := sc.new()
					provider := newCIBADecisionTestProvider(store)

					original := newCIBADecisionTestSession("john")
					original.SetDPoPJWKThumbprint("0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I")
					original.SetDPoPPublicKeyJWK([]byte(`{"kty":"EC","crv":"P-256","x":"x","y":"y"}`))
					original.SetOIDCKeyBindingGranted(true)

					request := newCIBADecisionTestRequest(original)
					request.RequestedScope = append(request.RequestedScope, consts.ScopeBoundKey)

					createCIBADecisionTestRequest(t, provider, request)

					loaded, err := provider.NewBackChannelAuthenticationDecisionRequest(t.Context(), cibaDecisionTestRequestID, openid.NewDefaultSession())
					require.NoError(t, err)

					for _, scope := range tc.grant {
						loaded.GrantScope(scope)
					}

					approval := newCIBADecisionTestSession("john")
					approval.SetOIDCKeyBindingGranted(true)

					_, err = provider.ApproveBackChannelAuthentication(t.Context(), loaded, approval)
					require.NoError(t, err)

					stored, err := store.GetCIBASessionByRequestID(t.Context(), cibaDecisionTestRequestID, openid.NewDefaultSession())
					require.NoError(t, err)

					session, ok := stored.GetSession().(*openid.DefaultSession)
					require.True(t, ok)
					assert.Equal(t, tc.expected, session.GetOIDCKeyBindingGranted())
				})
			}
		})
	}
}

func TestApproveSubjectMismatchDenied(t *testing.T) {
	for _, sc := range cibaDecisionTestStores {
		t.Run(sc.name, func(t *testing.T) {
			store := sc.new()
			provider := newCIBADecisionTestProvider(store)

			createCIBADecisionTestRequest(t, provider, newCIBADecisionTestRequest(newCIBADecisionTestSession("john")))

			loaded, err := provider.NewBackChannelAuthenticationDecisionRequest(t.Context(), cibaDecisionTestRequestID, openid.NewDefaultSession())
			require.NoError(t, err)

			result, err := provider.ApproveBackChannelAuthentication(t.Context(), loaded, newCIBADecisionTestSession("jane"))

			require.Error(t, err)
			assert.Nil(t, result)
			assert.ErrorIs(t, err, oauth2.ErrAccessDenied)
			assert.Equal(t, oauth2.CIBAStatusPending, loaded.GetStatus())
			assert.Equal(t, "john", loaded.GetSession().GetSubject())

			stored, err := store.GetCIBASessionByRequestID(t.Context(), cibaDecisionTestRequestID, openid.NewDefaultSession())
			require.NoError(t, err)

			assert.Equal(t, oauth2.CIBAStatusPending, stored.GetStatus())
			assert.Equal(t, "john", stored.GetSession().GetSubject())
		})
	}
}

func TestApproveIDTokenSubjectMismatchDenied(t *testing.T) {
	testCases := []struct {
		name     string
		client   oauth2.Client
		recorded string
		approved string
		err      bool
	}{
		{name: "ShouldAllowTheRecordedIDTokenSubject", recorded: "john", approved: "john"},
		{name: "ShouldAllowNoIDTokenSubject", recorded: "john", approved: ""},
		{name: "ShouldDenyAnIDTokenSubjectOfAnotherEndUser", recorded: "john", approved: "jane", err: true},
		{name: "ShouldAllowTheRecordedPairwiseIDTokenSubject", recorded: "pairwise-john", approved: "pairwise-john"},
		{name: "ShouldDenyAnotherPairwiseIDTokenSubject", recorded: "pairwise-john", approved: "pairwise-jane", err: true},
		{name: "ShouldAllowTheSubjectWhenNoIDTokenSubjectWasRecorded", recorded: "", approved: "john"},
		{name: "ShouldDenyAnotherSubjectWhenNoIDTokenSubjectWasRecorded", recorded: "", approved: "jane", err: true},
		{
			name:     "ShouldAllowAPairwiseIDTokenSubjectWhenNoneWasRecorded",
			client:   &oauth2.DefaultRegisteredClient{DefaultClient: &oauth2.DefaultClient{ID: "client"}, SubjectType: consts.SubjectTypePairwise},
			recorded: "",
			approved: "pairwise-john",
		},
	}

	for _, sc := range cibaDecisionTestStores {
		t.Run(sc.name, func(t *testing.T) {
			for _, tc := range testCases {
				t.Run(tc.name, func(t *testing.T) {
					store := sc.new()
					provider := newCIBADecisionTestProvider(store)

					original := newCIBADecisionTestSession("john")
					original.Claims.Subject = tc.recorded

					request := newCIBADecisionTestRequest(original)
					if tc.client != nil {
						request.Client = tc.client
					}

					createCIBADecisionTestRequest(t, provider, request)

					loaded, err := provider.NewBackChannelAuthenticationDecisionRequest(t.Context(), cibaDecisionTestRequestID, openid.NewDefaultSession())
					require.NoError(t, err)

					loaded.GrantScope(consts.ScopeOpenID)

					approval := newCIBADecisionTestSession("john")
					approval.Claims.Subject = tc.approved

					result, err := provider.ApproveBackChannelAuthentication(t.Context(), loaded, approval)

					stored, gerr := store.GetCIBASessionByRequestID(t.Context(), cibaDecisionTestRequestID, openid.NewDefaultSession())
					require.NoError(t, gerr)

					if tc.err {
						require.Error(t, err)
						assert.Nil(t, result)
						assert.ErrorIs(t, err, oauth2.ErrAccessDenied)
						assert.Equal(t, oauth2.CIBAStatusPending, stored.GetStatus())

						session, ok := stored.GetSession().(*openid.DefaultSession)
						require.True(t, ok)
						assert.Equal(t, tc.recorded, session.Claims.Subject)

						return
					}

					require.NoError(t, err)
					assert.Equal(t, oauth2.CIBAStatusApproved, stored.GetStatus())
				})
			}
		})
	}
}

func TestApproveCarriesTheRequestTime(t *testing.T) {
	testCases := []struct {
		name     string
		approval func() *openid.DefaultSession
	}{
		{
			name: "ShouldReplaceTheApprovalTime",
			approval: func() *openid.DefaultSession {
				session := newCIBADecisionTestSession("john")
				session.RequestedAt = time.Now().UTC()

				return session
			},
		},
		{
			name: "ShouldSetAnUnsetRequestTime",
			approval: func() *openid.DefaultSession {
				session := newCIBADecisionTestSession("john")
				session.RequestedAt = time.Time{}

				return session
			},
		},
	}

	for _, sc := range cibaDecisionTestStores {
		t.Run(sc.name, func(t *testing.T) {
			for _, tc := range testCases {
				t.Run(tc.name, func(t *testing.T) {
					store := sc.new()
					provider := newCIBADecisionTestProvider(store)

					requestedAt := time.Now().UTC().Add(-10 * time.Minute).Truncate(time.Second)

					original := newCIBADecisionTestSession("john")
					original.RequestedAt = requestedAt.Add(-time.Hour)

					request := newCIBADecisionTestRequest(original)
					request.RequestedAt = requestedAt

					createCIBADecisionTestRequest(t, provider, request)

					loaded, err := provider.NewBackChannelAuthenticationDecisionRequest(t.Context(), cibaDecisionTestRequestID, openid.NewDefaultSession())
					require.NoError(t, err)

					loaded.GrantScope(consts.ScopeOpenID)

					_, err = provider.ApproveBackChannelAuthentication(t.Context(), loaded, tc.approval())
					require.NoError(t, err)

					stored, err := store.GetCIBASessionByRequestID(t.Context(), cibaDecisionTestRequestID, openid.NewDefaultSession())
					require.NoError(t, err)

					session, ok := stored.GetSession().(*openid.DefaultSession)
					require.True(t, ok)
					assert.Equal(t, requestedAt, session.GetRequestedAt())
				})
			}
		})
	}
}

func TestApproveCannotWidenScopes(t *testing.T) {
	testCases := []struct {
		name  string
		grant func(request oauth2.BackChannelAuthenticationRequester)
		err   bool
	}{
		{
			name: "ShouldAllowNarrowing",
			grant: func(request oauth2.BackChannelAuthenticationRequester) {
				request.GrantScope(consts.ScopeOpenID)
				request.GrantScope("profile")
				request.GrantAudience("https://api.example.com")
				request.SetGrantedAuthorizationDetails(oauth2.AuthorizationDetails{{Type: "payment", Actions: []string{"read"}}})
			},
		},
		{
			name: "ShouldAllowEverythingRequested",
			grant: func(request oauth2.BackChannelAuthenticationRequester) {
				for _, scope := range request.GetRequestedScopes() {
					request.GrantScope(scope)
				}

				for _, audience := range request.GetRequestedAudience() {
					request.GrantAudience(audience)
				}

				request.SetGrantedAuthorizationDetails(request.GetRequestedAuthorizationDetails())
			},
		},
		{
			name:  "ShouldAllowOnlyOpenIDGranted",
			grant: func(request oauth2.BackChannelAuthenticationRequester) { request.GrantScope(consts.ScopeOpenID) },
		},
		{
			name:  "ShouldDenyNothingGranted",
			grant: func(request oauth2.BackChannelAuthenticationRequester) {},
			err:   true,
		},
		{
			name: "ShouldDenyOpenIDNarrowedAway",
			grant: func(request oauth2.BackChannelAuthenticationRequester) {
				request.GrantScope("profile")
				request.GrantScope("email")
				request.GrantAudience("https://api.example.com")
			},
			err: true,
		},
		{
			name: "ShouldDenyAScopeNotRequested",
			grant: func(request oauth2.BackChannelAuthenticationRequester) {
				request.GrantScope(consts.ScopeOpenID)
				request.GrantScope("offline_access")
			},
			err: true,
		},
		{
			name: "ShouldDenyAnAudienceNotRequested",
			grant: func(request oauth2.BackChannelAuthenticationRequester) {
				request.GrantAudience("https://evil.example.com")
			},
			err: true,
		},
		{
			name: "ShouldDenyAResourceNotRequested",
			grant: func(request oauth2.BackChannelAuthenticationRequester) {
				request.GrantResource("https://resource.example.com")
			},
			err: true,
		},
		{
			name: "ShouldDenyAWiderAuthorizationDetail",
			grant: func(request oauth2.BackChannelAuthenticationRequester) {
				request.SetGrantedAuthorizationDetails(oauth2.AuthorizationDetails{{Type: "payment", Actions: []string{"read", "write", "delete"}}})
			},
			err: true,
		},
		{
			name: "ShouldDenyAnAuthorizationDetailOfAnotherType",
			grant: func(request oauth2.BackChannelAuthenticationRequester) {
				request.SetGrantedAuthorizationDetails(oauth2.AuthorizationDetails{{Type: "account", Actions: []string{"read"}}})
			},
			err: true,
		},
	}

	for _, sc := range cibaDecisionTestStores {
		t.Run(sc.name, func(t *testing.T) {
			for _, tc := range testCases {
				t.Run(tc.name, func(t *testing.T) {
					store := sc.new()
					provider := newCIBADecisionTestProvider(store)

					createCIBADecisionTestRequest(t, provider, newCIBADecisionTestRequest(newCIBADecisionTestSession("john")))

					loaded, err := provider.NewBackChannelAuthenticationDecisionRequest(t.Context(), cibaDecisionTestRequestID, openid.NewDefaultSession())
					require.NoError(t, err)

					tc.grant(loaded)

					result, err := provider.ApproveBackChannelAuthentication(t.Context(), loaded, newCIBADecisionTestSession("john"))

					stored, gerr := store.GetCIBASessionByRequestID(t.Context(), cibaDecisionTestRequestID, openid.NewDefaultSession())
					require.NoError(t, gerr)

					if tc.err {
						require.Error(t, err)
						assert.Nil(t, result)
						assert.ErrorIs(t, err, oauth2.ErrAccessDenied)
						assert.Equal(t, oauth2.CIBAStatusPending, stored.GetStatus())

						return
					}

					require.NoError(t, err)
					assert.Equal(t, oauth2.CIBAStatusApproved, result.Status)
					assert.Equal(t, oauth2.CIBAStatusApproved, stored.GetStatus())
					assert.Equal(t, loaded.GetGrantedScopes(), stored.GetGrantedScopes())
					assert.Equal(t, loaded.GetGrantedAudience(), stored.GetGrantedAudience())
				})
			}
		})
	}
}

func TestApproveConcurrentOnlyOneWins(t *testing.T) {
	for _, sc := range cibaDecisionTestStores {
		t.Run(sc.name, func(t *testing.T) {
			store := sc.new()
			provider := newCIBADecisionTestProvider(store)

			createCIBADecisionTestRequest(t, provider, newCIBADecisionTestRequest(newCIBADecisionTestSession("john")))

			const deciders = 2

			var (
				wg    sync.WaitGroup
				start = make(chan struct{})
				errs  = make([]error, deciders)
			)

			for i := range deciders {
				loaded, err := provider.NewBackChannelAuthenticationDecisionRequest(t.Context(), cibaDecisionTestRequestID, openid.NewDefaultSession())
				require.NoError(t, err)

				loaded.GrantScope(consts.ScopeOpenID)

				wg.Go(func() {
					<-start

					_, errs[i] = provider.ApproveBackChannelAuthentication(t.Context(), loaded, newCIBADecisionTestSession("john"))
				})
			}

			close(start)
			wg.Wait()

			var won, lost int

			for _, err := range errs {
				switch {
				case err == nil:
					won++
				case assert.ErrorIs(t, err, oauth2.ErrInvalidRequest):
					assert.Contains(t, oauth2.ErrorToRFC6749Error(err).GetDescription(), "already decided")

					lost++
				}
			}

			assert.Equal(t, 1, won)
			assert.Equal(t, 1, lost)
		})
	}
}

func TestDenyAndFailSetStatus(t *testing.T) {
	testCases := []struct {
		name     string
		decide   func(provider *oauth2.Fosite, request oauth2.BackChannelAuthenticationRequester) (*oauth2.BackChannelAuthenticationDecisionResult, error)
		expected oauth2.CIBAStatus
		cause    string
	}{
		{
			name: "ShouldDeny",
			decide: func(provider *oauth2.Fosite, request oauth2.BackChannelAuthenticationRequester) (*oauth2.BackChannelAuthenticationDecisionResult, error) {
				return provider.DenyBackChannelAuthentication(t.Context(), request)
			},
			expected: oauth2.CIBAStatusDenied,
		},
		{
			name: "ShouldFail",
			decide: func(provider *oauth2.Fosite, request oauth2.BackChannelAuthenticationRequester) (*oauth2.BackChannelAuthenticationDecisionResult, error) {
				return provider.FailBackChannelAuthentication(t.Context(), request, "The authentication device is unreachable.")
			},
			expected: oauth2.CIBAStatusFailed,
			cause:    "The authentication device is unreachable.",
		},
	}

	for _, sc := range cibaDecisionTestStores {
		t.Run(sc.name, func(t *testing.T) {
			for _, tc := range testCases {
				t.Run(tc.name, func(t *testing.T) {
					store := sc.new()
					provider := newCIBADecisionTestProvider(store)

					createCIBADecisionTestRequest(t, provider, newCIBADecisionTestRequest(newCIBADecisionTestSession("john")))

					loaded, err := provider.NewBackChannelAuthenticationDecisionRequest(t.Context(), cibaDecisionTestRequestID, openid.NewDefaultSession())
					require.NoError(t, err)

					result, err := tc.decide(provider, loaded)
					require.NoError(t, err)
					require.NotNil(t, result)

					assert.Equal(t, tc.expected, result.Status)
					assert.Nil(t, result.Notification)

					stored, err := store.GetCIBASessionByRequestID(t.Context(), cibaDecisionTestRequestID, openid.NewDefaultSession())
					require.NoError(t, err)

					assert.Equal(t, tc.expected, stored.GetStatus())
					assert.Equal(t, tc.cause, stored.GetFailureCause())
					assert.Equal(t, "john", stored.GetSession().GetSubject())

					_, err = provider.NewBackChannelAuthenticationDecisionRequest(t.Context(), cibaDecisionTestRequestID, openid.NewDefaultSession())
					require.Error(t, err)
					assert.ErrorIs(t, err, oauth2.ErrInvalidRequest)
					assert.Contains(t, oauth2.ErrorToRFC6749Error(err).GetDescription(), "already decided")

					_, err = provider.ApproveBackChannelAuthentication(t.Context(), loaded, newCIBADecisionTestSession("john"))
					require.Error(t, err)
					assert.ErrorIs(t, err, oauth2.ErrInvalidRequest)
					assert.Contains(t, oauth2.ErrorToRFC6749Error(err).GetDescription(), "already decided")
				})
			}
		})
	}
}

func TestDecisionRequestExpired(t *testing.T) {
	for _, sc := range cibaDecisionTestStores {
		t.Run(sc.name, func(t *testing.T) {
			t.Run("ShouldReturnAnExpiredRequestWithTheError", func(t *testing.T) {
				store := sc.new()
				provider := newCIBADecisionTestProvider(store)

				session := newCIBADecisionTestSession("john")
				session.SetExpiresAt(oauth2.CIBAAuthRequestID, time.Now().Add(-time.Second).UTC())

				request := newCIBADecisionTestRequest(session)
				request.SetAuthRequestIDSignature("signature")

				require.NoError(t, store.CreateCIBASession(t.Context(), "signature", request))

				loaded, err := provider.NewBackChannelAuthenticationDecisionRequest(t.Context(), cibaDecisionTestRequestID, openid.NewDefaultSession())

				require.Error(t, err)
				assert.ErrorIs(t, err, oauth2.ErrDeviceExpiredToken)
				require.NotNil(t, loaded)
				assert.Equal(t, cibaDecisionTestRequestID, loaded.GetID())

				_, err = provider.ApproveBackChannelAuthentication(t.Context(), loaded, newCIBADecisionTestSession("john"))
				assert.ErrorIs(t, err, oauth2.ErrDeviceExpiredToken)
			})

			t.Run("ShouldNotLoadARequestPastTheLifespanWithoutAnExpiry", func(t *testing.T) {
				store := sc.new()
				provider := newCIBADecisionTestProvider(store)

				request := newCIBADecisionTestRequest(newCIBADecisionTestSession("john"))
				request.RequestedAt = time.Now().Add(-time.Hour).UTC()
				request.SetAuthRequestIDSignature("signature")

				require.NoError(t, store.CreateCIBASession(t.Context(), "signature", request))

				_, err := provider.NewBackChannelAuthenticationDecisionRequest(t.Context(), cibaDecisionTestRequestID, openid.NewDefaultSession())

				require.Error(t, err)
				assert.ErrorIs(t, err, oauth2.ErrDeviceExpiredToken)
			})

			t.Run("ShouldNotDecideARequestWhichExpiredAfterLoading", func(t *testing.T) {
				store := sc.new()
				provider := newCIBADecisionTestProvider(store)

				createCIBADecisionTestRequest(t, provider, newCIBADecisionTestRequest(newCIBADecisionTestSession("john")))

				loaded, err := provider.NewBackChannelAuthenticationDecisionRequest(t.Context(), cibaDecisionTestRequestID, openid.NewDefaultSession())
				require.NoError(t, err)

				loaded.GetSession().SetExpiresAt(oauth2.CIBAAuthRequestID, time.Now().Add(-time.Second).UTC())

				_, err = provider.ApproveBackChannelAuthentication(t.Context(), loaded, newCIBADecisionTestSession("john"))
				require.Error(t, err)
				assert.ErrorIs(t, err, oauth2.ErrDeviceExpiredToken)

				_, err = provider.DenyBackChannelAuthentication(t.Context(), loaded)
				require.Error(t, err)
				assert.ErrorIs(t, err, oauth2.ErrDeviceExpiredToken)
			})

			t.Run("ShouldReturnNotFoundForAnUnknownRequest", func(t *testing.T) {
				provider := newCIBADecisionTestProvider(sc.new())

				_, err := provider.NewBackChannelAuthenticationDecisionRequest(t.Context(), "unknown", openid.NewDefaultSession())

				require.Error(t, err)
				assert.ErrorIs(t, err, oauth2.ErrNotFound)
			})
		})
	}
}

func TestDecisionRequestRequiresStorageAndHandlers(t *testing.T) {
	t.Run("ShouldFailWithoutCIBAStorage", func(t *testing.T) {
		provider := &oauth2.Fosite{Store: storage.NewMemoryStore(), Config: &oauth2.Config{}}
		provider.Store = struct{ oauth2.Storage }{provider.Store}

		_, err := provider.NewBackChannelAuthenticationDecisionRequest(t.Context(), cibaDecisionTestRequestID, openid.NewDefaultSession())

		require.Error(t, err)
		assert.ErrorIs(t, err, oauth2.ErrServerError)
	})

	t.Run("ShouldFailWithoutASession", func(t *testing.T) {
		provider := newCIBADecisionTestProvider(storage.NewMemoryStore())

		_, err := provider.NewBackChannelAuthenticationDecisionRequest(t.Context(), cibaDecisionTestRequestID, nil)

		require.Error(t, err)
		assert.ErrorIs(t, err, oauth2.ErrServerError)
	})

	t.Run("ShouldFailWithoutDecisionHandlers", func(t *testing.T) {
		store := storage.NewMemoryStore()
		provider := newCIBADecisionTestProvider(store)

		createCIBADecisionTestRequest(t, provider, newCIBADecisionTestRequest(newCIBADecisionTestSession("john")))

		loaded, err := provider.NewBackChannelAuthenticationDecisionRequest(t.Context(), cibaDecisionTestRequestID, openid.NewDefaultSession())
		require.NoError(t, err)

		provider.Config.(*oauth2.Config).BackChannelAuthenticationDecisionHandlers = nil

		_, err = provider.DenyBackChannelAuthentication(t.Context(), loaded)

		require.Error(t, err)
		assert.ErrorIs(t, err, oauth2.ErrServerError)

		stored, err := store.GetCIBASessionByRequestID(t.Context(), cibaDecisionTestRequestID, openid.NewDefaultSession())
		require.NoError(t, err)
		assert.Equal(t, oauth2.CIBAStatusPending, stored.GetStatus())
	})

	t.Run("ShouldFailWithoutAnApprovalSession", func(t *testing.T) {
		store := storage.NewMemoryStore()
		provider := newCIBADecisionTestProvider(store)

		createCIBADecisionTestRequest(t, provider, newCIBADecisionTestRequest(newCIBADecisionTestSession("john")))

		loaded, err := provider.NewBackChannelAuthenticationDecisionRequest(t.Context(), cibaDecisionTestRequestID, openid.NewDefaultSession())
		require.NoError(t, err)

		_, err = provider.ApproveBackChannelAuthentication(t.Context(), loaded, nil)

		require.Error(t, err)
		assert.ErrorIs(t, err, oauth2.ErrServerError)
	})
}
