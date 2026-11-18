// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package grantmgmt

import (
	"encoding/base64"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/storage"
)

func TestBindAuthorizeRequestMerge(t *testing.T) {
	for _, sc := range bindTestStores {
		t.Run(sc.name, func(t *testing.T) {
			handler := newBindTestHandler(t, sc.new(), "alice")
			session := &oauth2.DefaultSession{Subject: "alice"}
			request := newBindTestRequest(session, "merge", "stored")

			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(handler.BindAuthorizeRequest(t.Context(), request)))

			assert.ElementsMatch(t, []string{"read", "write"}, request.GetGrantedScopes())
			assert.ElementsMatch(t, []string{"https://rs1", "https://rs2"}, request.GetGrantedAudience())
			assert.Contains(t, request.GetGrantedResource(), "https://rs1")
			assert.ElementsMatch(t, oauth2.AuthorizationDetails{bindTestDetailA, bindTestDetailB}, request.GetGrantedAuthorizationDetails())

			assert.Equal(t, "stored", session.GetGrantID())
			assert.Equal(t, oauth2.GrantManagementActionMerge, session.GetGrantManagementAction())

			snapshot := session.GetGrantPermissions()
			require.NotNil(t, snapshot)

			assert.ElementsMatch(t, []string{"read", "write"}, snapshot.ScopeValues())
			assert.ElementsMatch(t, []string{"https://rs1"}, snapshot.ResourceValues())
			assert.ElementsMatch(t, []string{"https://rs1", "https://rs2"}, snapshot.Audience)
			assert.ElementsMatch(t, []string{"address", "email", "name"}, snapshot.Claims)
			assert.ElementsMatch(t, oauth2.AuthorizationDetails{bindTestDetailA, bindTestDetailB}, snapshot.AuthorizationDetails)

			stored, err := handler.Storage.GetGrant(t.Context(), "stored")
			require.NoError(t, err)

			assert.Equal(t, oauth2.Arguments{"read"}, stored.Permissions.ScopeValues())
			assert.Equal(t, oauth2.AuthorizationDetails{bindTestDetailA}, stored.Permissions.AuthorizationDetails)
		})
	}
}

func TestBindAuthorizeRequestMergeIsIdempotent(t *testing.T) {
	handler := newBindTestHandler(t, storage.NewMemoryStore(), "alice")
	session := &oauth2.DefaultSession{Subject: "alice"}
	request := newBindTestRequest(session, "merge", "stored")

	request.GrantScope("read")
	request.GrantAudience("https://rs1")
	request.GrantResource("https://rs1")
	request.SetGrantedAuthorizationDetails(oauth2.AuthorizationDetails{bindTestDetailB, bindTestDetailA})

	require.NoError(t, oauth2.ErrorToDebugRFC6749Error(handler.BindAuthorizeRequest(t.Context(), request)))
	require.NoError(t, oauth2.ErrorToDebugRFC6749Error(handler.BindAuthorizeRequest(t.Context(), request)))

	assert.Equal(t, oauth2.Arguments{"write", "read"}, request.GetGrantedScopes())
	assert.Equal(t, oauth2.Arguments{"https://rs2", "https://rs1"}, request.GetGrantedAudience())
	assert.Equal(t, oauth2.Arguments{"https://rs1"}, request.GetGrantedResource())
	assert.Equal(t, oauth2.AuthorizationDetails{bindTestDetailB, bindTestDetailA}, request.GetGrantedAuthorizationDetails())
}

func TestBindAuthorizeRequestMergeClientAllowance(t *testing.T) {
	testCases := []struct {
		name      string
		client    *oauth2.DefaultClient
		scopes    []string
		audience  []string
		resources []string
		snapshot  []oauth2.GrantScope
	}{
		{
			name:      "ShouldMergeAllowedValues",
			client:    &oauth2.DefaultClient{ID: "c", Scopes: []string{"read", "write", "admin"}, Audience: []string{"https://rs1", "https://rs2", "https://rs3"}},
			scopes:    []string{"write", "read", "admin"},
			audience:  []string{"https://rs2", "https://rs1", "https://rs3"},
			resources: []string{"https://rs1", "https://rs3"},
			snapshot:  []oauth2.GrantScope{{Scope: "read admin", Resource: []string{"https://rs1"}}, {Scope: "admin", Resource: []string{"https://rs3"}}, {Scope: "write"}},
		},
		{
			name:      "ShouldDropAScopeNoLongerAllowed",
			client:    &oauth2.DefaultClient{ID: "c", Scopes: []string{"read", "write"}, Audience: []string{"https://rs1", "https://rs2", "https://rs3"}},
			scopes:    []string{"write", "read"},
			audience:  []string{"https://rs2", "https://rs1", "https://rs3"},
			resources: []string{"https://rs1"},
			snapshot:  []oauth2.GrantScope{{Scope: "read", Resource: []string{"https://rs1"}}, {Scope: "write"}},
		},
		{
			name:      "ShouldDropAnAudienceNoLongerAllowed",
			client:    &oauth2.DefaultClient{ID: "c", Scopes: []string{"read", "write", "admin"}, Audience: []string{"https://rs1", "https://rs2"}},
			scopes:    []string{"write", "read", "admin"},
			audience:  []string{"https://rs2", "https://rs1"},
			resources: []string{"https://rs1", "https://rs3"},
			snapshot:  []oauth2.GrantScope{{Scope: "read admin", Resource: []string{"https://rs1"}}, {Scope: "admin", Resource: []string{"https://rs3"}}, {Scope: "write"}},
		},
		{
			name:     "ShouldDropEveryStoredValueNoLongerAllowed",
			client:   &oauth2.DefaultClient{ID: "c", Scopes: []string{"write"}, Audience: []string{"https://rs2"}},
			scopes:   []string{"write"},
			audience: []string{"https://rs2"},
			snapshot: []oauth2.GrantScope{{Scope: "write"}},
		},
	}

	for _, sc := range bindTestStores {
		t.Run(sc.name, func(t *testing.T) {
			for _, tc := range testCases {
				t.Run(tc.name, func(t *testing.T) {
					store := sc.new()

					require.NoError(t, store.CreateGrant(t.Context(), &oauth2.Grant{
						ID:       "wide",
						ClientID: "c",
						Subject:  "alice",
						Permissions: oauth2.GrantPermissions{
							Scopes:   []oauth2.GrantScope{{Scope: "read admin", Resource: []string{"https://rs1"}}, {Scope: "admin", Resource: []string{"https://rs3"}}},
							Audience: []string{"https://rs1", "https://rs3"},
						},
					}))

					handler := newBindTestHandler(t, store, "alice")

					check := func(t *testing.T, request oauth2.Requester, session *oauth2.DefaultSession) {
						t.Helper()

						assert.Equal(t, oauth2.Arguments(tc.scopes), request.GetGrantedScopes())
						assert.Equal(t, oauth2.Arguments(tc.audience), request.GetGrantedAudience())
						assert.ElementsMatch(t, tc.resources, request.GetGrantedResource())

						snapshot := session.GetGrantPermissions()
						require.NotNil(t, snapshot)

						assert.Equal(t, tc.snapshot, snapshot.Scopes)
						assert.ElementsMatch(t, tc.audience, snapshot.Audience)
						assert.ElementsMatch(t, tc.scopes, snapshot.ScopeValues())
					}

					t.Run("AuthorizationRequest", func(t *testing.T) {
						session := &oauth2.DefaultSession{Subject: "alice"}
						request := newBindTestRequest(session, "merge", "wide")
						request.Client = tc.client

						require.NoError(t, oauth2.ErrorToDebugRFC6749Error(handler.BindAuthorizeRequest(t.Context(), request)))

						check(t, request, session)
					})

					t.Run("BackChannelApproval", func(t *testing.T) {
						session := &oauth2.DefaultSession{Subject: "alice", GrantID: "wide", GrantManagementAction: oauth2.GrantManagementActionMerge}
						request := newBackChannelTestApproval(session)
						request.Client = tc.client

						require.NoError(t, oauth2.ErrorToDebugRFC6749Error(handler.HandleBackChannelAuthenticationDecision(t.Context(), request, &oauth2.BackChannelAuthenticationDecisionResult{})))

						check(t, request, session)
					})

					stored, err := store.GetGrant(t.Context(), "wide")
					require.NoError(t, err)

					assert.Equal(t, oauth2.Arguments{"read", "admin"}, stored.Permissions.ScopeValues())
					assert.Equal(t, []string{"https://rs1", "https://rs3"}, stored.Permissions.Audience)
				})
			}
		})
	}
}

func TestBindAuthorizeRequestMergeOpenID(t *testing.T) {
	testCases := []struct {
		name      string
		requested oauth2.Arguments
		granted   []string
	}{
		{name: "ShouldNotGrantOpenIDWhenNotRequested", requested: oauth2.Arguments{"write"}, granted: []string{"write", "read"}},
		{name: "ShouldGrantOpenIDWhenRequested", requested: oauth2.Arguments{"openid", "write"}, granted: []string{"write", "read", "openid"}},
	}

	for _, sc := range bindTestStores {
		for _, tc := range testCases {
			t.Run(sc.name+"/"+tc.name, func(t *testing.T) {
				store := sc.new()

				require.NoError(t, store.CreateGrant(t.Context(), &oauth2.Grant{
					ID:          "oidc",
					ClientID:    "c",
					Subject:     "alice",
					Permissions: oauth2.GrantPermissions{Scopes: []oauth2.GrantScope{{Scope: "openid read"}}},
				}))

				handler := newBindTestHandler(t, store, "alice")
				session := &oauth2.DefaultSession{Subject: "alice"}
				request := newBindTestRequest(session, "merge", "oidc")

				request.Client = &oauth2.DefaultClient{ID: "c", Scopes: []string{"openid", "read", "write"}, Audience: []string{"https://rs2"}}
				request.RequestedScope = tc.requested

				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(handler.BindAuthorizeRequest(t.Context(), request)))

				assert.ElementsMatch(t, tc.granted, request.GetGrantedScopes())

				require.NotNil(t, session.GetGrantPermissions())
				assert.ElementsMatch(t, []string{"openid", "read", "write"}, session.GetGrantPermissions().ScopeValues())
			})
		}
	}
}

func TestBindAuthorizeRequestReplace(t *testing.T) {
	for _, sc := range bindTestStores {
		t.Run(sc.name, func(t *testing.T) {
			handler := newBindTestHandler(t, sc.new(), "alice")
			session := &oauth2.DefaultSession{Subject: "alice"}
			request := newBindTestRequest(session, "replace", "stored")

			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(handler.BindAuthorizeRequest(t.Context(), request)))

			assertBindTestRequestUnchanged(t, request)

			assert.Equal(t, "stored", session.GetGrantID())
			assert.Equal(t, oauth2.GrantManagementActionReplace, session.GetGrantManagementAction())
			assert.Equal(t, bindTestRequestPermissions(), session.GetGrantPermissions())
		})
	}
}

func TestBindAuthorizeRequestCreate(t *testing.T) {
	handler := newBindTestHandler(t, storage.NewMemoryStore(), "alice")
	session := &oauth2.DefaultSession{Subject: "alice", GrantID: "stale"}
	request := newBindTestRequest(session, "create", "")

	require.NoError(t, oauth2.ErrorToDebugRFC6749Error(handler.BindAuthorizeRequest(t.Context(), request)))

	assertBindTestRequestUnchanged(t, request)

	assert.NotEqual(t, "stale", session.GetGrantID())

	raw, err := base64.RawURLEncoding.DecodeString(session.GetGrantID())
	require.NoError(t, err)

	assert.GreaterOrEqual(t, len(raw), 16)
	assert.Equal(t, oauth2.GrantManagementActionCreate, session.GetGrantManagementAction())
	assert.Equal(t, bindTestRequestPermissions(), session.GetGrantPermissions())

	other := &oauth2.DefaultSession{Subject: "alice"}

	require.NoError(t, oauth2.ErrorToDebugRFC6749Error(handler.BindAuthorizeRequest(t.Context(), newBindTestRequest(other, "create", ""))))

	assert.NotEqual(t, session.GetGrantID(), other.GetGrantID())
}

func TestBindAuthorizeRequestSubjectMismatch(t *testing.T) {
	testCases := []struct {
		name    string
		grant   string
		subject string
	}{
		{name: "ShouldRejectAnotherSubject", grant: "bob", subject: "alice"},
		{name: "ShouldRejectASessionWithoutASubject", grant: "bob", subject: ""},
		{name: "ShouldRejectAGrantAndSessionWithoutASubject", grant: "", subject: ""},
	}

	for _, sc := range bindTestStores {
		t.Run(sc.name, func(t *testing.T) {
			for _, tc := range testCases {
				for _, action := range []string{"merge", "replace"} {
					t.Run(tc.name+"/"+action, func(t *testing.T) {
						handler := newBindTestHandler(t, sc.new(), tc.grant)
						session := &oauth2.DefaultSession{Subject: tc.subject}
						request := newBindTestRequest(session, action, "stored")

						err := handler.BindAuthorizeRequest(t.Context(), request)

						require.ErrorIs(t, err, oauth2.ErrInvalidGrantID)
						assert.Equal(t, consts.ErrorInvalidGrantID, oauth2.ErrorToRFC6749Error(err).ErrorField)

						assertBindTestRequestUnchanged(t, request)
						assert.Equal(t, &oauth2.DefaultSession{Subject: tc.subject}, session)
					})
				}
			}
		})
	}
}

func TestBindAuthorizeRequestNoAction(t *testing.T) {
	handler := newBindTestHandler(t, storage.NewMemoryStore(), "alice")
	session := &oauth2.DefaultSession{Subject: "alice"}
	request := newBindTestRequest(session, "", "")

	require.NoError(t, oauth2.ErrorToDebugRFC6749Error(handler.BindAuthorizeRequest(t.Context(), request)))

	assertBindTestRequestUnchanged(t, request)
	assert.Equal(t, &oauth2.DefaultSession{Subject: "alice"}, session)
}

func TestBindAuthorizeRequestSessionWithoutGrantManagement(t *testing.T) {
	handler := newBindTestHandler(t, storage.NewMemoryStore(), "alice")

	for _, session := range []oauth2.Session{nil, bindTestPlainSession{Session: &oauth2.DefaultSession{Subject: "alice"}}} {
		request := newBindTestRequest(session, "create", "")

		err := handler.BindAuthorizeRequest(t.Context(), request)

		require.ErrorIs(t, err, oauth2.ErrServerError)
		assertBindTestRequestUnchanged(t, request)
	}
}

func TestPermissionsFromRequest(t *testing.T) {
	request := oauth2.NewAuthorizeRequest()

	assert.Equal(t, &oauth2.GrantPermissions{}, permissionsFromRequest(request))

	request.GrantResource("https://rs1")
	request.GrantAudience("https://rs2")

	assert.Equal(t, &oauth2.GrantPermissions{Audience: []string{"https://rs2"}}, permissionsFromRequest(request))

	request.GrantScope("read")
	request.GrantScope("write")

	actual := permissionsFromRequest(request)

	assert.Equal(t, []oauth2.GrantScope{{Scope: "read write", Resource: []string{"https://rs1"}}}, actual.Scopes)
	assert.Equal(t, oauth2.Arguments{"read", "write"}, actual.ScopeValues())

	actual.Scopes[0].Resource[0] = "https://mutated"
	actual.Audience[0] = "https://mutated"

	assert.Equal(t, oauth2.Arguments{"https://rs1"}, request.GetGrantedResource())
	assert.Equal(t, oauth2.Arguments{"https://rs2"}, request.GetGrantedAudience())
}

type bindTestPlainSession struct {
	oauth2.Session
}

var bindTestStores = []struct {
	name string
	new  func() oauth2.GrantManagementStorage
}{
	{"MemoryStore", func() oauth2.GrantManagementStorage { return storage.NewMemoryStore() }},
	{"HydratingMemoryStore", func() oauth2.GrantManagementStorage { return storage.NewHydratingMemoryStore() }},
}

var (
	bindTestDetailA = oauth2.AuthorizationDetail{Type: "account", Actions: []string{"read"}}
	bindTestDetailB = oauth2.AuthorizationDetail{Type: "payment", Actions: []string{"write"}, Extra: map[string]any{"amount": "10"}}
)

func newBindTestHandler(t *testing.T, store oauth2.GrantManagementStorage, subject string) *Handler {
	t.Helper()

	require.NoError(t, store.CreateGrant(t.Context(), &oauth2.Grant{
		ID:       "stored",
		ClientID: "c",
		Subject:  subject,
		Permissions: oauth2.GrantPermissions{
			Scopes:               []oauth2.GrantScope{{Scope: "read", Resource: []string{"https://rs1"}}},
			Audience:             []string{"https://rs1"},
			Claims:               []string{"address"},
			AuthorizationDetails: oauth2.AuthorizationDetails{bindTestDetailA},
		},
	}))

	return &Handler{
		Config: &oauth2.Config{GrantManagement: &oauth2.GrantManagementConfig{
			Actions: []oauth2.GrantManagementAction{
				oauth2.GrantManagementActionCreate,
				oauth2.GrantManagementActionMerge,
				oauth2.GrantManagementActionReplace,
			},
		}},
		Storage: store,
	}
}

func newBindTestClient() *oauth2.DefaultClient {
	return &oauth2.DefaultClient{ID: "c", Scopes: []string{"read", "write"}, Audience: []string{"https://rs1", "https://rs2"}}
}

func newBindTestRequest(session oauth2.Session, action, id string) *oauth2.AuthorizeRequest {
	request := oauth2.NewAuthorizeRequest()
	request.Client = newBindTestClient()
	request.ResponseTypes = oauth2.Arguments{consts.ResponseTypeAuthorizationCodeFlow}
	request.Session = session
	request.Form = url.Values{}

	if action != "" {
		request.Form.Set(consts.FormParameterGrantManagementAction, action)
	}

	if id != "" {
		request.Form.Set(consts.FormParameterGrantID, id)
	}

	request.GrantScope("write")
	request.GrantAudience("https://rs2")
	request.SetGrantedAuthorizationDetails(oauth2.AuthorizationDetails{bindTestDetailB})
	request.SetClaims(&oauth2.ClaimsRequest{
		IDToken:  map[string]*oauth2.ClaimRequest{"email": nil, "name": nil},
		UserInfo: map[string]*oauth2.ClaimRequest{"email": nil},
	})

	return request
}

func bindTestRequestPermissions() *oauth2.GrantPermissions {
	return &oauth2.GrantPermissions{
		Scopes:               []oauth2.GrantScope{{Scope: "write"}},
		Audience:             []string{"https://rs2"},
		Claims:               []string{"email", "name"},
		AuthorizationDetails: oauth2.AuthorizationDetails{bindTestDetailB},
	}
}

func assertBindTestRequestUnchanged(t *testing.T, request oauth2.Requester) {
	t.Helper()

	assert.Equal(t, oauth2.Arguments{"write"}, request.GetGrantedScopes())
	assert.Equal(t, oauth2.Arguments{"https://rs2"}, request.GetGrantedAudience())
	assert.Empty(t, request.GetGrantedResource())
	assert.Equal(t, oauth2.AuthorizationDetails{bindTestDetailB}, request.GetGrantedAuthorizationDetails())
}
