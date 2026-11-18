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
)

func TestBindBackChannelAuthenticationRequest(t *testing.T) {
	testCases := []struct {
		name    string
		action  string
		id      string
		subject string
		public  bool
		plain   bool
		err     error
		check   func(t *testing.T, session *oauth2.DefaultSession)
	}{
		{
			name:    "ShouldIgnoreARequestWithoutTheParameters",
			subject: "alice",
			check: func(t *testing.T, session *oauth2.DefaultSession) {
				assert.Equal(t, &oauth2.DefaultSession{Subject: "alice"}, session)
			},
		},
		{
			name:    "ShouldRecordANewGrantIDForCreate",
			action:  "create",
			subject: "alice",
			check: func(t *testing.T, session *oauth2.DefaultSession) {
				raw, err := base64.RawURLEncoding.DecodeString(session.GetGrantID())
				require.NoError(t, err)

				assert.GreaterOrEqual(t, len(raw), 16)
				assert.Equal(t, oauth2.GrantManagementActionCreate, session.GetGrantManagementAction())
				assert.Nil(t, session.GetGrantPermissions())
			},
		},
		{
			name:    "ShouldRecordTheGrantForMerge",
			action:  "merge",
			id:      "stored",
			subject: "alice",
			check: func(t *testing.T, session *oauth2.DefaultSession) {
				assert.Equal(t, "stored", session.GetGrantID())
				assert.Equal(t, oauth2.GrantManagementActionMerge, session.GetGrantManagementAction())
				assert.Nil(t, session.GetGrantPermissions())
			},
		},
		{
			name:    "ShouldRecordTheGrantForReplace",
			action:  "replace",
			id:      "stored",
			subject: "alice",
			check: func(t *testing.T, session *oauth2.DefaultSession) {
				assert.Equal(t, "stored", session.GetGrantID())
				assert.Equal(t, oauth2.GrantManagementActionReplace, session.GetGrantManagementAction())
			},
		},
		{name: "ShouldRejectMergeForAnotherSubject", action: "merge", id: "stored", subject: "bob", err: oauth2.ErrInvalidGrantID},
		{name: "ShouldRejectReplaceForAnotherSubject", action: "replace", id: "stored", subject: "bob", err: oauth2.ErrInvalidGrantID},
		{name: "ShouldRejectAnUnknownGrant", action: "merge", id: "unknown", subject: "alice", err: oauth2.ErrInvalidGrantID},
		{name: "ShouldRejectAGrantIDWithoutAnAction", id: "stored", subject: "alice", err: oauth2.ErrInvalidRequest},
		{name: "ShouldRejectAPublicClient", action: "create", subject: "alice", public: true, err: oauth2.ErrInvalidRequest},
		{name: "ShouldRejectASessionWithoutGrantManagement", action: "create", subject: "alice", plain: true, err: oauth2.ErrServerError},
	}

	for _, sc := range bindTestStores {
		t.Run(sc.name, func(t *testing.T) {
			for _, tc := range testCases {
				t.Run(tc.name, func(t *testing.T) {
					handler := newBindTestHandler(t, sc.new(), "alice")
					session := &oauth2.DefaultSession{Subject: tc.subject}
					request := newBackChannelTestRequest(session, tc.action, tc.id)

					request.Client = &oauth2.DefaultClient{ID: "c", Public: tc.public}

					if tc.plain {
						request.Session = bindTestPlainSession{Session: session}
					}

					err := handler.BindBackChannelAuthenticationRequest(t.Context(), request)

					assert.Empty(t, request.GetGrantedScopes())

					if tc.err != nil {
						require.ErrorIs(t, err, tc.err)
						assert.Equal(t, &oauth2.DefaultSession{Subject: tc.subject}, session)

						return
					}

					require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

					tc.check(t, session)
				})
			}
		})
	}
}

func TestHandleBackChannelAuthenticationDecision(t *testing.T) {
	for _, sc := range bindTestStores {
		t.Run(sc.name, func(t *testing.T) {
			t.Run("ShouldUnionAMergedGrantIntoTheApprovedRequest", func(t *testing.T) {
				handler := newBindTestHandler(t, sc.new(), "alice")
				session := &oauth2.DefaultSession{Subject: "alice", GrantID: "stored", GrantManagementAction: oauth2.GrantManagementActionMerge}
				request := newBackChannelTestApproval(session)

				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(handler.HandleBackChannelAuthenticationDecision(t.Context(), request, &oauth2.BackChannelAuthenticationDecisionResult{})))

				assert.ElementsMatch(t, []string{"read", "write"}, request.GetGrantedScopes())
				assert.ElementsMatch(t, []string{"https://rs1", "https://rs2"}, request.GetGrantedAudience())
				assert.Contains(t, request.GetGrantedResource(), "https://rs1")
				assert.ElementsMatch(t, oauth2.AuthorizationDetails{bindTestDetailA, bindTestDetailB}, request.GetGrantedAuthorizationDetails())

				assert.Equal(t, "stored", session.GetGrantID())
				assert.Equal(t, oauth2.GrantManagementActionMerge, session.GetGrantManagementAction())
				require.NotNil(t, session.GetGrantPermissions())
				assert.ElementsMatch(t, []string{"read", "write"}, session.GetGrantPermissions().ScopeValues())
			})

			t.Run("ShouldSnapshotTheApprovedRequestForReplace", func(t *testing.T) {
				handler := newBindTestHandler(t, sc.new(), "alice")
				session := &oauth2.DefaultSession{Subject: "alice", GrantID: "stored", GrantManagementAction: oauth2.GrantManagementActionReplace}
				request := newBackChannelTestApproval(session)

				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(handler.HandleBackChannelAuthenticationDecision(t.Context(), request, &oauth2.BackChannelAuthenticationDecisionResult{})))

				assertBindTestRequestUnchanged(t, request)

				assert.Equal(t, "stored", session.GetGrantID())
				require.NotNil(t, session.GetGrantPermissions())
				assert.Equal(t, oauth2.Arguments{"write"}, session.GetGrantPermissions().ScopeValues())
				assert.Equal(t, oauth2.AuthorizationDetails{bindTestDetailB}, session.GetGrantPermissions().AuthorizationDetails)
			})

			t.Run("ShouldSnapshotTheApprovedRequestForCreate", func(t *testing.T) {
				handler := newBindTestHandler(t, sc.new(), "alice")
				session := &oauth2.DefaultSession{Subject: "alice", GrantID: "minted", GrantManagementAction: oauth2.GrantManagementActionCreate}
				request := newBackChannelTestApproval(session)

				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(handler.HandleBackChannelAuthenticationDecision(t.Context(), request, &oauth2.BackChannelAuthenticationDecisionResult{})))

				assertBindTestRequestUnchanged(t, request)

				assert.NotEmpty(t, session.GetGrantID())
				require.NotNil(t, session.GetGrantPermissions())
				assert.Equal(t, oauth2.Arguments{"write"}, session.GetGrantPermissions().ScopeValues())
			})

			for _, action := range []oauth2.GrantManagementAction{oauth2.GrantManagementActionMerge, oauth2.GrantManagementActionReplace} {
				t.Run("ShouldRejectADeletedGrant/"+string(action), func(t *testing.T) {
					handler := newBindTestHandler(t, sc.new(), "alice")
					session := &oauth2.DefaultSession{Subject: "alice", GrantID: "stored", GrantManagementAction: action}
					request := newBackChannelTestApproval(session)

					_, derr := handler.Storage.DeleteGrant(t.Context(), "stored")

					require.NoError(t, derr)

					err := handler.HandleBackChannelAuthenticationDecision(t.Context(), request, &oauth2.BackChannelAuthenticationDecisionResult{})

					require.ErrorIs(t, err, oauth2.ErrInvalidGrantID)
					assert.Equal(t, consts.ErrorInvalidGrantID, oauth2.ErrorToRFC6749Error(err).ErrorField)

					assertBindTestRequestUnchanged(t, request)
					assert.Nil(t, session.GetGrantPermissions())
				})

				t.Run("ShouldRejectAGrantOfAnotherSubject/"+string(action), func(t *testing.T) {
					handler := newBindTestHandler(t, sc.new(), "bob")
					session := &oauth2.DefaultSession{Subject: "alice", GrantID: "stored", GrantManagementAction: action}
					request := newBackChannelTestApproval(session)

					require.ErrorIs(t, handler.HandleBackChannelAuthenticationDecision(t.Context(), request, &oauth2.BackChannelAuthenticationDecisionResult{}), oauth2.ErrInvalidGrantID)

					assertBindTestRequestUnchanged(t, request)
				})
			}

			t.Run("ShouldIgnoreADecisionWhichIsNotAnApproval", func(t *testing.T) {
				for _, status := range []oauth2.CIBAStatus{oauth2.CIBAStatusDenied, oauth2.CIBAStatusFailed, oauth2.CIBAStatusExpired} {
					handler := newBindTestHandler(t, sc.new(), "alice")
					session := &oauth2.DefaultSession{Subject: "alice", GrantID: "stored", GrantManagementAction: oauth2.GrantManagementActionMerge}
					request := newBackChannelTestApproval(session)

					request.SetStatus(status)

					_, derr := handler.Storage.DeleteGrant(t.Context(), "stored")

					require.NoError(t, derr)
					require.NoError(t, handler.HandleBackChannelAuthenticationDecision(t.Context(), request, &oauth2.BackChannelAuthenticationDecisionResult{}))

					assertBindTestRequestUnchanged(t, request)
					assert.Nil(t, session.GetGrantPermissions())
				}
			})

			t.Run("ShouldIgnoreAnApprovalWithoutAnAction", func(t *testing.T) {
				handler := newBindTestHandler(t, sc.new(), "alice")
				session := &oauth2.DefaultSession{Subject: "alice"}
				request := newBackChannelTestApproval(session)

				require.NoError(t, handler.HandleBackChannelAuthenticationDecision(t.Context(), request, &oauth2.BackChannelAuthenticationDecisionResult{}))

				assertBindTestRequestUnchanged(t, request)
				assert.Equal(t, &oauth2.DefaultSession{Subject: "alice"}, session)
			})

			t.Run("ShouldIgnoreAnApprovalWithoutTheConfig", func(t *testing.T) {
				handler := newBindTestHandler(t, sc.new(), "alice")
				handler.Config = &oauth2.Config{}

				session := &oauth2.DefaultSession{Subject: "alice", GrantID: "stored", GrantManagementAction: oauth2.GrantManagementActionMerge}
				request := newBackChannelTestApproval(session)

				require.NoError(t, handler.HandleBackChannelAuthenticationDecision(t.Context(), request, &oauth2.BackChannelAuthenticationDecisionResult{}))

				assertBindTestRequestUnchanged(t, request)
			})
		})
	}
}

func newBackChannelTestRequest(session oauth2.Session, action, id string) *oauth2.BackChannelAuthenticationRequest {
	request := oauth2.NewBackChannelAuthenticationRequest()
	request.Client = newBindTestClient()
	request.Session = session
	request.DeliveryMode = consts.CIBAModePoll
	request.Form = url.Values{}

	if action != "" {
		request.Form.Set(consts.FormParameterGrantManagementAction, action)
	}

	if id != "" {
		request.Form.Set(consts.FormParameterGrantID, id)
	}

	return request
}

func newBackChannelTestApproval(session oauth2.Session) *oauth2.BackChannelAuthenticationRequest {
	request := newBackChannelTestRequest(session, "", "")

	request.SetStatus(oauth2.CIBAStatusApproved)
	request.GrantScope("write")
	request.GrantAudience("https://rs2")
	request.SetGrantedAuthorizationDetails(oauth2.AuthorizationDetails{bindTestDetailB})

	return request
}
