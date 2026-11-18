// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package grantmgmt

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
)

func TestBindAccessRequestCreate(t *testing.T) {
	for _, sc := range bindTestStores {
		t.Run(sc.name, func(t *testing.T) {
			for _, grantType := range []string{consts.GrantTypeAuthorizationCode, consts.GrantTypeOpenIDCIBA} {
				t.Run(grantType, func(t *testing.T) {
					handler, store := newTokenTestHandler(t, sc.new())
					session := newTokenTestSession("created", oauth2.GrantManagementActionCreate)
					request := newTokenTestRequest(session, grantType)

					before := time.Now().UTC()

					require.NoError(t, oauth2.ErrorToDebugRFC6749Error(tokenTestBindAndCommit(t, handler, request)))

					grant, err := store.GetGrant(t.Context(), "created")
					require.NoError(t, err)

					assert.Equal(t, "created", grant.ID)
					assert.Equal(t, "c", grant.ClientID)
					assert.Equal(t, "alice", grant.Subject)
					assert.Equal(t, *bindTestRequestPermissions(), grant.Permissions)
					assert.Equal(t, []string{"r3"}, grant.RequestIDs)
					assert.Equal(t, oauth2.GrantUpdatedByClient, grant.UpdatedBy)
					assert.Equal(t, "client", grant.UpdatedBy)
					assert.False(t, grant.CreatedAt.Before(before))
					assert.Equal(t, grant.CreatedAt, grant.UpdatedAt)
					assert.True(t, grant.ExpiresAt.IsZero())

					assert.Empty(t, store.refresh)
					assert.Empty(t, store.access)

					require.NoError(t, oauth2.ErrorToDebugRFC6749Error(tokenTestBindAndCommit(t, handler, request)))

					repeated, err := store.GetGrant(t.Context(), "created")
					require.NoError(t, err)

					assert.Equal(t, grant, repeated)
				})
			}
		})
	}
}

func TestBindAccessRequestMerge(t *testing.T) {
	for _, sc := range bindTestStores {
		t.Run(sc.name, func(t *testing.T) {
			handler, store := newTokenTestHandler(t, sc.new())
			session := newTokenTestSession("stored", oauth2.GrantManagementActionMerge)
			request := newTokenTestRequest(session, consts.GrantTypeAuthorizationCode)

			before := time.Now().UTC()

			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(tokenTestBindAndCommit(t, handler, request)))

			grant, err := store.GetGrant(t.Context(), "stored")
			require.NoError(t, err)

			assert.Equal(t, "c", grant.ClientID)
			assert.Equal(t, "alice", grant.Subject)
			assert.ElementsMatch(t, []string{"read", "write"}, grant.Permissions.ScopeValues())
			assert.Equal(t, oauth2.Arguments{"https://rs1"}, grant.Permissions.ResourceValues())
			assert.ElementsMatch(t, []string{"https://rs1", "https://rs2"}, grant.Permissions.Audience)
			assert.ElementsMatch(t, []string{"address", "email", "name"}, grant.Permissions.Claims)
			assert.ElementsMatch(t, oauth2.AuthorizationDetails{bindTestDetailA, bindTestDetailB}, grant.Permissions.AuthorizationDetails)
			assert.Equal(t, []string{"r1", "r2", "r3"}, grant.RequestIDs)
			assert.Equal(t, "client", grant.UpdatedBy)
			assert.Equal(t, tokenTestCreatedAt, grant.CreatedAt)
			assert.False(t, grant.UpdatedAt.Before(before))

			assert.Equal(t, []string{"r1", "r2"}, store.refresh)
			assert.Empty(t, store.access)

			store.refresh = nil

			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(tokenTestBindAndCommit(t, handler, request)))

			grant, err = store.GetGrant(t.Context(), "stored")
			require.NoError(t, err)

			assert.Equal(t, []string{"r1", "r2", "r3"}, grant.RequestIDs)
			assert.Equal(t, []string{"r1", "r2"}, store.refresh)
		})
	}
}

func TestBindAccessRequestReplace(t *testing.T) {
	for _, sc := range bindTestStores {
		t.Run(sc.name, func(t *testing.T) {
			handler, store := newTokenTestHandler(t, sc.new())
			session := newTokenTestSession("stored", oauth2.GrantManagementActionReplace)
			request := newTokenTestRequest(session, consts.GrantTypeOpenIDCIBA)

			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(tokenTestBindAndCommit(t, handler, request)))

			grant, err := store.GetGrant(t.Context(), "stored")
			require.NoError(t, err)

			assert.Equal(t, *bindTestRequestPermissions(), grant.Permissions)
			assert.Equal(t, []string{"r3"}, grant.RequestIDs)
			assert.Equal(t, "client", grant.UpdatedBy)
			assert.Equal(t, tokenTestCreatedAt, grant.CreatedAt)

			assert.Equal(t, []string{"r1", "r2"}, store.refresh)
			assert.Equal(t, []string{"r1", "r2"}, store.access)

			store.refresh, store.access = nil, nil

			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(tokenTestBindAndCommit(t, handler, request)))

			assert.Empty(t, store.refresh)
			assert.Empty(t, store.access)
		})
	}
}

func TestBindAccessRequestRefusal(t *testing.T) {
	failure := errors.New("storage failure")

	testCases := []struct {
		name     string
		action   oauth2.GrantManagementAction
		id       string
		setup    func(t *testing.T, handler *Handler, store *tokenTestStore, session *oauth2.DefaultSession, request *oauth2.AccessRequest)
		err      error
		commit   bool
		written  bool
		appended bool
	}{
		{
			name: "ShouldRefuseAGrantWhichIsGone", action: oauth2.GrantManagementActionMerge, id: "stored", err: oauth2.ErrInvalidGrant,
			setup: func(t *testing.T, _ *Handler, store *tokenTestStore, _ *oauth2.DefaultSession, _ *oauth2.AccessRequest) {
				_, derr := store.DeleteGrant(t.Context(), "stored")
				require.NoError(t, derr)
			},
		},
		{
			name: "ShouldRefuseAGrantWhichHasExpired", action: oauth2.GrantManagementActionReplace, id: "stored", err: oauth2.ErrInvalidGrant,
			setup: func(t *testing.T, _ *Handler, store *tokenTestStore, _ *oauth2.DefaultSession, _ *oauth2.AccessRequest) {
				grant, err := store.GetGrant(t.Context(), "stored")
				require.NoError(t, err)

				grant.ExpiresAt = time.Now().UTC().Add(-time.Second)

				require.NoError(t, store.UpdateGrant(t.Context(), grant))
			},
		},
		{
			name: "ShouldRefuseAGrantOfAnotherClient", action: oauth2.GrantManagementActionMerge, id: "stored", err: oauth2.ErrInvalidGrant,
			setup: func(_ *testing.T, _ *Handler, _ *tokenTestStore, _ *oauth2.DefaultSession, request *oauth2.AccessRequest) {
				request.Client = &oauth2.DefaultClient{ID: "other"}
			},
		},
		{
			name: "ShouldRefuseAGrantOfAnotherSubject", action: oauth2.GrantManagementActionReplace, id: "stored", err: oauth2.ErrInvalidGrant,
			setup: func(_ *testing.T, _ *Handler, _ *tokenTestStore, session *oauth2.DefaultSession, _ *oauth2.AccessRequest) {
				session.Subject = "mallory"
			},
		},
		{
			name: "ShouldRefuseAGrantWithoutASubject", action: oauth2.GrantManagementActionMerge, id: "stored", err: oauth2.ErrInvalidGrant,
			setup: func(_ *testing.T, _ *Handler, _ *tokenTestStore, session *oauth2.DefaultSession, _ *oauth2.AccessRequest) {
				session.Subject = ""
			},
		},
		{
			name: "ShouldFailClosedWithoutAPermissionSnapshot", action: oauth2.GrantManagementActionCreate, id: "created", err: oauth2.ErrServerError,
			setup: func(_ *testing.T, _ *Handler, _ *tokenTestStore, session *oauth2.DefaultSession, _ *oauth2.AccessRequest) {
				session.GrantPermissions = nil
			},
		},
		{
			name: "ShouldFailClosedWithoutAPermissionSnapshotOnMerge", action: oauth2.GrantManagementActionMerge, id: "stored", err: oauth2.ErrServerError,
			setup: func(_ *testing.T, _ *Handler, _ *tokenTestStore, session *oauth2.DefaultSession, _ *oauth2.AccessRequest) {
				session.GrantPermissions = nil
			},
		},
		{
			name: "ShouldFailClosedOnACreateWithoutASubject", action: oauth2.GrantManagementActionCreate, id: "created", err: oauth2.ErrServerError,
			setup: func(_ *testing.T, _ *Handler, _ *tokenTestStore, session *oauth2.DefaultSession, _ *oauth2.AccessRequest) {
				session.Subject = ""
			},
		},
		{name: "ShouldFailClosedWithoutAGrantID", action: oauth2.GrantManagementActionCreate, id: "", err: oauth2.ErrServerError},
		{name: "ShouldFailClosedOnAnUnknownAction", action: oauth2.GrantManagementActionQuery, id: "stored", err: oauth2.ErrServerError},
		{
			name: "ShouldFailClosedWithoutStorage", action: oauth2.GrantManagementActionCreate, id: "created", err: oauth2.ErrServerError,
			setup: func(_ *testing.T, handler *Handler, _ *tokenTestStore, _ *oauth2.DefaultSession, _ *oauth2.AccessRequest) {
				handler.Storage = nil
			},
		},
		{
			name: "ShouldFailOnACreateError", action: oauth2.GrantManagementActionCreate, id: "created", err: oauth2.ErrServerError, commit: true,
			setup: func(_ *testing.T, _ *Handler, store *tokenTestStore, _ *oauth2.DefaultSession, _ *oauth2.AccessRequest) {
				store.createErr = failure
			},
		},
		{
			name: "ShouldFailOnACreateOfAnExistingGrant", action: oauth2.GrantManagementActionCreate, id: "stored", err: oauth2.ErrServerError, commit: true,
		},
		{
			name: "ShouldFailOnAGetError", action: oauth2.GrantManagementActionMerge, id: "stored", err: oauth2.ErrServerError,
			setup: func(_ *testing.T, _ *Handler, store *tokenTestStore, _ *oauth2.DefaultSession, _ *oauth2.AccessRequest) {
				store.getErr = failure
			},
		},
		{
			name: "ShouldFailOnAnUpdateError", action: oauth2.GrantManagementActionMerge, id: "stored", err: oauth2.ErrServerError, commit: true, appended: true,
			setup: func(_ *testing.T, _ *Handler, store *tokenTestStore, _ *oauth2.DefaultSession, _ *oauth2.AccessRequest) {
				store.updateErr = failure
			},
		},
		{
			name: "ShouldRefuseAGrantDeletedBeforeTheMergeUpdate", action: oauth2.GrantManagementActionMerge, id: "stored", err: oauth2.ErrInvalidGrant, commit: true, appended: true,
			setup: func(_ *testing.T, _ *Handler, store *tokenTestStore, _ *oauth2.DefaultSession, _ *oauth2.AccessRequest) {
				store.updateErr = oauth2.ErrNotFound
			},
		},
		{
			name: "ShouldRefuseAGrantDeletedBeforeTheReplaceUpdate", action: oauth2.GrantManagementActionReplace, id: "stored", err: oauth2.ErrInvalidGrant, commit: true, written: true,
			setup: func(_ *testing.T, _ *Handler, store *tokenTestStore, _ *oauth2.DefaultSession, _ *oauth2.AccessRequest) {
				store.updateErr = oauth2.ErrNotFound
			},
		},
		{
			name: "ShouldFailOnARefreshTokenRevocationError", action: oauth2.GrantManagementActionMerge, id: "stored", err: oauth2.ErrServerError, commit: true, appended: true,
			setup: func(_ *testing.T, _ *Handler, store *tokenTestStore, _ *oauth2.DefaultSession, _ *oauth2.AccessRequest) {
				store.refreshErr = failure
			},
		},
		{
			name: "ShouldFailOnAnAccessTokenRevocationError", action: oauth2.GrantManagementActionReplace, id: "stored", err: oauth2.ErrServerError, commit: true, appended: true,
			setup: func(_ *testing.T, _ *Handler, store *tokenTestStore, _ *oauth2.DefaultSession, _ *oauth2.AccessRequest) {
				store.accessErr = failure
			},
		},
		{
			name: "ShouldTolerateTokensWhichAreAlreadyGone", action: oauth2.GrantManagementActionReplace, id: "stored", written: true,
			setup: func(_ *testing.T, _ *Handler, store *tokenTestStore, _ *oauth2.DefaultSession, _ *oauth2.AccessRequest) {
				store.refreshErr, store.accessErr = oauth2.ErrNotFound, oauth2.ErrNotFound
			},
		},
	}

	for _, sc := range bindTestStores {
		t.Run(sc.name, func(t *testing.T) {
			for _, tc := range testCases {
				t.Run(tc.name, func(t *testing.T) {
					handler, store := newTokenTestHandler(t, sc.new())
					session := newTokenTestSession(tc.id, tc.action)
					request := newTokenTestRequest(session, consts.GrantTypeAuthorizationCode)

					if tc.setup != nil {
						tc.setup(t, handler, store, session, request)
					}

					bound := handler.BindAccessRequest(t.Context(), request)

					if tc.err == nil || tc.commit {
						require.NoError(t, oauth2.ErrorToDebugRFC6749Error(bound))
					} else {
						require.ErrorIs(t, bound, tc.err)
					}

					assert.Empty(t, store.refresh)
					assert.Empty(t, store.access)

					err := tokenTestBindAndCommit(t, handler, request)

					store.getErr = nil

					stored, gerr := store.GetGrant(t.Context(), "stored")

					if tc.err == nil {
						require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
					} else {
						require.ErrorIs(t, err, tc.err)
						assert.Equal(t, oauth2.ErrorToRFC6749Error(tc.err).ErrorField, oauth2.ErrorToRFC6749Error(err).ErrorField)

						_, cerr := store.GetGrant(t.Context(), "created")
						assert.ErrorIs(t, cerr, oauth2.ErrNotFound)
					}

					if gerr != nil {
						return
					}

					switch {
					case tc.written:
						assert.Equal(t, []string{"r3"}, stored.RequestIDs)
					case tc.appended:
						assert.ElementsMatch(t, []string{"r1", "r2", "r3"}, stored.RequestIDs)
						assert.Equal(t, oauth2.Arguments{"read"}, stored.Permissions.ScopeValues())
					default:
						assert.Equal(t, []string{"r1", "r2"}, stored.RequestIDs)
						assert.Equal(t, oauth2.Arguments{"read"}, stored.Permissions.ScopeValues())
					}
				})
			}
		})
	}
}

func TestCommitAccessRequestKeepsOrRevokesConcurrentRequestIDs(t *testing.T) {
	testCases := []struct {
		name    string
		action  oauth2.GrantManagementAction
		inject  func(store *tokenTestStore, hook func())
		ids     []string
		refresh []string
		access  []string
	}{
		{
			name: "ShouldKeepAnIDAppendedBeforeTheMergeAppend", action: oauth2.GrantManagementActionMerge,
			inject: func(store *tokenTestStore, hook func()) { store.onAppend = hook },
			ids:    []string{"r1", "r2", "concurrent", "r3"}, refresh: []string{"r1", "r2", "concurrent"},
		},
		{
			name: "ShouldKeepAnIDAppendedWhileTheMergeRevokes", action: oauth2.GrantManagementActionMerge,
			inject: func(store *tokenTestStore, hook func()) { store.onRevokeRefresh = hook },
			ids:    []string{"r1", "r2", "r3", "concurrent"}, refresh: []string{"r1", "r2"},
		},
		{
			name: "ShouldRevokeAnIDAppendedBeforeTheReplaceSwap", action: oauth2.GrantManagementActionReplace,
			inject: func(store *tokenTestStore, hook func()) { store.onReplace = hook },
			ids:    []string{"r3"}, refresh: []string{"r1", "r2", "concurrent"}, access: []string{"r1", "r2", "concurrent"},
		},
	}

	for _, sc := range bindTestStores {
		for _, tc := range testCases {
			t.Run(sc.name+"/"+tc.name, func(t *testing.T) {
				handler, store := newTokenTestHandler(t, sc.new())
				request := newTokenTestRequest(newTokenTestSession("stored", tc.action), consts.GrantTypeAuthorizationCode)

				require.Equal(t, "r3", request.GetID())
				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(handler.BindAccessRequest(t.Context(), request)))

				injected := false

				tc.inject(store, func() {
					if injected {
						return
					}

					injected = true

					require.NoError(t, store.GrantManagementStorage.AppendGrantRequestID(t.Context(), "stored", "concurrent"))
				})

				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(handler.CommitAccessRequest(t.Context(), request)))
				require.True(t, injected)

				stored, err := store.GrantManagementStorage.GetGrant(t.Context(), "stored")
				require.NoError(t, err)

				assert.Equal(t, tc.ids, stored.RequestIDs)
				assert.Equal(t, tc.refresh, store.refresh)
				assert.Equal(t, tc.access, store.access)
				assert.Equal(t, oauth2.GrantUpdatedByClient, stored.UpdatedBy)
			})
		}
	}
}

func TestCommitAccessRequestMergeKeepsOverlappingMerges(t *testing.T) {
	for _, sc := range bindTestStores {
		t.Run(sc.name, func(t *testing.T) {
			handler, store := newTokenTestHandler(t, sc.new())

			detailC := oauth2.AuthorizationDetail{Type: "transfer", Actions: []string{"create"}}

			first := newTokenTestSession("stored", oauth2.GrantManagementActionMerge)
			first.GrantPermissions = &oauth2.GrantPermissions{
				Scopes:               []oauth2.GrantScope{{Scope: "read", Resource: []string{"https://rs1"}}, {Scope: "write"}},
				Audience:             []string{"https://rs1", "https://rs2"},
				Claims:               []string{"address", "email"},
				AuthorizationDetails: oauth2.AuthorizationDetails{bindTestDetailA, bindTestDetailB},
			}

			second := newTokenTestSession("stored", oauth2.GrantManagementActionMerge)
			second.GrantPermissions = &oauth2.GrantPermissions{
				Scopes:               []oauth2.GrantScope{{Scope: "read", Resource: []string{"https://rs1", "https://rs2"}}},
				Audience:             []string{"https://rs1"},
				Claims:               []string{"address", "name"},
				AuthorizationDetails: oauth2.AuthorizationDetails{bindTestDetailA, detailC},
			}

			requests := []*oauth2.AccessRequest{
				newTokenTestRequest(first, consts.GrantTypeAuthorizationCode),
				newTokenTestRequest(second, consts.GrantTypeAuthorizationCode),
			}

			requests[1].SetID("r4")

			// Both authorizations were bound to the grant before either was redeemed (Section 5.2).
			for _, request := range requests {
				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(handler.BindAccessRequest(t.Context(), request)))
			}

			for _, request := range requests {
				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(handler.CommitAccessRequest(t.Context(), request)))
			}

			grant, err := store.GetGrant(t.Context(), "stored")
			require.NoError(t, err)

			assert.ElementsMatch(t, []string{"read", "write"}, grant.Permissions.ScopeValues())
			assert.ElementsMatch(t, []string{"https://rs1", "https://rs2"}, grant.Permissions.ResourceValues())
			assert.ElementsMatch(t, []string{"https://rs1", "https://rs2"}, grant.Permissions.Audience)
			assert.ElementsMatch(t, []string{"address", "email", "name"}, grant.Permissions.Claims)
			assert.ElementsMatch(t, oauth2.AuthorizationDetails{bindTestDetailA, bindTestDetailB, detailC}, grant.Permissions.AuthorizationDetails)
			assert.Equal(t, []string{"r1", "r2", "r3", "r4"}, grant.RequestIDs)
		})
	}
}

func TestCommitAccessRequestMergeDropsAStoredScopeNoLongerAllowed(t *testing.T) {
	for _, sc := range bindTestStores {
		t.Run(sc.name, func(t *testing.T) {
			handler, store := newTokenTestHandler(t, sc.new())
			request := newTokenTestRequest(newTokenTestSession("stored", oauth2.GrantManagementActionMerge), consts.GrantTypeAuthorizationCode)

			request.Client = &oauth2.DefaultClient{ID: "c", Scopes: []string{"write"}, Audience: []string{"https://rs2"}}

			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(tokenTestBindAndCommit(t, handler, request)))

			grant, err := store.GetGrant(t.Context(), "stored")
			require.NoError(t, err)

			assert.Equal(t, oauth2.Arguments{"write"}, grant.Permissions.ScopeValues())
			assert.Equal(t, []string{"https://rs2"}, grant.Permissions.Audience)
		})
	}
}

func TestCommitAccessRequestReplaceAfterTheContextIsCancelled(t *testing.T) {
	testCases := []struct {
		name   string
		access error
		err    error
		ids    []string
		scopes oauth2.Arguments
	}{
		{name: "ShouldRestoreThePreviousRequestIDsWhenARevocationFails", access: errors.New("storage failure"), err: oauth2.ErrServerError, ids: []string{"r1", "r2", "r3"}, scopes: oauth2.Arguments{"read"}},
		{name: "ShouldFinishTheReplace", ids: []string{"r3"}, scopes: oauth2.Arguments{"write"}},
	}

	for _, sc := range bindTestStores {
		for _, tc := range testCases {
			t.Run(sc.name+"/"+tc.name, func(t *testing.T) {
				handler, store := newTokenTestHandler(t, sc.new())
				request := newTokenTestRequest(newTokenTestSession("stored", oauth2.GrantManagementActionReplace), consts.GrantTypeAuthorizationCode)

				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()

				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(handler.BindAccessRequest(ctx, request)))

				store.accessErr = tc.access
				store.onRevokeRefresh = cancel

				err := handler.CommitAccessRequest(ctx, request)

				if tc.err == nil {
					require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
				} else {
					require.ErrorIs(t, err, tc.err)
				}

				require.Error(t, ctx.Err())

				stored, err := store.GrantManagementStorage.GetGrant(t.Context(), "stored")
				require.NoError(t, err)

				assert.ElementsMatch(t, tc.ids, stored.RequestIDs)
				assert.Equal(t, tc.scopes, stored.Permissions.ScopeValues())
			})
		}
	}
}

func TestBindAccessRequestWritesNothing(t *testing.T) {
	testCases := []struct {
		name   string
		action oauth2.GrantManagementAction
		id     string
	}{
		{name: "ShouldNotCreateAGrant", action: oauth2.GrantManagementActionCreate, id: "created"},
		{name: "ShouldNotMergeAGrant", action: oauth2.GrantManagementActionMerge, id: "stored"},
		{name: "ShouldNotReplaceAGrant", action: oauth2.GrantManagementActionReplace, id: "stored"},
	}

	for _, sc := range bindTestStores {
		t.Run(sc.name, func(t *testing.T) {
			for _, tc := range testCases {
				t.Run(tc.name, func(t *testing.T) {
					handler, store := newTokenTestHandler(t, sc.new())
					request := newTokenTestRequest(newTokenTestSession(tc.id, tc.action), consts.GrantTypeAuthorizationCode)

					before, err := store.GetGrant(t.Context(), "stored")
					require.NoError(t, err)

					require.NoError(t, oauth2.ErrorToDebugRFC6749Error(handler.BindAccessRequest(t.Context(), request)))

					_, err = store.GetGrant(t.Context(), "created")
					assert.ErrorIs(t, err, oauth2.ErrNotFound)

					after, err := store.GetGrant(t.Context(), "stored")
					require.NoError(t, err)

					assert.Equal(t, before, after)
					assert.Empty(t, store.refresh)
					assert.Empty(t, store.access)
				})
			}
		})
	}
}

func TestBindAccessRequestInert(t *testing.T) {
	testCases := []struct {
		name      string
		config    oauth2.Configurator
		session   oauth2.Session
		grantType string
	}{
		{name: "ShouldIgnoreARequestWithoutConfiguration", config: &oauth2.Config{}, session: newTokenTestSession("created", oauth2.GrantManagementActionCreate), grantType: consts.GrantTypeAuthorizationCode},
		{name: "ShouldIgnoreARequestWithoutAConfigurationProvider", config: tokenTestPlainConfig{}, session: newTokenTestSession("created", oauth2.GrantManagementActionCreate), grantType: consts.GrantTypeAuthorizationCode},
		{name: "ShouldIgnoreASessionWithoutGrantManagement", session: &bindTestPlainSession{Session: &oauth2.DefaultSession{Subject: "alice"}}, grantType: consts.GrantTypeAuthorizationCode},
		{name: "ShouldIgnoreASessionWithoutAnAction", session: &oauth2.DefaultSession{Subject: "alice", GrantID: "created"}, grantType: consts.GrantTypeAuthorizationCode},
		{name: "ShouldIgnoreARefresh", session: newTokenTestSession("created", oauth2.GrantManagementActionCreate), grantType: consts.GrantTypeRefreshToken},
		{name: "ShouldIgnoreATokenExchange", session: newTokenTestSession("created", oauth2.GrantManagementActionCreate), grantType: consts.GrantTypeOAuthTokenExchange},
		{name: "ShouldIgnoreADeviceCodeGrant", session: newTokenTestSession("created", oauth2.GrantManagementActionCreate), grantType: consts.GrantTypeOAuthDeviceCode},
	}

	for _, sc := range bindTestStores {
		t.Run(sc.name, func(t *testing.T) {
			for _, tc := range testCases {
				t.Run(tc.name, func(t *testing.T) {
					handler, store := newTokenTestHandler(t, sc.new())

					if tc.config != nil {
						handler.Config = tc.config
					}

					request := newTokenTestRequest(tc.session, tc.grantType)

					require.NoError(t, oauth2.ErrorToDebugRFC6749Error(tokenTestBindAndCommit(t, handler, request)))

					_, err := store.GetGrant(t.Context(), "created")
					assert.ErrorIs(t, err, oauth2.ErrNotFound)

					assert.Equal(t, 1, store.gets)
					assert.Empty(t, store.refresh)
					assert.Empty(t, store.access)
				})
			}
		})
	}
}

func TestPopulateBoundTokenEndpointResponse(t *testing.T) {
	testCases := []struct {
		name      string
		config    oauth2.Configurator
		session   oauth2.Session
		grantType string
		expected  any
	}{
		{name: "ShouldEchoForTheAuthorizationCodeGrant", session: newTokenTestSession("stored", oauth2.GrantManagementActionMerge), grantType: consts.GrantTypeAuthorizationCode, expected: "stored"},
		{name: "ShouldEchoForTheCIBAGrant", session: newTokenTestSession("stored", oauth2.GrantManagementActionCreate), grantType: consts.GrantTypeOpenIDCIBA, expected: "stored"},
		{name: "ShouldEchoForTheRefreshTokenGrant", session: newTokenTestSession("stored", oauth2.GrantManagementActionReplace), grantType: consts.GrantTypeRefreshToken, expected: "stored"},
		{name: "ShouldNotEchoForATokenExchange", session: newTokenTestSession("stored", oauth2.GrantManagementActionMerge), grantType: consts.GrantTypeOAuthTokenExchange},
		{name: "ShouldNotEchoForADeviceCodeGrant", session: newTokenTestSession("stored", oauth2.GrantManagementActionMerge), grantType: consts.GrantTypeOAuthDeviceCode},
		{name: "ShouldNotEchoWithoutAnAction", session: &oauth2.DefaultSession{Subject: "alice", GrantID: "stored"}, grantType: consts.GrantTypeRefreshToken},
		{name: "ShouldNotEchoWithoutAGrantID", session: newTokenTestSession("", oauth2.GrantManagementActionMerge), grantType: consts.GrantTypeAuthorizationCode},
		{name: "ShouldNotEchoForASessionWithoutGrantManagement", session: &bindTestPlainSession{Session: &oauth2.DefaultSession{Subject: "alice"}}, grantType: consts.GrantTypeAuthorizationCode},
		{name: "ShouldNotEchoWithoutConfiguration", config: &oauth2.Config{}, session: newTokenTestSession("stored", oauth2.GrantManagementActionMerge), grantType: consts.GrantTypeAuthorizationCode},
		{name: "ShouldNotEchoWithoutAConfigurationProvider", config: tokenTestPlainConfig{}, session: newTokenTestSession("stored", oauth2.GrantManagementActionMerge), grantType: consts.GrantTypeAuthorizationCode},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			handler, store := newTokenTestHandler(t, bindTestStores[0].new())

			if tc.config != nil {
				handler.Config = tc.config
			}

			request := newTokenTestRequest(tc.session, tc.grantType)
			response := oauth2.NewAccessResponse()

			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(handler.PopulateBoundTokenEndpointResponse(t.Context(), request, response)))

			assert.Equal(t, tc.expected, response.GetExtra(consts.AccessResponseGrantID))
			assert.Equal(t, "grant_id", consts.AccessResponseGrantID)
			assert.Zero(t, store.gets)
		})
	}
}

func tokenTestBindAndCommit(t *testing.T, handler *Handler, request oauth2.AccessRequester) error {
	t.Helper()

	if err := handler.BindAccessRequest(t.Context(), request); err != nil {
		return err
	}

	return handler.CommitAccessRequest(t.Context(), request)
}

type tokenTestPlainConfig struct {
	oauth2.Configurator
}

type tokenTestStore struct {
	oauth2.GrantManagementStorage

	gets    int
	refresh []string
	access  []string

	onAppend        func()
	onReplace       func()
	onRevokeRefresh func()

	getErr     error
	createErr  error
	updateErr  error
	refreshErr error
	accessErr  error
}

func (s *tokenTestStore) GetGrant(ctx context.Context, id string) (*oauth2.Grant, error) {
	s.gets++

	if s.getErr != nil {
		return nil, s.getErr
	}

	return s.GrantManagementStorage.GetGrant(ctx, id)
}

func (s *tokenTestStore) CreateGrant(ctx context.Context, grant *oauth2.Grant) error {
	if s.createErr != nil {
		return s.createErr
	}

	return s.GrantManagementStorage.CreateGrant(ctx, grant)
}

func (s *tokenTestStore) AppendGrantRequestID(ctx context.Context, id, requestID string) error {
	if s.onAppend != nil {
		s.onAppend()
	}

	if err := ctx.Err(); err != nil {
		return err
	}

	return s.GrantManagementStorage.AppendGrantRequestID(ctx, id, requestID)
}

func (s *tokenTestStore) UpdateGrant(ctx context.Context, grant *oauth2.Grant) error {
	if s.updateErr != nil {
		return s.updateErr
	}

	if err := ctx.Err(); err != nil {
		return err
	}

	return s.GrantManagementStorage.UpdateGrant(ctx, grant)
}

func (s *tokenTestStore) ReplaceGrantRequestIDs(ctx context.Context, id string, requestIDs []string) ([]string, error) {
	if s.onReplace != nil {
		s.onReplace()
	}

	return s.GrantManagementStorage.ReplaceGrantRequestIDs(ctx, id, requestIDs)
}

func (s *tokenTestStore) RevokeRefreshToken(ctx context.Context, requestID string) error {
	if s.onRevokeRefresh != nil {
		s.onRevokeRefresh()
	}

	if err := ctx.Err(); err != nil {
		return err
	}

	s.refresh = append(s.refresh, requestID)

	return s.refreshErr
}

func (s *tokenTestStore) RevokeAccessToken(ctx context.Context, requestID string) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	s.access = append(s.access, requestID)

	return s.accessErr
}

var tokenTestCreatedAt = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

func newTokenTestHandler(t *testing.T, storage oauth2.GrantManagementStorage) (*Handler, *tokenTestStore) {
	t.Helper()

	handler := newBindTestHandler(t, storage, "alice")

	grant, err := storage.GetGrant(t.Context(), "stored")
	require.NoError(t, err)

	grant.CreatedAt, grant.UpdatedAt = tokenTestCreatedAt, tokenTestCreatedAt
	grant.UpdatedBy = oauth2.GrantUpdatedByAuthorizationServer

	require.NoError(t, storage.UpdateGrant(t.Context(), grant))

	_, err = storage.ReplaceGrantRequestIDs(t.Context(), "stored", []string{"r1", "r2"})
	require.NoError(t, err)

	store := &tokenTestStore{GrantManagementStorage: storage}

	handler.Storage = store

	return handler, store
}

func newTokenTestSession(id string, action oauth2.GrantManagementAction) *oauth2.DefaultSession {
	return &oauth2.DefaultSession{
		Subject:               "alice",
		GrantID:               id,
		GrantManagementAction: action,
		GrantPermissions:      bindTestRequestPermissions(),
	}
}

func newTokenTestRequest(session oauth2.Session, grantType string) *oauth2.AccessRequest {
	request := oauth2.NewAccessRequest(session)
	request.Client = newBindTestClient()
	request.GrantTypes = oauth2.Arguments{grantType}
	request.SetID("r3")

	return request
}
