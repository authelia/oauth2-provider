// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/storage"
)

func TestCarrySessionBindingGrantManagementRestored(t *testing.T) {
	type store interface {
		CreateAccessTokenSession(ctx context.Context, signature string, request oauth2.Requester) (err error)
		GetAccessTokenSession(ctx context.Context, signature string, session oauth2.Session) (request oauth2.Requester, err error)
	}

	testCases := []struct {
		name  string
		store store
	}{
		{name: "MemoryStore", store: storage.NewMemoryStore()},
		{name: "HydratingMemoryStore", store: storage.NewHydratingMemoryStore()},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()

			identifier := "account-1"

			newPermissions := func() *oauth2.GrantPermissions {
				return &oauth2.GrantPermissions{
					Scopes:   []oauth2.GrantScope{{Scope: "read", Resource: []string{"https://rs1"}}, {Scope: "write", Resource: []string{"https://rs2"}}},
					Audience: []string{"https://rs1", "https://rs2"},
					Claims:   []string{"email"},
					AuthorizationDetails: oauth2.AuthorizationDetails{{
						Type:       "account_information",
						Locations:  []string{"https://rs1"},
						Actions:    []string{"read"},
						Identifier: &identifier,
						Extra:      map[string]any{"limit": map[string]any{"currency": "EUR"}},
					}},
				}
			}

			request := oauth2.NewRequest()
			request.ID = "request-1"
			request.Client = &oauth2.DefaultClient{ID: "client-1"}
			request.Session = &oauth2.DefaultSession{
				Subject:               "alice",
				GrantID:               "grant-1",
				GrantManagementAction: oauth2.GrantManagementActionMerge,
				GrantPermissions:      newPermissions(),
			}

			require.NoError(t, tc.store.CreateAccessTokenSession(ctx, "signature", request))

			restored, err := tc.store.GetAccessTokenSession(ctx, "signature", &oauth2.DefaultSession{})
			require.NoError(t, err)

			session := &oauth2.DefaultSession{Subject: "alice"}

			oauth2.CarrySessionBindingForTest(restored.GetSession(), session)

			assert.Equal(t, "alice", session.GetSubject())
			assert.Equal(t, "grant-1", session.GetGrantID())
			assert.Equal(t, oauth2.GrantManagementActionMerge, session.GetGrantManagementAction())

			actual := session.GetGrantPermissions()
			require.NotNil(t, actual)

			assert.NotSame(t, restored.GetSession().(*oauth2.DefaultSession).GrantPermissions, actual)
			assert.Equal(t, newPermissions().Scopes, actual.Scopes)
			assert.Equal(t, newPermissions().Audience, actual.Audience)
			assert.Equal(t, newPermissions().Claims, actual.Claims)
			assert.Equal(t, oauth2.Arguments{"read", "write"}, actual.ScopeValues())
			assert.Equal(t, oauth2.Arguments{"https://rs1", "https://rs2"}, actual.ResourceValues())

			expected, err := json.Marshal(newPermissions())
			require.NoError(t, err)

			data, err := json.Marshal(actual)
			require.NoError(t, err)

			assert.JSONEq(t, string(expected), string(data))
		})
	}
}
