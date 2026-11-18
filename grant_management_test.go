// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2/internal/clone/clonetest"
)

func TestNewGrantID(t *testing.T) {
	first, err := NewGrantID()
	require.NoError(t, err)

	second, err := NewGrantID()
	require.NoError(t, err)

	decoded, err := base64.RawURLEncoding.DecodeString(first)
	require.NoError(t, err)

	assert.GreaterOrEqual(t, len(decoded), 16)
	assert.Equal(t, first, base64.RawURLEncoding.EncodeToString(decoded))
	assert.NotEqual(t, first, second)
}

func TestGrantPermissionsMerge(t *testing.T) {
	a := AuthorizationDetail{Type: "account_information", Actions: []string{"read"}, Extra: map[string]any{"iban": "DE1"}}
	b := AuthorizationDetail{Type: "payment_initiation", Locations: []string{"https://rs2"}}

	testCases := []struct {
		name      string
		have      *GrantPermissions
		other     *GrantPermissions
		scopes    Arguments
		resources Arguments
		expected  *GrantPermissions
	}{
		{
			name:      "ShouldUnionDistinctPermissions",
			have:      &GrantPermissions{Scopes: []GrantScope{{Scope: "read", Resource: []string{"https://rs1"}}}, AuthorizationDetails: AuthorizationDetails{a}},
			other:     &GrantPermissions{Scopes: []GrantScope{{Scope: "write", Resource: []string{"https://rs2"}}}, AuthorizationDetails: AuthorizationDetails{a.Clone(), b}, Claims: []string{"email"}},
			scopes:    Arguments{"read", "write"},
			resources: Arguments{"https://rs1", "https://rs2"},
			expected: &GrantPermissions{
				Scopes:               []GrantScope{{Scope: "read", Resource: []string{"https://rs1"}}, {Scope: "write", Resource: []string{"https://rs2"}}},
				Claims:               []string{"email"},
				AuthorizationDetails: AuthorizationDetails{a, b},
			},
		},
		{
			name:      "ShouldUnionResourcesOfTheSameScope",
			have:      &GrantPermissions{Scopes: []GrantScope{{Scope: "read", Resource: []string{"https://rs1"}}}, Audience: []string{"https://rs1"}, Claims: []string{"email"}},
			other:     &GrantPermissions{Scopes: []GrantScope{{Scope: "read", Resource: []string{"https://rs1", "https://rs2"}}}, Audience: []string{"https://rs1", "https://rs2"}, Claims: []string{"email", "name"}},
			scopes:    Arguments{"read"},
			resources: Arguments{"https://rs1", "https://rs2"},
			expected: &GrantPermissions{
				Scopes:   []GrantScope{{Scope: "read", Resource: []string{"https://rs1", "https://rs2"}}},
				Audience: []string{"https://rs1", "https://rs2"},
				Claims:   []string{"email", "name"},
			},
		},
		{
			name:      "ShouldCopyOtherWhenReceiverNil",
			other:     &GrantPermissions{Scopes: []GrantScope{{Scope: "read"}}},
			scopes:    Arguments{"read"},
			resources: nil,
			expected:  &GrantPermissions{Scopes: []GrantScope{{Scope: "read"}}},
		},
		{
			name:      "ShouldCopyReceiverWhenOtherNil",
			have:      &GrantPermissions{Scopes: []GrantScope{{Scope: "read"}}},
			scopes:    Arguments{"read"},
			resources: nil,
			expected:  &GrantPermissions{Scopes: []GrantScope{{Scope: "read"}}},
		},
		{
			name:     "ShouldReturnEmptyWhenBothNil",
			expected: &GrantPermissions{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			have, other := tc.have.Clone(), tc.other.Clone()

			actual := tc.have.Merge(tc.other)

			require.NotNil(t, actual)
			assert.Equal(t, tc.scopes, actual.ScopeValues())
			assert.Equal(t, tc.resources, actual.ResourceValues())
			assert.Equal(t, tc.expected, actual)
			assert.Equal(t, have, tc.have)
			assert.Equal(t, other, tc.other)

			if tc.have != nil && len(tc.have.Scopes) != 0 && len(actual.Scopes) != 0 {
				actual.Scopes[0].Scope = "mutated"
				actual.Scopes[0].Resource = append(actual.Scopes[0].Resource, "https://mutated")

				assert.Equal(t, have, tc.have)
			}
		})
	}
}

func TestGrantPermissionsValues(t *testing.T) {
	var permissions *GrantPermissions

	assert.Nil(t, permissions.ScopeValues())
	assert.Nil(t, permissions.ResourceValues())
	assert.Nil(t, permissions.Clone())

	permissions = &GrantPermissions{Scopes: []GrantScope{
		{Scope: "read", Resource: []string{"https://rs1", "https://rs2"}},
		{Scope: "write", Resource: []string{"https://rs2"}},
		{Scope: "read"},
	}}

	assert.Equal(t, Arguments{"read", "write"}, permissions.ScopeValues())
	assert.Equal(t, Arguments{"https://rs1", "https://rs2"}, permissions.ResourceValues())

	permissions = &GrantPermissions{Scopes: []GrantScope{
		{Scope: "read write", Resource: []string{"https://rs1"}},
		{Scope: "write  admin"},
	}}

	assert.Equal(t, Arguments{"read", "write", "admin"}, permissions.ScopeValues())
}

func TestGrantClone(t *testing.T) {
	var grant *Grant

	assert.Nil(t, grant.Clone())

	grant = newTestGrant()

	clonetest.AssertDeepCopy(t, grant, grant.Clone())
}

func TestErrInvalidGrantID(t *testing.T) {
	assert.Equal(t, "invalid_grant_id", ErrInvalidGrantID.ErrorField)
	assert.Equal(t, http.StatusBadRequest, ErrInvalidGrantID.CodeField)
}

func TestCarrySessionBindingGrantManagement(t *testing.T) {
	testCases := []struct {
		name    string
		restore func(t *testing.T, session *DefaultSession) Session
	}{
		{
			name: "ShouldCarryFromStoredPointer",
			restore: func(t *testing.T, session *DefaultSession) Session {
				return session
			},
		},
		{
			name: "ShouldCarryFromHydratedSession",
			restore: func(t *testing.T, session *DefaultSession) Session {
				data, err := json.Marshal(session)
				require.NoError(t, err)

				restored := &DefaultSession{}
				require.NoError(t, json.Unmarshal(data, restored))

				return restored
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			permissions := newTestGrant().Permissions

			restored := tc.restore(t, &DefaultSession{
				GrantID:               "grant-1",
				GrantManagementAction: GrantManagementActionMerge,
				GrantPermissions:      permissions.Clone(),
			})

			session := &DefaultSession{Subject: "alice"}

			carrySessionBinding(restored, session)

			assert.Equal(t, "alice", session.GetSubject())
			assert.Equal(t, "grant-1", session.GetGrantID())
			assert.Equal(t, GrantManagementActionMerge, session.GetGrantManagementAction())
			require.NotNil(t, session.GetGrantPermissions())
			assert.Equal(t, permissions.ScopeValues(), session.GetGrantPermissions().ScopeValues())
			assert.Equal(t, permissions.ResourceValues(), session.GetGrantPermissions().ResourceValues())
			assert.Equal(t, permissions.Claims, session.GetGrantPermissions().Claims)
			assert.Len(t, session.GetGrantPermissions().AuthorizationDetails, 1)
			assert.NotSame(t, restored.(*DefaultSession).GrantPermissions, session.GrantPermissions)
		})
	}

	t.Run("ShouldKeepReplacementValuesWhenRestoredHasNone", func(t *testing.T) {
		permissions := &GrantPermissions{Claims: []string{"email"}}
		session := &DefaultSession{GrantID: "grant-2", GrantManagementAction: GrantManagementActionReplace, GrantPermissions: permissions}

		carrySessionBinding(&DefaultSession{}, session)

		assert.Equal(t, "grant-2", session.GetGrantID())
		assert.Equal(t, GrantManagementActionReplace, session.GetGrantManagementAction())
		assert.Same(t, permissions, session.GetGrantPermissions())
	})
}

func TestValidateSessionBindingCarryGrantManagement(t *testing.T) {
	testCases := []struct {
		name     string
		restored Session
		session  Session
		err      bool
	}{
		{name: "ShouldRejectAGrantID", restored: &DefaultSession{GrantID: "grant-1"}, session: testPlainSession{Session: &DefaultSession{}}, err: true},
		{name: "ShouldRejectAGrantManagementAction", restored: &DefaultSession{GrantManagementAction: GrantManagementActionMerge}, session: testPlainSession{Session: &DefaultSession{}}, err: true},
		{name: "ShouldRejectGrantPermissions", restored: &DefaultSession{GrantPermissions: &GrantPermissions{}}, session: testPlainSession{Session: &DefaultSession{}}, err: true},
		{name: "ShouldAllowASessionWhichCarriesTheFields", restored: &DefaultSession{GrantID: "grant-1", GrantManagementAction: GrantManagementActionMerge}, session: &DefaultSession{}},
		{name: "ShouldAllowARestoredSessionWithoutTheFields", restored: &DefaultSession{}, session: testPlainSession{Session: &DefaultSession{}}},
		{name: "ShouldAllowARestoredSessionWhichCannotCarryTheFields", restored: testPlainSession{Session: &DefaultSession{GrantID: "grant-1"}}, session: testPlainSession{Session: &DefaultSession{}}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateSessionBindingCarry(tc.restored, tc.session)

			if tc.err {
				require.ErrorIs(t, err, ErrServerError)

				return
			}

			require.NoError(t, err)
		})
	}
}

func TestDefaultSessionGrantManagementJSON(t *testing.T) {
	data, err := json.Marshal(&DefaultSession{})
	require.NoError(t, err)
	assert.NotContains(t, string(data), "grant_id")
	assert.NotContains(t, string(data), "grant_management_action")
	assert.NotContains(t, string(data), "grant_permissions")

	permissions := newTestGrant().Permissions

	have := &DefaultSession{}
	have.SetGrantID("grant-1")
	have.SetGrantManagementAction(GrantManagementActionCreate)
	have.SetGrantPermissions(&permissions)

	data, err = json.Marshal(have)
	require.NoError(t, err)

	session := &DefaultSession{}
	require.NoError(t, json.Unmarshal(data, session))

	assert.Equal(t, "grant-1", session.GetGrantID())
	assert.Equal(t, GrantManagementActionCreate, session.GetGrantManagementAction())
	require.NotNil(t, session.GetGrantPermissions())
	assert.Equal(t, permissions.Scopes, session.GetGrantPermissions().Scopes)
	assert.Equal(t, permissions.Audience, session.GetGrantPermissions().Audience)
	assert.Equal(t, permissions.Claims, session.GetGrantPermissions().Claims)

	expected, err := json.Marshal(permissions.AuthorizationDetails)
	require.NoError(t, err)

	actual, err := json.Marshal(session.GetGrantPermissions().AuthorizationDetails)
	require.NoError(t, err)

	assert.JSONEq(t, string(expected), string(actual))
}

func TestDefaultSessionGrantManagementNil(t *testing.T) {
	var session *DefaultSession

	assert.Empty(t, session.GetGrantID())
	assert.Empty(t, session.GetGrantManagementAction())
	assert.Nil(t, session.GetGrantPermissions())
}

func newTestGrant() *Grant {
	identifier := "account-1"

	return &Grant{
		ID:       "grant-1",
		ClientID: "client-1",
		Subject:  "alice",
		Permissions: GrantPermissions{
			Scopes:   []GrantScope{{Scope: "read", Resource: []string{"https://rs1"}}},
			Audience: []string{"https://rs1"},
			Claims:   []string{"email"},
			AuthorizationDetails: AuthorizationDetails{{
				Type:       "account_information",
				Locations:  []string{"https://rs1"},
				Actions:    []string{"read"},
				DataTypes:  []string{"balances"},
				Identifier: &identifier,
				Privileges: []string{"admin"},
				Extra:      map[string]any{"limit": map[string]any{"currency": "EUR"}},
			}},
		},
		CreatedAt:  time.Unix(1700000000, 0).UTC(),
		UpdatedAt:  time.Unix(1700000100, 0).UTC(),
		ExpiresAt:  time.Unix(1700003600, 0).UTC(),
		UpdatedBy:  "client",
		RequestIDs: []string{"request-1"},
	}
}

type testPlainSession struct {
	Session
}
