// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package grantmgmt

import (
	"context"
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/storage"
)

func TestValidateAuthorizeRequest(t *testing.T) {
	all := &oauth2.GrantManagementConfig{
		Actions: []oauth2.GrantManagementAction{
			oauth2.GrantManagementActionQuery,
			oauth2.GrantManagementActionRevoke,
			oauth2.GrantManagementActionCreate,
			oauth2.GrantManagementActionMerge,
			oauth2.GrantManagementActionReplace,
		},
	}

	required := &oauth2.GrantManagementConfig{Actions: all.Actions, ActionRequired: true}

	createOnly := &oauth2.GrantManagementConfig{
		Actions: []oauth2.GrantManagementAction{oauth2.GrantManagementActionCreate},
	}

	confidential := &oauth2.DefaultClient{ID: "client"}
	public := &oauth2.DefaultClient{ID: "client", Public: true}

	code := oauth2.Arguments{consts.ResponseTypeAuthorizationCodeFlow}

	testCases := []struct {
		name          string
		config        oauth2.Configurator
		storage       oauth2.GrantManagementStorage
		client        oauth2.Client
		action        []string
		id            []string
		responseTypes oauth2.Arguments
		err           error
		hint          string
	}{
		{
			name:          "ShouldIgnoreTheParametersWithoutTheConfig",
			config:        &oauth2.Config{},
			client:        public,
			action:        []string{"merge"},
			id:            []string{"unknown"},
			responseTypes: oauth2.Arguments{consts.ResponseTypeImplicitFlowToken},
		},
		{
			name:          "ShouldIgnoreTheParametersWhenTheConfiguratorIsNotAProvider",
			config:        struct{ oauth2.Configurator }{&oauth2.Config{GrantManagement: all}},
			client:        public,
			action:        []string{"merge"},
			id:            []string{"unknown"},
			responseTypes: code,
		},
		{
			name:          "ShouldPassWithoutTheParameters",
			config:        &oauth2.Config{GrantManagement: all},
			client:        public,
			responseTypes: oauth2.Arguments{consts.ResponseTypeImplicitFlowToken},
		},
		{
			name:          "ShouldRejectWithoutTheParametersWhenTheActionIsRequired",
			config:        &oauth2.Config{GrantManagement: required},
			client:        confidential,
			responseTypes: code,
			err:           oauth2.ErrInvalidRequest,
			hint:          "The 'grant_management_action' parameter is required.",
		},
		{
			name:          "ShouldRejectAnUnknownAction",
			config:        &oauth2.Config{GrantManagement: all},
			client:        confidential,
			action:        []string{"update"},
			responseTypes: code,
			err:           oauth2.ErrInvalidRequest,
			hint:          "The 'grant_management_action' parameter value 'update' is not supported.",
		},
		{
			name:          "ShouldRejectAnAPIAction",
			config:        &oauth2.Config{GrantManagement: all},
			client:        confidential,
			action:        []string{"query"},
			id:            []string{"own"},
			responseTypes: code,
			err:           oauth2.ErrInvalidRequest,
			hint:          "The 'grant_management_action' parameter value 'query' is not supported.",
		},
		{
			name:          "ShouldRejectAnActionWhichIsNotSupported",
			config:        &oauth2.Config{GrantManagement: createOnly},
			client:        confidential,
			action:        []string{"merge"},
			id:            []string{"own"},
			responseTypes: code,
			err:           oauth2.ErrInvalidRequest,
			hint:          "The 'grant_management_action' parameter value 'merge' is not supported.",
		},
		{
			name:          "ShouldRejectARepeatedAction",
			config:        &oauth2.Config{GrantManagement: all},
			client:        confidential,
			action:        []string{"create", "merge"},
			responseTypes: code,
			err:           oauth2.ErrInvalidRequest,
			hint:          "The 'grant_management_action' parameter must not be included more than once.",
		},
		{
			name:          "ShouldRejectARepeatedGrantID",
			config:        &oauth2.Config{GrantManagement: all},
			client:        confidential,
			action:        []string{"merge"},
			id:            []string{"own", "other"},
			responseTypes: code,
			err:           oauth2.ErrInvalidRequest,
			hint:          "The 'grant_id' parameter must not be included more than once.",
		},
		{
			name:          "ShouldRejectAGrantIDWithoutAnAction",
			config:        &oauth2.Config{GrantManagement: all},
			client:        confidential,
			id:            []string{"own"},
			responseTypes: code,
			err:           oauth2.ErrInvalidRequest,
			hint:          "The 'grant_id' parameter must not be included without the 'grant_management_action' parameter.",
		},
		{
			name:          "ShouldRejectCreateWithAGrantID",
			config:        &oauth2.Config{GrantManagement: all},
			client:        confidential,
			action:        []string{"create"},
			id:            []string{"own"},
			responseTypes: code,
			err:           oauth2.ErrInvalidRequest,
			hint:          "The 'grant_id' parameter must not be included when the 'grant_management_action' parameter is 'create'.",
		},
		{
			name:          "ShouldRejectMergeWithoutAGrantID",
			config:        &oauth2.Config{GrantManagement: all},
			client:        confidential,
			action:        []string{"merge"},
			responseTypes: code,
			err:           oauth2.ErrInvalidRequest,
			hint:          "The 'grant_id' parameter is required when the 'grant_management_action' parameter is 'merge'.",
		},
		{
			name:          "ShouldRejectReplaceWithoutAGrantID",
			config:        &oauth2.Config{GrantManagement: all},
			client:        confidential,
			action:        []string{"replace"},
			responseTypes: code,
			err:           oauth2.ErrInvalidRequest,
			hint:          "The 'grant_id' parameter is required when the 'grant_management_action' parameter is 'replace'.",
		},
		{
			name:          "ShouldRejectAPublicClient",
			config:        &oauth2.Config{GrantManagement: all},
			client:        public,
			action:        []string{"create"},
			responseTypes: code,
			err:           oauth2.ErrInvalidRequest,
			hint:          "Grant management is only available to confidential clients.",
		},
		{
			name:          "ShouldRejectAResponseTypeWithoutCode",
			config:        &oauth2.Config{GrantManagement: all},
			client:        confidential,
			action:        []string{"create"},
			responseTypes: oauth2.Arguments{consts.ResponseTypeImplicitFlowIDToken},
			err:           oauth2.ErrInvalidRequest,
			hint:          "Grant management requires a response type which includes 'code' and does not include 'token'.",
		},
		{
			name:          "ShouldRejectNoResponseType",
			config:        &oauth2.Config{GrantManagement: all},
			client:        confidential,
			action:        []string{"create"},
			responseTypes: nil,
			err:           oauth2.ErrInvalidRequest,
			hint:          "Grant management requires a response type which includes 'code' and does not include 'token'.",
		},
		{
			name:          "ShouldRejectAResponseTypeWithToken",
			config:        &oauth2.Config{GrantManagement: all},
			client:        confidential,
			action:        []string{"create"},
			responseTypes: oauth2.Arguments{consts.ResponseTypeAuthorizationCodeFlow, consts.ResponseTypeImplicitFlowToken},
			err:           oauth2.ErrInvalidRequest,
			hint:          "Grant management requires a response type which includes 'code' and does not include 'token'.",
		},
		{
			name:          "ShouldAcceptCreate",
			config:        &oauth2.Config{GrantManagement: all},
			client:        confidential,
			action:        []string{"create"},
			responseTypes: code,
		},
		{
			name:          "ShouldAcceptCreateWithCodeIDToken",
			config:        &oauth2.Config{GrantManagement: all},
			client:        confidential,
			action:        []string{"create"},
			responseTypes: oauth2.Arguments{consts.ResponseTypeAuthorizationCodeFlow, consts.ResponseTypeImplicitFlowIDToken},
		},
		{
			name:          "ShouldAcceptCreateWhenTheActionIsRequired",
			config:        &oauth2.Config{GrantManagement: required},
			client:        confidential,
			action:        []string{"create"},
			responseTypes: code,
		},
		{
			name:          "ShouldRejectMergeWithAnUnknownGrant",
			config:        &oauth2.Config{GrantManagement: all},
			client:        confidential,
			action:        []string{"merge"},
			id:            []string{"unknown"},
			responseTypes: code,
			err:           oauth2.ErrInvalidGrantID,
		},
		{
			name:          "ShouldRejectMergeWithTheGrantOfAnotherClient",
			config:        &oauth2.Config{GrantManagement: all},
			client:        confidential,
			action:        []string{"merge"},
			id:            []string{"other"},
			responseTypes: code,
			err:           oauth2.ErrInvalidGrantID,
		},
		{
			name:          "ShouldRejectReplaceWithTheGrantOfAnotherClient",
			config:        &oauth2.Config{GrantManagement: all},
			client:        confidential,
			action:        []string{"replace"},
			id:            []string{"other"},
			responseTypes: code,
			err:           oauth2.ErrInvalidGrantID,
		},
		{
			name:          "ShouldRejectMergeWhenTheStorageFails",
			config:        &oauth2.Config{GrantManagement: all},
			storage:       failingStorage{},
			client:        confidential,
			action:        []string{"merge"},
			id:            []string{"own"},
			responseTypes: code,
			err:           oauth2.ErrServerError,
		},
		{
			name:          "ShouldAcceptMerge",
			config:        &oauth2.Config{GrantManagement: all},
			client:        confidential,
			action:        []string{"merge"},
			id:            []string{"own"},
			responseTypes: code,
		},
		{
			name:          "ShouldAcceptReplace",
			config:        &oauth2.Config{GrantManagement: all},
			client:        confidential,
			action:        []string{"replace"},
			id:            []string{"own"},
			responseTypes: code,
		},
		{
			name:          "ShouldRejectMergeWithAnExpiredGrant",
			config:        &oauth2.Config{GrantManagement: all},
			client:        confidential,
			action:        []string{"merge"},
			id:            []string{"expired"},
			responseTypes: code,
			err:           oauth2.ErrInvalidGrantID,
		},
		{
			name:          "ShouldRejectReplaceWithAnExpiredGrant",
			config:        &oauth2.Config{GrantManagement: all},
			client:        confidential,
			action:        []string{"replace"},
			id:            []string{"expired"},
			responseTypes: code,
			err:           oauth2.ErrInvalidGrantID,
		},
		{
			name:          "ShouldAcceptMergeWithAGrantWhichDoesNotExpire",
			config:        &oauth2.Config{GrantManagement: all},
			client:        confidential,
			action:        []string{"merge"},
			id:            []string{"own"},
			responseTypes: code,
		},
		{
			name:          "ShouldAcceptMergeWithAGrantWhichExpiresInTheFuture",
			config:        &oauth2.Config{GrantManagement: all},
			client:        confidential,
			action:        []string{"merge"},
			id:            []string{"future"},
			responseTypes: code,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			store := newGrantStore(t)

			handler := &Handler{Config: tc.config, Storage: store}

			if tc.storage != nil {
				handler.Storage = tc.storage
			}

			request := oauth2.NewAuthorizeRequest()
			request.Client = tc.client
			request.ResponseTypes = tc.responseTypes
			request.Session = &oauth2.DefaultSession{Subject: "peter"}
			request.Form = url.Values{}

			if tc.action != nil {
				request.Form[consts.FormParameterGrantManagementAction] = tc.action
			}

			if tc.id != nil {
				request.Form[consts.FormParameterGrantID] = tc.id
			}

			for name, validate := range map[string]func(context.Context, oauth2.AuthorizeRequester) error{
				"ValidateAuthorizeRequest": handler.ValidateAuthorizeRequest,
				"BindAuthorizeRequest":     handler.BindAuthorizeRequest,
			} {
				err := validate(t.Context(), request)

				if tc.err == nil {
					assert.NoError(t, oauth2.ErrorToDebugRFC6749Error(err), name)

					continue
				}

				require.ErrorIs(t, err, tc.err, name)

				if tc.hint != "" {
					assert.Equal(t, tc.hint, oauth2.ErrorToRFC6749Error(err).HintField, name)
				}
			}

			assert.Len(t, store.Grants, 4)
		})
	}
}

func TestValidateRequest(t *testing.T) {
	config := &oauth2.Config{GrantManagement: &oauth2.GrantManagementConfig{
		Actions: []oauth2.GrantManagementAction{
			oauth2.GrantManagementActionCreate,
			oauth2.GrantManagementActionMerge,
			oauth2.GrantManagementActionReplace,
		},
	}}

	client := &oauth2.DefaultClient{ID: "client"}

	testCases := []struct {
		name     string
		form     url.Values
		action   oauth2.GrantManagementAction
		expected string
	}{
		{name: "ShouldReturnNothingWithoutTheParameters", form: url.Values{}},
		{
			name:   "ShouldReturnCreateWithoutAGrant",
			form:   url.Values{consts.FormParameterGrantManagementAction: {"create"}},
			action: oauth2.GrantManagementActionCreate,
		},
		{
			name:     "ShouldReturnMergeAndTheGrant",
			form:     url.Values{consts.FormParameterGrantManagementAction: {"merge"}, consts.FormParameterGrantID: {"own"}},
			action:   oauth2.GrantManagementActionMerge,
			expected: "own",
		},
		{
			name:     "ShouldReturnReplaceAndTheGrant",
			form:     url.Values{consts.FormParameterGrantManagementAction: {"replace"}, consts.FormParameterGrantID: {"own"}},
			action:   oauth2.GrantManagementActionReplace,
			expected: "own",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			handler := &Handler{Config: config, Storage: newGrantStore(t)}

			// A nil response types value is the CIBA request, which has no response type to check.
			action, grant, err := handler.validateRequest(t.Context(), client, tc.form, nil)
			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

			assert.Equal(t, tc.action, action)

			if tc.expected == "" {
				assert.Nil(t, grant)

				return
			}

			require.NotNil(t, grant)
			assert.Equal(t, tc.expected, grant.ID)
		})
	}
}

func TestBindRFC8628DeviceAuthorizeRequest(t *testing.T) {
	enabled := &oauth2.GrantManagementConfig{
		Actions: []oauth2.GrantManagementAction{oauth2.GrantManagementActionCreate, oauth2.GrantManagementActionMerge},
	}

	testCases := []struct {
		name   string
		config *oauth2.GrantManagementConfig
		form   url.Values
		err    bool
	}{
		{name: "ShouldPassWithoutTheParameters", config: enabled, form: url.Values{}},
		{
			name:   "ShouldPassWithoutTheParametersWhenTheActionIsRequired",
			config: &oauth2.GrantManagementConfig{Actions: enabled.Actions, ActionRequired: true},
			form:   url.Values{},
		},
		{
			name:   "ShouldRejectTheAction",
			config: enabled,
			form:   url.Values{consts.FormParameterGrantManagementAction: {"create"}},
			err:    true,
		},
		{
			name:   "ShouldRejectTheGrantID",
			config: enabled,
			form:   url.Values{consts.FormParameterGrantID: {"own"}},
			err:    true,
		},
		{
			name:   "ShouldRejectBothParameters",
			config: enabled,
			form:   url.Values{consts.FormParameterGrantManagementAction: {"merge"}, consts.FormParameterGrantID: {"own"}},
			err:    true,
		},
		{
			name:   "ShouldRejectTheActionAfterAnEmptyValue",
			config: enabled,
			form:   url.Values{consts.FormParameterGrantManagementAction: {"", "create"}},
			err:    true,
		},
		{
			name:   "ShouldRejectTheGrantIDAfterAnEmptyValue",
			config: enabled,
			form:   url.Values{consts.FormParameterGrantID: {"", "own"}},
			err:    true,
		},
		{
			name:   "ShouldPassWithEmptyParameters",
			config: enabled,
			form:   url.Values{consts.FormParameterGrantManagementAction: {""}, consts.FormParameterGrantID: {"", ""}},
		},
		{
			name: "ShouldIgnoreTheParametersWithoutTheConfig",
			form: url.Values{consts.FormParameterGrantManagementAction: {"merge"}, consts.FormParameterGrantID: {"own"}},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			handler := &Handler{Config: &oauth2.Config{GrantManagement: tc.config}, Storage: newGrantStore(t)}

			request := oauth2.NewDeviceAuthorizeRequest()
			request.Client = &oauth2.DefaultClient{ID: "client"}
			request.Form = tc.form

			err := handler.BindRFC8628DeviceAuthorizeRequest(t.Context(), request)

			if !tc.err {
				assert.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

				return
			}

			require.ErrorIs(t, err, oauth2.ErrInvalidRequest)
			assert.Equal(t, "Grant management is not supported at the device authorization endpoint.", oauth2.ErrorToRFC6749Error(err).HintField)
		})
	}
}

func TestHandlesGrantManagement(t *testing.T) {
	config := &oauth2.GrantManagementConfig{Endpoint: "https://as.example.com/grants"}

	testCases := []struct {
		name     string
		config   oauth2.Configurator
		expected bool
	}{
		{name: "ShouldHandleWithTheConfig", config: &oauth2.Config{GrantManagement: config}, expected: true},
		{name: "ShouldNotHandleWithoutTheConfig", config: &oauth2.Config{}},
		{name: "ShouldNotHandleWhenTheConfiguratorIsNotAProvider", config: struct{ oauth2.Configurator }{&oauth2.Config{GrantManagement: config}}},
		{name: "ShouldNotHandleWithoutAConfigurator"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			handler := &Handler{Config: tc.config}

			assert.Equal(t, tc.expected, handler.HandlesGrantManagement(t.Context()))
		})
	}
}

type failingStorage struct {
	oauth2.GrantManagementStorage
}

func (failingStorage) GetGrant(_ context.Context, _ string) (grant *oauth2.Grant, err error) {
	return nil, errors.New("storage is unavailable")
}

func newGrantStore(t *testing.T) *storage.MemoryStore {
	t.Helper()

	store := storage.NewMemoryStore()

	require.NoError(t, store.CreateGrant(t.Context(), &oauth2.Grant{ID: "own", ClientID: "client", Subject: "peter"}))
	require.NoError(t, store.CreateGrant(t.Context(), &oauth2.Grant{ID: "other", ClientID: "another", Subject: "peter"}))
	require.NoError(t, store.CreateGrant(t.Context(), &oauth2.Grant{ID: "expired", ClientID: "client", Subject: "peter", ExpiresAt: time.Now().UTC().Add(-time.Minute)}))
	require.NoError(t, store.CreateGrant(t.Context(), &oauth2.Grant{ID: "future", ClientID: "client", Subject: "peter", ExpiresAt: time.Now().UTC().Add(time.Hour)}))

	return store
}
