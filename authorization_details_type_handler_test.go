// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
)

func TestDefaultAuthorizationDetailsTypeHandlerValidate(t *testing.T) {
	errSchema := errors.New("schema")

	testCases := []struct {
		name    string
		handler *oauth2.DefaultAuthorizationDetailsTypeHandler
		detail  oauth2.AuthorizationDetail
		err     string
	}{
		{name: "ShouldAcceptAnythingWhenUnrestricted", handler: &oauth2.DefaultAuthorizationDetailsTypeHandler{}, detail: oauth2.AuthorizationDetail{Actions: []string{testRARActionWrite}, Privileges: []string{testRARPrivilegeAdmin}, Extra: map[string]any{testRARMemberCustom: true}}},
		{name: "ShouldAcceptPermittedValues", handler: newDefaultRARTypeHandler(), detail: oauth2.AuthorizationDetail{Locations: []string{testRARLocationA}, Actions: []string{testRARActionRead}, Extra: map[string]any{testRARMemberCreditorName: testRARCreditorName}}},
		{name: "ShouldRejectAnAction", handler: newDefaultRARTypeHandler(), detail: oauth2.AuthorizationDetail{Locations: []string{testRARLocationA}, Actions: []string{testRARActionWrite}}, err: "the 'actions' value 'write' is not permitted"},
		{name: "ShouldRejectALocation", handler: newDefaultRARTypeHandler(), detail: oauth2.AuthorizationDetail{Locations: []string{testRARLocationB}, Actions: []string{testRARActionRead}}, err: "the 'locations' value 'https://b.example.com' is not permitted"},
		{name: "ShouldRejectEveryValueOfAnEmptyList", handler: newDefaultRARTypeHandler(), detail: oauth2.AuthorizationDetail{Locations: []string{testRARLocationA}, Actions: []string{testRARActionRead}, Privileges: []string{testRARPrivilegeAdmin}}, err: testRARErrPrivilegeNotPermitted},
		{name: "ShouldRejectAMember", handler: newDefaultRARTypeHandler(), detail: oauth2.AuthorizationDetail{Locations: []string{testRARLocationA}, Actions: []string{testRARActionRead}, Extra: map[string]any{testRARMemberCustom: true}}, err: "the 'custom' member is not permitted"},
		{name: "ShouldRequireACommonField", handler: newDefaultRARTypeHandler(), detail: oauth2.AuthorizationDetail{Locations: []string{testRARLocationA}}, err: "the 'actions' member is required"},
		{name: "ShouldRequireAMember", handler: &oauth2.DefaultAuthorizationDetailsTypeHandler{Required: []string{testRARMemberCreditorName}}, detail: oauth2.AuthorizationDetail{}, err: "the 'creditorName' member is required"},
		{name: "ShouldRequireAnIdentifier", handler: &oauth2.DefaultAuthorizationDetailsTypeHandler{Required: []string{"identifier"}}, detail: oauth2.AuthorizationDetail{}, err: "the 'identifier' member is required"},
		{name: "ShouldReturnTheValidatorError", handler: &oauth2.DefaultAuthorizationDetailsTypeHandler{Validator: func(context.Context, oauth2.Requester, oauth2.AuthorizationDetail) error { return errSchema }}, detail: oauth2.AuthorizationDetail{}, err: "schema"},
		{name: "ShouldNotCallTheValidatorForARejectedDetail", handler: &oauth2.DefaultAuthorizationDetailsTypeHandler{Actions: []string{}, Validator: func(context.Context, oauth2.Requester, oauth2.AuthorizationDetail) error { return errSchema }}, detail: oauth2.AuthorizationDetail{Actions: []string{testRARActionRead}}, err: "the 'actions' value 'read' is not permitted"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.handler.Validate(context.Background(), &oauth2.Request{}, tc.detail)

			if tc.err == "" {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, tc.err)
			}
		})
	}
}

func TestDefaultAuthorizationDetailsTypeHandlerAssign(t *testing.T) {
	identifier, other := testRARIdentifierOther, "acct-1"

	granted := oauth2.AuthorizationDetails{
		{Type: testRARTypeOther, Locations: []string{testRARLocationA}, Actions: []string{testRARActionRead, testRARActionWrite}, Identifier: &identifier, Extra: map[string]any{testRARMemberCreditorName: testRARCreditorName}},
		{Type: testRARTypeOther, Locations: []string{testRARLocationA}, Actions: []string{testRARActionRead}},
	}

	testCases := []struct {
		name      string
		requested oauth2.AuthorizationDetails
		expected  oauth2.AuthorizationDetails
		err       string
	}{
		{name: "ShouldAssignEveryGrantedDetailWithoutARequest", expected: granted},
		{name: "ShouldNarrowTheActions", requested: oauth2.AuthorizationDetails{{Type: testRARTypeOther, Actions: []string{testRARActionWrite}}}, expected: oauth2.AuthorizationDetails{{Type: testRARTypeOther, Locations: []string{testRARLocationA}, Actions: []string{testRARActionWrite}, Identifier: &identifier, Extra: map[string]any{testRARMemberCreditorName: testRARCreditorName}}}},
		{name: "ShouldMatchEachRequestToADistinctGrant", requested: oauth2.AuthorizationDetails{{Type: testRARTypeOther, Actions: []string{testRARActionRead}}, {Type: testRARTypeOther, Actions: []string{testRARActionRead}}}, expected: oauth2.AuthorizationDetails{{Type: testRARTypeOther, Locations: []string{testRARLocationA}, Actions: []string{testRARActionRead}, Identifier: &identifier, Extra: map[string]any{testRARMemberCreditorName: testRARCreditorName}}, {Type: testRARTypeOther, Locations: []string{testRARLocationA}, Actions: []string{testRARActionRead}}}},
		{name: "ShouldSelectByIdentifier", requested: oauth2.AuthorizationDetails{{Type: testRARTypeOther, Identifier: &identifier}}, expected: oauth2.AuthorizationDetails{granted[0]}},
		{name: "ShouldSelectByMember", requested: oauth2.AuthorizationDetails{{Type: testRARTypeOther, Extra: map[string]any{testRARMemberCreditorName: testRARCreditorName}}}, expected: oauth2.AuthorizationDetails{granted[0]}},
		{name: "ShouldRejectAnUngrantedAction", requested: oauth2.AuthorizationDetails{{Type: testRARTypeOther, Locations: []string{testRARLocationA}, Actions: []string{testRARActionStatus}}}, err: testRARErrNotContained},
		{name: "ShouldRejectAnotherIdentifier", requested: oauth2.AuthorizationDetails{{Type: testRARTypeOther, Identifier: &other}}, err: testRARErrNotContained},
		{name: "ShouldRejectAnotherMemberValue", requested: oauth2.AuthorizationDetails{{Type: testRARTypeOther, Extra: map[string]any{testRARMemberCreditorName: testRARValueChanged}}}, err: testRARErrNotContained},
		{name: "ShouldRejectMoreRequestsThanGrants", requested: oauth2.AuthorizationDetails{{Type: testRARTypeOther}, {Type: testRARTypeOther}, {Type: testRARTypeOther}}, err: testRARErrNotContained},
		{name: "ShouldRejectAValueThatIsNotPermitted", requested: oauth2.AuthorizationDetails{{Type: testRARTypeOther, Privileges: []string{testRARPrivilegeAdmin}}}, err: testRARErrPrivilegeNotPermitted},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			handler := &oauth2.DefaultAuthorizationDetailsTypeHandler{Name: testRARTypeOther, Privileges: []string{}}

			actual, err := handler.Assign(context.Background(), &oauth2.AccessRequest{}, granted, tc.requested)

			if tc.err != "" {
				assert.EqualError(t, err, tc.err)
				assert.Nil(t, actual)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.expected, actual)
		})
	}
}

func TestDefaultAuthorizationDetailsTypeHandlerDisclose(t *testing.T) {
	a := oauth2.AuthorizationDetail{Type: testRARTypeOther, Locations: []string{testRARLocationA}}
	b := oauth2.AuthorizationDetail{Type: testRARTypeOther, Locations: []string{testRARLocationB}}
	ab := oauth2.AuthorizationDetail{Type: testRARTypeOther, Locations: []string{testRARLocationA, testRARLocationB}}
	anywhere := oauth2.AuthorizationDetail{Type: testRARTypeOther, Actions: []string{testRARActionRead}}
	details := oauth2.AuthorizationDetails{a, b, ab, anywhere}

	testCases := []struct {
		name      string
		limit     bool
		recipient oauth2.AuthorizationDetailsRecipient
		expected  oauth2.AuthorizationDetails
	}{
		{name: "ShouldDiscloseEveryDetailUnlessLimited", recipient: oauth2.AuthorizationDetailsRecipient{Audience: []string{testRARLocationA}}, expected: details},
		{name: "ShouldDiscloseToTheAudience", limit: true, recipient: oauth2.AuthorizationDetailsRecipient{Audience: []string{testRARLocationA}}, expected: oauth2.AuthorizationDetails{a, ab, anywhere}},
		{name: "ShouldDiscloseOnlyDetailsLocatedAtEveryAudience", limit: true, recipient: oauth2.AuthorizationDetailsRecipient{Audience: []string{testRARLocationA, testRARLocationB}}, expected: oauth2.AuthorizationDetails{ab, anywhere}},
		{name: "ShouldDiscloseToTheClientIdentifier", limit: true, recipient: oauth2.AuthorizationDetailsRecipient{Client: &oauth2.DefaultClient{ID: testRARLocationB}}, expected: oauth2.AuthorizationDetails{b, ab, anywhere}},
		{name: "ShouldNotDiscloseToTheClientAudience", limit: true, recipient: oauth2.AuthorizationDetailsRecipient{Client: &oauth2.DefaultClient{ID: testRARClientID, Audience: []string{testRARLocationA, testRARLocationB}}}, expected: oauth2.AuthorizationDetails{anywhere}},
		{name: "ShouldDiscloseOnlyDetailsWithoutLocationsToAnUnknownRecipient", limit: true, recipient: oauth2.AuthorizationDetailsRecipient{}, expected: oauth2.AuthorizationDetails{anywhere}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			handler := &oauth2.DefaultAuthorizationDetailsTypeHandler{Name: testRARTypeOther, LimitDisclosure: tc.limit}

			actual, err := handler.Disclose(context.Background(), &oauth2.Request{}, tc.recipient, details)

			require.NoError(t, err)
			assert.Equal(t, tc.expected, actual)
		})
	}
}

func TestDefaultAuthorizationDetailsTypeHandlerErrors(t *testing.T) {
	config := &oauth2.Config{AuthorizationDetailsTypeHandlers: []oauth2.AuthorizationDetailsTypeHandler{newDefaultRARTypeHandler()}}
	request := &oauth2.AccessRequest{Request: oauth2.Request{Client: &oauth2.DefaultClient{}}}

	err := oauth2.ValidateAuthorizationDetails(context.Background(), config, request, oauth2.AuthorizationDetails{{Type: testRARTypeOther, Locations: []string{testRARLocationB}}})
	assert.ErrorIs(t, err, oauth2.ErrInvalidAuthorizationDetails)

	request.SetRequestedAuthorizationDetails(oauth2.AuthorizationDetails{{Type: testRARTypeOther, Actions: []string{testRARActionWrite}}})

	_, err = oauth2.AssignAuthorizationDetails(context.Background(), config, request, oauth2.AuthorizationDetails{{Type: testRARTypeOther, Actions: []string{testRARActionRead}}})
	assert.ErrorIs(t, err, oauth2.ErrInvalidAuthorizationDetails)
}

func newDefaultRARTypeHandler() *oauth2.DefaultAuthorizationDetailsTypeHandler {
	return &oauth2.DefaultAuthorizationDetailsTypeHandler{
		Name:       testRARTypeOther,
		Locations:  []string{testRARLocationA},
		Actions:    []string{testRARActionRead},
		Privileges: []string{},
		Members:    []string{testRARMemberCreditorName},
		Required:   []string{"locations", "actions"},
	}
}
