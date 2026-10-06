// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal"
)

func TestParseAuthorizationDetails(t *testing.T) {
	testCases := []struct {
		name     string
		raw      string
		expected oauth2.AuthorizationDetails
		err      string
	}{
		{name: "ShouldReturnNilForAbsent", raw: ""},
		{name: "ShouldRejectNull", raw: testRARNullJSON, err: testRARHintNotArray},
		{name: "ShouldRejectString", raw: `"payment_initiation"`, err: testRARHintNotArray},
		{name: "ShouldRejectObject", raw: `{"type":"a"}`, err: testRARHintNotArray},
		{name: "ShouldRejectTruncated", raw: `[{"type":`, err: testRARHintNotArray},
		{name: "ShouldRejectEmptyArray", raw: `[]`, err: "The 'authorization_details' parameter must contain at least one authorization details object."},
		{name: "ShouldRejectNonObjectElement", raw: `["a"]`, err: testRARHintNotObject},
		{name: "ShouldRejectNullElement", raw: `[null]`, err: testRARHintNotObject},
		{name: "ShouldRejectMissingType", raw: `[{"actions":["read"]}]`, err: testRARHintMissingType},
		{name: "ShouldRejectEmptyType", raw: `[{"type":""}]`, err: testRARHintMissingType},
		{name: "ShouldRejectNonStringType", raw: `[{"type":1}]`, err: "The 'authorization_details' parameter element at index 0 is malformed."},
		{name: "ShouldRejectNullType", raw: `[{"type":null}]`, err: "The 'authorization_details' parameter element at index 0 member 'type' must not be null."},
		{name: "ShouldRejectNullLocations", raw: `[{"type":"a","locations":null}]`, err: "The 'authorization_details' parameter element at index 0 member 'locations' must not be null."},
		{name: "ShouldRejectNullActions", raw: `[{"type":"a"},{"type":"b","actions":null}]`, err: "The 'authorization_details' parameter element at index 1 member 'actions' must not be null."},
		{name: "ShouldRejectNullDataTypes", raw: `[{"type":"a","datatypes":null}]`, err: "The 'authorization_details' parameter element at index 0 member 'datatypes' must not be null."},
		{name: "ShouldRejectNullIdentifier", raw: `[{"type":"a","identifier":null}]`, err: "The 'authorization_details' parameter element at index 0 member 'identifier' must not be null."},
		{name: "ShouldRejectNullPrivileges", raw: `[{"type":"a","privileges":null}]`, err: testRARHintNullPrivileges},
		{name: "ShouldRejectNullPrivilegesWithWhitespace", raw: `[{"type":"a","privileges": null }]`, err: testRARHintNullPrivileges},
		{name: "ShouldRejectNullLocationsElement", raw: `[{"type":"a","locations":[null]}]`, err: "The 'authorization_details' parameter element at index 0 member 'locations' must not contain null."},
		{name: "ShouldRejectNullActionsElement", raw: `[{"type":"a"},{"type":"b","actions":["read",null]}]`, err: "The 'authorization_details' parameter element at index 1 member 'actions' must not contain null."},
		{name: "ShouldRejectNullDataTypesElement", raw: `[{"type":"a","datatypes":[null,"x"]}]`, err: "The 'authorization_details' parameter element at index 0 member 'datatypes' must not contain null."},
		{name: "ShouldRejectNullPrivilegesElement", raw: `[{"type":"a","privileges":[null]}]`, err: "The 'authorization_details' parameter element at index 0 member 'privileges' must not contain null."},
		{name: "ShouldAcceptNullExtraMember", raw: `[{"type":"a","custom":null}]`, expected: oauth2.AuthorizationDetails{{Type: "a", Extra: map[string]any{testRARMemberCustom: nil}}}},
		{name: "ShouldRejectWrongCommonMemberType", raw: `[{"type":"a"},{"type":"b","actions":"read"}]`, err: "The 'authorization_details' parameter element at index 1 is malformed."},
		{
			name: "ShouldParseCommonAndExtraMembers",
			raw:  `[{"type":"payment_initiation","locations":["https://example.com/payments"],"actions":["initiate"],"datatypes":["x"],"identifier":"id-1","privileges":["p"],"creditorName":"Merchant A","instructedAmount":{"currency":"EUR","amount":"123.50"}}]`,
			expected: oauth2.AuthorizationDetails{{
				Type:       internal.AuthorizationDetailsTypePaymentInitiation,
				Locations:  []string{"https://example.com/payments"},
				Actions:    []string{testRARActionInitiate},
				DataTypes:  []string{"x"},
				Identifier: new("id-1"),
				Privileges: []string{"p"},
				Extra: map[string]any{
					testRARMemberCreditorName: testRARCreditorName,
					"instructedAmount":        map[string]any{"currency": "EUR", "amount": "123.50"},
				},
			}},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual, err := oauth2.ParseAuthorizationDetails(tc.raw)

			if tc.err != "" {
				require.Error(t, err)
				assert.ErrorIs(t, err, oauth2.ErrInvalidAuthorizationDetails)
				assert.Equal(t, tc.err, oauth2.ErrorToRFC6749Error(err).HintField)
				assert.Nil(t, actual)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.expected, actual)
		})
	}
}

func TestAuthorizationDetailsJSONRoundTrip(t *testing.T) {
	raw := `[{"type":"payment_initiation","actions":["initiate"],"amount":12345678901234567890,"nested":{"list":[1,"a",true]}}]`

	details, err := oauth2.ParseAuthorizationDetails(raw)
	require.NoError(t, err)

	encoded, err := json.Marshal(details)
	require.NoError(t, err)

	assert.JSONEq(t, raw, string(encoded))
	assert.Contains(t, string(encoded), "12345678901234567890")
}

func TestAuthorizationDetailsJSONRoundTripPresence(t *testing.T) {
	testCases := []struct {
		name string
		raw  string
	}{
		{name: "ShouldKeepAbsentCommonMembersAbsent", raw: `[{"type":"t"}]`},
		{name: "ShouldKeepEmptyCommonMembers", raw: `[{"type":"t","actions":["read"],"locations":[],"datatypes":[],"privileges":[],"identifier":""}]`},
		{name: "ShouldKeepEmptyActions", raw: `[{"type":"t","actions":[]}]`},
		{name: "ShouldKeepEmptyIdentifier", raw: `[{"type":"t","identifier":""}]`},
		{name: "ShouldKeepPopulatedCommonMembers", raw: `[{"type":"t","actions":["read"],"locations":["https://a.example.com"],"datatypes":["x"],"privileges":["p"],"identifier":"id-1"}]`},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			details, err := oauth2.ParseAuthorizationDetails(tc.raw)
			require.NoError(t, err)

			encoded, err := json.Marshal(details)
			require.NoError(t, err)

			assert.JSONEq(t, tc.raw, string(encoded))

			encoded, err = json.Marshal(details.Clone())
			require.NoError(t, err)

			assert.JSONEq(t, tc.raw, string(encoded))

			reparsed, err := oauth2.ParseAuthorizationDetails(string(encoded))
			require.NoError(t, err)

			assert.Equal(t, details, reparsed)
		})
	}
}

func TestAuthorizationDetailMarshalCommonFieldsWinOverExtra(t *testing.T) {
	detail := oauth2.AuthorizationDetail{
		Type:  "a",
		Extra: map[string]any{testRARMemberType: "b", testRARMemberActions: []string{"x"}, testRARMemberCustom: 1},
	}

	encoded, err := json.Marshal(detail)
	require.NoError(t, err)

	assert.JSONEq(t, `{"type":"a","custom":1}`, string(encoded))
}

func TestAuthorizationDetailsClone(t *testing.T) {
	assert.Nil(t, oauth2.AuthorizationDetails(nil).Clone())

	original := oauth2.AuthorizationDetails{{
		Type:       "a",
		Actions:    []string{testRARActionRead},
		Locations:  []string{},
		Identifier: new(testRARIdentifierOther),
		Extra:      map[string]any{"nested": map[string]any{"k": "v"}},
	}}

	clone := original.Clone()
	require.Equal(t, original, clone)
	assert.NotNil(t, clone[0].Locations)
	assert.Nil(t, clone[0].DataTypes)

	*clone[0].Identifier = testRARValueChanged
	clone[0].Actions[0] = testRARActionWrite
	clone[0].Extra["nested"].(map[string]any)["k"] = testRARValueChanged

	assert.Equal(t, testRARActionRead, original[0].Actions[0])
	assert.Equal(t, testRARIdentifierOther, *original[0].Identifier)
	assert.Equal(t, "v", original[0].Extra["nested"].(map[string]any)["k"])
}

func TestParseRequestedAuthorizationDetails(t *testing.T) {
	testCases := []struct {
		name     string
		config   any
		client   oauth2.Client
		raw      string
		expected oauth2.AuthorizationDetails
		hint     string
	}{
		{name: "ShouldIgnoreWhenNoHandlers", config: &oauth2.Config{}, client: &oauth2.DefaultClient{}, raw: testRARMalformedJSON},
		{name: "ShouldIgnoreWhenConfigLacksProvider", config: struct{}{}, client: &oauth2.DefaultClient{}, raw: testRARMalformedJSON},
		{name: "ShouldReturnNilWhenAbsent", config: newRARConfig(), client: &oauth2.DefaultClient{}, raw: ""},
		{name: "ShouldAccept", config: newRARConfig(), client: &oauth2.DefaultClient{}, raw: testRARDetailsJSON, expected: oauth2.AuthorizationDetails{{Type: internal.AuthorizationDetailsTypePaymentInitiation, Actions: []string{testRARActionInitiate}}}},
		{name: "ShouldRejectNonArray", config: newRARConfig(), client: &oauth2.DefaultClient{}, raw: testRARNullJSON, hint: testRARHintNotArray},
		{name: "ShouldRejectUnsupportedType", config: newRARConfig(), client: &oauth2.DefaultClient{}, raw: `[{"type":"account_information"}]`, hint: "The authorization details type 'account_information' is not supported."},
		{name: "ShouldRejectTypeNotAllowedForClient", config: newRARConfig(), client: &internal.AuthorizationDetailsClient{DefaultClient: &oauth2.DefaultClient{}, AuthorizationDetailsTypes: []string{testRARTypeOther}}, raw: testRARDetailsJSON, hint: testRARHintTypeNotAllowed},
		{name: "ShouldRejectEveryTypeForClientWithEmptyAllowList", config: newRARConfig(), client: &internal.AuthorizationDetailsClient{DefaultClient: &oauth2.DefaultClient{}, AuthorizationDetailsTypes: []string{}}, raw: testRARDetailsJSON, hint: testRARHintTypeNotAllowed},
		{name: "ShouldAcceptEveryTypeForClientWithNilAllowList", config: newRARConfig(), client: &internal.AuthorizationDetailsClient{DefaultClient: &oauth2.DefaultClient{}}, raw: testRARDetailsJSON, expected: oauth2.AuthorizationDetails{{Type: internal.AuthorizationDetailsTypePaymentInitiation, Actions: []string{testRARActionInitiate}}}},
		{name: "ShouldAcceptTypeAllowedForClient", config: newRARConfig(), client: &internal.AuthorizationDetailsClient{DefaultClient: &oauth2.DefaultClient{}, AuthorizationDetailsTypes: []string{internal.AuthorizationDetailsTypePaymentInitiation}}, raw: testRARDetailsJSON, expected: oauth2.AuthorizationDetails{{Type: internal.AuthorizationDetailsTypePaymentInitiation, Actions: []string{testRARActionInitiate}}}},
		{name: "ShouldAcceptDefaultMaximum", config: newRARConfig(), client: &oauth2.DefaultClient{}, raw: newRARDetailsJSON(32), expected: newRARDetails(32)},
		{name: "ShouldRejectOverDefaultMaximum", config: newRARConfig(), client: &oauth2.DefaultClient{}, raw: newRARDetailsJSON(33), hint: testRARHintMaxObjectsDefault},
		{name: "ShouldAcceptConfiguredMaximum", config: &oauth2.Config{AuthorizationDetailsTypeHandlers: newRARConfig().AuthorizationDetailsTypeHandlers, AuthorizationDetailsMaxObjects: 2}, client: &oauth2.DefaultClient{}, raw: newRARDetailsJSON(2), expected: newRARDetails(2)},
		{name: "ShouldRejectOverConfiguredMaximum", config: &oauth2.Config{AuthorizationDetailsTypeHandlers: newRARConfig().AuthorizationDetailsTypeHandlers, AuthorizationDetailsMaxObjects: 2}, client: &oauth2.DefaultClient{}, raw: newRARDetailsJSON(3), hint: "The 'authorization_details' parameter must not contain more than 2 authorization details objects."},
		{name: "ShouldNotCallValidate", config: newRARConfig(), client: &oauth2.DefaultClient{}, raw: `[{"type":"payment_initiation"}]`, expected: oauth2.AuthorizationDetails{{Type: internal.AuthorizationDetailsTypePaymentInitiation}}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual, err := oauth2.ParseRequestedAuthorizationDetails(context.Background(), tc.config, tc.client, url.Values{"authorization_details": {tc.raw}})

			if tc.hint != "" {
				require.Error(t, err)
				assert.ErrorIs(t, err, oauth2.ErrInvalidAuthorizationDetails)
				assert.Equal(t, tc.hint, oauth2.ErrorToRFC6749Error(err).HintField)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.expected, actual)
		})
	}
}

func TestGetAuthorizationDetailsMaxObjects(t *testing.T) {
	testCases := []struct {
		name     string
		config   any
		expected int
	}{
		{name: "ShouldDefaultWhenConfigLacksProvider", config: struct{}{}, expected: 32},
		{name: "ShouldDefaultWhenNil", config: nil, expected: 32},
		{name: "ShouldDefaultWhenUnset", config: &oauth2.Config{}, expected: 32},
		{name: "ShouldDefaultWhenNegative", config: &oauth2.Config{AuthorizationDetailsMaxObjects: -1}, expected: 32},
		{name: "ShouldUseConfigured", config: &oauth2.Config{AuthorizationDetailsMaxObjects: 5}, expected: 5},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, oauth2.GetAuthorizationDetailsMaxObjects(context.Background(), tc.config))
		})
	}
}

func TestValidateAuthorizationDetails(t *testing.T) {
	rejecting := &oauth2.Config{AuthorizationDetailsTypeHandlers: []oauth2.AuthorizationDetailsTypeHandler{rfcErrorTypeHandler{}}}

	testCases := []struct {
		name    string
		config  any
		client  oauth2.Client
		details oauth2.AuthorizationDetails
		hint    string
	}{
		{name: "ShouldAcceptEmpty", config: newRARConfig(), client: &oauth2.DefaultClient{}},
		{name: "ShouldAcceptConforming", config: newRARConfig(), client: &oauth2.DefaultClient{}, details: newRARDetails(1)},
		{name: "ShouldRejectTypeNotAllowedForClient", config: newRARConfig(), client: &internal.AuthorizationDetailsClient{DefaultClient: &oauth2.DefaultClient{}, AuthorizationDetailsTypes: []string{}}, details: newRARDetails(1), hint: testRARHintTypeNotAllowed},
		{name: "ShouldWrapHandlerError", config: newRARConfig(), client: &oauth2.DefaultClient{}, details: oauth2.AuthorizationDetails{{Type: internal.AuthorizationDetailsTypePaymentInitiation}}, hint: "The authorization details object of type 'payment_initiation' is invalid."},
		{name: "ShouldPreserveRFC6749Error", config: rejecting, client: &oauth2.DefaultClient{}, details: newRARDetails(1), hint: "custom hint"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := oauth2.ValidateAuthorizationDetails(context.Background(), tc.config, &oauth2.Request{Client: tc.client}, tc.details)

			if tc.hint == "" {
				assert.NoError(t, err)

				return
			}

			require.Error(t, err)
			assert.ErrorIs(t, err, oauth2.ErrInvalidAuthorizationDetails)
			assert.Equal(t, tc.hint, oauth2.ErrorToRFC6749Error(err).HintField)
		})
	}
}

func TestValidateAuthorizationDetailsTypes(t *testing.T) {
	details := oauth2.AuthorizationDetails{{Type: internal.AuthorizationDetailsTypePaymentInitiation}}
	rejecting := &oauth2.Config{AuthorizationDetailsTypeHandlers: []oauth2.AuthorizationDetailsTypeHandler{rfcErrorTypeHandler{}}}

	testCases := []struct {
		name    string
		config  any
		client  oauth2.Client
		details oauth2.AuthorizationDetails
		hint    string
	}{
		{name: "ShouldAcceptEmpty", config: &oauth2.Config{}, client: &oauth2.DefaultClient{}},
		{name: "ShouldNotCallValidate", config: rejecting, client: &oauth2.DefaultClient{}, details: details},
		{name: "ShouldAcceptNilAllowList", config: newRARConfig(), client: &internal.AuthorizationDetailsClient{DefaultClient: &oauth2.DefaultClient{}}, details: details},
		{name: "ShouldRejectEmptyAllowList", config: newRARConfig(), client: &internal.AuthorizationDetailsClient{DefaultClient: &oauth2.DefaultClient{}, AuthorizationDetailsTypes: []string{}}, details: details, hint: testRARHintTypeNotAllowed},
		{name: "ShouldRejectMissingHandler", config: &oauth2.Config{}, client: &oauth2.DefaultClient{}, details: details, hint: "The authorization details type 'payment_initiation' is not supported."},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := oauth2.ValidateAuthorizationDetailsTypes(context.Background(), tc.config, tc.client, tc.details)

			if tc.hint == "" {
				assert.NoError(t, err)

				return
			}

			require.Error(t, err)
			assert.ErrorIs(t, err, oauth2.ErrInvalidAuthorizationDetails)
			assert.Equal(t, tc.hint, oauth2.ErrorToRFC6749Error(err).HintField)
		})
	}
}

func TestAssignAuthorizationDetails(t *testing.T) {
	granted := oauth2.AuthorizationDetails{
		{Type: internal.AuthorizationDetailsTypePaymentInitiation, Actions: []string{testRARActionInitiate}, Locations: []string{testRARLocationA}},
		{Type: internal.AuthorizationDetailsTypePaymentInitiation, Actions: []string{testRARActionInitiate, testRARActionStatus}, Locations: []string{testRARLocationB}},
	}

	payment := oauth2.AuthorizationDetail{Type: internal.AuthorizationDetailsTypePaymentInitiation, Actions: []string{testRARActionInitiate}, Extra: map[string]any{testRARMemberCreditorName: testRARCreditorName}}
	initiate := oauth2.AuthorizationDetail{Type: internal.AuthorizationDetailsTypePaymentInitiation, Actions: []string{testRARActionInitiate}}
	statusB := oauth2.AuthorizationDetail{Type: internal.AuthorizationDetailsTypePaymentInitiation, Actions: []string{testRARActionStatus}, Locations: []string{testRARLocationB}}
	locationB := oauth2.AuthorizationDetail{Type: internal.AuthorizationDetailsTypePaymentInitiation, Locations: []string{testRARLocationB}}

	testCases := []struct {
		name      string
		config    any
		client    oauth2.Client
		granted   oauth2.AuthorizationDetails
		requested oauth2.AuthorizationDetails
		expected  oauth2.AuthorizationDetails
		hint      string
	}{
		{name: "ShouldAssignNoneWhenNoneGranted", granted: oauth2.AuthorizationDetails{}},
		{name: "ShouldAssignGrantedWhenNoneRequested", expected: granted},
		{name: "ShouldAssignGrantedNarrowedToRequestedActions", requested: oauth2.AuthorizationDetails{statusB}, expected: oauth2.AuthorizationDetails{{Type: internal.AuthorizationDetailsTypePaymentInitiation, Actions: []string{testRARActionStatus}, Locations: []string{testRARLocationB}}}},
		{name: "ShouldAssignGrantedMembersOmittedFromRequested", requested: oauth2.AuthorizationDetails{locationB}, expected: oauth2.AuthorizationDetails{granted[1]}},
		{name: "ShouldAssignGrantedExtraOmittedFromRequested", granted: oauth2.AuthorizationDetails{payment}, requested: oauth2.AuthorizationDetails{initiate}, expected: oauth2.AuthorizationDetails{payment}},
		{name: "ShouldRejectExceedingAll", requested: oauth2.AuthorizationDetails{{Type: internal.AuthorizationDetailsTypePaymentInitiation, Actions: []string{"cancel"}}}, hint: testRARHintNotGranted},
		{name: "ShouldRejectMalformedRequested", requested: oauth2.AuthorizationDetails{{Type: internal.AuthorizationDetailsTypePaymentInitiation, Extra: map[string]any{"unknown": true}}}, hint: testRARHintNotGranted},
		{name: "ShouldRejectRequestedWhenNoneGranted", granted: oauth2.AuthorizationDetails{}, requested: oauth2.AuthorizationDetails{initiate}, hint: testRARHintNotGranted},
		{name: "ShouldRejectUnregisteredRequestedType", requested: oauth2.AuthorizationDetails{{Type: testRARTypeOther}}, hint: "The authorization details type 'other' is not supported."},
		{name: "ShouldRejectUnregisteredGrantedType", granted: oauth2.AuthorizationDetails{{Type: testRARTypeOther}}, hint: "The authorization details type 'other' is not supported."},
		{name: "ShouldRejectGrantedTypeNotAllowedForClient", client: &internal.AuthorizationDetailsClient{DefaultClient: &oauth2.DefaultClient{}, AuthorizationDetailsTypes: []string{}}, hint: testRARHintTypeNotAllowed},
		{name: "ShouldRejectRequestedTypeNotAllowedForClient", client: &internal.AuthorizationDetailsClient{DefaultClient: &oauth2.DefaultClient{}, AuthorizationDetailsTypes: []string{}}, requested: oauth2.AuthorizationDetails{initiate}, hint: testRARHintTypeNotAllowed},
		{name: "ShouldRejectOneGrantedForTwoRequested", granted: oauth2.AuthorizationDetails{payment}, requested: oauth2.AuthorizationDetails{payment, payment}, hint: testRARHintNotGranted},
		{name: "ShouldAssignTwoGrantedForTwoRequested", granted: oauth2.AuthorizationDetails{payment, payment}, requested: oauth2.AuthorizationDetails{payment, payment}, expected: oauth2.AuthorizationDetails{payment, payment}},
		{name: "ShouldRejectMoreRequestedThanGranted", requested: oauth2.AuthorizationDetails{initiate, initiate, initiate}, hint: testRARHintNotGranted},
		{name: "ShouldAssignWhenGreedyFirstFitFails", granted: oauth2.AuthorizationDetails{granted[1], granted[0]}, requested: oauth2.AuthorizationDetails{initiate, statusB}, expected: oauth2.AuthorizationDetails{{Type: internal.AuthorizationDetailsTypePaymentInitiation, Actions: []string{testRARActionInitiate}, Locations: []string{testRARLocationA}}, {Type: internal.AuthorizationDetailsTypePaymentInitiation, Actions: []string{testRARActionStatus}, Locations: []string{testRARLocationB}}}},
		{name: "ShouldRejectTwoRequestedOnlySecondContains", requested: oauth2.AuthorizationDetails{statusB, statusB}, hint: testRARHintNotGranted},
		{name: "ShouldPreserveRFC6749Error", config: &oauth2.Config{AuthorizationDetailsTypeHandlers: []oauth2.AuthorizationDetailsTypeHandler{rfcErrorTypeHandler{}}}, requested: oauth2.AuthorizationDetails{initiate}, hint: "custom hint"},
		{name: "ShouldRejectEmptyAssignmentForRequested", config: &oauth2.Config{AuthorizationDetailsTypeHandlers: []oauth2.AuthorizationDetailsTypeHandler{assigningTypeHandler{}}}, requested: oauth2.AuthorizationDetails{initiate}, hint: testRARHintNotGranted},
		{name: "ShouldAssignNoneWhenTypeAssignsNoneOfGranted", config: &oauth2.Config{AuthorizationDetailsTypeHandlers: []oauth2.AuthorizationDetailsTypeHandler{assigningTypeHandler{}}}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			g := granted

			if tc.granted != nil {
				g = tc.granted
			}

			var config any = newRARConfig()

			if tc.config != nil {
				config = tc.config
			}

			var client oauth2.Client = &oauth2.DefaultClient{}

			if tc.client != nil {
				client = tc.client
			}

			request := &oauth2.AccessRequest{Request: oauth2.Request{Client: client, RequestedAuthorizationDetails: tc.requested}}

			actual, err := oauth2.AssignAuthorizationDetails(context.Background(), config, request, g)

			if tc.hint == "" {
				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
				assert.Equal(t, tc.expected, actual)
				assert.Equal(t, tc.requested, request.GetRequestedAuthorizationDetails())

				return
			}

			require.Error(t, err)
			assert.True(t, errors.Is(err, oauth2.ErrInvalidAuthorizationDetails))
			assert.Equal(t, tc.hint, oauth2.ErrorToRFC6749Error(err).HintField)
		})
	}
}

func TestAssignAuthorizationDetailsRejectsAssignedTypeMismatch(t *testing.T) {
	config := &oauth2.Config{AuthorizationDetailsTypeHandlers: []oauth2.AuthorizationDetailsTypeHandler{assigningTypeHandler{assigned: oauth2.AuthorizationDetails{{Type: testRARTypeOther}}}}}

	_, err := oauth2.AssignAuthorizationDetails(context.Background(), config, &oauth2.AccessRequest{Request: oauth2.Request{Client: &oauth2.DefaultClient{}}}, newRARDetails(1))

	assert.ErrorIs(t, err, oauth2.ErrServerError)
}

func TestAssignAuthorizationDetailsRejectsWidenedMembers(t *testing.T) {
	granted := oauth2.AuthorizationDetails{
		{Type: internal.AuthorizationDetailsTypePaymentInitiation, Actions: []string{testRARActionInitiate}, Identifier: new("acct-1"), DataTypes: []string{testRARDataTypeBalance}, Privileges: []string{testRARActionRead}},
	}

	testCases := []struct {
		name      string
		requested oauth2.AuthorizationDetail
		contained bool
	}{
		{name: "ShouldAcceptEqual", requested: granted[0], contained: true},
		{name: "ShouldAcceptOmittedIdentifierAndSubsets", requested: oauth2.AuthorizationDetail{Type: internal.AuthorizationDetailsTypePaymentInitiation, Actions: []string{testRARActionInitiate}}, contained: true},
		{name: "ShouldRejectChangedIdentifier", requested: oauth2.AuthorizationDetail{Type: internal.AuthorizationDetailsTypePaymentInitiation, Actions: []string{testRARActionInitiate}, Identifier: new(testRARIdentifierOther)}},
		{name: "ShouldRejectAddedDataTypes", requested: oauth2.AuthorizationDetail{Type: internal.AuthorizationDetailsTypePaymentInitiation, Actions: []string{testRARActionInitiate}, DataTypes: []string{testRARDataTypeBalance, testRARDataTypeAll}}},
		{name: "ShouldRejectAddedPrivileges", requested: oauth2.AuthorizationDetail{Type: internal.AuthorizationDetailsTypePaymentInitiation, Actions: []string{testRARActionInitiate}, Privileges: []string{testRARPrivilegeAdmin}}},
		{name: "ShouldRejectAddedExtra", requested: oauth2.AuthorizationDetail{Type: internal.AuthorizationDetailsTypePaymentInitiation, Actions: []string{testRARActionInitiate}, Extra: map[string]any{testRARMemberCreditorName: testRARCreditorName}}},
		{name: "ShouldRejectReviewerRepro", requested: oauth2.AuthorizationDetail{Type: internal.AuthorizationDetailsTypePaymentInitiation, Actions: []string{testRARActionInitiate}, Identifier: new(testRARIdentifierOther), Privileges: []string{testRARPrivilegeAdmin}, DataTypes: []string{testRARDataTypeAll}}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			request := &oauth2.AccessRequest{Request: oauth2.Request{Client: &oauth2.DefaultClient{}, RequestedAuthorizationDetails: oauth2.AuthorizationDetails{tc.requested}}}

			actual, err := oauth2.AssignAuthorizationDetails(context.Background(), newRARConfig(), request, granted)

			if tc.contained {
				require.NoError(t, err)
				assert.Equal(t, granted, actual)

				return
			}

			require.Error(t, err)
			assert.True(t, errors.Is(err, oauth2.ErrInvalidAuthorizationDetails))
			assert.Equal(t, testRARHintNotGranted, oauth2.ErrorToRFC6749Error(err).HintField)
		})
	}
}

func TestMatchAuthorizationDetails(t *testing.T) {
	contains := func(granted, requested oauth2.AuthorizationDetail) bool {
		for _, action := range requested.Actions {
			if !slices.Contains(granted.Actions, action) {
				return false
			}
		}

		return true
	}

	detail := func(t string, actions ...string) oauth2.AuthorizationDetail {
		return oauth2.AuthorizationDetail{Type: t, Actions: actions}
	}

	testCases := []struct {
		name      string
		granted   oauth2.AuthorizationDetails
		requested oauth2.AuthorizationDetails
		expected  []int
		ok        bool
	}{
		{name: "ShouldMatchNoneRequested", granted: oauth2.AuthorizationDetails{detail("a", "x")}, expected: []int{}, ok: true},
		{name: "ShouldMatchContained", granted: oauth2.AuthorizationDetails{detail("a", "x"), detail("a", "y")}, requested: oauth2.AuthorizationDetails{detail("a", "y")}, expected: []int{1}, ok: true},
		{name: "ShouldMatchWhenGreedyFirstFitFails", granted: oauth2.AuthorizationDetails{detail("a", "x", "y"), detail("a", "x")}, requested: oauth2.AuthorizationDetails{detail("a", "x"), detail("a", "y")}, expected: []int{1, 0}, ok: true},
		{name: "ShouldNotMatchAnotherType", granted: oauth2.AuthorizationDetails{detail("b", "x")}, requested: oauth2.AuthorizationDetails{detail("a", "x")}},
		{name: "ShouldNotMatchOneGrantedTwice", granted: oauth2.AuthorizationDetails{detail("a", "x")}, requested: oauth2.AuthorizationDetails{detail("a", "x"), detail("a", "x")}},
		{name: "ShouldNotMatchUncontained", granted: oauth2.AuthorizationDetails{detail("a", "x")}, requested: oauth2.AuthorizationDetails{detail("a", "z")}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual, ok := oauth2.MatchAuthorizationDetails(tc.granted, tc.requested, contains)

			assert.Equal(t, tc.ok, ok)
			assert.Equal(t, tc.expected, actual)
		})
	}
}

func newRARDetailsJSON(n int) string {
	return "[" + strings.TrimSuffix(strings.Repeat(`{"type":"payment_initiation","actions":["initiate"]},`, n), ",") + "]"
}

func newRARDetails(n int) oauth2.AuthorizationDetails {
	details := make(oauth2.AuthorizationDetails, n)

	for i := range details {
		details[i] = oauth2.AuthorizationDetail{Type: internal.AuthorizationDetailsTypePaymentInitiation, Actions: []string{testRARActionInitiate}}
	}

	return details
}

func newRARConfig() *oauth2.Config {
	return &oauth2.Config{AuthorizationDetailsTypeHandlers: []oauth2.AuthorizationDetailsTypeHandler{internal.PaymentInitiationTypeHandler{}}}
}

type rfcErrorTypeHandler struct {
	internal.PaymentInitiationTypeHandler
}

func (rfcErrorTypeHandler) Validate(context.Context, oauth2.Requester, oauth2.AuthorizationDetail) error {
	return oauth2.ErrInvalidAuthorizationDetails.WithHint("custom hint")
}

func (rfcErrorTypeHandler) Assign(context.Context, oauth2.AccessRequester, oauth2.AuthorizationDetails, oauth2.AuthorizationDetails) (oauth2.AuthorizationDetails, error) {
	return nil, oauth2.ErrInvalidAuthorizationDetails.WithHint("custom hint")
}

type assigningTypeHandler struct {
	internal.PaymentInitiationTypeHandler

	assigned oauth2.AuthorizationDetails
}

func (h assigningTypeHandler) Assign(context.Context, oauth2.AccessRequester, oauth2.AuthorizationDetails, oauth2.AuthorizationDetails) (oauth2.AuthorizationDetails, error) {
	return h.assigned, nil
}
