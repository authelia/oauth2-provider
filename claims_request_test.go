// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
)

func TestParseClaimsRequest(t *testing.T) {
	const (
		hintObject   = "The 'claims' parameter must be a JSON object."
		hintRepeated = "The 'claims' parameter must not be included more than once."
		hintIDToken  = "The 'claims' parameter member 'id_token' is malformed."
		hintUserInfo = "The 'claims' parameter member 'userinfo' is malformed."
	)

	testCases := []struct {
		name     string
		raw      []string
		expected *oauth2.ClaimsRequest
		hint     string
	}{
		{name: "ShouldReturnNilForAbsent"},
		{name: "ShouldReturnNilForEmpty", raw: []string{""}},
		{
			name: "ShouldParseSpecificationExample",
			raw: []string{`{
				"userinfo": {
					"given_name": {"essential": true},
					"nickname": null,
					"http://example.info/claims/groups": null
				},
				"id_token": {
					"auth_time": {"essential": true},
					"acr": {"values": ["urn:mace:incommon:iap:silver"]}
				}
			}`},
			expected: &oauth2.ClaimsRequest{
				UserInfo: map[string]*oauth2.ClaimRequest{
					"given_name":                        {Essential: true},
					"nickname":                          nil,
					"http://example.info/claims/groups": nil,
				},
				IDToken: map[string]*oauth2.ClaimRequest{
					"auth_time": {Essential: true},
					"acr":       {Values: []any{"urn:mace:incommon:iap:silver"}},
				},
			},
		},
		{
			name:     "ShouldParseValue",
			raw:      []string{`{"id_token":{"sub":{"value":"248289761001"}}}`},
			expected: &oauth2.ClaimsRequest{IDToken: map[string]*oauth2.ClaimRequest{"sub": {Value: "248289761001"}}},
		},
		{
			name:     "ShouldIgnoreUnknownMembers",
			raw:      []string{`{"verified_claims":{"x":1},"id_token":{"acr":{"essential":true,"purpose":"login"}}}`},
			expected: &oauth2.ClaimsRequest{IDToken: map[string]*oauth2.ClaimRequest{"acr": {Essential: true}}},
		},
		{
			name:     "ShouldKeepEmptyMemberDistinctFromAbsent",
			raw:      []string{`{"userinfo":{}}`},
			expected: &oauth2.ClaimsRequest{UserInfo: map[string]*oauth2.ClaimRequest{}},
		},
		{
			name:     "ShouldIgnoreMemberNamesOfDifferentCase",
			raw:      []string{`{"id_token":{"acr":{"ESSENTIAL":true,"Values":["gold"]}}}`},
			expected: &oauth2.ClaimsRequest{IDToken: map[string]*oauth2.ClaimRequest{"acr": {}}},
		},
		{
			name:     "ShouldTreatNullValueAsAbsent",
			raw:      []string{`{"id_token":{"acr":{"essential":true,"value":null}}}`},
			expected: &oauth2.ClaimsRequest{IDToken: map[string]*oauth2.ClaimRequest{"acr": {Essential: true}}},
		},
		{
			name:     "ShouldTreatNullEssentialAndValuesAsAbsent",
			raw:      []string{`{"id_token":{"acr":{"essential":null,"values":null}}}`},
			expected: &oauth2.ClaimsRequest{IDToken: map[string]*oauth2.ClaimRequest{"acr": {}}},
		},
		{
			name:     "ShouldParseNullClaimRequestAsNil",
			raw:      []string{`{"userinfo":{"email":null}}`},
			expected: &oauth2.ClaimsRequest{UserInfo: map[string]*oauth2.ClaimRequest{"email": nil}},
		},
		{name: "ShouldParseEmptyObject", raw: []string{`{}`}, expected: &oauth2.ClaimsRequest{}},
		{name: "ShouldRejectRepeated", raw: []string{`{}`, `{}`}, hint: hintRepeated},
		{name: "ShouldRejectNull", raw: []string{`null`}, hint: hintObject},
		{name: "ShouldRejectArray", raw: []string{`[]`}, hint: hintObject},
		{name: "ShouldRejectString", raw: []string{`"id_token"`}, hint: hintObject},
		{name: "ShouldRejectTruncated", raw: []string{`{"id_token":`}, hint: hintObject},
		{name: "ShouldRejectTrailingData", raw: []string{`{} {}`}, hint: hintObject},
		{name: "ShouldRejectNullIDToken", raw: []string{`{"id_token":null}`}, hint: hintIDToken},
		{name: "ShouldRejectArrayIDToken", raw: []string{`{"id_token":[]}`}, hint: hintIDToken},
		{name: "ShouldRejectNullUserInfo", raw: []string{`{"userinfo":null}`}, hint: hintUserInfo},
		{name: "ShouldRejectStringUserInfo", raw: []string{`{"userinfo":"email"}`}, hint: hintUserInfo},
		{name: "ShouldRejectBooleanClaimRequest", raw: []string{`{"id_token":{"acr":true}}`}, hint: hintIDToken},
		{name: "ShouldRejectArrayClaimRequest", raw: []string{`{"userinfo":{"email":[]}}`}, hint: hintUserInfo},
		{name: "ShouldRejectNonBooleanEssential", raw: []string{`{"id_token":{"acr":{"essential":"true"}}}`}, hint: hintIDToken},
		{name: "ShouldRejectNonArrayValues", raw: []string{`{"id_token":{"acr":{"values":"gold"}}}`}, hint: hintIDToken},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			form := url.Values{}

			if tc.raw != nil {
				form["claims"] = tc.raw
			}

			actual, err := oauth2.ParseClaimsRequest(form)

			if tc.hint != "" {
				require.Error(t, err)
				assert.ErrorIs(t, err, oauth2.ErrInvalidRequest)

				var rfc *oauth2.RFC6749Error

				require.ErrorAs(t, err, &rfc)
				assert.Equal(t, tc.hint, rfc.HintField)
				assert.Nil(t, actual)

				return
			}

			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
			assert.Equal(t, tc.expected, actual)
		})
	}
}

func TestClaimRequestMatches(t *testing.T) {
	testCases := []struct {
		name     string
		request  *oauth2.ClaimRequest
		value    any
		expected bool
	}{
		{name: "ShouldMatchAnythingWhenNil", request: nil, value: "x", expected: true},
		{name: "ShouldMatchAnythingWithoutValues", request: &oauth2.ClaimRequest{Essential: true}, value: "x", expected: true},
		{name: "ShouldMatchValue", request: &oauth2.ClaimRequest{Value: "gold"}, value: "gold", expected: true},
		{name: "ShouldNotMatchDifferentValue", request: &oauth2.ClaimRequest{Value: "gold"}, value: "silver"},
		{name: "ShouldNotMatchEmptyString", request: &oauth2.ClaimRequest{Value: "gold"}, value: ""},
		{name: "ShouldMatchOneOfValues", request: &oauth2.ClaimRequest{Values: []any{"gold", "silver"}}, value: "silver", expected: true},
		{name: "ShouldNotMatchOutsideValues", request: &oauth2.ClaimRequest{Values: []any{"gold", "silver"}}, value: "bronze"},
		{name: "ShouldMatchNumberAgainstInt64", request: &oauth2.ClaimRequest{Value: float64(5)}, value: int64(5), expected: true},
		{name: "ShouldMatchNumberAgainstJSONNumber", request: &oauth2.ClaimRequest{Value: float64(5)}, value: json.Number("5"), expected: true},
		{name: "ShouldNotMatchNumberAgainstString", request: &oauth2.ClaimRequest{Value: float64(5)}, value: "5"},
		{name: "ShouldMatchBoolean", request: &oauth2.ClaimRequest{Value: true}, value: true, expected: true},
		{name: "ShouldMatchArrayDeeply", request: &oauth2.ClaimRequest{Value: []any{"a", "b"}}, value: []any{"a", "b"}, expected: true},
		{name: "ShouldNotMatchNilValue", request: &oauth2.ClaimRequest{Value: "gold"}, value: nil},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.request.Matches(tc.value))
		})
	}
}

func TestClaimRequestHasValues(t *testing.T) {
	var absent *oauth2.ClaimRequest

	assert.False(t, absent.HasValues())
	assert.False(t, (&oauth2.ClaimRequest{Essential: true}).HasValues())
	assert.False(t, (&oauth2.ClaimRequest{Values: []any{}}).HasValues())
	assert.False(t, (&oauth2.ClaimRequest{Essential: true, Value: nil}).HasValues())
	assert.True(t, (&oauth2.ClaimRequest{Value: "a"}).HasValues())
	assert.True(t, (&oauth2.ClaimRequest{Values: []any{"a"}}).HasValues())
}

func TestClaimsRequestClone(t *testing.T) {
	var absent *oauth2.ClaimsRequest

	assert.Nil(t, absent.Clone())

	original := &oauth2.ClaimsRequest{
		IDToken: map[string]*oauth2.ClaimRequest{
			"acr":       {Essential: true, Values: []any{"gold"}},
			"auth_time": nil,
			"address":   {Value: map[string]any{"country": "AU"}},
		},
		UserInfo: map[string]*oauth2.ClaimRequest{},
	}

	clone := original.Clone()

	require.Equal(t, original, clone)
	assert.NotNil(t, clone.UserInfo)

	clone.IDToken["acr"].Values[0] = "silver"
	clone.IDToken["acr"].Essential = false
	clone.IDToken["address"].Value.(map[string]any)["country"] = "NZ"
	clone.IDToken["email"] = nil

	assert.Equal(t, "gold", original.IDToken["acr"].Values[0])
	assert.True(t, original.IDToken["acr"].Essential)
	assert.Equal(t, "AU", original.IDToken["address"].Value.(map[string]any)["country"])
	assert.NotContains(t, original.IDToken, "email")
}

type claimsMaxLengthProvider int

func (p claimsMaxLengthProvider) GetClaimsParameterMaxLength(_ context.Context) int { return int(p) }

func TestParseRequestedClaims(t *testing.T) {
	const hint = "The 'claims' parameter must not be longer than %d bytes."

	// padded returns a valid claims parameter of exactly n bytes.
	padded := func(n int) string {
		base := `{"id_token":{"` + `":null}}`
		return `{"id_token":{"` + strings.Repeat("a", n-len(base)) + `":null}}`
	}

	testCases := []struct {
		name     string
		config   any
		raw      []string
		maximum  int
		rejected bool
	}{
		{name: "ShouldAcceptDefaultLength", config: &oauth2.Config{}, raw: []string{padded(8192)}, maximum: 8192},
		{name: "ShouldRejectOneByteOverDefault", config: &oauth2.Config{}, raw: []string{padded(8193)}, maximum: 8192, rejected: true},
		{name: "ShouldRejectAnyValueOverDefault", config: &oauth2.Config{}, raw: []string{`{}`, padded(8193)}, maximum: 8192, rejected: true},
		{name: "ShouldAcceptConfiguredLength", config: &oauth2.Config{ClaimsParameterMaxLength: 16}, raw: []string{`{"id_token":{}}`}, maximum: 16},
		{name: "ShouldRejectOverConfiguredLength", config: &oauth2.Config{ClaimsParameterMaxLength: 16}, raw: []string{`{"id_token":{} }`, `{"id_token":{}  }`}, maximum: 16, rejected: true},
		{name: "ShouldRejectSeventeenBytes", config: &oauth2.Config{ClaimsParameterMaxLength: 16}, raw: []string{`{"id_token":  {}}`}, maximum: 16, rejected: true},
		{name: "ShouldSelectDefaultForZero", config: &oauth2.Config{ClaimsParameterMaxLength: 0}, raw: []string{padded(8193)}, maximum: 8192, rejected: true},
		{name: "ShouldSelectDefaultForNegative", config: claimsMaxLengthProvider(-1), raw: []string{padded(8192)}, maximum: 8192},
		{name: "ShouldSelectDefaultWithoutProvider", config: struct{}{}, raw: []string{padded(8193)}, maximum: 8192, rejected: true},
		{name: "ShouldAcceptWithoutProvider", config: struct{}{}, raw: []string{padded(8192)}, maximum: 8192},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.maximum, oauth2.GetClaimsParameterMaxLength(context.Background(), tc.config))

			claims, err := oauth2.ParseRequestedClaims(context.Background(), tc.config, url.Values{"claims": tc.raw})

			if tc.rejected {
				require.Error(t, err)
				assert.ErrorIs(t, err, oauth2.ErrInvalidRequest)

				var rfc *oauth2.RFC6749Error

				require.ErrorAs(t, err, &rfc)
				assert.Equal(t, fmt.Sprintf(hint, tc.maximum), rfc.HintField)
				assert.Nil(t, claims)

				return
			}

			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
			assert.NotNil(t, claims)
		})
	}
}
