// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
)

func TestClaimRequestMembers(t *testing.T) {
	const raw = `{"essential":true,"verification":{"trust_framework":null},"claims":{":adult":{"value":true},"given_name":null},"max_age":600,"purpose":"age check"}`

	request := &oauth2.ClaimRequest{}
	require.NoError(t, json.Unmarshal([]byte(raw), request))

	expected := &oauth2.ClaimRequest{
		Essential: true,
		Members: map[string]*oauth2.ClaimRequest{
			"verification": {Members: map[string]*oauth2.ClaimRequest{"trust_framework": nil}},
			"claims":       {Members: map[string]*oauth2.ClaimRequest{":adult": {Value: true}, "given_name": nil}},
		},
	}

	assert.Equal(t, expected, request)

	encoded, err := json.Marshal(request)
	require.NoError(t, err)

	assert.JSONEq(t, `{"essential":true,"verification":{"trust_framework":null},"claims":{":adult":{"value":true},"given_name":null}}`, string(encoded))

	decoded := &oauth2.ClaimRequest{}
	require.NoError(t, json.Unmarshal(encoded, decoded))
	assert.Equal(t, expected, decoded)
}

func TestClaimRequestIgnoresMalformedMembers(t *testing.T) {
	request := &oauth2.ClaimRequest{}
	require.NoError(t, json.Unmarshal([]byte(`{"good":{"essential":true},"bad":{"essential":"yes"},"list":[1],"none":null}`), request))

	assert.Equal(t, &oauth2.ClaimRequest{Members: map[string]*oauth2.ClaimRequest{"good": {Essential: true}, "none": nil}}, request)
}

func TestClaimRequestMarshalWithoutMembers(t *testing.T) {
	testCases := []struct {
		name     string
		request  *oauth2.ClaimRequest
		expected string
	}{
		{name: "ShouldEncodeNil", expected: `null`},
		{name: "ShouldEncodeEmpty", request: &oauth2.ClaimRequest{}, expected: `{}`},
		{name: "ShouldEncodeValues", request: &oauth2.ClaimRequest{Essential: true, Values: []any{"gold"}}, expected: `{"essential":true,"values":["gold"]}`},
		{name: "ShouldEncodeValue", request: &oauth2.ClaimRequest{Value: "peter"}, expected: `{"value":"peter"}`},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			encoded, err := json.Marshal(map[string]*oauth2.ClaimRequest{"claim": tc.request})
			require.NoError(t, err)

			assert.JSONEq(t, `{"claim":`+tc.expected+`}`, string(encoded))
		})
	}
}

func TestParseClaimsRequestDropsAdvancedSyntax(t *testing.T) {
	const raw = `{"id_token":{"verified_claims":{"claims":{":adult":null}}},"_asc":{"sao":{"id_token":[{"loc":"/email","else":"abort"}]}}}`

	claims, err := oauth2.ParseClaimsRequest(url.Values{"claims": {raw}})
	require.NoError(t, err)

	assert.Equal(t, &oauth2.ClaimsRequest{IDToken: map[string]*oauth2.ClaimRequest{"verified_claims": {}}}, claims)
	assert.False(t, claims.HasSelectiveAbortOmit())
}

func TestTransformedClaimFunctionJSON(t *testing.T) {
	testCases := []struct {
		name     string
		raw      string
		expected oauth2.TransformedClaimFunction
		encoded  string
		err      bool
	}{
		{name: "ShouldDecodeString", raw: `"years_ago"`, expected: oauth2.TransformedClaimFunction{Name: "years_ago"}, encoded: `"years_ago"`},
		{name: "ShouldDecodeArray", raw: `["gte",18]`, expected: oauth2.TransformedClaimFunction{Name: "gte", Args: []any{float64(18)}}, encoded: `["gte",18]`},
		{name: "ShouldDecodeArrayWithoutArguments", raw: `["any"]`, expected: oauth2.TransformedClaimFunction{Name: "any"}, encoded: `"any"`},
		{name: "ShouldRejectEmptyArray", raw: `[]`, err: true},
		{name: "ShouldRejectArrayWithoutName", raw: `[18,"gte"]`, err: true},
		{name: "ShouldRejectObject", raw: `{"name":"gte"}`, err: true},
		{name: "ShouldRejectNumber", raw: `18`, err: true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var actual oauth2.TransformedClaimFunction

			err := json.Unmarshal([]byte(tc.raw), &actual)

			if tc.err {
				require.Error(t, err)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.expected, actual)

			encoded, err := json.Marshal(actual)
			require.NoError(t, err)
			assert.JSONEq(t, tc.encoded, string(encoded))
		})
	}
}

func TestClaimsRequestASCJSONRoundTrip(t *testing.T) {
	claims := newTestClaimsRequestASC()

	encoded, err := json.Marshal(claims)
	require.NoError(t, err)

	decoded := &oauth2.ClaimsRequest{}
	require.NoError(t, json.Unmarshal(encoded, decoded))

	assert.Equal(t, claims, decoded)
	assert.True(t, decoded.HasSelectiveAbortOmit())
}

func TestClaimsRequestASCClone(t *testing.T) {
	claims := newTestClaimsRequestASC()
	clone := claims.Clone()

	require.Equal(t, claims, clone)

	clone.IDToken["verified_claims"].Members["claims"].Members[":adult"].Value = false
	clone.ASC.SAO.IDToken[0].Values[0] = "changed"
	clone.ASC.SAO.IDToken[1].What[0] = "/changed"
	clone.ASC.SAO.IDToken[2].Schema[0] = '['
	clone.ASC.TransformedClaims["adult"].Fn[1].Args[0] = float64(21)

	assert.Equal(t, newTestClaimsRequestASC(), claims)

	assert.Nil(t, (*oauth2.ClaimsRequestASC)(nil).Clone())
	assert.False(t, (*oauth2.ClaimsRequest)(nil).HasSelectiveAbortOmit())
}

func TestParseRequestedClaimsASC(t *testing.T) {
	const (
		adult = `"transformed_claims":{"adult":{"claim":"birthdate","fn":["years_ago",["gte",18]]}}`
		rule  = `{"loc":"/email","else":"abort"}`
	)

	both := oauth2.ClaimsASC{SelectiveAbortOmit: true, TransformedClaims: true, Evaluator: stubClaimsASCEvaluator{}}
	schema := oauth2.ClaimsASC{SelectiveAbortOmit: true, Evaluator: stubClaimsASCEvaluator{schema: true}}

	sao := func(rules string) string {
		return `{"id_token":{"email":null},"_asc":{"sao":{"id_token":[` + rules + `]}}}`
	}

	tc := func(definitions string) string {
		return `{"id_token":{":adult":null},"_asc":{"transformed_claims":` + definitions + `}}`
	}

	definitions := make([]string, 17)

	for i := range definitions {
		definitions[i] = fmt.Sprintf(`"c%d":{"claim":"birthdate","fn":["years_ago"]}`, i)
	}

	manyDefinitions := "{" + strings.Join(definitions, ",") + "}"
	longChain := strings.TrimSuffix(strings.Repeat(`"years_ago",`, 9), ",")

	testCases := []struct {
		name   string
		config oauth2.ClaimsASC
		raw    string
		hint   string
		err    error
		check  func(t *testing.T, claims *oauth2.ClaimsRequest)
	}{
		{
			name:   "ShouldParseBothComponents",
			config: both,
			raw:    `{"id_token":{":adult":{"value":true},"verified_claims":{"claims":{":adult":null}}},"_asc":{"sao":{"id_token":[` + rule + `]},` + adult + `}}`,
			check: func(t *testing.T, claims *oauth2.ClaimsRequest) {
				require.NotNil(t, claims.ASC)
				assert.Equal(t, []oauth2.SelectiveAbortOmitRule{{Loc: "/email", Else: "abort"}}, claims.ASC.SAO.IDToken)
				assert.Equal(t, &oauth2.TransformedClaim{Claim: "birthdate", Fn: []oauth2.TransformedClaimFunction{{Name: "years_ago"}, {Name: "gte", Args: []any{float64(18)}}}}, claims.ASC.TransformedClaims["adult"])
				assert.Contains(t, claims.IDToken["verified_claims"].Members["claims"].Members, ":adult")
			},
		},
		{
			name: "ShouldMatchParseClaimsRequestWhenDisabled",
			raw:  `{"id_token":{"verified_claims":{"claims":{":adult":null}}},"_asc":{"sao":{"id_token":[` + rule + `]},` + adult + `}}`,
			check: func(t *testing.T, claims *oauth2.ClaimsRequest) {
				assert.Equal(t, &oauth2.ClaimsRequest{IDToken: map[string]*oauth2.ClaimRequest{"verified_claims": {}}}, claims)
			},
		},
		{
			name:   "ShouldIgnoreSAOWhenOnlyTransformedClaimsEnabled",
			config: oauth2.ClaimsASC{TransformedClaims: true, Evaluator: stubClaimsASCEvaluator{}},
			raw:    `{"_asc":{"sao":"malformed",` + adult + `}}`,
			check: func(t *testing.T, claims *oauth2.ClaimsRequest) {
				assert.Nil(t, claims.ASC.SAO)
				assert.Len(t, claims.ASC.TransformedClaims, 1)
			},
		},
		{
			name:   "ShouldIgnoreTransformedClaimsWhenOnlySAOEnabled",
			config: oauth2.ClaimsASC{SelectiveAbortOmit: true, Evaluator: stubClaimsASCEvaluator{}},
			raw:    `{"_asc":{"sao":{"id_token":[` + rule + `]},"transformed_claims":"malformed"}}`,
			check: func(t *testing.T, claims *oauth2.ClaimsRequest) {
				assert.Nil(t, claims.ASC.TransformedClaims)
				assert.Len(t, claims.ASC.SAO.IDToken, 1)
			},
		},
		{
			name:   "ShouldLeaveASCNilWhenAbsent",
			config: both,
			raw:    `{"id_token":{"email":null}}`,
			check: func(t *testing.T, claims *oauth2.ClaimsRequest) {
				assert.Nil(t, claims.ASC)
			},
		},
		{
			name:   "ShouldAcceptUndefinedTransformedClaimRequest",
			config: both,
			raw:    `{"id_token":{":undefined":null,"::undefined":null}}`,
			check: func(t *testing.T, claims *oauth2.ClaimsRequest) {
				assert.Contains(t, claims.IDToken, ":undefined")
			},
		},
		{
			name:   "ShouldParseSpecificationExample1",
			config: schema,
			raw:    `{"id_token":{"verified_claims":{"verification":{"trust_framework":null,"assurance_level":null},"claims":{"family_name":{"value":"nonexistent_family_name"},"given_name":null,"birthdate":null,"address":null}}},"userinfo":{"address":null},"_asc":{"sao":{"id_token":[{"loc":"/verified_claims/verification/assurance_level","method":"simple","value":"example_assurance_level","else":"abort"},{"loc":"/verified_claims/claims","method":"schema","schema":{"$schema":"http://json-schema.org/draft-07/schema#","type":"object","properties":{"birthdate":{"type":"string","const":"1900-01-01"}}},"else":"omit"},{"loc":"/verified_claims/claims/family_name","method":"simple","value":"nonexistent_family_name","else":"omit","what":["/verified_claims"]}],"userinfo":[{"loc":"/address/postal_code","method":"exists","else":"abort"}]}}}`,
			check: func(t *testing.T, claims *oauth2.ClaimsRequest) {
				require.Len(t, claims.ASC.SAO.IDToken, 3)
				assert.Equal(t, "example_assurance_level", claims.ASC.SAO.IDToken[0].Value)
				assert.Contains(t, string(claims.ASC.SAO.IDToken[1].Schema), `"const":"1900-01-01"`)
				assert.Equal(t, []string{"/verified_claims"}, claims.ASC.SAO.IDToken[2].What)
				assert.Equal(t, []oauth2.SelectiveAbortOmitRule{{Loc: "/address/postal_code", Method: "exists", Else: "abort"}}, claims.ASC.SAO.UserInfo)
			},
		},
		{name: "ShouldAcceptEmptyLocWithAbort", config: both, raw: sao(`{"loc":"","else":"abort"}`), check: func(t *testing.T, claims *oauth2.ClaimsRequest) {
			assert.Equal(t, "", claims.ASC.SAO.IDToken[0].Loc)
		}},
		{name: "ShouldAcceptSimpleValues", config: both, raw: sao(`{"loc":"/acr","method":"simple","values":["gold",2,true],"else":"omit"}`), check: func(t *testing.T, claims *oauth2.ClaimsRequest) {
			assert.Equal(t, []any{"gold", float64(2), true}, claims.ASC.SAO.IDToken[0].Values)
		}},

		{name: "ShouldRejectASCNotObject", config: both, raw: `{"_asc":[]}`, hint: "member '_asc' must be a JSON object."},
		{name: "ShouldRejectSAONotObject", config: both, raw: `{"_asc":{"sao":[]}}`, hint: "member '_asc/sao' must be a JSON object."},
		{name: "ShouldRejectDeliveryNotArray", config: both, raw: `{"_asc":{"sao":{"userinfo":{}}}}`, hint: "member '_asc/sao/userinfo' must be an array."},
		{name: "ShouldRejectRuleNotObject", config: both, raw: sao(`"rule"`), hint: "member '_asc/sao/id_token/0' must be a JSON object."},
		{name: "ShouldRejectMissingLoc", config: both, raw: sao(`{"else":"abort"}`), hint: "member '_asc/sao/id_token/0/loc' is required and must be a string."},
		{name: "ShouldRejectLocNotString", config: both, raw: sao(`{"loc":1,"else":"abort"}`), hint: "member '_asc/sao/id_token/0/loc' is required and must be a string."},
		{name: "ShouldRejectLocNotPointer", config: both, raw: sao(`{"loc":"email","else":"abort"}`), hint: "member '_asc/sao/id_token/0/loc' must be a JSON Pointer."},
		{name: "ShouldRejectLocBadEscape", config: both, raw: sao(`{"loc":"/a~2","else":"abort"}`), hint: "member '_asc/sao/id_token/0/loc' must be a JSON Pointer."},
		{name: "ShouldRejectUnknownMethod", config: both, raw: sao(`{"loc":"/a","method":"regex","else":"abort"}`), hint: "member '_asc/sao/id_token/0/method' must be one of 'exists', 'simple' or 'schema'."},
		{name: "ShouldRejectSchemaMethodWithoutSchema", config: schema, raw: sao(`{"loc":"/a","method":"schema","else":"abort"}`), hint: "member '_asc/sao/id_token/0/schema' is required when the method is 'schema'."},
		{name: "ShouldRejectSchemaWithOtherMethod", config: schema, raw: sao(`{"loc":"/a","schema":{},"else":"abort"}`), hint: "member '_asc/sao/id_token/0/schema' must not be present unless the method is 'schema'."},
		{name: "ShouldRejectSchemaNotObject", config: schema, raw: sao(`{"loc":"/a","method":"schema","schema":true,"else":"abort"}`), hint: "member '_asc/sao/id_token/0/schema' must be a JSON object."},
		{name: "ShouldRejectSchemaWhenUnsupported", config: both, raw: sao(`{"loc":"/a","method":"schema","schema":{},"else":"abort"}`), hint: "member '_asc/sao/id_token/0/method' has the value 'schema' which is not supported."},
		{name: "ShouldRejectSimpleWithoutValue", config: both, raw: sao(`{"loc":"/a","method":"simple","else":"abort"}`), hint: "member '_asc/sao/id_token/0' must have exactly one of 'value' and 'values' when the method is 'simple'."},
		{name: "ShouldRejectSimpleWithBoth", config: both, raw: sao(`{"loc":"/a","method":"simple","value":1,"values":[1],"else":"abort"}`), hint: "member '_asc/sao/id_token/0' must have exactly one of 'value' and 'values' when the method is 'simple'."},
		{name: "ShouldRejectValueWithExists", config: both, raw: sao(`{"loc":"/a","value":1,"else":"abort"}`), hint: "member '_asc/sao/id_token/0' must not have 'value' or 'values' unless the method is 'simple'."},
		{name: "ShouldRejectValueObject", config: both, raw: sao(`{"loc":"/a","method":"simple","value":{},"else":"abort"}`), hint: "member '_asc/sao/id_token/0/value' must be a string, number or boolean."},
		{name: "ShouldRejectValueNull", config: both, raw: sao(`{"loc":"/a","method":"simple","value":null,"else":"abort"}`), hint: "member '_asc/sao/id_token/0/value' must be a string, number or boolean."},
		{name: "ShouldRejectValuesEmpty", config: both, raw: sao(`{"loc":"/a","method":"simple","values":[],"else":"abort"}`), hint: "member '_asc/sao/id_token/0/values' must be a non-empty array of strings, numbers or booleans."},
		{name: "ShouldRejectValuesNested", config: both, raw: sao(`{"loc":"/a","method":"simple","values":[[1]],"else":"abort"}`), hint: "member '_asc/sao/id_token/0/values' must be a non-empty array of strings, numbers or booleans."},
		{name: "ShouldRejectMissingElse", config: both, raw: sao(`{"loc":"/a"}`), hint: "member '_asc/sao/id_token/0/else' must be 'abort' or 'omit'."},
		{name: "ShouldRejectUnknownElse", config: both, raw: sao(`{"loc":"/a","else":"skip"}`), hint: "member '_asc/sao/id_token/0/else' must be 'abort' or 'omit'."},
		{name: "ShouldRejectWhatWithAbort", config: both, raw: sao(`{"loc":"/a","else":"abort","what":["/a"]}`), hint: "member '_asc/sao/id_token/0/what' must not be present unless the action is 'omit'."},
		{name: "ShouldRejectWhatEmpty", config: both, raw: sao(`{"loc":"/a","else":"omit","what":[]}`), hint: "member '_asc/sao/id_token/0/what' must be a non-empty array of JSON Pointers."},
		{name: "ShouldRejectWhatNotPointer", config: both, raw: sao(`{"loc":"/a","else":"omit","what":["a"]}`), hint: "member '_asc/sao/id_token/0/what' must be a non-empty array of JSON Pointers."},
		{name: "ShouldRejectWhatWholeDocument", config: both, raw: sao(`{"loc":"/a","else":"omit","what":[""]}`), hint: "member '_asc/sao/id_token/0/what' must be a non-empty array of JSON Pointers."},
		{name: "ShouldRejectOmitOfWholeDocument", config: both, raw: sao(`{"loc":"","else":"omit"}`), hint: "member '_asc/sao/id_token/0/what' is required when 'loc' is the whole document."},
		{name: "ShouldReportSecondRule", config: both, raw: sao(rule + `,{"loc":"/a"}`), hint: "member '_asc/sao/id_token/1/else' must be 'abort' or 'omit'."},

		{name: "ShouldRejectTransformedClaimsNotObject", config: both, raw: tc(`[]`), hint: "member '_asc/transformed_claims' must be a JSON object."},
		{name: "ShouldRejectDefinitionNotObject", config: both, raw: tc(`{"adult":"birthdate"}`), hint: "member '_asc/transformed_claims/adult' must be a JSON object with a 'claim' string and an 'fn' array."},
		{name: "ShouldRejectMissingClaim", config: both, raw: tc(`{"adult":{"fn":["years_ago"]}}`), hint: "member '_asc/transformed_claims/adult/claim' is required and must be a string."},
		{name: "ShouldRejectEmptyFn", config: both, raw: tc(`{"adult":{"claim":"birthdate","fn":[]}}`), hint: "member '_asc/transformed_claims/adult/fn' must be a non-empty array."},
		{name: "ShouldRejectFunctionNotStringOrArray", config: both, raw: tc(`{"adult":{"claim":"birthdate","fn":[18]}}`), hint: "member '_asc/transformed_claims/adult/fn/0' must be a function name or an array which starts with one."},
		{name: "ShouldRejectUnsupportedFunction", config: both, raw: tc(`{"adult":{"claim":"birthdate","fn":["years_ago","reverse"]}}`), hint: "member '_asc/transformed_claims/adult/fn/1' uses the function 'reverse' which is not supported or has arguments which are not valid: unsupported reverse."},
		{name: "ShouldRejectWrongArguments", config: both, raw: tc(`{"adult":{"claim":"birthdate","fn":[["gte"]]}}`), hint: "member '_asc/transformed_claims/adult/fn/0' uses the function 'gte' which is not supported or has arguments which are not valid: unsupported gte."},
		{name: "ShouldRejectDefinitionNameWithColon", config: both, raw: tc(`{":adult":{"claim":"birthdate","fn":["years_ago"]}}`), hint: "member '_asc/transformed_claims' must not define a transformed claim with a name which is empty or starts with a colon."},
		{name: "ShouldRejectDefinitionNameEmpty", config: both, raw: tc(`{"":{"claim":"birthdate","fn":["years_ago"]}}`), hint: "member '_asc/transformed_claims' must not define a transformed claim with a name which is empty or starts with a colon."},
		{
			name:   "ShouldRejectTooManyDefinitions",
			config: oauth2.ClaimsASC{TransformedClaims: true, TransformedClaimsMaxCount: 1, Evaluator: stubClaimsASCEvaluator{}},
			raw:    tc(`{"a":{"claim":"birthdate","fn":["years_ago"]},"b":{"claim":"birthdate","fn":["years_ago"]}}`),
			hint:   "member '_asc/transformed_claims' must not define more than 1 transformed claims.",
		},
		{
			name:   "ShouldRejectTooLongChain",
			config: oauth2.ClaimsASC{TransformedClaims: true, TransformedClaimsMaxDepth: 1, Evaluator: stubClaimsASCEvaluator{}},
			raw:    tc(`{"adult":{"claim":"birthdate","fn":["years_ago",["gte",18]]}}`),
			hint:   "member '_asc/transformed_claims/adult/fn' must not apply more than 1 functions.",
		},
		{
			name:   "ShouldRejectMoreDefinitionsThanTheDefault",
			config: oauth2.ClaimsASC{TransformedClaims: true, Evaluator: stubClaimsASCEvaluator{}},
			raw:    tc(manyDefinitions),
			hint:   "member '_asc/transformed_claims' must not define more than 16 transformed claims.",
		},
		{
			name:   "ShouldAcceptAnyNumberOfDefinitionsWithoutLimit",
			config: oauth2.ClaimsASC{TransformedClaims: true, TransformedClaimsMaxCount: -1, Evaluator: stubClaimsASCEvaluator{}},
			raw:    tc(manyDefinitions),
			check: func(t *testing.T, claims *oauth2.ClaimsRequest) {
				assert.Len(t, claims.ASC.TransformedClaims, 17)
			},
		},
		{
			name:   "ShouldRejectLongerChainThanTheDefault",
			config: oauth2.ClaimsASC{TransformedClaims: true, Evaluator: stubClaimsASCEvaluator{}},
			raw:    tc(`{"adult":{"claim":"birthdate","fn":[` + longChain + `]}}`),
			hint:   "member '_asc/transformed_claims/adult/fn' must not apply more than 8 functions.",
		},
		{
			name:   "ShouldAcceptChainOfAnyLengthWithoutLimit",
			config: oauth2.ClaimsASC{TransformedClaims: true, TransformedClaimsMaxDepth: -1, Evaluator: stubClaimsASCEvaluator{}},
			raw:    tc(`{"adult":{"claim":"birthdate","fn":[` + longChain + `]}}`),
			check: func(t *testing.T, claims *oauth2.ClaimsRequest) {
				assert.Len(t, claims.ASC.TransformedClaims["adult"].Fn, 9)
			},
		},
		{
			name:   "ShouldCheckLimitsBeforeFunctions",
			config: oauth2.ClaimsASC{TransformedClaims: true, TransformedClaimsMaxDepth: 1, Evaluator: stubClaimsASCEvaluator{}},
			raw:    tc(`{"a":{"claim":"birthdate","fn":["reverse"]},"b":{"claim":"birthdate","fn":["years_ago",["gte",18]]}}`),
			hint:   "member '_asc/transformed_claims/b/fn' must not apply more than 1 functions.",
		},
		{
			name:   "ShouldRejectCustomDefinitionsWhenDisabled",
			config: oauth2.ClaimsASC{TransformedClaims: true, DisableCustomTransformedClaims: true, Evaluator: stubClaimsASCEvaluator{}},
			raw:    tc(`{"adult":{"claim":"birthdate","fn":["years_ago"]}}`),
			hint:   "member '_asc/transformed_claims' must not define transformed claims as only predefined transformed claims are supported.",
		},
		{
			name:   "ShouldAcceptEmptyDefinitionsWhenCustomDisabled",
			config: oauth2.ClaimsASC{TransformedClaims: true, DisableCustomTransformedClaims: true, Evaluator: stubClaimsASCEvaluator{}},
			raw:    `{"id_token":{"::adult":null},"_asc":{"transformed_claims":{}}}`,
			check: func(t *testing.T, claims *oauth2.ClaimsRequest) {
				assert.Nil(t, claims.ASC)
			},
		},
		{name: "ShouldFailSAOWithoutEvaluator", config: oauth2.ClaimsASC{SelectiveAbortOmit: true}, raw: sao(rule), err: oauth2.ErrServerError},
		{name: "ShouldFailTransformedClaimsWithoutEvaluator", config: oauth2.ClaimsASC{TransformedClaims: true}, raw: tc(`{"adult":{"claim":"birthdate","fn":["years_ago"]}}`), err: oauth2.ErrServerError},
		{name: "ShouldPassWithoutEvaluatorWhenKeyAbsent", config: oauth2.ClaimsASC{SelectiveAbortOmit: true, TransformedClaims: true}, raw: `{"id_token":{"email":null}}`, check: func(t *testing.T, claims *oauth2.ClaimsRequest) {
			assert.Nil(t, claims.ASC)
		}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			claims, err := oauth2.ParseRequestedClaims(t.Context(), &oauth2.Config{ClaimsASC: tc.config}, url.Values{"claims": {tc.raw}})

			switch {
			case tc.err != nil:
				require.Error(t, err)
				assert.ErrorIs(t, err, tc.err)
			case tc.hint != "":
				require.Error(t, err)
				assert.ErrorIs(t, err, oauth2.ErrInvalidRequest)
				assert.Equal(t, "The 'claims' parameter "+tc.hint, oauth2.ErrorToRFC6749Error(err).HintField)
			default:
				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))
				tc.check(t, claims)
			}
		})
	}
}

func TestClaimRequestMembersDepthLimit(t *testing.T) {
	const levels = 10

	raw := strings.Repeat(`{"n":`, levels) + `null` + strings.Repeat(`}`, levels)

	request := &oauth2.ClaimRequest{}
	require.NoError(t, json.Unmarshal([]byte(raw), request))

	depth := 0

	for current := request; current != nil && current.Members != nil; depth++ {
		current = current.Members["n"]
	}

	assert.Equal(t, 8, depth)
}

func TestParseClaimsRequestDeeplyNested(t *testing.T) {
	const levels = 1300

	nested := strings.Repeat(`{"n":`, levels) + `null` + strings.Repeat(`}`, levels)
	raw := `{"id_token":{"claim":` + nested + `}}`

	require.LessOrEqual(t, len(raw), 8000)

	form := url.Values{"claims": {raw}}

	claims, err := oauth2.ParseClaimsRequest(form)
	require.NoError(t, err)
	require.NotNil(t, claims)

	config := &oauth2.Config{ClaimsASC: oauth2.ClaimsASC{TransformedClaims: true, Evaluator: stubClaimsASCEvaluator{}}}

	claims, err = oauth2.ParseRequestedClaims(t.Context(), config, form)
	require.NoError(t, err)
	require.NotNil(t, claims)
	require.Contains(t, claims.IDToken, "claim")
	assert.NotEmpty(t, claims.IDToken["claim"].Members)
}

func TestGetRequestedACRValuesWithSelectiveAbortOmit(t *testing.T) {
	config := &oauth2.Config{ClaimsASC: oauth2.ClaimsASC{SelectiveAbortOmit: true, Evaluator: stubClaimsASCEvaluator{}}}

	testCases := []struct {
		name     string
		raw      string
		expected []string
	}{
		{name: "ShouldPreferClaimValuesToDefaultValues", raw: `{"id_token":{"acr":{"values":["gold"]}}}`},
		{name: "ShouldIgnoreClaimValuesWithSelectiveAbortOmit", raw: `{"id_token":{"acr":{"values":["gold"]}},"_asc":{"sao":{}}}`, expected: []string{"phr"}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			claims, err := oauth2.ParseRequestedClaims(t.Context(), config, url.Values{"claims": {tc.raw}})
			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

			request := oauth2.NewAuthorizeRequest()
			request.Client = &oauth2.DefaultRegisteredClient{DefaultACRValues: []string{"phr"}}
			request.SetClaims(claims)

			assert.Equal(t, tc.expected, oauth2.GetRequestedACRValues(request))
		})
	}
}

func TestGetClaimsASC(t *testing.T) {
	assert.Equal(t, oauth2.ClaimsASC{TransformedClaimsMaxDepth: 8, TransformedClaimsMaxCount: 16}, oauth2.GetClaimsASC(t.Context(), struct{}{}))
	assert.Equal(t, oauth2.ClaimsASC{TransformedClaimsMaxDepth: 8, TransformedClaimsMaxCount: 16}, oauth2.GetClaimsASC(t.Context(), &oauth2.Config{}))

	configured := oauth2.GetClaimsASC(t.Context(), &oauth2.Config{ClaimsASC: oauth2.ClaimsASC{SelectiveAbortOmit: true, TransformedClaimsMaxDepth: 2, TransformedClaimsMaxCount: 3}})

	assert.True(t, configured.SelectiveAbortOmit)
	assert.Equal(t, 2, configured.TransformedClaimsMaxDepth)
	assert.Equal(t, 3, configured.TransformedClaimsMaxCount)
	unlimited := oauth2.GetClaimsASC(t.Context(), &oauth2.Config{ClaimsASC: oauth2.ClaimsASC{TransformedClaimsMaxDepth: -1, TransformedClaimsMaxCount: -1}})

	assert.Equal(t, -1, unlimited.TransformedClaimsMaxDepth)
	assert.Equal(t, -1, unlimited.TransformedClaimsMaxCount)

	assert.Equal(t, 8, oauth2.DefaultTransformedClaimsMaxDepth)
	assert.Equal(t, 16, oauth2.DefaultTransformedClaimsMaxCount)
}

func newTestClaimsRequestASC() *oauth2.ClaimsRequest {
	return &oauth2.ClaimsRequest{
		IDToken: map[string]*oauth2.ClaimRequest{
			"verified_claims": {Members: map[string]*oauth2.ClaimRequest{
				"claims": {Members: map[string]*oauth2.ClaimRequest{":adult": {Value: true}}},
			}},
		},
		ASC: &oauth2.ClaimsRequestASC{
			SAO: &oauth2.SelectiveAbortOmit{
				IDToken: []oauth2.SelectiveAbortOmitRule{
					{Loc: "/acr", Method: oauth2.SelectiveAbortOmitMethodSimple, Values: []any{"gold", "silver"}, Else: oauth2.SelectiveAbortOmitActionAbort},
					{Loc: "/email", Else: oauth2.SelectiveAbortOmitActionOmit, What: []string{"/email", "/email_verified"}},
					{Loc: "", Method: oauth2.SelectiveAbortOmitMethodSchema, Schema: json.RawMessage(`{"type":"object"}`), Else: oauth2.SelectiveAbortOmitActionAbort},
				},
			},
			TransformedClaims: map[string]*oauth2.TransformedClaim{
				"adult": {Claim: "birthdate", Fn: []oauth2.TransformedClaimFunction{{Name: "years_ago"}, {Name: "gte", Args: []any{float64(18)}}}},
			},
		},
	}
}

type stubClaimsASCEvaluator struct {
	schema bool
}

func (s stubClaimsASCEvaluator) ValidateTransformedClaimFunction(name string, args []any) error {
	switch {
	case name == "years_ago" && len(args) == 0, name == "gte" && len(args) == 1:
		return nil
	default:
		return errors.New("unsupported " + strings.ToLower(name))
	}
}

func (s stubClaimsASCEvaluator) SupportsSchema() bool {
	return s.schema
}

func (s stubClaimsASCEvaluator) FunctionNames() []string {
	return []string{"years_ago", "gte"}
}

func (s stubClaimsASCEvaluator) PredefinedTransformedClaims() map[string]*oauth2.TransformedClaim {
	return nil
}

func (s stubClaimsASCEvaluator) Evaluate(_ context.Context, _ *oauth2.ClaimsRequest, _ string, claims, _ map[string]any, _ []string) (map[string]any, error) {
	return claims, nil
}
