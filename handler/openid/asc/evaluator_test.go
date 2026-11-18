// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package asc_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/handler/openid/asc"
)

func TestEvaluatorTransformedClaims(t *testing.T) {
	const adult = `"_asc":{"transformed_claims":{"adult":{"claim":"birthdate","fn":["years_ago",["gte",18]]}}}`

	testCases := []struct {
		name     string
		raw      string
		claims   map[string]any
		sources  map[string]any
		expected string
	}{
		{
			name:     "ShouldTransformReleasedClaim",
			raw:      `{"id_token":{":adult":null},` + adult + `}`,
			claims:   map[string]any{"sub": "peter", "birthdate": "2000-01-01"},
			expected: `{"sub":"peter","birthdate":"2000-01-01",":adult":true}`,
		},
		{
			name:     "ShouldTransformSourceClaimWithoutReleasingIt",
			raw:      `{"id_token":{":adult":null},` + adult + `}`,
			claims:   map[string]any{"sub": "peter"},
			sources:  map[string]any{"birthdate": "2015-01-01"},
			expected: `{"sub":"peter",":adult":false}`,
		},
		{
			name:     "ShouldPreferReleasedClaimOverSource",
			raw:      `{"id_token":{":adult":null},` + adult + `}`,
			claims:   map[string]any{"birthdate": "2000-01-01"},
			sources:  map[string]any{"birthdate": "2015-01-01"},
			expected: `{"birthdate":"2000-01-01",":adult":true}`,
		},
		{
			name:     "ShouldOmitWhenBaseClaimUnavailable",
			raw:      `{"id_token":{":adult":null},` + adult + `}`,
			claims:   map[string]any{"sub": "peter"},
			expected: `{"sub":"peter"}`,
		},
		{
			name:     "ShouldOmitWhenFunctionInputMismatched",
			raw:      `{"id_token":{":adult":null},` + adult + `}`,
			claims:   map[string]any{"birthdate": true},
			expected: `{"birthdate":true}`,
		},
		{
			name:     "ShouldSkipUndefinedTransformedClaim",
			raw:      `{"id_token":{":minor":null,"::minor":null},` + adult + `}`,
			claims:   map[string]any{"birthdate": "2000-01-01"},
			expected: `{"birthdate":"2000-01-01"}`,
		},
		{
			name:     "ShouldNotTransformForOtherDelivery",
			raw:      `{"userinfo":{":adult":null},` + adult + `}`,
			claims:   map[string]any{"birthdate": "2000-01-01"},
			expected: `{"birthdate":"2000-01-01"}`,
		},
		{
			name:     "ShouldResolveBaseClaimRelativeToLocation",
			raw:      `{"id_token":{"verified_claims":{"claims":{":adult":null}}},` + adult + `}`,
			claims:   map[string]any{"birthdate": "2020-01-01", "verified_claims": map[string]any{"claims": map[string]any{"birthdate": "2000-01-01"}}},
			expected: `{"birthdate":"2020-01-01","verified_claims":{"claims":{"birthdate":"2000-01-01",":adult":true}}}`,
		},
		{
			name:     "ShouldCreateIntermediateObjectsForSourceClaim",
			raw:      `{"id_token":{"verified_claims":{"claims":{":adult":null}}},` + adult + `}`,
			claims:   map[string]any{"sub": "peter"},
			sources:  map[string]any{"verified_claims": map[string]any{"claims": map[string]any{"birthdate": "2000-01-01"}}},
			expected: `{"sub":"peter","verified_claims":{"claims":{":adult":true}}}`,
		},
		{
			name:     "ShouldNotCreateIntermediateObjectsWhenUnavailable",
			raw:      `{"id_token":{"verified_claims":{"claims":{":adult":null}}},` + adult + `}`,
			claims:   map[string]any{"sub": "peter"},
			sources:  map[string]any{"verified_claims": map[string]any{"claims": map[string]any{}}},
			expected: `{"sub":"peter"}`,
		},
		{
			name:     "ShouldNotReplaceNonObjectAtNestedLocation",
			raw:      `{"id_token":{"verified_claims":{"claims":{":adult":null}}},` + adult + `}`,
			claims:   map[string]any{"verified_claims": []any{"opaque"}},
			sources:  map[string]any{"verified_claims": map[string]any{"claims": map[string]any{"birthdate": "2000-01-01"}}},
			expected: `{"verified_claims":["opaque"]}`,
		},
		{
			name:     "ShouldTransformInEveryObjectOfAnArray",
			raw:      `{"id_token":{"verified_claims":{"claims":{":adult":null}}},` + adult + `}`,
			claims:   map[string]any{"verified_claims": []any{map[string]any{"claims": map[string]any{"birthdate": "2000-01-01"}}, "opaque", map[string]any{"claims": map[string]any{"birthdate": "2015-01-01"}}, map[string]any{"claims": map[string]any{}}}},
			expected: `{"verified_claims":[{"claims":{"birthdate":"2000-01-01",":adult":true}},"opaque",{"claims":{"birthdate":"2015-01-01",":adult":false}},{"claims":{}}]}`,
		},
		{
			name:     "ShouldTransformInArrayFromSourcesOfTheSameLength",
			raw:      `{"id_token":{"verified_claims":{"claims":{":adult":null}}},` + adult + `}`,
			claims:   map[string]any{"verified_claims": []any{map[string]any{"claims": map[string]any{"given_name": "Peter"}}, map[string]any{"claims": map[string]any{"given_name": "Petra"}}}},
			sources:  map[string]any{"verified_claims": []any{map[string]any{"claims": map[string]any{"birthdate": "2000-01-01"}}, map[string]any{"claims": map[string]any{"birthdate": "2015-01-01"}}}},
			expected: `{"verified_claims":[{"claims":{"given_name":"Peter",":adult":true}},{"claims":{"given_name":"Petra",":adult":false}}]}`,
		},
		{
			name:     "ShouldNotTransformInArrayFromSourcesOfAnotherLength",
			raw:      `{"id_token":{"verified_claims":{"claims":{":adult":null}}},` + adult + `}`,
			claims:   map[string]any{"verified_claims": []any{map[string]any{"claims": map[string]any{"given_name": "Peter"}}}},
			sources:  map[string]any{"verified_claims": []any{map[string]any{"claims": map[string]any{"birthdate": "2000-01-01"}}, map[string]any{"claims": map[string]any{"birthdate": "2015-01-01"}}}},
			expected: `{"verified_claims":[{"claims":{"given_name":"Peter"}}]}`,
		},
		{
			name:     "ShouldCreateArrayForSourceArray",
			raw:      `{"id_token":{"verified_claims":{"claims":{":adult":null}}},` + adult + `}`,
			claims:   map[string]any{"sub": "peter"},
			sources:  map[string]any{"verified_claims": []any{map[string]any{"claims": map[string]any{"birthdate": "2000-01-01"}}, map[string]any{"claims": map[string]any{}}, "opaque"}},
			expected: `{"sub":"peter","verified_claims":[{"claims":{":adult":true}}]}`,
		},
		{
			name:     "ShouldNotCreateArrayWhenUnavailable",
			raw:      `{"id_token":{"verified_claims":{"claims":{":adult":null}}},` + adult + `}`,
			claims:   map[string]any{"sub": "peter"},
			sources:  map[string]any{"verified_claims": []any{map[string]any{"claims": map[string]any{}}}},
			expected: `{"sub":"peter"}`,
		},
		{
			name:     "ShouldTransformPredefinedClaim",
			raw:      `{"id_token":{"::senior":null}}`,
			claims:   map[string]any{"birthdate": "1950-01-01"},
			expected: `{"birthdate":"1950-01-01","::senior":true}`,
		},
		{
			name:     "ShouldReleaseTransformedClaimMatchingValue",
			raw:      `{"id_token":{":adult":{"value":true,"essential":true}},` + adult + `}`,
			claims:   map[string]any{"birthdate": "2000-01-01"},
			expected: `{"birthdate":"2000-01-01",":adult":true}`,
		},
		{
			name:     "ShouldNotReleaseTransformedClaimNotMatchingValue",
			raw:      `{"id_token":{":adult":{"value":true,"essential":true}},` + adult + `}`,
			claims:   map[string]any{"sub": "peter"},
			sources:  map[string]any{"birthdate": "2015-01-01"},
			expected: `{"sub":"peter"}`,
		},
		{
			name:     "ShouldReleaseTransformedClaimMatchingFalseValue",
			raw:      `{"id_token":{":adult":{"value":false}},` + adult + `}`,
			claims:   map[string]any{"birthdate": "2015-01-01"},
			expected: `{"birthdate":"2015-01-01",":adult":false}`,
		},
		{
			name:     "ShouldReleaseTransformedClaimMatchingOneOfValues",
			raw:      `{"id_token":{":age":{"values":[25,26]}},"_asc":{"transformed_claims":{"age":{"claim":"birthdate","fn":["years_ago"]}}}}`,
			claims:   map[string]any{"birthdate": "2000-01-01"},
			expected: `{"birthdate":"2000-01-01",":age":26}`,
		},
		{
			name:     "ShouldNotReleaseTransformedClaimMatchingNoneOfValues",
			raw:      `{"id_token":{":age":{"values":[18,19]}},"_asc":{"transformed_claims":{"age":{"claim":"birthdate","fn":["years_ago"]}}}}`,
			claims:   map[string]any{"birthdate": "2000-01-01"},
			expected: `{"birthdate":"2000-01-01"}`,
		},
		{
			name:     "ShouldNotReleaseNestedTransformedClaimNotMatchingValue",
			raw:      `{"id_token":{"verified_claims":{"claims":{":adult":{"value":true}}}},` + adult + `}`,
			claims:   map[string]any{"verified_claims": map[string]any{"claims": map[string]any{"birthdate": "2015-01-01"}}},
			expected: `{"verified_claims":{"claims":{"birthdate":"2015-01-01"}}}`,
		},
		{
			name:     "ShouldNotReleasePredefinedClaimNotMatchingValue",
			raw:      `{"id_token":{"::senior":{"value":true}}}`,
			claims:   map[string]any{"birthdate": "2000-01-01"},
			expected: `{"birthdate":"2000-01-01"}`,
		},
		{
			name:     "ShouldIgnoreValueOfTransformedClaimWithSelectiveAbortOmit",
			raw:      `{"id_token":{":adult":{"value":true}},"_asc":{"sao":{"id_token":[]},"transformed_claims":{"adult":{"claim":"birthdate","fn":["years_ago",["gte",18]]}}}}`,
			claims:   map[string]any{"birthdate": "2015-01-01"},
			expected: `{"birthdate":"2015-01-01",":adult":false}`,
		},
		{
			name:     "ShouldEvaluateSpecificationArrayExample",
			raw:      `{"id_token":{":nationality_usa":null},"_asc":{"transformed_claims":{"nationality_usa":{"claim":"nationalities","fn":[["eq","USA"],"any"]}}}}`,
			claims:   map[string]any{"nationalities": []string{"DEU", "USA"}},
			expected: `{"nationalities":["DEU","USA"],":nationality_usa":true}`,
		},
		{
			name:     "ShouldEvaluateTypedClaimValues",
			raw:      `{"id_token":{":recent":null},"_asc":{"transformed_claims":{"recent":{"claim":"updated_at","fn":[["gt",1000]]}}}}`,
			claims:   map[string]any{"updated_at": int64(9007199254740993), "address": typedAddress{Country: "GB"}},
			expected: `{"updated_at":9007199254740993,"address":{"country":"GB"},":recent":true}`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			evaluator := newTestEvaluator()
			evaluator.Predefined = map[string]*oauth2.TransformedClaim{
				"senior": {Claim: "birthdate", Fn: []oauth2.TransformedClaimFunction{{Name: "years_ago"}, {Name: "gte", Args: []any{float64(65)}}}},
			}

			result, err := evaluator.Evaluate(t.Context(), mustParseClaims(t, evaluator, tc.raw), asc.DeliveryIDToken, tc.claims, tc.sources, nil)
			require.NoError(t, err)

			encoded, err := json.Marshal(result)
			require.NoError(t, err)

			assert.JSONEq(t, tc.expected, string(encoded))
		})
	}
}

func TestEvaluatorSelectiveAbortOmit(t *testing.T) {
	sao := func(rules string) string {
		return `{"id_token":{"email":null},"_asc":{"sao":{"id_token":[` + rules + `]}}}`
	}

	testCases := []struct {
		name      string
		raw       string
		claims    map[string]any
		protected []string
		expected  string
		abort     *asc.AbortError
	}{
		{
			name:     "ShouldPassExistsRule",
			raw:      sao(`{"loc":"/email","else":"abort"}`),
			claims:   map[string]any{"email": "peter@example.com"},
			expected: `{"email":"peter@example.com"}`,
		},
		{
			name:   "ShouldAbortWhenClaimMissing",
			raw:    sao(`{"loc":"/email","else":"abort"}`),
			claims: map[string]any{"sub": "peter"},
			abort:  &asc.AbortError{Delivery: asc.DeliveryIDToken, Rule: 0},
		},
		{
			name:     "ShouldPassExistsRuleForNullValue",
			raw:      sao(`{"loc":"/email","method":"exists","else":"abort"}`),
			claims:   map[string]any{"email": nil},
			expected: `{"email":null}`,
		},
		{
			name:     "ShouldPassSimpleValue",
			raw:      sao(`{"loc":"/acr","method":"simple","value":"gold","else":"abort"}`),
			claims:   map[string]any{"acr": "gold"},
			expected: `{"acr":"gold"}`,
		},
		{
			name:   "ShouldAbortOnSimpleValueMismatch",
			raw:    sao(`{"loc":"/acr","method":"simple","value":"gold","else":"abort"}`),
			claims: map[string]any{"acr": "silver"},
			abort:  &asc.AbortError{Delivery: asc.DeliveryIDToken, Rule: 0},
		},
		{
			name:     "ShouldPassSimpleValues",
			raw:      sao(`{"loc":"/level","method":"simple","values":[1,2],"else":"abort"}`),
			claims:   map[string]any{"level": 2},
			expected: `{"level":2}`,
		},
		{
			name:   "ShouldAbortWhenSimpleValueIsNotScalar",
			raw:    sao(`{"loc":"/address","method":"simple","value":"GB","else":"abort"}`),
			claims: map[string]any{"address": map[string]any{"country": "GB"}},
			abort:  &asc.AbortError{Delivery: asc.DeliveryIDToken, Rule: 0},
		},
		{
			name:     "ShouldOmitLocWhenWhatAbsent",
			raw:      sao(`{"loc":"/email_verified","method":"simple","value":true,"else":"omit"}`),
			claims:   map[string]any{"email": "peter@example.com", "email_verified": false},
			expected: `{"email":"peter@example.com"}`,
		},
		{
			name:     "ShouldOmitWhat",
			raw:      sao(`{"loc":"/email_verified","method":"simple","value":true,"else":"omit","what":["/email","/email_verified","/absent"]}`),
			claims:   map[string]any{"sub": "peter", "email": "peter@example.com", "email_verified": false},
			expected: `{"sub":"peter"}`,
		},
		{
			name:     "ShouldOmitArrayElement",
			raw:      sao(`{"loc":"/addresses/0/verified","method":"simple","value":true,"else":"omit","what":["/addresses/0"]}`),
			claims:   map[string]any{"addresses": []any{map[string]any{"verified": false}, map[string]any{"verified": true}}},
			expected: `{"addresses":[{"verified":true}]}`,
		},
		{
			name:     "ShouldOmitSeveralElementsOfOneArray",
			raw:      sao(`{"loc":"/phone","else":"omit","what":["/list/0","/list/1"]}`),
			claims:   map[string]any{"list": []any{"a", "b", "c"}},
			expected: `{"list":["c"]}`,
		},
		{
			name:     "ShouldOmitArrayElementsAcrossRulesByOriginalIndex",
			raw:      sao(`{"loc":"/phone","else":"omit","what":["/list/0"]},{"loc":"/phone","else":"omit","what":["/list/1"]}`),
			claims:   map[string]any{"list": []any{"a", "b", "c"}},
			expected: `{"list":["c"]}`,
		},
		{
			name:   "ShouldTriggerOnArrayElementOmittedByEarlierRule",
			raw:    sao(`{"loc":"/phone","else":"omit","what":["/list/0"]},{"loc":"/list/0","else":"abort"}`),
			claims: map[string]any{"list": []any{"a", "b", "c"}},
			abort:  &asc.AbortError{Delivery: asc.DeliveryIDToken, Rule: 1},
		},
		{
			name:     "ShouldMatchArrayElementAfterEarlierElementOmitted",
			raw:      sao(`{"loc":"/phone","else":"omit","what":["/list/0"]},{"loc":"/list/1","method":"simple","value":"b","else":"abort"}`),
			claims:   map[string]any{"list": []any{"a", "b", "c"}},
			expected: `{"list":["b","c"]}`,
		},
		{
			name:   "ShouldAbortOnTransformedValueInArray",
			raw:    `{"id_token":{"verified_claims":{"claims":{":adult":null}}},"_asc":{"transformed_claims":{"adult":{"claim":"birthdate","fn":["years_ago",["gte",18]]}},"sao":{"id_token":[{"loc":"/verified_claims/0/claims/:adult","method":"simple","value":true,"else":"abort"}]}}}`,
			claims: map[string]any{"verified_claims": []any{map[string]any{"claims": map[string]any{"birthdate": "2015-01-01"}}}},
			abort:  &asc.AbortError{Delivery: asc.DeliveryIDToken, Rule: 0},
		},
		{
			name:   "ShouldTriggerOnElementOmittedByEarlierRule",
			raw:    sao(`{"loc":"/phone","else":"omit","what":["/email"]},{"loc":"/email","else":"abort"}`),
			claims: map[string]any{"email": "peter@example.com"},
			abort:  &asc.AbortError{Delivery: asc.DeliveryIDToken, Rule: 1},
		},
		{
			name:   "ShouldNotExecuteRulesAfterAbort",
			raw:    sao(`{"loc":"/phone","else":"abort"},{"loc":"/phone","else":"omit","what":["/email"]}`),
			claims: map[string]any{"email": "peter@example.com"},
			abort:  &asc.AbortError{Delivery: asc.DeliveryIDToken, Rule: 0},
		},
		{
			name:      "ShouldNotOmitProtectedClaim",
			raw:       sao(`{"loc":"/phone","else":"omit","what":["/sub","/email"]}`),
			claims:    map[string]any{"sub": "peter", "email": "peter@example.com"},
			protected: []string{"sub"},
			expected:  `{"sub":"peter"}`,
		},
		{
			name:      "ShouldNotOmitBelowProtectedClaim",
			raw:       sao(`{"loc":"/phone","else":"omit","what":["/cnf/jkt"]}`),
			claims:    map[string]any{"cnf": map[string]any{"jkt": "thumbprint"}},
			protected: []string{"cnf"},
			expected:  `{"cnf":{"jkt":"thumbprint"}}`,
		},
		{
			name:      "ShouldNotOmitArrayElementsOfProtectedClaims",
			raw:       sao(`{"loc":"/phone","else":"omit","what":["/aud/0","/amr/0","/email"]}`),
			claims:    map[string]any{"aud": []any{"a", "b"}, "amr": []any{"pwd"}, "email": "e"},
			protected: []string{"aud", "amr"},
			expected:  `{"aud":["a","b"],"amr":["pwd"]}`,
		},
		{
			name:      "ShouldNotOmitProtectedClaimNamedByLoc",
			raw:       sao(`{"loc":"/sub","method":"simple","value":"other","else":"omit"}`),
			claims:    map[string]any{"sub": "peter"},
			protected: []string{"sub"},
			expected:  `{"sub":"peter"}`,
		},
		{
			name:     "ShouldCopyDerivedValueBeforeOmitUnderDerivedPath",
			raw:      `{"id_token":{":l":null},"_asc":{"transformed_claims":{"l":{"claim":"a","fn":[["get","list"]]}},"sao":{"id_token":[{"loc":"/phone","else":"omit","what":["/:l/0"]}]}}}`,
			claims:   map[string]any{"a": map[string]any{"list": []any{"x", "y"}}},
			expected: `{":l":["y"],"a":{"list":["x","y"]}}`,
		},
		{
			name:     "ShouldCopyDerivedValueBeforeOmitUnderBasePath",
			raw:      `{"id_token":{":l":null},"_asc":{"transformed_claims":{"l":{"claim":"a","fn":[["get","list"]]}},"sao":{"id_token":[{"loc":"/phone","else":"omit","what":["/a/list/0"]}]}}}`,
			claims:   map[string]any{"a": map[string]any{"list": []any{"x", "y"}}},
			expected: `{":l":["x","y"],"a":{"list":["y"]}}`,
		},
		{
			name:     "ShouldIgnoreRulesOfOtherDelivery",
			raw:      `{"_asc":{"sao":{"userinfo":[{"loc":"/phone","else":"abort"}]}}}`,
			claims:   map[string]any{"sub": "peter"},
			expected: `{"sub":"peter"}`,
		},
		{
			name:     "ShouldApplyRuleToTransformedValue",
			raw:      `{"id_token":{":adult":{"value":true}},"_asc":{"transformed_claims":{"adult":{"claim":"birthdate","fn":["years_ago",["gte",18]]}},"sao":{"id_token":[{"loc":"/:adult","method":"simple","value":true,"else":"abort"}]}}}`,
			claims:   map[string]any{"birthdate": "2000-01-01"},
			expected: `{"birthdate":"2000-01-01",":adult":true}`,
		},
		{
			name:   "ShouldAbortOnTransformedValue",
			raw:    `{"id_token":{":adult":{"value":true}},"_asc":{"transformed_claims":{"adult":{"claim":"birthdate","fn":["years_ago",["gte",18]]}},"sao":{"id_token":[{"loc":"/:adult","method":"simple","value":true,"else":"abort"}]}}}`,
			claims: map[string]any{"birthdate": "2015-01-01"},
			abort:  &asc.AbortError{Delivery: asc.DeliveryIDToken, Rule: 0},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			evaluator := newTestEvaluator()

			result, err := evaluator.Evaluate(t.Context(), mustParseClaims(t, evaluator, tc.raw), asc.DeliveryIDToken, tc.claims, nil, tc.protected)

			if tc.abort != nil {
				var aborted *asc.AbortError

				require.ErrorAs(t, err, &aborted)
				assert.Equal(t, tc.abort, aborted)
				assert.Nil(t, result)

				return
			}

			require.NoError(t, err)

			encoded, err := json.Marshal(result)
			require.NoError(t, err)

			assert.JSONEq(t, tc.expected, string(encoded))
		})
	}
}

func TestEvaluatorSourceBases(t *testing.T) {
	const get = `"_asc":{"transformed_claims":{"x":{"claim":"verified_claims","fn":[["get","claims"]]}}}`

	nested := map[string]any{"claims": map[string]any{"birthdate": "2000-01-01", "country": "DE"}}

	testCases := []struct {
		name       string
		raw        string
		predefined map[string]*oauth2.TransformedClaim
		claims     map[string]any
		sources    map[string]any
		expected   string
	}{
		{
			name:     "ShouldNotReleaseSourceObjectThroughGetOnly",
			raw:      `{"id_token":{":x":null},` + get + `}`,
			claims:   map[string]any{"sub": "peter"},
			sources:  map[string]any{"verified_claims": nested},
			expected: `{"sub":"peter"}`,
		},
		{
			name:     "ShouldTransformSourceThroughGetAndFunctions",
			raw:      `{"id_token":{":adult":null},"_asc":{"transformed_claims":{"adult":{"claim":"verified_claims","fn":[["get","claims"],["get","birthdate"],"years_ago",["gte",18]]}}}}`,
			claims:   map[string]any{"sub": "peter"},
			sources:  map[string]any{"verified_claims": nested},
			expected: `{"sub":"peter",":adult":true}`,
		},
		{
			name:     "ShouldTransformSourceThroughGetThenFunction",
			raw:      `{"id_token":{":de":null},"_asc":{"transformed_claims":{"de":{"claim":"verified_claims","fn":[["get","claims"],["get","country"],["eq","DE"]]}}}}`,
			claims:   map[string]any{},
			sources:  map[string]any{"verified_claims": nested},
			expected: `{":de":true}`,
		},
		{
			name:     "ShouldReleaseMemberOfReleasedBase",
			raw:      `{"id_token":{":c":null},"_asc":{"transformed_claims":{"c":{"claim":"address","fn":[["get","country"]]}}}}`,
			claims:   map[string]any{"address": map[string]any{"country": "GB"}},
			expected: `{"address":{"country":"GB"},":c":"GB"}`,
		},
		{
			name:       "ShouldNotWriteEmptyChainOnSourceBase",
			raw:        `{"id_token":{"::raw":null}}`,
			predefined: map[string]*oauth2.TransformedClaim{"raw": {Claim: "birthdate"}},
			claims:     map[string]any{"sub": "peter"},
			sources:    map[string]any{"birthdate": "2000-01-01"},
			expected:   `{"sub":"peter"}`,
		},
		{
			name:       "ShouldNotWriteEmptyChainOnReleasedBase",
			raw:        `{"id_token":{"::raw":null}}`,
			predefined: map[string]*oauth2.TransformedClaim{"raw": {Claim: "birthdate"}},
			claims:     map[string]any{"birthdate": "2000-01-01"},
			expected:   `{"birthdate":"2000-01-01"}`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			evaluator := newTestEvaluator()
			evaluator.Predefined = tc.predefined

			result, err := evaluator.Evaluate(t.Context(), mustParseClaims(t, evaluator, tc.raw), asc.DeliveryIDToken, tc.claims, tc.sources, nil)
			require.NoError(t, err)

			encoded, err := json.Marshal(result)
			require.NoError(t, err)

			assert.JSONEq(t, tc.expected, string(encoded))
		})
	}
}

func TestEvaluatorUnknownDelivery(t *testing.T) {
	evaluator := newTestEvaluator()

	for _, delivery := range []string{"", "UserInfo", "access_token"} {
		t.Run(delivery, func(t *testing.T) {
			result, err := evaluator.Evaluate(t.Context(), nil, delivery, map[string]any{"sub": "peter"}, nil, nil)

			var aborted *asc.AbortError

			assert.EqualError(t, err, "the delivery '"+delivery+"' is not known")
			assert.NotErrorAs(t, err, &aborted)
			assert.Nil(t, result)
		})
	}
}

func TestEvaluatorBaseIsTransformedClaim(t *testing.T) {
	const raw = `{"id_token":{":a":null,":b":null},"_asc":{"transformed_claims":{"a":{"claim":":b","fn":[["gte",18]]},"b":{"claim":"birthdate","fn":["years_ago"]}}}}`

	evaluator := newTestEvaluator()
	request := mustParseClaims(t, evaluator, raw)

	for range 50 {
		result, err := evaluator.Evaluate(t.Context(), request, asc.DeliveryIDToken, map[string]any{"birthdate": "2000-01-01"}, nil, nil)
		require.NoError(t, err)

		assert.Contains(t, result, ":b")
		assert.NotContains(t, result, ":a")
	}
}

func TestEvaluatorSpecificationExample1(t *testing.T) {
	const raw = `{"id_token":{"verified_claims":{"verification":{"trust_framework":null,"assurance_level":null},"claims":{"family_name":{"value":"nonexistent_family_name"},"given_name":null,"birthdate":null,"address":null}}},"userinfo":{"address":null},"_asc":{"sao":{"id_token":[{"loc":"/verified_claims/verification/assurance_level","method":"simple","value":"example_assurance_level","else":"abort"},{"loc":"/verified_claims/claims","method":"schema","schema":{"type":"object","properties":{"birthdate":{"type":"string","const":"1900-01-01"}}},"else":"omit"},{"loc":"/verified_claims/claims/family_name","method":"simple","value":"nonexistent_family_name","else":"omit","what":["/verified_claims"]}],"userinfo":[{"loc":"/address/postal_code","method":"exists","else":"abort"}]}}}`

	evaluator := newTestEvaluator()
	evaluator.SchemaValidator = birthdateSchemaValidator{}

	request := mustParseClaims(t, evaluator, raw)

	verified := func(level, birthdate, family string) map[string]any {
		return map[string]any{"verified_claims": map[string]any{
			"verification": map[string]any{"assurance_level": level},
			"claims":       map[string]any{"birthdate": birthdate, "family_name": family},
		}}
	}

	t.Run("ShouldAbortOnAssuranceLevel", func(t *testing.T) {
		_, err := evaluator.Evaluate(t.Context(), request, asc.DeliveryIDToken, verified("low", "1900-01-01", "nonexistent_family_name"), nil, nil)

		var aborted *asc.AbortError

		require.ErrorAs(t, err, &aborted)
		assert.Equal(t, 0, aborted.Rule)
	})

	t.Run("ShouldOmitClaimsThenVerifiedClaimsOnSchemaMismatch", func(t *testing.T) {
		result, err := evaluator.Evaluate(t.Context(), request, asc.DeliveryIDToken, verified("example_assurance_level", "2000-01-01", "nonexistent_family_name"), nil, nil)
		require.NoError(t, err)

		assert.Empty(t, result)
	})

	t.Run("ShouldOmitVerifiedClaimsOnFamilyNameMismatch", func(t *testing.T) {
		result, err := evaluator.Evaluate(t.Context(), request, asc.DeliveryIDToken, verified("example_assurance_level", "1900-01-01", "Meier"), nil, nil)
		require.NoError(t, err)

		assert.Empty(t, result)
	})

	t.Run("ShouldReleaseWhenEveryRuleIsFulfilled", func(t *testing.T) {
		claims := verified("example_assurance_level", "1900-01-01", "nonexistent_family_name")

		result, err := evaluator.Evaluate(t.Context(), request, asc.DeliveryIDToken, claims, nil, nil)
		require.NoError(t, err)

		assert.Equal(t, claims, result)
	})

	t.Run("ShouldAbortUserInfoWithoutPostalCode", func(t *testing.T) {
		_, err := evaluator.Evaluate(t.Context(), request, asc.DeliveryUserInfo, map[string]any{"address": map[string]any{"country": "GB"}}, nil, nil)

		var aborted *asc.AbortError

		require.ErrorAs(t, err, &aborted)
		assert.Equal(t, asc.DeliveryUserInfo, aborted.Delivery)
	})
}

func TestEvaluatorSchemaWithoutValidator(t *testing.T) {
	request := &oauth2.ClaimsRequest{ASC: &oauth2.ClaimsRequestASC{SAO: &oauth2.SelectiveAbortOmit{IDToken: []oauth2.SelectiveAbortOmitRule{
		{Loc: "/email", Method: oauth2.SelectiveAbortOmitMethodSchema, Schema: json.RawMessage(`{}`), Else: oauth2.SelectiveAbortOmitActionAbort},
	}}}}

	_, err := newTestEvaluator().Evaluate(t.Context(), request, asc.DeliveryIDToken, map[string]any{"email": "peter@example.com"}, nil, nil)

	var aborted *asc.AbortError

	assert.ErrorAs(t, err, &aborted)
}

func TestEvaluatorSchemaAfterOmittedArrayElement(t *testing.T) {
	const raw = `{"_asc":{"sao":{"id_token":[{"loc":"/phone","else":"omit","what":["/list/0"]},{"loc":"/list","method":"schema","schema":{},"else":"abort"}]}}}`

	validator := &recordingSchemaValidator{}

	evaluator := newTestEvaluator()
	evaluator.SchemaValidator = validator

	result, err := evaluator.Evaluate(t.Context(), mustParseClaims(t, evaluator, raw), asc.DeliveryIDToken, map[string]any{"list": []any{"a", "b"}}, nil, nil)
	require.NoError(t, err)

	assert.Equal(t, []any{[]any{"b"}}, validator.values)
	assert.Equal(t, map[string]any{"list": []any{"b"}}, result)
}

func TestEvaluatorLeavesInputsUnmodified(t *testing.T) {
	const raw = `{"id_token":{":adult":null},"_asc":{"transformed_claims":{"adult":{"claim":"birthdate","fn":["years_ago",["gte",18]]}},"sao":{"id_token":[{"loc":"/phone","else":"omit","what":["/address/country","/list/0"]}]}}}`

	evaluator := newTestEvaluator()

	claims := map[string]any{"address": map[string]any{"country": "GB"}, "list": []any{"a", "b"}}
	sources := map[string]any{"birthdate": "2000-01-01"}

	result, err := evaluator.Evaluate(t.Context(), mustParseClaims(t, evaluator, raw), asc.DeliveryIDToken, claims, sources, nil)
	require.NoError(t, err)

	assert.Equal(t, map[string]any{"address": map[string]any{}, "list": []any{"b"}, ":adult": true}, result)
	assert.Equal(t, map[string]any{"address": map[string]any{"country": "GB"}, "list": []any{"a", "b"}}, claims)
	assert.Equal(t, map[string]any{"birthdate": "2000-01-01"}, sources)
}

func TestEvaluatorWithoutAdvancedSyntax(t *testing.T) {
	evaluator := newTestEvaluator()

	claims := map[string]any{"sub": "peter", "typed": []string{"a"}}

	testCases := []struct {
		name    string
		request *oauth2.ClaimsRequest
	}{
		{name: "ShouldReturnCopyForNilRequest"},
		{name: "ShouldReturnCopyForPlainRequest", request: &oauth2.ClaimsRequest{IDToken: map[string]*oauth2.ClaimRequest{"email": nil}}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := evaluator.Evaluate(t.Context(), tc.request, asc.DeliveryIDToken, claims, nil, nil)
			require.NoError(t, err)

			assert.Equal(t, claims, result)

			result["sub"] = "changed"

			assert.Equal(t, "peter", claims["sub"])
		})
	}
}

func TestEvaluatorValidation(t *testing.T) {
	evaluator := asc.NewEvaluator()

	assert.NoError(t, evaluator.ValidateTransformedClaimFunction("gte", []any{float64(18)}))
	assert.EqualError(t, evaluator.ValidateTransformedClaimFunction("gte", nil), "expected 1 argument")
	assert.EqualError(t, evaluator.ValidateTransformedClaimFunction("reverse", nil), "the function 'reverse' is not supported")

	assert.False(t, evaluator.SupportsSchema())

	evaluator.SchemaValidator = birthdateSchemaValidator{}
	assert.True(t, evaluator.SupportsSchema())

	assert.Equal(t, []string{"all", "any", "contains", "ends_with", "eq", "get", "gt", "gte", "hash", "lt", "lte", "match", "none", "starts_with", "years_ago"}, evaluator.FunctionNames())

	var _ oauth2.ClaimsASCEvaluator = evaluator

	assert.EqualError(t, &asc.AbortError{Delivery: asc.DeliveryUserInfo, Rule: 2}, "selective abort/omit rule 2 of the 'userinfo' delivery was not fulfilled")
}

func TestEvaluatorMatchTimeout(t *testing.T) {
	const raw = `{"id_token":{":company_email":null},"_asc":{"transformed_claims":{"company_email":{"claim":"email","fn":[["match","@company\\.com$"]]}}}}`

	expired, cancel := context.WithCancel(t.Context())
	cancel()

	testCases := []struct {
		name     string
		ctx      context.Context
		timeout  time.Duration
		expected map[string]any
	}{
		{name: "ShouldMatchWithinLimit", ctx: t.Context(), timeout: time.Minute, expected: map[string]any{"email": "peter@company.com", ":company_email": true}},
		{name: "ShouldMatchWithoutLimit", ctx: expired, timeout: -1, expected: map[string]any{"email": "peter@company.com", ":company_email": true}},
		{name: "ShouldBeUnavailableWhenContextIsDone", ctx: expired, timeout: time.Minute, expected: map[string]any{"email": "peter@company.com"}},
		{name: "ShouldBeUnavailableWhenContextIsDoneWithDefaultLimit", ctx: expired, expected: map[string]any{"email": "peter@company.com"}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			evaluator := asc.NewEvaluator()
			evaluator.MatchTimeout = tc.timeout

			result, err := evaluator.Evaluate(tc.ctx, mustParseClaims(t, evaluator, raw), asc.DeliveryIDToken, map[string]any{"email": "peter@company.com"}, nil, nil)
			require.NoError(t, err)

			assert.Equal(t, tc.expected, result)
		})
	}

	assert.Equal(t, 10*time.Millisecond, asc.DefaultMatchTimeout)
}

func TestEvaluatorCustomFunction(t *testing.T) {
	evaluator := newTestEvaluator()
	evaluator.Functions["x-upper"] = upperFunction{}

	const raw = `{"id_token":{":shout":null},"_asc":{"transformed_claims":{"shout":{"claim":"name","fn":["x-upper"]}}}}`

	result, err := evaluator.Evaluate(t.Context(), mustParseClaims(t, evaluator, raw), asc.DeliveryIDToken, map[string]any{"name": "peter"}, nil, nil)
	require.NoError(t, err)

	assert.Equal(t, "PETER", result[":shout"])
}

func TestEvaluatorProtectedClaimIsNotTransformed(t *testing.T) {
	const raw = `{"id_token":{"cnf":{":x":null}},"_asc":{"transformed_claims":{"x":{"claim":"jkt","fn":[["hash","sha-256"]]}}}}`

	evaluator := newTestEvaluator()
	request := mustParseClaims(t, evaluator, raw)
	claims := map[string]any{"cnf": map[string]any{"jkt": "abc"}}

	result, err := evaluator.Evaluate(t.Context(), request, asc.DeliveryIDToken, claims, nil, []string{"cnf"})
	require.NoError(t, err)

	assert.Equal(t, map[string]any{"cnf": map[string]any{"jkt": "abc"}}, result)

	result, err = evaluator.Evaluate(t.Context(), request, asc.DeliveryIDToken, claims, nil, nil)
	require.NoError(t, err)

	assert.Equal(t, map[string]any{"jkt": "abc", ":x": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"}, result["cnf"])
}

func TestEvaluatorRuleWithUnknownMethod(t *testing.T) {
	request := &oauth2.ClaimsRequest{ASC: &oauth2.ClaimsRequestASC{SAO: &oauth2.SelectiveAbortOmit{
		IDToken: []oauth2.SelectiveAbortOmitRule{{Loc: "/email", Method: "Simple", Else: oauth2.SelectiveAbortOmitActionAbort}},
	}}}

	_, err := newTestEvaluator().Evaluate(t.Context(), request, asc.DeliveryIDToken, map[string]any{"email": "peter@example.com"}, nil, nil)

	var aborted *asc.AbortError

	require.ErrorAs(t, err, &aborted)
	assert.Equal(t, 0, aborted.Rule)
}

func newTestEvaluator() *asc.Evaluator {
	evaluator := asc.NewEvaluator()
	evaluator.MatchTimeout = time.Minute
	evaluator.Clock = func() time.Time {
		return time.Date(2026, time.October, 7, 12, 0, 0, 0, time.UTC)
	}

	return evaluator
}

func mustParseClaims(t *testing.T, evaluator *asc.Evaluator, raw string) *oauth2.ClaimsRequest {
	t.Helper()

	config := &oauth2.Config{ClaimsASC: oauth2.ClaimsASC{SelectiveAbortOmit: true, TransformedClaims: true, Evaluator: evaluator}}

	claims, err := oauth2.ParseRequestedClaims(t.Context(), config, url.Values{"claims": {raw}})
	require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

	return claims
}

type birthdateSchemaValidator struct{}

func (birthdateSchemaValidator) ValidateSchema(_ context.Context, _ json.RawMessage, value any) error {
	object, ok := value.(map[string]any)
	if !ok || object["birthdate"] != "1900-01-01" {
		return errors.New("schema does not apply")
	}

	return nil
}

type recordingSchemaValidator struct {
	values []any
}

func (v *recordingSchemaValidator) ValidateSchema(_ context.Context, _ json.RawMessage, value any) error {
	v.values = append(v.values, value)

	return nil
}

type upperFunction struct{}

func (upperFunction) Validate(args []any) error {
	if len(args) != 0 {
		return errors.New("expected no arguments")
	}

	return nil
}

func (upperFunction) Apply(_ context.Context, input any, _ []any) (any, bool) {
	s, ok := input.(string)
	if !ok {
		return nil, false
	}

	out := []byte(s)

	for i, c := range out {
		if c >= 'a' && c <= 'z' {
			out[i] = c - 32
		}
	}

	return string(out), true
}

type typedAddress struct {
	Country string `json:"country"`
}
