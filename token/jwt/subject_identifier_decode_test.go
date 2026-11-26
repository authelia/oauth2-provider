// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package jwt

import (
	"encoding/json"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSubjectIdentifierDecodeReceiver(t *testing.T) {
	testCases := []struct {
		name     string
		have     string
		expected *SubjectIdentifier
		marshal  string
	}{
		{
			"ShouldDecodeDefinedMembersOnly",
			`{"format":"iss_sub","iss":"https://issuer.example.com","sub":"1234"}`,
			&SubjectIdentifier{Format: SubjectIdentifierFormatIssuerSubject, Issuer: "https://issuer.example.com", Subject: "1234"},
			`{"format":"iss_sub","iss":"https://issuer.example.com","sub":"1234"}`,
		},
		{
			"ShouldIgnoreUndefinedMember",
			`{"format":"email","email":"user@example.com","extra":true,"id":"x","count":9007199254740993}`,
			&SubjectIdentifier{Format: SubjectIdentifierFormatEmail, Email: "user@example.com", Additional: map[string]any{"extra": true, "id": "x", "count": int64(9007199254740993)}},
			`{"format":"email","email":"user@example.com"}`,
		},
		{
			"ShouldIgnoreUndefinedMemberOfAnyType",
			`{"format":"opaque","id":"x","email":5,"user":"u"}`,
			&SubjectIdentifier{Format: SubjectIdentifierFormatOpaque, ID: "x", Additional: map[string]any{"email": int64(5), "user": "u"}},
			`{"format":"opaque","id":"x"}`,
		},
		{
			"ShouldKeepUnknownFormat",
			`{"format":"catalog_item","catalog_id":"c0384/winter/2354122"}`,
			&SubjectIdentifier{Format: "catalog_item", Additional: map[string]any{"catalog_id": "c0384/winter/2354122"}},
			`{"format":"catalog_item"}`,
		},
		{
			"ShouldKeepUnknownFormatMemberNamedAsDefinedOne",
			`{"format":"catalog_item","id":7,"email":"user@example.com"}`,
			&SubjectIdentifier{Format: "catalog_item", Additional: map[string]any{"id": int64(7), "email": "user@example.com"}},
			`{"format":"catalog_item"}`,
		},
		{
			"ShouldKeepMembersOfMissingFormat",
			`{"email":"user@example.com"}`,
			&SubjectIdentifier{Additional: map[string]any{"email": "user@example.com"}},
			`{"format":""}`,
		},
		{
			"ShouldKeepAdditionalComplexMember",
			`{"format":"complex","user":{"format":"email","email":"user@example.com","extra":1},"catalog":{"format":"catalog_item","catalog_id":"c0384"}}`,
			&SubjectIdentifier{
				Format:                          SubjectIdentifierFormatComplex,
				SubjectIdentifierComplexMembers: SubjectIdentifierComplexMembers{User: &SubjectIdentifier{Format: SubjectIdentifierFormatEmail, Email: "user@example.com", Additional: map[string]any{"extra": int64(1)}}},
				Additional:                      map[string]any{"catalog": map[string]any{"format": "catalog_item", "catalog_id": "c0384"}},
			},
			`{"format":"complex","user":{"format":"email","email":"user@example.com"}}`,
		},
		{
			"ShouldKeepUnknownFormatOfComplexMember",
			`{"format":"complex","tenant":{"format":"catalog_item","catalog_id":"c0384"},"group":null}`,
			&SubjectIdentifier{
				Format:                          SubjectIdentifierFormatComplex,
				SubjectIdentifierComplexMembers: SubjectIdentifierComplexMembers{Tenant: &SubjectIdentifier{Format: "catalog_item", Additional: map[string]any{"catalog_id": "c0384"}}},
			},
			`{"format":"complex","tenant":{"format":"catalog_item"}}`,
		},
		{
			"ShouldIgnoreUndefinedMemberOfAlias",
			`{"format":"aliases","identifiers":[{"format":"opaque","id":"x","extra":"y"},{"format":"catalog_item","catalog_id":"c0384"}]}`,
			&SubjectIdentifier{Format: SubjectIdentifierFormatAliases, Identifiers: []SubjectIdentifier{
				{Format: SubjectIdentifierFormatOpaque, ID: "x", Additional: map[string]any{"extra": "y"}},
				{Format: "catalog_item", Additional: map[string]any{"catalog_id": "c0384"}},
			}},
			`{"format":"aliases","identifiers":[{"format":"opaque","id":"x"},{"format":"catalog_item"}]}`,
		},
		{"ShouldRejectDefinedMemberOfWrongType", `{"format":"email","email":5}`, nil, ""},
		{"ShouldRejectComplexMemberOfWrongType", `{"format":"complex","user":"u"}`, nil, ""},
		{"ShouldRejectAliasOfWrongType", `{"format":"aliases","identifiers":["x"]}`, nil, ""},
		{"ShouldRejectIdentifiersOfWrongType", `{"format":"aliases","identifiers":{"format":"opaque","id":"x"}}`, nil, ""},
		{"ShouldKeepCaseFoldedMemberAsAdditional", `{"format":"email","EMAIL":"user@example.com"}`, &SubjectIdentifier{Format: SubjectIdentifierFormatEmail, Additional: map[string]any{"EMAIL": "user@example.com"}}, `{"format":"email"}`},
		{"ShouldRejectDuplicateMember", `{"format":"email","email":"a@example.com","email":"b@example.com"}`, nil, ""},
		{"ShouldRejectDuplicateUndefinedMember", `{"format":"email","email":"a@example.com","extra":1,"extra":2}`, nil, ""},
		{"ShouldRejectDuplicateMemberInAlias", `{"format":"aliases","identifiers":[{"format":"opaque","id":"x","id":"y"}]}`, nil, ""},
		{"ShouldRejectNumberFormat", `{"format":5}`, nil, ""},
		{"ShouldRejectString", `"email"`, nil, ""},
		{"ShouldRejectArray", `[]`, nil, ""},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := &SubjectIdentifier{}

			err := actual.decode([]byte(tc.have), true)

			if tc.expected == nil {
				require.ErrorIs(t, err, ErrInvalidSubjectIdentifier)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.expected, actual)

			data, err := json.Marshal(actual)

			require.NoError(t, err)
			assert.JSONEq(t, tc.marshal, string(data))
		})
	}

	t.Run("ShouldLeaveNull", func(t *testing.T) {
		actual := &SubjectIdentifier{Format: SubjectIdentifierFormatOpaque, ID: "x"}

		require.NoError(t, actual.decode([]byte(` null `), true))
		assert.Equal(t, &SubjectIdentifier{Format: SubjectIdentifierFormatOpaque, ID: "x"}, actual)
	})

	t.Run("ShouldReplaceThePreviousValue", func(t *testing.T) {
		actual := &SubjectIdentifier{Format: SubjectIdentifierFormatOpaque, ID: "x", Additional: map[string]any{"extra": true}}

		require.NoError(t, actual.decode([]byte(`{"format":"email","email":"user@example.com"}`), true))
		assert.Equal(t, &SubjectIdentifier{Format: SubjectIdentifierFormatEmail, Email: "user@example.com"}, actual)
	})
}

func TestSubjectIdentifierDecodeStrict(t *testing.T) {
	t.Run("ShouldStillRejectOnStrictPath", func(t *testing.T) {
		for _, have := range []string{
			`{"format":"email","email":"user@example.com","extra":true}`,
			`{"format":"opaque","id":"x","email":5}`,
			`{"format":"complex","user":{"format":"email","email":"user@example.com"},"catalog":{"format":"catalog_item","catalog_id":"c0384"}}`,
			`{"format":"complex","user":{"format":"email","email":"user@example.com","extra":1}}`,
			`{"format":"aliases","identifiers":[{"format":"opaque","id":"x","extra":"y"}]}`,
		} {
			actual := &SubjectIdentifier{}

			assert.ErrorIs(t, json.Unmarshal([]byte(have), actual), ErrInvalidSubjectIdentifier, have)
			assert.ErrorIs(t, actual.decode([]byte(have), false), ErrInvalidSubjectIdentifier, have)
		}
	})

	t.Run("ShouldNotSetAdditionalOnStrictPath", func(t *testing.T) {
		actual := &SubjectIdentifier{}

		require.NoError(t, json.Unmarshal([]byte(`{"format":"catalog_item","catalog_id":"c0384/winter/2354122"}`), actual))
		assert.Equal(t, &SubjectIdentifier{Format: "catalog_item"}, actual)
		assert.ErrorIs(t, actual.Validate(), ErrInvalidSubjectIdentifier)
	})

	t.Run("ShouldNotMarshalAdditional", func(t *testing.T) {
		data, err := json.Marshal(SubjectIdentifier{Format: SubjectIdentifierFormatOpaque, ID: "x", Additional: map[string]any{"extra": true}})

		require.NoError(t, err)
		assert.JSONEq(t, `{"format":"opaque","id":"x"}`, string(data))
	})
}

func TestSubjectIdentifierDecodeNesting(t *testing.T) {
	const email = `{"format":"email","email":"user@example.com"}`

	testCases := []struct {
		name     string
		have     string
		receiver bool
		strict   bool
	}{
		{"ShouldDecodeAliasesInComplex", `{"format":"complex","user":{"format":"aliases","identifiers":[` + email + `]}}`, true, true},
		{"ShouldRejectComplexInComplex", `{"format":"complex","user":{"format":"complex","user":` + email + `}}`, false, false},
		{"ShouldRejectAliasesInAliases", `{"format":"aliases","identifiers":[{"format":"aliases","identifiers":[` + email + `]}]}`, false, false},
		{"ShouldRejectComplexInAliases", `{"format":"aliases","identifiers":[{"format":"complex","user":` + email + `}]}`, false, false},
		{"ShouldRejectComplexInAliasesInComplex", `{"format":"complex","user":{"format":"aliases","identifiers":[{"format":"complex","user":` + email + `}]}}`, false, false},
		{"ShouldNotDecodeNestedMemberOfUnknownFormatOnStrictPath", `{"format":"catalog_item","user":{"format":"catalog_item","user":` + email + `}}`, true, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			for receiver, expected := range map[bool]bool{true: tc.receiver, false: tc.strict} {
				actual := &SubjectIdentifier{}

				err := actual.decode([]byte(tc.have), receiver)

				if expected {
					assert.NoError(t, err)
				} else {
					assert.ErrorIs(t, err, ErrInvalidSubjectIdentifier)
				}
			}
		})
	}

	t.Run("ShouldLeaveNestedMemberOfUnknownFormatOnStrictPath", func(t *testing.T) {
		actual := &SubjectIdentifier{}

		require.NoError(t, json.Unmarshal([]byte(`{"format":"catalog_item","email":"user@example.com","user":`+email+`,"identifiers":[`+email+`]}`), actual))
		assert.Equal(t, &SubjectIdentifier{Format: "catalog_item", Email: "user@example.com"}, actual)
	})
}

// RFC 9493 Section 3.2.8 and SSF Section 3.3 bound the nesting, so the cost of decoding is linear in the size of the
// input: twice the depth costs less than three times as much.
func TestSubjectIdentifierDecodeNestingCost(t *testing.T) {
	const depth = 1000

	testCases := []struct {
		name  string
		nest  func(depth int) string
		paths []bool
	}{
		{"ShouldRejectNestedComplex", func(depth int) string { return testNestSubjectIdentifier(`{"format":"complex","user":`, `}`, depth) }, []bool{true, false}},
		{"ShouldRejectNestedAliases", func(depth int) string {
			return testNestSubjectIdentifier(`{"format":"aliases","identifiers":[`, `]}`, depth)
		}, []bool{true, false}},
		{"ShouldNotDecodeNestedMemberOfUnknownFormat", func(depth int) string {
			return testNestSubjectIdentifier(`{"format":"catalog_item","user":`, `}`, depth)
		}, []bool{false}},
	}

	for _, tc := range testCases {
		for _, receiver := range tc.paths {
			name := tc.name + "Strict"
			if receiver {
				name = tc.name + "Receiver"
			}

			t.Run(name, func(t *testing.T) {
				allocs := func(depth int) float64 {
					data := []byte(tc.nest(depth))

					return testing.AllocsPerRun(5, func() {
						_ = (&SubjectIdentifier{}).decode(data, receiver)
					})
				}

				assert.Less(t, allocs(2*depth), 3*allocs(depth))
			})
		}
	}

	t.Run("ShouldRejectNestedSubjectOfReceivedClaims", func(t *testing.T) {
		for _, tc := range testCases[:2] {
			allocated := func(depth int) uint64 {
				payload := []byte(`{"iss":"https://issuer.example.com","jti":"1","iat":1,"aud":"a","events":{"https://example.com/event":{}},"sub_id":` + tc.nest(depth) + `}`)

				var before, after runtime.MemStats

				runtime.ReadMemStats(&before)

				for range 4 {
					_, err := ParseSecurityEventTokenClaims(payload)

					require.Error(t, err)
				}

				runtime.ReadMemStats(&after)

				return after.TotalAlloc - before.TotalAlloc
			}

			assert.Less(t, allocated(2*depth), 3*allocated(depth), tc.name)
		}
	})
}

func testNestSubjectIdentifier(open, shut string, depth int) string {
	return strings.Repeat(open, depth) + `{"format":"email","email":"user@example.com"}` + strings.Repeat(shut, depth)
}
