// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"go/ast"
	"go/parser"
	"go/token"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSingleValuedRequestParametersClassifyEveryFormParameter(t *testing.T) {
	// RFC 8707 Section 2 and RFC 8693 Section 2.1 define 'resource' and 'audience' as repeatable.
	repeatable := []string{"resource", "audience"}

	responses := []string{"error", "error_description", "error_hint", "error_uri", "iss", "session_state", "issued_token_type", "response", "logout_token"}

	values := formParameterValues(t)

	require.NotEmpty(t, values)

	for _, value := range values {
		single := slices.Contains(singleValuedRequestParameters, value)

		switch {
		case slices.Contains(repeatable, value):
			assert.False(t, single, "the repeatable parameter '%s' is listed as single-valued", value)
		case slices.Contains(responses, value):
			assert.False(t, single, "the response parameter '%s' is listed as single-valued", value)
		default:
			assert.True(t, single, "the request parameter '%s' is not classified as single-valued, repeatable or a response parameter", value)
		}
	}
}

func TestValidateRequestQueryAndBodyParametersNotRepeated(t *testing.T) {
	testCases := []struct {
		name     string
		target   string
		body     url.Values
		form     url.Values
		repeated bool
	}{
		{name: "ShouldAcceptAParameterInTheQuery", target: "/?user_code=ABCD"},
		{name: "ShouldAcceptTheSameParameterInTheQueryAndTheBody", target: "/?user_code=ABCD", body: url.Values{"user_code": {"ABCD"}}},
		{name: "ShouldAcceptDifferentValuesInTheQueryAndTheBody", target: "/?user_code=ABCD", body: url.Values{"user_code": {"wdjb-mjht"}}},
		{name: "ShouldRejectARepeatInTheQuery", target: "/?user_code=ABCD&user_code=EFGH", repeated: true},
		{name: "ShouldRejectARepeatInTheBody", target: "/", body: url.Values{"user_code": {"ABCD", "EFGH"}}, repeated: true},
		{name: "ShouldRejectARepeatInAFormSetWithoutParsing", form: url.Values{"user_code": {"ABCD", "EFGH"}}, repeated: true},
		{name: "ShouldAcceptAFormSetWithoutParsing", form: url.Values{"user_code": {"ABCD"}}},
		{name: "ShouldAcceptARepeatedParameterWhichIsNotSingleValued", target: "/?resource=https://a.example.com&resource=https://b.example.com"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var r *http.Request

			if tc.form != nil {
				r = &http.Request{Form: tc.form}
			} else {
				r = httptest.NewRequest(http.MethodPost, tc.target, strings.NewReader(tc.body.Encode()))
				r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

				require.NoError(t, r.ParseForm())
			}

			err := validateRequestQueryAndBodyParametersNotRepeated(r)

			if tc.repeated {
				assert.ErrorIs(t, err, ErrInvalidRequest)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func formParameterValues(t *testing.T) (values []string) {
	t.Helper()

	entries, err := os.ReadDir("internal/consts")
	require.NoError(t, err)

	literals := map[string]string{}
	identifiers := map[string]string{}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}

		file, err := parser.ParseFile(token.NewFileSet(), filepath.Join("internal/consts", entry.Name()), nil, 0)
		require.NoError(t, err)

		ast.Inspect(file, func(node ast.Node) bool {
			spec, ok := node.(*ast.ValueSpec)
			if !ok {
				return true
			}

			for i, name := range spec.Names {
				if i >= len(spec.Values) {
					continue
				}

				switch value := spec.Values[i].(type) {
				case *ast.BasicLit:
					unquoted, err := strconv.Unquote(value.Value)
					require.NoError(t, err)

					literals[name.Name] = unquoted
				case *ast.Ident:
					identifiers[name.Name] = value.Name
				}
			}

			return true
		})
	}

	for name := range maps.Keys(literals) {
		if strings.HasPrefix(name, "FormParameter") {
			values = append(values, literals[name])
		}
	}

	for name, identifier := range identifiers {
		if !strings.HasPrefix(name, "FormParameter") {
			continue
		}

		value, ok := literals[identifier]
		require.True(t, ok, "the value of '%s' could not be resolved", name)

		values = append(values, value)
	}

	return values
}
