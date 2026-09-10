// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package clone

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMap(t *testing.T) {
	testCases := []struct {
		name  string
		check func(t *testing.T)
	}{
		{
			name: "ShouldReturnNilForNil",
			check: func(t *testing.T) {
				assert.Nil(t, Map(nil))
			},
		},
		{
			name: "ShouldReturnNonNilForEmpty",
			check: func(t *testing.T) {
				actual := Map(map[string]any{})

				assert.NotNil(t, actual)
				assert.Empty(t, actual)
			},
		},
		{
			name: "ShouldDeepCopyNestedValues",
			check: func(t *testing.T) {
				original := map[string]any{
					"string":  "value",
					"number":  float64(1),
					"object":  map[string]any{"key": "value"},
					"array":   []any{"a", map[string]any{"key": "value"}},
					"strings": []string{"a", "b"},
				}

				actual := Map(original)

				assert.Equal(t, original, actual)

				original["string"] = "changed"
				original["object"].(map[string]any)["key"] = "changed"
				original["array"].([]any)[0] = "changed"
				original["array"].([]any)[1].(map[string]any)["key"] = "changed"
				original["strings"].([]string)[0] = "changed"

				assert.Equal(t, map[string]any{
					"string":  "value",
					"number":  float64(1),
					"object":  map[string]any{"key": "value"},
					"array":   []any{"a", map[string]any{"key": "value"}},
					"strings": []string{"a", "b"},
				}, actual)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, tc.check)
	}
}

func TestSlice(t *testing.T) {
	testCases := []struct {
		name  string
		check func(t *testing.T)
	}{
		{
			name: "ShouldReturnNilForNil",
			check: func(t *testing.T) {
				assert.Nil(t, Slice(nil))
			},
		},
		{
			name: "ShouldReturnNonNilForEmpty",
			check: func(t *testing.T) {
				actual := Slice([]any{})

				assert.NotNil(t, actual)
				assert.Empty(t, actual)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, tc.check)
	}
}

func TestValue(t *testing.T) {
	testCases := []struct {
		name     string
		have     any
		expected any
	}{
		{"ShouldReturnNil", nil, nil},
		{"ShouldReturnString", "value", "value"},
		{"ShouldReturnBool", true, true},
		{"ShouldPreserveTypedNilMap", map[string]any(nil), map[string]any(nil)},
		{"ShouldPreserveTypedNilSlice", []any(nil), []any(nil)},
		{"ShouldPreserveTypedNilStrings", []string(nil), []string(nil)},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, Value(tc.have))
		})
	}
}
