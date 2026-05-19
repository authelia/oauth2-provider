// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package jwt

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewHeaders(t *testing.T) {
	h := NewHeaders()

	assert.NotNil(t, h)
	assert.NotNil(t, h.Extra)
	assert.Empty(t, h.Extra)
}

func TestHeaders_ToMap(t *testing.T) {
	testCases := []struct {
		name     string
		extra    map[string]any
		add      map[string]any
		expected map[string]any
	}{
		{
			name:     "ShouldReturnAddedValue",
			add:      map[string]any{"foo": "bar"},
			expected: map[string]any{"foo": "bar"},
		},
		{
			name:     "ShouldReturnEmptyMapWhenNoExtra",
			expected: map[string]any{},
		},
		{
			name:     "ShouldMergeAddAndExtra",
			extra:    map[string]any{"abc": 1},
			add:      map[string]any{"foo": "bar"},
			expected: map[string]any{"abc": 1, "foo": "bar"},
		},
		{
			name:     "ShouldFilterAlgorithmHeader",
			extra:    map[string]any{JSONWebTokenHeaderAlgorithm: "RS256", "kid": "abc"},
			expected: map[string]any{"kid": "abc"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			header := &Headers{Extra: tc.extra}

			for k, v := range tc.add {
				header.Add(k, v)
			}

			for k, v := range tc.add {
				assert.Equal(t, v, header.Get(k))
			}

			assert.Equal(t, tc.expected, header.ToMap())
		})
	}
}

func TestHeaders_Get(t *testing.T) {
	h := &Headers{Extra: map[string]any{"foo": "bar"}}

	assert.Equal(t, "bar", h.Get("foo"))
	assert.Nil(t, h.Get("missing"))
}

func TestHeaders_ToMapClaims(t *testing.T) {
	h := Headers{Extra: map[string]any{
		JSONWebTokenHeaderAlgorithm: "RS256",
		"kid":                       "abc",
	}}

	mc := h.ToMapClaims()
	assert.Equal(t, MapClaims{"kid": "abc"}, mc)
}

func TestHeaders_SetDefaultString(t *testing.T) {
	testCases := []struct {
		name     string
		initial  map[string]any
		key      string
		value    string
		expected any
	}{
		{
			name:     "ShouldInitializeExtraWhenNil",
			initial:  nil,
			key:      "kid",
			value:    "abc",
			expected: "abc",
		},
		{
			name:     "ShouldSetValueWhenKeyMissing",
			initial:  map[string]any{"other": "value"},
			key:      "kid",
			value:    "abc",
			expected: "abc",
		},
		{
			name:     "ShouldKeepExistingNonEmptyString",
			initial:  map[string]any{"kid": "existing"},
			key:      "kid",
			value:    "abc",
			expected: "existing",
		},
		{
			name:     "ShouldOverwriteEmptyString",
			initial:  map[string]any{"kid": ""},
			key:      "kid",
			value:    "abc",
			expected: "abc",
		},
		{
			name:     "ShouldOverwriteNonStringValue",
			initial:  map[string]any{"kid": 123},
			key:      "kid",
			value:    "abc",
			expected: "abc",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			h := &Headers{Extra: tc.initial}
			h.SetDefaultString(tc.key, tc.value)
			assert.Equal(t, tc.expected, h.Extra[tc.key])
		})
	}
}
