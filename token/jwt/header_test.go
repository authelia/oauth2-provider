// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package jwt

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

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