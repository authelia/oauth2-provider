// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package reflection

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetField(t *testing.T) {
	value := 1

	testCases := []struct {
		name     string
		obj      any
		field    string
		expected any
		err      string
	}{
		{
			name:     "ShouldReturnFieldFromStruct",
			obj:      testStruct{Exported: fieldValue},
			field:    fieldExported,
			expected: fieldValue,
		},
		{
			name:     "ShouldReturnFieldFromStructPointer",
			obj:      &testStruct{Exported: fieldValue},
			field:    fieldExported,
			expected: fieldValue,
		},
		{
			name:  "ShouldRejectMissingField",
			obj:   testStruct{},
			field: "Missing",
			err:   "no such field: Missing in obj",
		},
		{
			name:  "ShouldRejectNil",
			obj:   nil,
			field: fieldExported,
			err:   errNonStruct,
		},
		{
			name:  "ShouldRejectTypedNilPointer",
			obj:   (*testStruct)(nil),
			field: fieldExported,
			err:   "cannot use GetField on a nil pointer",
		},
		{
			name:  "ShouldRejectPointerToNonStruct",
			obj:   &value,
			field: fieldExported,
			err:   errNonStruct,
		},
		{
			name:  "ShouldRejectNonStruct",
			obj:   value,
			field: fieldExported,
			err:   errNonStruct,
		},
		{
			name:  "ShouldRejectUnexportedField",
			obj:   testStruct{unexported: fieldValue},
			field: "unexported",
			err:   "cannot use GetField on unexported field: unexported in obj",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var (
				actual any
				err    error
			)

			require.NotPanics(t, func() {
				actual, err = GetField(tc.obj, tc.field)
			})

			if tc.err != "" {
				assert.EqualError(t, err, tc.err)
				assert.Nil(t, actual)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expected, actual)
			}
		})
	}
}

type testStruct struct {
	Exported   string
	unexported string
}

const (
	fieldExported = "Exported"
	fieldValue    = "value"
	errNonStruct  = "cannot use GetField on a non-struct interface"
)
