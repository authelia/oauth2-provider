// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package reflection

import (
	"reflect"
)

// IsNil reports whether v is a nil interface or an interface holding a nil value of a nilable kind.
func IsNil(v any) bool {
	if v == nil {
		return true
	}

	switch rv := reflect.ValueOf(v); rv.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return rv.IsNil()
	default:
		return false
	}
}
