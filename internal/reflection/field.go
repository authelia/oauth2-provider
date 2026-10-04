// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package reflection

import (
	"errors"
	"fmt"
	"reflect"
)

func GetField(obj any, name string) (any, error) {
	objValue := reflect.ValueOf(obj)

	if objValue.Kind() == reflect.Pointer {
		if objValue.IsNil() {
			return nil, errors.New("cannot use GetField on a nil pointer")
		}

		objValue = objValue.Elem()
	}

	if objValue.Kind() != reflect.Struct {
		return nil, errors.New("cannot use GetField on a non-struct interface")
	}

	field := objValue.FieldByName(name)
	if !field.IsValid() {
		return nil, fmt.Errorf("no such field: %s in obj", name)
	}

	if !field.CanInterface() {
		return nil, fmt.Errorf("cannot use GetField on unexported field: %s in obj", name)
	}

	return field.Interface(), nil
}
