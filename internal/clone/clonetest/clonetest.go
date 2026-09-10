// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

// Package clonetest asserts that a hand-written Clone is a complete deep copy.
package clonetest

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
)

// AssertDeepCopy asserts that cloned is equal to original and that the two share no map, slice, or pointer. Every
// exported struct field reachable from original must be non-zero, so a field added later fails here until the test
// populates it, at which point a Clone that does not copy it fails the equality or sharing check.
func AssertDeepCopy(t *testing.T, original, cloned any) {
	t.Helper()

	assertPopulated(t, reflect.ValueOf(original), reflect.TypeOf(original).String())
	assert.Equal(t, original, cloned)
	assertDisjoint(t, reflect.ValueOf(original), reflect.ValueOf(cloned), reflect.TypeOf(original).String())
}

func assertPopulated(t *testing.T, v reflect.Value, path string) {
	t.Helper()

	switch v.Kind() {
	case reflect.Pointer, reflect.Interface:
		if !v.IsNil() {
			assertPopulated(t, v.Elem(), path)
		}
	case reflect.Map:
		iter := v.MapRange()

		for iter.Next() {
			assertPopulated(t, iter.Value(), path+"["+iter.Key().String()+"]")
		}
	case reflect.Slice:
		for i := range v.Len() {
			assertPopulated(t, v.Index(i), path+"[]")
		}
	case reflect.Struct:
		for i := range v.NumField() {
			field := v.Type().Field(i)

			if !field.IsExported() {
				continue
			}

			fieldPath := path + "." + field.Name

			if v.Field(i).IsZero() {
				t.Errorf("%s is zero: populate it so its clone is checked", fieldPath)

				continue
			}

			assertPopulated(t, v.Field(i), fieldPath)
		}
	}
}

func assertDisjoint(t *testing.T, a, b reflect.Value, path string) {
	t.Helper()

	if !a.IsValid() || !b.IsValid() || a.Type() != b.Type() || assertNotShared(t, a, b, path) {
		return
	}

	switch a.Kind() {
	case reflect.Pointer, reflect.Interface:
		if !a.IsNil() && !b.IsNil() {
			assertDisjoint(t, a.Elem(), b.Elem(), path)
		}
	case reflect.Map:
		iter := a.MapRange()

		for iter.Next() {
			assertDisjoint(t, iter.Value(), b.MapIndex(iter.Key()), path+"["+iter.Key().String()+"]")
		}
	case reflect.Slice:
		for i := range min(a.Len(), b.Len()) {
			assertDisjoint(t, a.Index(i), b.Index(i), path+"[]")
		}
	case reflect.Struct:
		for i := range a.NumField() {
			if field := a.Type().Field(i); field.IsExported() {
				assertDisjoint(t, a.Field(i), b.Field(i), path+"."+field.Name)
			}
		}
	}
}

// assertNotShared fails t and returns true when a and b are pointers, maps, or slices that refer to the same memory.
func assertNotShared(t *testing.T, a, b reflect.Value, path string) (shared bool) {
	t.Helper()

	switch a.Kind() {
	case reflect.Pointer, reflect.Map, reflect.Slice:
		if isEmpty(a) || isEmpty(b) || a.Pointer() != b.Pointer() {
			return false
		}

		t.Errorf("%s is shared between the original and the clone", path)

		return true
	default:
		return false
	}
}

// isEmpty reports whether v, a pointer, map, or slice, has no memory for a clone to share.
func isEmpty(v reflect.Value) bool {
	if v.Kind() == reflect.Slice {
		return v.Len() == 0
	}

	return v.IsNil()
}
