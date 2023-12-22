package reflection

import (
	"errors"
	"fmt"
	"reflect"
)

func GetField(obj any, name string) (any, error) {
	if !hasValidType(obj, []reflect.Kind{reflect.Struct, reflect.Ptr}) {
		return nil, errors.New("Cannot use GetField on a non-struct interface")
	}

	objValue := reflectValue(obj)
	field := objValue.FieldByName(name)
	if !field.IsValid() {
		return nil, fmt.Errorf("No such field: %s in obj", name)
	}

	return field.Interface(), nil
}

func hasValidType(obj any, types []reflect.Kind) bool {
	for _, t := range types {
		if reflect.TypeOf(obj).Kind() == t {
			return true
		}
	}

	return false
}

func reflectValue(obj any) reflect.Value {
	var val reflect.Value

	if reflect.TypeOf(obj).Kind() == reflect.Ptr {
		val = reflect.ValueOf(obj).Elem()
	} else {
		val = reflect.ValueOf(obj)
	}

	return val
}
