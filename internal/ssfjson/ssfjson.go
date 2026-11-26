// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

// Package ssfjson provides the strict JSON and Retry-After helpers shared by the Shared Signals Framework transmitter
// and receiver.
package ssfjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
)

// MaxRetryAfter is the bound of the delay RetryAfter returns.
const MaxRetryAfter = 5 * time.Minute

const jsonNull = "null"

// ParseObject returns the members of a single JSON object by their exact names. A repeated name is an error.
func ParseObject(data []byte) (members map[string]json.RawMessage, err error) {
	_, members, err = ParseOrderedObject(data)

	return members, err
}

// ParseOrderedObject returns the members of a single JSON object by their exact names, and the names in the order of
// the object. A repeated name is an error.
func ParseOrderedObject(data []byte) (names []string, members map[string]json.RawMessage, err error) {
	decoder := json.NewDecoder(bytes.NewReader(data))

	var token json.Token

	if token, err = decoder.Token(); err != nil {
		return nil, nil, err
	}

	if token != json.Delim('{') {
		return nil, nil, errors.New("the value is not a JSON object")
	}

	members = map[string]json.RawMessage{}

	for decoder.More() {
		if token, err = decoder.Token(); err != nil {
			return nil, nil, err
		}

		name, ok := token.(string)
		if !ok {
			return nil, nil, errors.New("the member name is not a string")
		}

		if _, ok = members[name]; ok {
			return nil, nil, errors.New("a member name is repeated")
		}

		var value json.RawMessage

		if err = decoder.Decode(&value); err != nil {
			return nil, nil, err
		}

		names, members[name] = append(names, name), value
	}

	if _, err = decoder.Token(); err != nil {
		return nil, nil, err
	}

	if _, err = decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, nil, errors.New("the value is followed by more data")
	}

	return names, members, nil
}

// UnmarshalMembers decodes the members of a single JSON object into the targets by their exact names, in the order of
// the names. A repeated name is an error, whether or not it has a target, and a member without a target is ignored. A
// null in place of the object decodes nothing, as [json.Unmarshal] does.
func UnmarshalMembers(data []byte, targets map[string]any) (err error) {
	if string(bytes.TrimSpace(data)) == jsonNull {
		return nil
	}

	var members map[string]json.RawMessage

	if members, err = ParseObject(data); err != nil {
		return err
	}

	for _, name := range slices.Sorted(maps.Keys(targets)) {
		value, ok := members[name]
		if !ok {
			continue
		}

		if err = json.Unmarshal(value, targets[name]); err != nil {
			return fmt.Errorf("the '%s' member is not valid: %w", name, err)
		}
	}

	return nil
}

// Member returns the named member, which is absent when it is null.
func Member(members map[string]json.RawMessage, name string) (value json.RawMessage, ok bool) {
	if value, ok = members[name]; !ok || string(value) == jsonNull {
		return nil, false
	}

	return value, true
}

// ParseString returns the value of a JSON string. Any other JSON value, null included, is not a string.
func ParseString(data json.RawMessage) (value string, ok bool) {
	if len(data) == 0 || data[0] != '"' {
		return "", false
	}

	if json.Unmarshal(data, &value) != nil {
		return "", false
	}

	return value, true
}

// IsNumber reports whether the JSON value is a number.
func IsNumber(data json.RawMessage) (ok bool) {
	return len(data) != 0 && (data[0] == '-' || (data[0] >= '0' && data[0] <= '9'))
}

// RetryAfter parses a Retry-After delay in seconds or an HTTP date, bounded to MaxRetryAfter.
//
// See: https://www.rfc-editor.org/rfc/rfc9110.html#section-10.2.3
func RetryAfter(value string, now time.Time) (d time.Duration) {
	value = strings.TrimSpace(value)

	if value == "" {
		return 0
	}

	// RFC 9110 Section 10.2.3: delay-seconds is 1*DIGIT, so it has no sign.
	if !strings.ContainsFunc(value, func(r rune) bool { return r < '0' || r > '9' }) {
		seconds, err := strconv.ParseUint(value, 10, 64)

		// A value out of range is still bounded rather than dropped.
		if err != nil || seconds > uint64(MaxRetryAfter/time.Second) {
			return MaxRetryAfter
		}

		return time.Duration(seconds) * time.Second
	}

	at, err := http.ParseTime(value)
	if err != nil {
		return 0
	}

	switch d = at.Sub(now); {
	case d <= 0:
		return 0
	case d > MaxRetryAfter:
		return MaxRetryAfter
	default:
		return d
	}
}
