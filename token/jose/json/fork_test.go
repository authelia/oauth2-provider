// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package json

import (
	"bytes"
	"errors"
	"math"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"
)

// This file covers the behaviour that makes this package a fork of the standard
// library's encoding/json, rather than a copy of it. See the package README.

// TestForkCaseSensitive verifies that object member names are matched
// case-sensitively, unlike the standard library which falls back to a
// case-insensitive match.
func TestForkCaseSensitive(t *testing.T) {
	type S struct {
		Alpha string `json:"alpha"`
		Beta  string // no tag; matched by field name
	}

	tests := []struct {
		name      string
		in        string
		wantAlpha string
		wantBeta  string
	}{
		{"exact tag", `{"alpha":"a"}`, "a", ""},
		{"exact field name", `{"Beta":"b"}`, "", "b"},
		{"upper tag does not match", `{"ALPHA":"a"}`, "", ""},
		{"title tag does not match", `{"Alpha":"a"}`, "", ""},
		{"lower field name does not match", `{"beta":"b"}`, "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var s S
			if err := Unmarshal([]byte(tt.in), &s); err != nil {
				t.Fatalf("Unmarshal error: %v", err)
			}
			if s.Alpha != tt.wantAlpha || s.Beta != tt.wantBeta {
				t.Errorf("got {Alpha:%q Beta:%q}, want {Alpha:%q Beta:%q}",
					s.Alpha, s.Beta, tt.wantAlpha, tt.wantBeta)
			}
		})
	}
}

// TestForkDuplicateKeys verifies that duplicate object members are rejected
// rather than silently resolved to the last occurrence.
func TestForkDuplicateKeys(t *testing.T) {
	tests := []struct {
		name string
		in   string
		ptr  func() any
	}{
		{"struct", `{"alpha":"a","alpha":"b"}`, func() any {
			return &struct {
				Alpha string `json:"alpha"`
			}{}
		}},
		{"interface", `{"alpha":"a","alpha":"b"}`, func() any { var v any; return &v }},
		{"map", `{"alpha":"a","alpha":"b"}`, func() any { return &map[string]string{} }},
		{"nested in object", `{"outer":{"k":1,"k":2}}`, func() any { var v any; return &v }},
		{"nested in array", `[{"k":1,"k":2}]`, func() any { var v any; return &v }},
		{"duplicate null", `{"I":0,"I":null}`, func() any { var v any; return &v }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Unmarshal([]byte(tt.in), tt.ptr())
			if err == nil {
				t.Fatalf("Unmarshal(%s) succeeded, want duplicate key error", tt.in)
			}
			if !strings.Contains(err.Error(), "duplicate key") {
				t.Fatalf("Unmarshal(%s) error = %v, want a duplicate key error", tt.in, err)
			}
		})
	}
}

// TestForkDuplicateKeysAccepted verifies the fork does not over-reject: the same
// member name at different nesting levels is not a duplicate.
func TestForkDuplicateKeysAccepted(t *testing.T) {
	for _, in := range []string{
		`{"a":1,"b":2}`,
		`{"k":{"k":1}}`,
		`{"a":[{"k":1},{"k":2}]}`,
	} {
		var v any
		if err := Unmarshal([]byte(in), &v); err != nil {
			t.Errorf("Unmarshal(%s) error = %v, want nil", in, err)
		}
	}
}

// TestForkNumberType verifies Decoder.SetNumberType, which controls how a JSON
// number is unmarshaled into an interface value.
func TestForkNumberType(t *testing.T) {
	tests := []struct {
		name       string
		in         string
		numberType NumberUnmarshalType
		want       any
	}{
		{"default is float64", `2`, UnmarshalFloat, float64(2)},
		{"json number", `2`, UnmarshalJSONNumber, Number("2")},
		{"int or float: integer", `2`, UnmarshalIntOrFloat, int64(2)},
		{"int or float: fraction", `2.1`, UnmarshalIntOrFloat, float64(2.1)},
		{"int or float: scientific whole", `1.5e2`, UnmarshalIntOrFloat, int64(150)},
		{"int or float: max int64", `9223372036854775807`, UnmarshalIntOrFloat, int64(9223372036854775807)},
		{"int or float: whole with zero fraction", `9007199254740992.000000`, UnmarshalIntOrFloat, int64(9007199254740992)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got any
			dec := NewDecoder(bytes.NewReader([]byte(tt.in)))
			dec.SetNumberType(tt.numberType)
			if err := dec.Decode(&got); err != nil {
				t.Fatalf("Decode error: %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Decode(%s) = %#v (%T), want %#v (%T)", tt.in, got, got, tt.want, tt.want)
			}
		})
	}
}

// TestForkUseNumber verifies the deprecated UseNumber remains equivalent to
// SetNumberType(UnmarshalJSONNumber).
func TestForkUseNumber(t *testing.T) {
	var got any
	dec := NewDecoder(bytes.NewReader([]byte(`2`)))
	dec.UseNumber()
	if err := dec.Decode(&got); err != nil {
		t.Fatalf("Decode error: %v", err)
	}
	if want := Number("2"); got != want {
		t.Errorf("Decode = %#v, want %#v", got, want)
	}
}

func TestForkUnquoteErrors(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []byte
		err  error
	}{
		{"plain", `"abc"`, []byte("abc"), nil},
		{"escape", `"a\nb"`, []byte("a\nb"), nil},
		{"unicode escape", `"aéb"`, []byte("aéb"), nil},
		{"surrogate pair", `"😀"`, []byte("\U0001f600"), nil},
		{"lone surrogate", `"\ud83d"`, []byte("�"), nil},
		{"unterminated", `"abc`, nil, errPhase},
		{"not a literal", `abc`, nil, errPhase},
		{"bad escape", `"a\xb"`, nil, errPhase},
		{"truncated escape", `"a\`, nil, errPhase},
		{"short unicode escape", `"\u00"`, nil, errPhase},
		{"raw control character", "\"a\x01b\"", nil, errPhase},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := unquoteBytes([]byte(tt.in))
			if !errors.Is(err, tt.err) {
				t.Fatalf("unquoteBytes(%q) error = %v, want %v", tt.in, err, tt.err)
			}
			if tt.err != nil {
				return
			}
			if !bytes.Equal(got, tt.want) {
				t.Errorf("unquoteBytes(%q) = %q, want %q", tt.in, got, tt.want)
			}
			s, err := unquote([]byte(tt.in))
			if err != nil || s != string(tt.want) {
				t.Errorf("unquote(%q) = %q, %v, want %q, nil", tt.in, s, err, tt.want)
			}
		})
	}
}

func TestForkUnquoteSizeBounds(t *testing.T) {
	if sized := maxUnquoteInitial + 2*utf8.UTFMax; sized < 0 || sized > math.MaxInt {
		t.Errorf("maxUnquoteInitial %d overflows when sized: got %d", maxUnquoteInitial, sized)
	}

	if grown := (maxUnquoteRegrow + utf8.UTFMax) * 2; grown < 0 || grown > math.MaxInt {
		t.Errorf("maxUnquoteRegrow %d overflows when doubled: got %d", maxUnquoteRegrow, grown)
	}
}

func TestForkIndentSizeBounds(t *testing.T) {
	if factored := indentGrowthFactor * maxIndentHint; factored < 0 || factored > math.MaxInt {
		t.Errorf("maxIndentHint %d overflows when multiplied: got %d", maxIndentHint, factored)
	}
}

func TestForkQuoteChar(t *testing.T) {
	stdlib := func(c byte) string {
		// special cases - different from quoted strings
		if c == '\'' {
			return `'\''`
		}
		if c == '"' {
			return `'"'`
		}

		// use quoted string with different quotation marks
		s := strconv.Quote(string(c))
		return "'" + s[1:len(s)-1] + "'"
	}

	for i := 0; i < 256; i++ {
		c := byte(i)
		got, want := quoteChar(c), stdlib(c)
		if got != want {
			t.Errorf("quoteChar(%#02x) = %s, want %s", c, got, want)
		}
		if body := got[1 : len(got)-1]; strings.Count(body, `'`) != strings.Count(body, `\'`) {
			t.Errorf("quoteChar(%#02x) = %s contains an unescaped quote", c, got)
		}
	}
}
