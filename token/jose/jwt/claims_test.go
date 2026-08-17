/*-
 * Copyright 2016 Zbigniew Mandziejewicz
 * Copyright 2016 Square, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package jwt

import (
	"math"
	"testing"
	"time"

	"authelia.com/provider/oauth2/token/jose/json"
	"authelia.com/provider/oauth2/token/jose/testutils/assert"
)

func TestEncodeClaims(t *testing.T) {
	now := time.Date(2016, 1, 1, 0, 0, 0, 0, time.UTC)

	c := Claims{
		Issuer:    "issuer",
		Subject:   "subject",
		Audience:  Audience{"a1", "a2"},
		NotBefore: NewNumericDate(time.Time{}),
		IssuedAt:  NewNumericDate(now),
		Expiry:    NewNumericDate(now.Add(1 * time.Hour)),
	}

	b, err := json.Marshal(c)
	assert.NoError(t, err)

	expected := `{"iss":"issuer","sub":"subject","aud":["a1","a2"],"exp":1451610000,"iat":1451606400}`
	assert.Equal(t, expected, string(b))
}

func TestEncodeClaimsWithSingleAudience(t *testing.T) {
	now := time.Date(2016, 1, 1, 0, 0, 0, 0, time.UTC)

	c := Claims{
		Issuer:    "issuer",
		Subject:   "subject",
		Audience:  Audience{"a1"},
		NotBefore: NewNumericDate(time.Time{}),
		IssuedAt:  NewNumericDate(now),
		Expiry:    NewNumericDate(now.Add(1 * time.Hour)),
	}

	b, err := json.Marshal(c)
	assert.NoError(t, err)

	expected := `{"iss":"issuer","sub":"subject","aud":"a1","exp":1451610000,"iat":1451606400}`
	assert.Equal(t, expected, string(b))
}

func TestDecodeClaims(t *testing.T) {
	s := []byte(`{"iss":"issuer","sub":"subject","aud":["a1","a2"],"exp":1451610000,"iat":1451606400}`)
	now := time.Date(2016, 1, 1, 0, 0, 0, 0, time.UTC)

	c := Claims{}
	if err := json.Unmarshal(s, &c); assert.NoError(t, err) {
		assert.Equal(t, "issuer", c.Issuer)
		assert.Equal(t, "subject", c.Subject)
		assert.EqualSlice(t, Audience{"a1", "a2"}, c.Audience)
		if !now.Equal(c.IssuedAt.Time()) {
			t.Errorf("IssuedAt = %s, want %s", c.IssuedAt.Time(), now)
		}
		if !now.Add(1 * time.Hour).Equal(c.Expiry.Time()) {
			t.Errorf("Expiry = %s, want %s", c.Expiry.Time(), now.Add(1*time.Hour))
		}
	}

	s2 := []byte(`{"aud": "a1"}`)
	c2 := Claims{}
	if err := json.Unmarshal(s2, &c2); assert.NoError(t, err) {
		assert.EqualSlice(t, Audience{"a1"}, c2.Audience)
	}

	invalid := []struct {
		Raw string
		Err error
	}{
		{`{"aud": 5}`, ErrUnmarshalAudience},
		{`{"aud": ["foo", 5, "bar"]}`, ErrUnmarshalAudience},
		{`{"exp": "invalid"}`, ErrUnmarshalNumericDate},
	}

	for _, v := range invalid {
		c := Claims{}
		assert.Equal(t, v.Err, json.Unmarshal([]byte(v.Raw), &c))
	}
}

func TestNumericDate(t *testing.T) {
	zeroDate := NewNumericDate(time.Time{})
	if !zeroDate.Time().Equal(time.Time{}) {
		t.Errorf("zeroDate.Time() = %s, want %s", zeroDate.Time(), time.Time{})
	}

	zeroDate2 := (*NumericDate)(nil)
	if !zeroDate2.Time().Equal(time.Time{}) {
		t.Errorf("zeroDate2.Time() = %s, want %s", zeroDate2.Time(), time.Time{})
	}

	nonZeroDate := NewNumericDate(time.Unix(0, 0))
	expected := time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC)
	if !nonZeroDate.Time().Equal(expected) {
		t.Errorf("nonZeroDate.Time() = %s, want %s", nonZeroDate.Time(), expected)
	}
}

// A NumericDate is an int64 number of seconds. Converting a float64 which falls outside the range of an int64 is
// implementation-dependent in Go, so such values must be rejected rather than silently truncated to whatever the
// platform happens to produce.
func TestNumericDateUnmarshalRejectsValuesOutOfRange(t *testing.T) {
	testCases := []struct {
		name string
		have string
		err  error
	}{
		{"ShouldRejectLargePositive", `1e300`, ErrNumericDateOutOfRange},
		{"ShouldRejectLargeNegative", `-1e300`, ErrNumericDateOutOfRange},
		{"ShouldRejectMaxInt64Exceeded", `9223372036854775808`, ErrNumericDateOutOfRange},
		{"ShouldRejectMinInt64Exceeded", `-9223372036854775809`, ErrNumericDateOutOfRange},
		{"ShouldRejectNaN", `NaN`, ErrUnmarshalNumericDate},
		{"ShouldRejectInf", `Inf`, ErrUnmarshalNumericDate},
		{"ShouldRejectNegativeInf", `-Inf`, ErrUnmarshalNumericDate},
		{"ShouldRejectOutOfFloatRange", `1e400`, ErrUnmarshalNumericDate},
		{"ShouldRejectString", `"invalid"`, ErrUnmarshalNumericDate},
		{"ShouldParseEpoch", `0`, nil},
		{"ShouldParseFractional", `1.5`, nil},
		{"ShouldParseNegative", `-1700000000`, nil},
		{"ShouldParseSeconds", `1700000000`, nil},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var date NumericDate

			assert.Equal(t, tc.err, date.UnmarshalJSON([]byte(tc.have)))
		})
	}
}

// time.Unix stores seconds relative to year 1, so a large positive number of seconds since the epoch overflows and
// wraps around to a time in the past. Ordering must be preserved so that a date in the future never compares as one
// in the past, which would silently skip the nbf and iat checks.
func TestNumericDateTimeDoesNotWrapAround(t *testing.T) {
	now := time.Date(2026, 8, 17, 0, 0, 0, 0, time.UTC)

	testCases := []struct {
		name   string
		have   NumericDate
		future bool
	}{
		{"ShouldOrderMaxInt64AsFuture", NumericDate(math.MaxInt64), true},
		{"ShouldOrderMinInt64AsPast", NumericDate(math.MinInt64), false},
		{"ShouldOrderYear9999AsFuture", NumericDate(253402300799), true},
		{"ShouldOrderEpochAsPast", NumericDate(0), false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.have.Time().After(now), tc.future)
			assert.Equal(t, tc.have.Time().Before(now), !tc.future)
		})
	}
}

// A token which is not valid until a date beyond the representable range must not be accepted before that date.
func TestValidateRejectsNotBeforeOutOfRange(t *testing.T) {
	now := time.Date(2026, 8, 17, 0, 0, 0, 0, time.UTC)

	notBefore := NumericDate(math.MaxInt64)
	c := Claims{NotBefore: &notBefore}

	assert.Equal(t, ErrNotValidYet, c.ValidateWithLeeway(Expected{Time: now}, 0))
}

func TestEncodeClaimsTimeValues(t *testing.T) {
	now := time.Date(2016, 1, 1, 0, 0, 0, 0, time.UTC)

	c := Claims{
		NotBefore: NewNumericDate(time.Time{}),
		IssuedAt:  NewNumericDate(time.Unix(0, 0)),
		Expiry:    NewNumericDate(now),
	}

	b, err := json.Marshal(c)
	assert.NoError(t, err)

	expected := `{"exp":1451606400,"iat":0}`
	assert.Equal(t, expected, string(b))

	c2 := Claims{}
	if err := json.Unmarshal(b, &c2); assert.NoError(t, err) {
		if !c.NotBefore.Time().Equal(c2.NotBefore.Time()) {
			t.Errorf("c2.NotBefore = %s, want %s", c2.NotBefore.Time(), c.NotBefore.Time())
		}
		if !c.IssuedAt.Time().Equal(c2.IssuedAt.Time()) {
			t.Errorf("c2.IssuedAt = %s, want %s", c2.IssuedAt.Time(), c.IssuedAt.Time())
		}
		if !c.Expiry.Time().Equal(c2.Expiry.Time()) {
			t.Errorf("c2.Expiry = %s, want %s", c2.Expiry.Time(), c.Expiry.Time())
		}
	}
}
