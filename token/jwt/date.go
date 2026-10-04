// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package jwt

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"time"
)

type NumericDate struct {
	time.Time
}

// Now returns a NumericDate for the current time.
func Now() *NumericDate {
	return NewNumericDate(time.Now())
}

// NewNumericDate returns a NumericDate for t in UTC truncated to TimePrecision.
func NewNumericDate(t time.Time) *NumericDate {
	return &NumericDate{t.UTC().Truncate(TimePrecision)}
}

func (date *NumericDate) clone() *NumericDate {
	if date == nil {
		return nil
	}

	cloned := *date

	return &cloned
}

func newNumericDateFromSeconds(f float64) *NumericDate {
	round, frac := math.Modf(f)

	return NewNumericDate(time.Unix(int64(round), int64(frac*1e9)))
}

// MarshalJSON encodes the date as a JSON number of seconds since the Unix epoch, with fractional digits when
// TimePrecision is finer than a second.
func (date NumericDate) MarshalJSON() (b []byte, err error) {
	var prec int

	if TimePrecision < time.Second {
		prec = int(math.Log10(float64(time.Second) / float64(TimePrecision)))
	}

	truncatedDate := date.UTC().Truncate(TimePrecision)

	seconds := strconv.FormatInt(truncatedDate.Unix(), 10)
	nanosecondsOffset := strconv.FormatFloat(float64(truncatedDate.Nanosecond())/float64(time.Second), 'f', prec, 64)

	output := append([]byte(seconds), []byte(nanosecondsOffset)[1:]...)

	return output, nil
}

// UnmarshalJSON decodes a JSON number of seconds since the Unix epoch, which may have a fractional part.
func (date *NumericDate) UnmarshalJSON(b []byte) (err error) {
	var (
		number json.Number
		f      float64
	)

	if err = json.Unmarshal(b, &number); err != nil {
		return fmt.Errorf("could not parse NumericDate: %w", err)
	}

	if f, err = number.Float64(); err != nil {
		return fmt.Errorf("could not convert json number value to float: %w", err)
	}

	n := newNumericDateFromSeconds(f)
	*date = *n

	return nil
}

// Int64 returns the time value with UTC as the location, truncated with TimePrecision; as a number of
// since the Unix epoch.
func (date *NumericDate) Int64() (val int64) {
	if date == nil {
		return 0
	}

	return date.UTC().Truncate(TimePrecision).Unix()
}

type ClaimStrings []string

// Valid reports whether any of the values is equal to cmp, using a constant time comparison. When there are no values
// it returns true only if required is false.
func (s ClaimStrings) Valid(cmp string, required bool) (valid bool) {
	if len(s) == 0 {
		return !required
	}

	for _, str := range s {
		if subtle.ConstantTimeCompare([]byte(str), []byte(cmp)) == 1 {
			return true
		}
	}

	return false
}

// ValidAny reports whether any of the values is equal to any value in cmp, using a constant time comparison. When there
// are no values it returns true only if required is false.
func (s ClaimStrings) ValidAny(cmp ClaimStrings, required bool) (valid bool) {
	if len(s) == 0 {
		return !required
	}

	for _, strCmp := range cmp {
		for _, str := range s {
			if subtle.ConstantTimeCompare([]byte(str), []byte(strCmp)) == 1 {
				return true
			}
		}
	}

	return false
}

// ValidAll reports whether every value in cmp is equal to one of the values, using a constant time comparison. When
// there are no values it returns true only if required is false.
func (s ClaimStrings) ValidAll(cmp ClaimStrings, required bool) (valid bool) {
	if len(s) == 0 {
		return !required
	}

outer:
	for _, strCmp := range cmp {
		for _, str := range s {
			if subtle.ConstantTimeCompare([]byte(str), []byte(strCmp)) == 1 {
				continue outer
			}
		}

		return false
	}

	return true
}

// UnmarshalJSON decodes a JSON string or a JSON array of strings, and returns ErrInvalidType for any other value. A
// JSON null leaves the values unchanged.
func (s *ClaimStrings) UnmarshalJSON(data []byte) (err error) {
	var value interface{}

	if err = json.Unmarshal(data, &value); err != nil {
		return err
	}

	var aud []string

	switch v := value.(type) {
	case string:
		aud = append(aud, v)
	case []string:
		aud = ClaimStrings(v)
	case []interface{}:
		for _, vv := range v {
			vs, ok := vv.(string)
			if !ok {
				return ErrInvalidType
			}
			aud = append(aud, vs)
		}
	case nil:
		return nil
	default:
		return ErrInvalidType
	}

	*s = aud

	return
}

// MarshalJSON encodes the values as a JSON array, or as a JSON string when there is a single value and
// MarshalSingleStringAsArray is false.
func (s ClaimStrings) MarshalJSON() (b []byte, err error) {
	if len(s) == 1 && !MarshalSingleStringAsArray {
		return json.Marshal(s[0])
	}

	return json.Marshal([]string(s))
}

var (
	ErrInvalidType = errors.New("invalid type for claim")
)
