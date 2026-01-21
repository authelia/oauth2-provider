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

func Now() *NumericDate {
	return NewNumericDate(TimeFunc())
}

func NewNumericDate(t time.Time) *NumericDate {
	return &NumericDate{t.UTC().Truncate(TimePrecision)}
}

func newNumericDateFromSeconds(f float64) *NumericDate {
	round, frac := math.Modf(f)

	return NewNumericDate(time.Unix(int64(round), int64(frac*1e9)))
}

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

func (date *NumericDate) UnmarshalJSON(b []byte) (err error) {
	var (
		number json.Number
		f      float64
	)

	if err = json.Unmarshal(b, &number); err != nil {
		return fmt.Errorf("could not parse NumericData: %w", err)
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

func (s ClaimStrings) MarshalJSON() (b []byte, err error) {
	if len(s) == 1 && !MarshalSingleStringAsArray {
		return json.Marshal(s[0])
	}

	return json.Marshal([]string(s))
}

var (
	ErrInvalidType = errors.New("invalid type for claim")
)
