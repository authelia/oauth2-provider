// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package asc

import (
	"encoding/json"
	"math"
	"time"
)

const (
	minEpoch = -62135596800
	maxEpoch = 253402300799
)

type instant struct {
	time     time.Time
	datetime bool
}

func number(value any) (n float64, ok bool) {
	switch v := value.(type) {
	case float64:
		return v, true
	case json.Number:
		n, err := v.Float64()

		return n, err == nil
	case int:
		return float64(v), true
	case int64:
		return float64(v), true
	default:
		return 0, false
	}
}

// See: https://openid.net/specs/openid-connect-advanced-syntax-for-claims-1_0.html#section-8.3
func parseInstant(value any) (i instant, ok bool) {
	if text, isText := value.(string); isText {
		if t, err := time.Parse(time.DateOnly, text); err == nil {
			return instant{time: t}, true
		}

		if t, err := time.Parse(time.RFC3339, text); err == nil {
			return instant{time: t.UTC(), datetime: true}, true
		}

		return instant{}, false
	}

	if n, isNumber := number(value); isNumber && !math.IsNaN(n) && !math.IsInf(n, 0) {
		if n = math.Floor(n); n >= minEpoch && n <= maxEpoch {
			return instant{time: time.Unix(int64(n), 0).UTC(), datetime: true}, true
		}
	}

	return instant{}, false
}

func compareInstants(a, b instant) int {
	if !a.datetime || !b.datetime {
		a.time, b.time = dateOf(a.time), dateOf(b.time)
	}

	return a.time.Compare(b.time)
}

func dateOf(t time.Time) time.Time {
	year, month, day := t.Date()

	return time.Date(year, month, day, 0, 0, 0, 0, time.UTC)
}

func equal(a, b any) bool {
	if an, ok := number(a); ok {
		bn, ok := number(b)

		return ok && an == bn
	}

	switch av := a.(type) {
	case string:
		bv, ok := b.(string)

		return ok && av == bv
	case bool:
		bv, ok := b.(bool)

		return ok && av == bv
	default:
		return false
	}
}

func isScalar(value any) bool {
	switch value.(type) {
	case string, bool:
		return true
	default:
		_, ok := number(value)

		return ok
	}
}
