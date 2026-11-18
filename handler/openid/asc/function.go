// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package asc

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"math"
	"regexp"
	"strings"
	"time"
)

// Function is a transformation function of a Transformed Claim. It must use nothing but the input, the arguments, and
// information which is public, and must be safe for every input and argument.
//
// See: https://openid.net/specs/openid-connect-advanced-syntax-for-claims-1_0.html#section-8.4.8
type Function interface {
	// Validate returns an error when the static arguments are wrong in number or type.
	Validate(args []any) (err error)

	// Apply returns the output for the input. It returns false when the resulting claim is unavailable.
	Apply(ctx context.Context, input any, args []any) (output any, ok bool)
}

const (
	maxPatternLength = 1000

	hashSHA256 = "sha-256"
	hashSHA512 = "sha-512"
)

type function struct {
	prepare func(args []any) (prepared any, err error)
	apply   func(input, prepared any) (any, bool)
	whole   bool
}

func (f function) Validate(args []any) error {
	_, err := f.prepare(args)

	return err
}

func (f function) Apply(_ context.Context, input any, args []any) (any, bool) {
	prepared, err := f.prepare(args)
	if err != nil {
		return nil, false
	}

	items, ok := input.([]any)
	if !ok || f.whole {
		return f.apply(input, prepared)
	}

	output := make([]any, len(items))

	for i, item := range items {
		if output[i], ok = f.apply(item, prepared); !ok {
			return nil, false
		}
	}

	return output, true
}

type limited struct {
	Function

	limit func() time.Duration
}

type limitedResult struct {
	output any
	ok     bool
}

// See: https://openid.net/specs/openid-connect-advanced-syntax-for-claims-1_0.html#section-8.4.7
func (f limited) Apply(ctx context.Context, input any, args []any) (output any, ok bool) {
	limit := f.limit()

	if limit < 0 {
		return f.Function.Apply(ctx, input, args)
	}

	if ctx.Err() != nil {
		return nil, false
	}

	done := make(chan limitedResult, 1)

	go func() {
		output, ok := f.Function.Apply(ctx, input, args)

		done <- limitedResult{output: output, ok: ok}
	}()

	timer := time.NewTimer(limit)
	defer timer.Stop()

	select {
	case result := <-done:
		return result.output, result.ok
	case <-timer.C:
		return nil, false
	case <-ctx.Done():
		return nil, false
	}
}

// See: https://openid.net/specs/openid-connect-advanced-syntax-for-claims-1_0.html#section-8.4
func functions(clock func() time.Time, limit func() time.Duration) map[string]Function {
	return map[string]Function{
		"years_ago":   function{prepare: prepareYearsAgo, apply: yearsAgo(clock)},
		"eq":          function{prepare: prepareScalar, apply: equality},
		"contains":    function{prepare: prepareString, apply: text(strings.Contains)},
		"starts_with": function{prepare: prepareString, apply: text(strings.HasPrefix)},
		"ends_with":   function{prepare: prepareString, apply: text(strings.HasSuffix)},
		"gt":          function{prepare: prepareOrdered, apply: comparison(func(c int) bool { return c > 0 })},
		"lt":          function{prepare: prepareOrdered, apply: comparison(func(c int) bool { return c < 0 })},
		"gte":         function{prepare: prepareOrdered, apply: comparison(func(c int) bool { return c >= 0 })},
		"lte":         function{prepare: prepareOrdered, apply: comparison(func(c int) bool { return c <= 0 })},
		"hash":        function{prepare: prepareHash, apply: hash},
		"any":         function{prepare: prepareNone, apply: booleans(func(trues, count int) bool { return trues > 0 }), whole: true},
		"all":         function{prepare: prepareNone, apply: booleans(func(trues, count int) bool { return trues == count }), whole: true},
		"none":        function{prepare: prepareNone, apply: booleans(func(trues, count int) bool { return trues == 0 }), whole: true},
		"get":         function{prepare: prepareString, apply: get, whole: true},
		"match":       limited{Function: function{prepare: prepareMatch, apply: match}, limit: limit},
	}
}

type ordered struct {
	n       float64
	number  bool
	instant instant
}

func prepareNone(args []any) (any, error) {
	if len(args) != 0 {
		return nil, errors.New("expected no arguments")
	}

	return nil, nil
}

func prepareOne(args []any) (any, error) {
	if len(args) != 1 {
		return nil, errors.New("expected 1 argument")
	}

	return args[0], nil
}

func prepareString(args []any) (any, error) {
	arg, err := prepareOne(args)
	if err != nil {
		return nil, err
	}

	s, ok := arg.(string)
	if !ok {
		return nil, errors.New("the argument must be a string")
	}

	return s, nil
}

func prepareScalar(args []any) (any, error) {
	arg, err := prepareOne(args)
	if err != nil {
		return nil, err
	}

	if !isScalar(arg) {
		return nil, errors.New("the argument must be a string, number or boolean")
	}

	return arg, nil
}

func prepareOrdered(args []any) (any, error) {
	arg, err := prepareOne(args)
	if err != nil {
		return nil, err
	}

	if n, ok := number(arg); ok {
		if math.IsNaN(n) || math.IsInf(n, 0) {
			return nil, errors.New("the argument must be a number, date or datetime")
		}

		return ordered{n: n, number: true}, nil
	}

	if _, ok := arg.(string); ok {
		if i, ok := parseInstant(arg); ok {
			return ordered{instant: i}, nil
		}
	}

	return nil, errors.New("the argument must be a number, date or datetime")
}

func prepareYearsAgo(args []any) (any, error) {
	switch len(args) {
	case 0:
		return (*instant)(nil), nil
	case 1:
		if text, ok := args[0].(string); ok {
			if t, err := time.Parse(time.DateOnly, text); err == nil {
				return &instant{time: t}, nil
			}
		}

		return nil, errors.New("the argument must be a date")
	default:
		return nil, errors.New("expected at most 1 argument")
	}
}

func prepareHash(args []any) (any, error) {
	arg, err := prepareString(args)
	if err != nil {
		return nil, err
	}

	switch arg {
	case hashSHA256, hashSHA512:
		return arg, nil
	default:
		return nil, errors.New("the argument must be 'sha-256' or 'sha-512'")
	}
}

func prepareMatch(args []any) (any, error) {
	arg, err := prepareString(args)
	if err != nil {
		return nil, err
	}

	pattern := arg.(string)

	if len(pattern) > maxPatternLength {
		return nil, errors.New("the argument must be a regular expression of at most 1000 bytes")
	}

	expression, err := regexp.Compile(pattern)
	if err != nil {
		return nil, errors.New("the argument must be a regular expression")
	}

	return expression, nil
}

// See: https://openid.net/specs/openid-connect-advanced-syntax-for-claims-1_0.html#section-8.4.1
func yearsAgo(clock func() time.Time) func(input, prepared any) (any, bool) {
	return func(input, prepared any) (any, bool) {
		reference, ok := prepared.(*instant)
		if !ok {
			return nil, false
		}

		from, ok := parseInstant(input)
		if !ok || from.time.Year() == 0 {
			return nil, false
		}

		to := clock().UTC()

		if reference != nil {
			to = reference.time
		}

		years := to.Year() - from.time.Year()

		if to.Month() < from.time.Month() || (to.Month() == from.time.Month() && to.Day() < from.time.Day()) {
			years--
		}

		return float64(years), true
	}
}

// A number argument is compared as a number only, and a date or datetime argument is a string.
//
// See: https://openid.net/specs/openid-connect-advanced-syntax-for-claims-1_0.html#section-8.4.2
func equality(input, prepared any) (any, bool) {
	switch arg := prepared.(type) {
	case string:
		if b, ok := parseInstant(arg); ok {
			if a, ok := parseInstant(input); ok {
				return compareInstants(a, b) == 0, true
			}
		}

		s, ok := input.(string)

		return s == arg, ok
	case bool:
		b, ok := input.(bool)

		return b == arg, ok
	default:
		b, ok := number(prepared)
		if !ok {
			return nil, false
		}

		a, ok := number(input)

		return a == b, ok
	}
}

func text(compare func(s, sub string) bool) func(input, prepared any) (any, bool) {
	return func(input, prepared any) (any, bool) {
		s, ok := input.(string)
		if !ok {
			return nil, false
		}

		sub, ok := prepared.(string)
		if !ok {
			return nil, false
		}

		return compare(s, sub), true
	}
}

// A number argument is compared as a number only, and a date or datetime argument is a string.
//
// See: https://openid.net/specs/openid-connect-advanced-syntax-for-claims-1_0.html#section-8.4.3
func comparison(satisfied func(c int) bool) func(input, prepared any) (any, bool) {
	return func(input, prepared any) (any, bool) {
		arg, ok := prepared.(ordered)
		if !ok {
			return nil, false
		}

		if !arg.number {
			a, ok := parseInstant(input)
			if !ok {
				return nil, false
			}

			return satisfied(compareInstants(a, arg.instant)), true
		}

		a, ok := number(input)

		switch {
		case !ok, math.IsNaN(a):
			return nil, false
		case a < arg.n:
			return satisfied(-1), true
		case a > arg.n:
			return satisfied(1), true
		default:
			return satisfied(0), true
		}
	}
}

// See: https://openid.net/specs/openid-connect-advanced-syntax-for-claims-1_0.html#section-8.4.4
func hash(input, prepared any) (any, bool) {
	s, ok := input.(string)
	if !ok {
		return nil, false
	}

	switch prepared {
	case hashSHA512:
		sum := sha512.Sum512([]byte(s))

		return hex.EncodeToString(sum[:]), true
	case hashSHA256:
		sum := sha256.Sum256([]byte(s))

		return hex.EncodeToString(sum[:]), true
	default:
		return nil, false
	}
}

// See: https://openid.net/specs/openid-connect-advanced-syntax-for-claims-1_0.html#section-8.4.5
func booleans(satisfied func(trues, count int) bool) func(input, prepared any) (any, bool) {
	return func(input, _ any) (any, bool) {
		items, ok := input.([]any)
		if !ok {
			return nil, false
		}

		trues := 0

		for _, item := range items {
			value, ok := item.(bool)
			if !ok {
				return nil, false
			}

			if value {
				trues++
			}
		}

		return satisfied(trues, len(items)), true
	}
}

// See: https://openid.net/specs/openid-connect-advanced-syntax-for-claims-1_0.html#section-8.4.6
func get(input, prepared any) (any, bool) {
	object, ok := input.(map[string]any)
	if !ok {
		return nil, false
	}

	name, ok := prepared.(string)
	if !ok {
		return nil, false
	}

	value, ok := object[name]

	return value, ok
}

// The regexp package matches in time linear in the size of the input, and the operation is abandoned at the time
// limit of the Evaluator.
//
// See: https://openid.net/specs/openid-connect-advanced-syntax-for-claims-1_0.html#section-8.4.7
func match(input, prepared any) (any, bool) {
	s, ok := input.(string)
	if !ok {
		return nil, false
	}

	expression, ok := prepared.(*regexp.Regexp)
	if !ok {
		return nil, false
	}

	return expression.MatchString(s), true
}
