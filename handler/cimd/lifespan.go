// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package cimd

import (
	"errors"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	maxDeltaSeconds = uint64(math.MaxInt64 / time.Second)
)

type cachePolicy struct {
	lifespan   time.Duration
	store      bool
	revalidate bool
}

func newCachePolicy(header http.Header, now time.Time, maximum, fallback time.Duration) (policy cachePolicy) {
	var (
		noCache, hasMaxAge, hasSharedMaxAge bool
		maxAge, sharedMaxAge                time.Duration
		seen                                = map[string]bool{}
	)

	policy.store = true

	for _, value := range header.Values("Cache-Control") {
		for _, directive := range strings.Split(value, ",") {
			name, argument, qualified := strings.Cut(strings.TrimSpace(directive), "=")

			if name = strings.ToLower(strings.TrimSpace(name)); seen[name] {
				continue
			}

			seen[name] = true

			switch name {
			case "no-store":
				policy.store = false
			case "private":
				policy.store = policy.store && qualified
			case "no-cache":
				noCache = !qualified
			case "must-revalidate", "proxy-revalidate":
				policy.revalidate = true
			case "max-age":
				hasMaxAge, maxAge = true, deltaSeconds(argument, maximum)
			case "s-maxage":
				hasSharedMaxAge, sharedMaxAge = true, deltaSeconds(argument, maximum)
				policy.revalidate = true
			}
		}
	}

	var freshness time.Duration

	switch {
	case noCache:
		policy.revalidate = true
	case hasSharedMaxAge:
		freshness = sharedMaxAge - age(header)
	case hasMaxAge:
		freshness = maxAge - age(header)
	case len(header.Values("Expires")) != 0:
		freshness = expires(header, now)
	default:
		freshness = fallback
	}

	policy.lifespan = min(max(freshness, 0), maximum)

	return policy
}

func age(header http.Header) (d time.Duration) {
	seconds, err := strconv.ParseUint(strings.TrimSpace(header.Get("Age")), 10, 32)
	if err != nil {
		return 0
	}

	return time.Duration(seconds) * time.Second
}

func expires(header http.Header, now time.Time) (d time.Duration) {
	value, err := http.ParseTime(header.Get("Expires"))
	if err != nil {
		return 0
	}

	if date, err := http.ParseTime(header.Get("Date")); err == nil {
		now = date
	}

	return value.Sub(now)
}

func deltaSeconds(argument string, maximum time.Duration) (d time.Duration) {
	seconds, err := strconv.ParseUint(strings.Trim(strings.TrimSpace(argument), `"`), 10, 63)

	switch {
	case errors.Is(err, strconv.ErrRange):
		return maximum
	case err != nil:
		return 0
	}

	if seconds > maxDeltaSeconds {
		return maximum
	}

	return min(time.Duration(seconds)*time.Second, maximum)
}
