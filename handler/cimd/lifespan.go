// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package cimd

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func lifespan(header http.Header, now time.Time, minimum, maximum, fallback time.Duration) (d time.Duration) {
	return min(max(freshness(header, now, minimum, maximum, fallback), minimum), maximum)
}

func freshness(header http.Header, now time.Time, minimum, maximum, fallback time.Duration) (d time.Duration) {
	var (
		age          time.Duration
		maxAge       = time.Duration(-1)
		sharedMaxAge = time.Duration(-1)
	)

	// The authorization server is a shared cache, so 'private' is not stored and 's-maxage' replaces 'max-age'.
	//
	// See: https://www.rfc-editor.org/rfc/rfc9111#section-5.2.2
	for _, value := range header.Values("Cache-Control") {
		for _, directive := range strings.Split(value, ",") {
			name, argument, _ := strings.Cut(strings.TrimSpace(directive), "=")

			switch strings.ToLower(strings.TrimSpace(name)) {
			case "no-store", "no-cache", "private":
				return minimum
			case "max-age":
				if seconds, ok := deltaSeconds(argument, maximum); ok {
					maxAge = seconds
				}
			case "s-maxage":
				if seconds, ok := deltaSeconds(argument, maximum); ok {
					sharedMaxAge = seconds
				}
			}
		}
	}

	if sharedMaxAge >= 0 {
		maxAge = sharedMaxAge
	}

	if maxAge >= 0 {
		if seconds, err := strconv.ParseUint(strings.TrimSpace(header.Get("Age")), 10, 32); err == nil {
			age = time.Duration(seconds) * time.Second
		}

		return maxAge - age
	}

	// See: https://www.rfc-editor.org/rfc/rfc9111#section-5.3
	if value := header.Get("Expires"); value != "" {
		expires, err := http.ParseTime(value)
		if err != nil {
			return minimum
		}

		if date, err := http.ParseTime(header.Get("Date")); err == nil {
			now = date
		}

		return expires.Sub(now)
	}

	return fallback
}

func deltaSeconds(argument string, maximum time.Duration) (d time.Duration, ok bool) {
	seconds, err := strconv.ParseUint(strings.Trim(strings.TrimSpace(argument), `"`), 10, 64)

	switch {
	case errors.Is(err, strconv.ErrRange):
		return maximum, true
	case err != nil:
		return 0, false
	case seconds > uint64(maximum/time.Second):
		return maximum, true
	default:
		return time.Duration(seconds) * time.Second, true
	}
}
