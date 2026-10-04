// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/hashicorp/go-retryablehttp"
)

// StringInSlice returns true if needle exists in haystack
func StringInSlice(needle string, haystack []string) bool {
	return slices.Contains(haystack, needle)
}

// StringInSliceFold returns true if needle exists in haystack (case-insensitive).
func StringInSliceFold(needle string, haystack []string) bool {
	for _, b := range haystack {
		if strings.EqualFold(b, needle) {
			return true
		}
	}
	return false
}

// RemoveEmpty returns a new slice containing the non-empty, whitespace-trimmed entries of args. It is commonly used to
// normalize space-delimited OAuth 2.0 parameters such as 'scope', 'audience', and 'prompt'.
func RemoveEmpty(args []string) (ret []string) {
	for _, v := range args {
		v = strings.TrimSpace(v)
		if v != "" {
			ret = append(ret, v)
		}
	}
	return
}

// EscapeJSONString does a poor man's JSON encoding. Useful when we do not want to use full JSON encoding
// because we just had an error doing the JSON encoding. The characters that MUST be escaped: quotation mark,
// reverse solidus, and the control characters (U+0000 through U+001F).
// See: https://datatracker.ietf.org/doc/html/rfc8259#section-7
func EscapeJSONString(str string) string {
	// Escape reverse solidus.
	str = strings.ReplaceAll(str, `\`, `\\`)

	// Escape control characters.
	for r := range ' ' {
		str = strings.ReplaceAll(str, string(r), fmt.Sprintf(`\u%04x`, r))
	}

	// Escape quotation mark.
	str = strings.ReplaceAll(str, `"`, `\"`)

	return str
}

// DeviceAuthorizeStatusToString returns a human-readable label for the RFC 8628 device authorization status, or
// "Invalid" for unknown values.
func DeviceAuthorizeStatusToString(status DeviceAuthorizeStatus) string {
	switch status {
	case DeviceAuthorizeStatusApproved:
		return "Approved"
	case DeviceAuthorizeStatusDenied:
		return "Denied"
	case DeviceAuthorizeStatusNew:
		return "New"
	default:
		return "Invalid"
	}
}

// MaxFetchedBodyBytes bounds the number of bytes read from a response to a fetch of a client-supplied URI, being a
// 'jwks_uri' or a 'request_uri'. RFC 9101 Section 10.4.1 names a "request_uri" returning "extremely large content" as
// a denial of service against the authorization server; the same reasoning covers a 'jwks_uri'.
//
// See: https://www.rfc-editor.org/rfc/rfc9101#section-10.4.1
const MaxFetchedBodyBytes = 1 << 20

// HTTPClientWithoutRedirects returns a copy of client that refuses to follow HTTP redirects, returning the first
// redirect response as-is. client itself, typically the shared instance, is not mutated: the copy is built from its
// exported fields, and its unexported sync.Once guards are not copied.
func HTTPClientWithoutRedirects(client *retryablehttp.Client) (scoped *retryablehttp.Client) {
	refuseRedirect := func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	inner := &http.Client{CheckRedirect: refuseRedirect}

	if client.HTTPClient != nil {
		innerCopy := *client.HTTPClient
		innerCopy.CheckRedirect = refuseRedirect
		inner = &innerCopy
	}

	return &retryablehttp.Client{
		HTTPClient:      inner,
		Logger:          client.Logger,
		RetryWaitMin:    client.RetryWaitMin,
		RetryWaitMax:    client.RetryWaitMax,
		RetryMax:        client.RetryMax,
		RequestLogHook:  client.RequestLogHook,
		ResponseLogHook: client.ResponseLogHook,
		CheckRetry:      client.CheckRetry,
		Backoff:         client.Backoff,
		ErrorHandler:    client.ErrorHandler,
		PrepareRetry:    client.PrepareRetry,
	}
}
