package urls

import (
	"net/url"
)

// IsRequestURL checks if the string raw, assuming
// it was received in an HTTP request, is a valid
// URL confirm to RFC 3986.
func IsRequestURL(raw string) bool {
	if uri, err := url.ParseRequestURI(raw); err != nil {
		return false
	} else {
		return uri.IsAbs()
	}
}
