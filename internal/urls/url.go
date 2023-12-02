package urls

import (
	"net/url"
)

// IsRequestURL checks if the string rawurl, assuming
// it was received in an HTTP request, is a valid
// URL confirm to RFC 3986
func IsRequestURL(raw string) bool {
	url, err := url.ParseRequestURI(raw)
	if err != nil {
		return false //Couldn't even parse the rawurl
	}
	if len(url.Scheme) == 0 {
		return false //No Scheme found
	}
	return true
}
