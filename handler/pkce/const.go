package pkce

import "regexp"

var (
	verifierWrongFormat = regexp.MustCompile(`[^\w.~-]`)
)
