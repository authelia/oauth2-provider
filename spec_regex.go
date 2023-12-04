package goauth2

import (
	"regexp"
)

var (
	// RegexSpecificationVSCHAR matches strings which only contain the ASCII visible printable
	// range %x20-7E per https://datatracker.ietf.org/doc/html/rfc6749#appendix-A i.e. VSCHAR. Presumably the Visible
	// with Spaces characters.
	RegexSpecificationVSCHAR = regexp.MustCompile(`^[\pL\pM\pN\pP\pS ]+$`)

	// RegexSpecificationNQCHAR matches strings which only contain the ASCII visible printable
	// ranges %x21 / %x23-5B / %x5D-7E per https://datatracker.ietf.org/doc/html/rfc6749#appendix-A i.e. NQCHAR.
	// Presumably the Non-Quoted character range.
	RegexSpecificationNQCHAR = regexp.MustCompile(`^[\pL\pM\pN\pS!#-@_\[\]{}]+$`)

	// RegexSpecificationNQSCHAR matches strings which only contain the ASCII visible printable
	// ranges %x20-21 / %x23-5B / %x5D-7E per https://datatracker.ietf.org/doc/html/rfc6749#appendix-A i.e. NQSCHAR.
	// Presumably the Non-Quoted with Spaces character range.
	RegexSpecificationNQSCHAR = regexp.MustCompile(`^[\pL\pM\pN\pS!#-@_\[\]{}]+$`)
)
