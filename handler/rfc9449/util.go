package rfc9449

import (
	"bytes"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/x/errorsx"
)

func singleDPoPHeader(r *http.Request) (header string, err error) {
	if len(r.Header.Values(consts.HeaderDPoP)) > 1 {
		return "", errorsx.WithStack(oauth2.ErrInvalidDPoPProof.WithHint("The request contains more than one DPoP proof but only one is allowed."))
	}

	return r.Header.Get(consts.HeaderDPoP), nil
}

// requestURL reconstructs the request target URI (htu) from the request. It lives in the core package so the pushed
// authorization request endpoint, which is handled there, reconstructs the htu identically; see oauth2.RequestURL for
// the scheme and path caveats.
func requestURL(r *http.Request) string {
	return oauth2.RequestURL(r)
}

// normalizeHTU prepares an absolute URI for the RFC 9449 4.3 'htu' comparison. RFC 9449 requires servers to apply
// syntax-based normalization (RFC 3986 Section 6.2.2) and scheme-based normalization (RFC 3986 Section 6.2.3) before
// comparing, and to compare ignoring the query and fragment parts.
func normalizeHTU(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}

	if u.Scheme == "" || u.Host == "" {
		return "", errors.New("the URI is not absolute")
	}

	u.RawQuery = ""
	u.Fragment = ""
	u.RawFragment = ""
	u.ForceQuery = false

	// RFC 3986 6.2.2.1: the scheme and host are case-insensitive.
	u.Scheme = strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Host)

	// RFC 3986 6.2.3: an empty port and the scheme's default port are equivalent to no port at all.
	if (u.Scheme == consts.SchemeHTTPS && strings.HasSuffix(host, ":443")) || (u.Scheme == consts.SchemeHTTP && strings.HasSuffix(host, ":80")) {
		host = host[:strings.LastIndex(host, ":")]
	}

	u.Host = host

	// RFC 3986 6.2.2.2 then 6.2.2.3, in that order: decoding the percent-encoded unreserved characters first is what
	// makes an encoded dot-segment such as '/%2E%2E/' visible to the segment normalization that follows. Both operate
	// on the escaped path so that an encoded delimiter (notably '%2F') is never conflated with a real one.
	path := removeDotSegments(normalizePercentEncoding(u.EscapedPath()))

	// RFC 3986 6.2.3: for http(s) an empty path is equivalent to '/'.
	if path == "" {
		path = "/"
	}

	if u.Path, err = url.PathUnescape(path); err != nil {
		return "", err
	}

	u.RawPath = path

	return u.String(), nil
}

const upperhex = "0123456789ABCDEF"

// normalizePercentEncoding applies RFC 3986 Section 6.2.2.1 and 6.2.2.2 to an escaped path: the hexadecimal digits of
// a percent-encoding triplet are upper-cased, and a triplet encoding an unreserved character is decoded to it.
func normalizePercentEncoding(path string) string {
	var b strings.Builder

	b.Grow(len(path))

	for i := 0; i < len(path); i++ {
		if path[i] != '%' || i+2 >= len(path) || !ishex(path[i+1]) || !ishex(path[i+2]) {
			b.WriteByte(path[i])

			continue
		}

		c := unhex(path[i+1])<<4 | unhex(path[i+2])

		if isunreserved(c) {
			b.WriteByte(c)
		} else {
			b.WriteByte('%')
			b.WriteByte(upperhex[c>>4])
			b.WriteByte(upperhex[c&0xF])
		}

		i += 2
	}

	return b.String()
}

// removeDotSegments implements the RFC 3986 Section 5.2.4 algorithm used by the path segment normalization of Section
// 6.2.2.3. Unlike path.Clean it preserves a trailing slash and empty segments, both of which are significant.
func removeDotSegments(path string) string {
	out := make([]byte, 0, len(path))

	for len(path) > 0 {
		switch {
		case strings.HasPrefix(path, "../"):
			path = path[3:]
		case strings.HasPrefix(path, "./"):
			path = path[2:]
		case strings.HasPrefix(path, "/./"):
			path = path[2:]
		case path == "/.":
			path = "/"
		case strings.HasPrefix(path, "/../"):
			path = path[3:]
			out = removeLastSegment(out)
		case path == "/..":
			path = "/"
			out = removeLastSegment(out)
		case path == "." || path == "..":
			path = ""
		default:
			i := 1
			if !strings.HasPrefix(path, "/") {
				i = 0
			}

			if j := strings.IndexByte(path[i:], '/'); j < 0 {
				out, path = append(out, path...), ""
			} else {
				out, path = append(out, path[:i+j]...), path[i+j:]
			}
		}
	}

	return string(out)
}

func removeLastSegment(out []byte) []byte {
	if i := bytes.LastIndexByte(out, '/'); i >= 0 {
		return out[:i]
	}

	return out[:0]
}

func ishex(c byte) bool {
	return ('0' <= c && c <= '9') || ('a' <= c && c <= 'f') || ('A' <= c && c <= 'F')
}

func unhex(c byte) byte {
	switch {
	case '0' <= c && c <= '9':
		return c - '0'
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10
	default:
		return c - 'A' + 10
	}
}

// isunreserved reports whether c is an RFC 3986 Section 2.3 unreserved character, which is exactly the set that must
// not remain percent-encoded in a normalized URI.
func isunreserved(c byte) bool {
	return ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z') || ('0' <= c && c <= '9') || c == '-' || c == '.' || c == '_' || c == '~'
}
