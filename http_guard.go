// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"syscall"
	"time"

	"github.com/hashicorp/go-retryablehttp"
)

// ErrSpecialUseAddress is returned, wrapped, when a guarded HTTP client refuses to connect to a special-use address.
var ErrSpecialUseAddress = errors.New("the address is a special-use address")

var specialUsePrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),       // RFC 791, this network.
	netip.MustParsePrefix("10.0.0.0/8"),      // RFC 1918, private use.
	netip.MustParsePrefix("100.64.0.0/10"),   // RFC 6598, shared address space.
	netip.MustParsePrefix("127.0.0.0/8"),     // RFC 1122, loopback.
	netip.MustParsePrefix("169.254.0.0/16"),  // RFC 3927, link local.
	netip.MustParsePrefix("172.16.0.0/12"),   // RFC 1918, private use.
	netip.MustParsePrefix("192.0.0.0/24"),    // RFC 6890, IETF protocol assignments.
	netip.MustParsePrefix("192.0.2.0/24"),    // RFC 5737, documentation.
	netip.MustParsePrefix("192.31.196.0/24"), // RFC 7535, AS112-v4.
	netip.MustParsePrefix("192.52.193.0/24"), // RFC 7450, AMT.
	netip.MustParsePrefix("192.88.99.0/24"),  // RFC 7526, deprecated 6to4 relay anycast.
	netip.MustParsePrefix("192.168.0.0/16"),  // RFC 1918, private use.
	netip.MustParsePrefix("192.175.48.0/24"), // RFC 7534, direct delegation AS112 service.
	netip.MustParsePrefix("198.18.0.0/15"),   // RFC 2544, benchmarking.
	netip.MustParsePrefix("198.51.100.0/24"), // RFC 5737, documentation.
	netip.MustParsePrefix("203.0.113.0/24"),  // RFC 5737, documentation.
	netip.MustParsePrefix("224.0.0.0/4"),     // RFC 5771, multicast.
	netip.MustParsePrefix("240.0.0.0/4"),     // RFC 1112, reserved, and RFC 919, limited broadcast.

	netip.MustParsePrefix("::/128"),            // RFC 4291, unspecified.
	netip.MustParsePrefix("::1/128"),           // RFC 4291, loopback.
	netip.MustParsePrefix("::/96"),             // RFC 4291, deprecated IPv4-compatible.
	netip.MustParsePrefix("::ffff:0:0/96"),     // RFC 4291, IPv4-mapped.
	netip.MustParsePrefix("64:ff9b::/96"),      // RFC 6052, IPv4-IPv6 translation.
	netip.MustParsePrefix("64:ff9b:1::/48"),    // RFC 8215, IPv4-IPv6 translation.
	netip.MustParsePrefix("100::/64"),          // RFC 6666, discard only.
	netip.MustParsePrefix("100:0:0:1::/64"),    // RFC 9780, dummy IPv6 prefix.
	netip.MustParsePrefix("2001::/23"),         // RFC 2928, IETF protocol assignments.
	netip.MustParsePrefix("2001:db8::/32"),     // RFC 3849, documentation.
	netip.MustParsePrefix("2002::/16"),         // RFC 3056, 6to4.
	netip.MustParsePrefix("2620:4f:8000::/48"), // RFC 7534, direct delegation AS112 service.
	netip.MustParsePrefix("3fff::/20"),         // RFC 9637, documentation.
	netip.MustParsePrefix("5f00::/16"),         // RFC 9602, segment routing SIDs.
	netip.MustParsePrefix("fc00::/7"),          // RFC 4193, unique local.
	netip.MustParsePrefix("fe80::/10"),         // RFC 4291, link local.
	netip.MustParsePrefix("fec0::/10"),         // RFC 3879, deprecated site local.
	netip.MustParsePrefix("ff00::/8"),          // RFC 4291, multicast.
}

// IsSpecialUseAddress reports whether addr is within the IANA IPv4 or IPv6 Special-Purpose Address Registries or is
// a multicast address. An IPv4-mapped IPv6 address is tested as its IPv4 address. An invalid address is special-use.
//
// See: https://www.rfc-editor.org/rfc/rfc6890
// See: https://www.iana.org/assignments/iana-ipv4-special-registry
// See: https://www.iana.org/assignments/iana-ipv6-special-registry
func IsSpecialUseAddress(addr netip.Addr) (special bool) {
	if !addr.IsValid() {
		return true
	}

	addr = addr.Unmap().WithZone("")

	for _, prefix := range specialUsePrefixes {
		if prefix.Contains(addr) {
			return true
		}
	}

	return false
}

type specialUseAddressGuard struct {
	loopback netip.Addr
}

// SpecialUseAddressGuardOption configures NewSpecialUseAddressGuardedHTTPClient.
type SpecialUseAddressGuardOption func(*specialUseAddressGuard)

// WithSpecialUseAddressGuardAllowLoopback permits connections to the given loopback address, which is the address the
// authorization server itself is running on. No other loopback address is permitted, and the option has no effect
// when the address is not a loopback address. It is for development and testing and MUST NOT be used in production.
//
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-02#section-8.6
func WithSpecialUseAddressGuardAllowLoopback(server netip.Addr) SpecialUseAddressGuardOption {
	return func(guard *specialUseAddressGuard) {
		if server = server.Unmap().WithZone(""); server.IsLoopback() {
			guard.loopback = server
		}
	}
}

// NewSpecialUseAddressGuardedHTTPClient returns an HTTP client which refuses to connect to a special-use address. The
// address checked is the one being connected to, after name resolution. The client ignores proxy settings, does not
// follow redirects, does not retry, times out after ten seconds, and opens at most four connections to a host.
//
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-02#section-8.6
func NewSpecialUseAddressGuardedHTTPClient(opts ...SpecialUseAddressGuardOption) (client *retryablehttp.Client) {
	guard := &specialUseAddressGuard{}

	for _, opt := range opts {
		opt(guard)
	}

	dialer := &net.Dialer{
		Timeout:   5 * time.Second,
		KeepAlive: 30 * time.Second,
		Control:   guard.control,
	}

	return &retryablehttp.Client{
		HTTPClient: &http.Client{
			Transport: &http.Transport{
				DialContext:           dialer.DialContext,
				ForceAttemptHTTP2:     true,
				MaxIdleConns:          16,
				MaxConnsPerHost:       4,
				IdleConnTimeout:       90 * time.Second,
				TLSHandshakeTimeout:   5 * time.Second,
				ResponseHeaderTimeout: 5 * time.Second,
			},
			Timeout: 10 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		RetryMax:     0,
		CheckRetry:   retryablehttp.DefaultRetryPolicy,
		Backoff:      retryablehttp.DefaultBackoff,
		ErrorHandler: retryablehttp.PassthroughErrorHandler,
	}
}

func (g *specialUseAddressGuard) control(network, address string, _ syscall.RawConn) (err error) {
	var ap netip.AddrPort

	if ap, err = netip.ParseAddrPort(address); err != nil {
		return fmt.Errorf("%w: '%s' could not be parsed", ErrSpecialUseAddress, address)
	}

	addr := ap.Addr().Unmap()

	if g.loopback.IsValid() && addr.WithZone("") == g.loopback {
		return nil
	}

	if IsSpecialUseAddress(addr) {
		return fmt.Errorf("%w: '%s'", ErrSpecialUseAddress, addr)
	}

	return nil
}
