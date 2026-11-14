// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
	"weak"

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
	allowed  []netip.Prefix

	lookupNetIP func(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// SpecialUseAddressGuardOption configures NewSpecialUseAddressGuardedHTTPClient.
type SpecialUseAddressGuardOption func(*specialUseAddressGuard)

// WithSpecialUseAddressGuardAllowLoopback permits connections to the given loopback address, which is the address the
// authorization server itself is running on. No other loopback address is permitted, and the option has no effect
// when the address is not a loopback address. It is for development and testing and MUST NOT be used in production.
//
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-03#section-10.7
func WithSpecialUseAddressGuardAllowLoopback(server netip.Addr) SpecialUseAddressGuardOption {
	return func(guard *specialUseAddressGuard) {
		if server = server.Unmap().WithZone(""); server.IsLoopback() {
			guard.loopback = server
		}
	}
}

// WithSpecialUseAddressGuardAllowedNetworks permits connections to an address within any of the given networks, even
// when it is a special-use address. A nil or invalid network is ignored.
//
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-rfc8725bis-10#section-3.10
func WithSpecialUseAddressGuardAllowedNetworks(networks ...*net.IPNet) SpecialUseAddressGuardOption {
	return func(guard *specialUseAddressGuard) {
		guard.allowed = append(guard.allowed, allowedNetworkPrefixes(networks)...)
	}
}

func allowedNetworkPrefixes(networks []*net.IPNet) (prefixes []netip.Prefix) {
	for _, network := range networks {
		if network == nil {
			continue
		}

		addr, ok := netip.AddrFromSlice(network.IP)
		if !ok {
			continue
		}

		ones, bits := network.Mask.Size()
		if bits == 0 {
			continue
		}

		if addr = addr.Unmap(); addr.Is4() && bits == net.IPv6len*8 {
			ones -= 96
		}

		if prefix, err := addr.Prefix(ones); err == nil {
			prefixes = append(prefixes, prefix)
		}
	}

	return prefixes
}

// NewSpecialUseAddressGuardedHTTPClient returns an HTTP client which refuses to connect to a special-use address. The
// address checked is the one being connected to, after name resolution. The client ignores proxy settings, does not
// follow redirects, does not retry, times out after ten seconds, and opens at most four connections to a host.
//
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-03#section-10.7
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

	return g.check(ap.Addr())
}

func (g *specialUseAddressGuard) check(addr netip.Addr) (err error) {
	addr = addr.Unmap()

	if g.loopback.IsValid() && addr.WithZone("") == g.loopback {
		return nil
	}

	for _, prefix := range g.allowed {
		if prefix.Contains(addr.WithZone("")) {
			return nil
		}
	}

	if IsSpecialUseAddress(addr) {
		return fmt.Errorf("%w: '%s'", ErrSpecialUseAddress, addr)
	}

	return nil
}

func (g *specialUseAddressGuard) checkConn(conn net.Conn) (err error) {
	if err = g.control("", conn.RemoteAddr().String(), nil); err != nil {
		_ = conn.Close()
	}

	return err
}

type dialContextFunc func(ctx context.Context, network, address string) (net.Conn, error)

func (g *specialUseAddressGuard) dialContext(dial dialContextFunc) dialContextFunc {
	return func(ctx context.Context, network, address string) (conn net.Conn, err error) {
		var host, service string

		if host, service, err = net.SplitHostPort(address); err != nil {
			return nil, fmt.Errorf("%w: '%s' could not be parsed", ErrSpecialUseAddress, address)
		}

		var port int

		if port, err = net.DefaultResolver.LookupPort(ctx, network, service); err != nil {
			return nil, err
		}

		ipNetwork := "ip"

		switch network {
		case "tcp4", "udp4":
			ipNetwork = "ip4"
		case "tcp6", "udp6":
			ipNetwork = "ip6"
		}

		var addrs []netip.Addr

		lookup := g.lookupNetIP

		if lookup == nil {
			lookup = net.DefaultResolver.LookupNetIP
		}

		if addrs, err = lookup(ctx, ipNetwork, host); err != nil {
			return nil, err
		}

		for _, addr := range addrs {
			if err = g.check(addr); err != nil {
				return nil, err
			}
		}

		if len(addrs) == 0 {
			return nil, fmt.Errorf("the host '%s' did not resolve to an address", host)
		}

		targets := make([]string, len(addrs))

		for i, addr := range addrs {
			targets[i] = netip.AddrPortFrom(addr, uint16(port)).String() //nolint:gosec
		}

		return g.dialStaggered(ctx, dial, network, targets)
	}
}

// addressDialDelay is the delay before the next address is attempted while an earlier attempt is still pending.
//
// See: https://www.rfc-editor.org/rfc/rfc8305#section-5
const addressDialDelay = 250 * time.Millisecond

type dialResult struct {
	conn net.Conn
	err  error
}

// dialStaggered dials the targets in order, starting the next attempt when the previous one fails or has not
// connected within addressDialDelay, so an address that does not answer cannot consume the time of the others. The
// first connection to pass checkConn is returned, and every other attempt is cancelled and its connection closed.
func (g *specialUseAddressGuard) dialStaggered(ctx context.Context, dial dialContextFunc, network string, targets []string) (conn net.Conn, err error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	results := make(chan dialResult, len(targets))

	var (
		errs          []error
		next, pending int
	)

	defer func() {
		go closeDialResults(results, pending)
	}()

	timer := time.NewTimer(0)
	defer timer.Stop()

	for next < len(targets) || pending > 0 {
		var start <-chan time.Time

		if next < len(targets) {
			start = timer.C
		}

		select {
		case <-start:
			go func(target string) {
				c, e := dial(ctx, network, target)
				results <- dialResult{conn: c, err: e}
			}(targets[next])

			next++
			pending++

			timer.Reset(addressDialDelay)
		case result := <-results:
			pending--

			if result.err != nil {
				errs = append(errs, result.err)

				timer.Reset(0)

				continue
			}

			if err = g.checkConn(result.conn); err != nil {
				return nil, err
			}

			return result.conn, nil
		case <-ctx.Done():
			return nil, errors.Join(append(errs, context.Cause(ctx))...)
		}
	}

	return nil, errors.Join(errs...)
}

func closeDialResults(results <-chan dialResult, pending int) {
	for range pending {
		if result := <-results; result.conn != nil {
			_ = result.conn.Close()
		}
	}
}

// GuardHTTPClient returns a copy of base whose transport refuses to connect to a special-use address. A host name is
// resolved and every address it resolves to is checked before the transport's own dial function is called with each
// address in turn, the next attempt starting when the previous one fails or has not connected within 250 milliseconds,
// and the remote address of the established connection is checked again before any request is sent. The proxy of the
// transport is ignored. The transport must be a non-nil *http.Transport without a custom TLS dial function, or nil for
// http.DefaultTransport, since a custom TLS dial function connects before its address can be checked. Neither base
// nor its transport is mutated.
//
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-rfc8725bis-10#section-3.10
func GuardHTTPClient(base *retryablehttp.Client, opts ...SpecialUseAddressGuardOption) (client *retryablehttp.Client, err error) {
	if base == nil {
		return nil, fmt.Errorf("%w: the HTTP client is nil", ErrSpecialUseAddress)
	}

	guard := &specialUseAddressGuard{}

	for _, opt := range opts {
		opt(guard)
	}

	inner := &http.Client{}

	if base.HTTPClient != nil {
		copied := *base.HTTPClient
		inner = &copied
	}

	rt := inner.Transport

	if rt == nil {
		rt = http.DefaultTransport
	}

	transport, ok := rt.(*http.Transport)
	if !ok || transport == nil {
		return nil, fmt.Errorf("%w: the transport of type '%T' cannot be guarded", ErrSpecialUseAddress, rt)
	}

	if transport.DialTLSContext != nil || transport.DialTLS != nil { //nolint:staticcheck
		return nil, fmt.Errorf("%w: a transport with a custom TLS dial function cannot be guarded", ErrSpecialUseAddress)
	}

	transport = transport.Clone()
	transport.Proxy = nil

	dial := transport.DialContext

	switch {
	case dial != nil:
	case transport.Dial != nil: //nolint:staticcheck
		legacy := transport.Dial //nolint:staticcheck
		dial = func(_ context.Context, network, address string) (net.Conn, error) { return legacy(network, address) }
	default:
		dial = (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext
	}

	transport.Dial = nil //nolint:staticcheck
	transport.DialContext = guard.dialContext(dial)
	inner.Transport = transport

	return &retryablehttp.Client{
		HTTPClient:      inner,
		Logger:          base.Logger,
		RetryWaitMin:    base.RetryWaitMin,
		RetryWaitMax:    base.RetryWaitMax,
		RetryMax:        base.RetryMax,
		RequestLogHook:  base.RequestLogHook,
		ResponseLogHook: base.ResponseLogHook,
		CheckRetry:      base.CheckRetry,
		Backoff:         base.Backoff,
		ErrorHandler:    base.ErrorHandler,
		PrepareRetry:    base.PrepareRetry,
	}, nil
}

// SpecialUseAddressGuardProvider returns the provider for disabling the special-use address guard.
type SpecialUseAddressGuardProvider interface {
	// GetDisableSpecialUseAddressGuard returns true if a fetch of, or delivery to, a location supplied by a client or
	// another party that is not trusted may connect to a special-use address. It is refused when this returns false.
	//
	// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-rfc8725bis-10#section-3.10
	GetDisableSpecialUseAddressGuard(ctx context.Context) (disable bool)

	// GetSpecialUseAddressGuardAllowedNetworks returns the networks the special-use address guard permits a
	// connection to, even when the address is a special-use address.
	GetSpecialUseAddressGuardAllowedNetworks(ctx context.Context) (networks []*net.IPNet)
}

// SpecialUseAddressGuardEnabled reports whether the special-use address guard applies to config, which it does unless
// config implements SpecialUseAddressGuardProvider and disables it.
func SpecialUseAddressGuardEnabled(ctx context.Context, config any) (enabled bool) {
	provider, ok := config.(SpecialUseAddressGuardProvider)

	return !ok || !provider.GetDisableSpecialUseAddressGuard(ctx)
}

// SpecialUseAddressGuardAllowedNetworks returns the networks config permits the special-use address guard to connect
// to, or nil when config does not implement SpecialUseAddressGuardProvider.
func SpecialUseAddressGuardAllowedNetworks(ctx context.Context, config any) (networks []*net.IPNet) {
	if provider, ok := config.(SpecialUseAddressGuardProvider); ok {
		return provider.GetSpecialUseAddressGuardAllowedNetworks(ctx)
	}

	return nil
}

// SpecialUseAddressGuardHTTPClient returns the HTTP client to fetch, or deliver to, a location supplied by a client or
// another party that is not trusted: base when the special-use address guard is disabled, otherwise base guarded by
// GuardHTTPClient with the networks SpecialUseAddressGuardAllowedNetworks returns. The guarded copy of a given base is
// made once for each set of allowed networks and reused, so it keeps its own connection pool.
//
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-rfc8725bis-10#section-3.10
func SpecialUseAddressGuardHTTPClient(ctx context.Context, config any, base *retryablehttp.Client) (client *retryablehttp.Client, err error) {
	if !SpecialUseAddressGuardEnabled(ctx, config) {
		return base, nil
	}

	return guardedHTTPClient(base, allowedNetworkPrefixes(SpecialUseAddressGuardAllowedNetworks(ctx, config)))
}

var guardedHTTPClients sync.Map

type guardedHTTPClientKey struct {
	base    weak.Pointer[retryablehttp.Client]
	allowed string
}

func allowedNetworksKey(allowed []netip.Prefix) string {
	parts := make([]string, len(allowed))

	for i, prefix := range allowed {
		parts[i] = prefix.String()
	}

	return strings.Join(parts, ",")
}

func guardedHTTPClient(base *retryablehttp.Client, allowed []netip.Prefix) (client *retryablehttp.Client, err error) {
	opt := func(guard *specialUseAddressGuard) { guard.allowed = allowed }

	if base == nil {
		return GuardHTTPClient(base, opt)
	}

	key := guardedHTTPClientKey{base: weak.Make(base), allowed: allowedNetworksKey(allowed)}

	if value, ok := guardedHTTPClients.Load(key); ok {
		return value.(*retryablehttp.Client), nil
	}

	if client, err = GuardHTTPClient(base, opt); err != nil {
		return nil, err
	}

	value, loaded := guardedHTTPClients.LoadOrStore(key, client)

	if !loaded {
		runtime.AddCleanup(base, func(key guardedHTTPClientKey) { guardedHTTPClients.Delete(key) }, key)
	}

	return value.(*retryablehttp.Client), nil
}
