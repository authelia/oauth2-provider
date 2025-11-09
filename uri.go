package oauth2

import (
	"context"
	"net"
	"net/url"
	"strings"

	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/urls"
	"authelia.com/provider/oauth2/x/errorsx"
)

// IsValidRedirectURI validates a redirect_uri as specified in:
//
// * https://datatracker.ietf.org/doc/html/rfc6749#section-3.1.2
//   - The redirection endpoint URI MUST be an absolute URI as defined by [RFC3986] Section 4.3.
//   - The endpoint URI MUST NOT include a fragment component.
//   - https://datatracker.ietf.org/doc/html/rfc3986#section-4.3
//     absolute-URI  = scheme ":" hier-part [ "?" query ]
//   - https://datatracker.ietf.org/doc/html/rfc6819#section-5.1.1
func IsValidRedirectURI(uri *url.URL) bool {
	// We need to explicitly check for a scheme
	if !urls.IsRequestURL(uri.String()) {
		return false
	}

	if uri.Fragment != "" {
		// "The endpoint URI MUST NOT include a fragment component."
		return false
	}

	return true
}

func IsRedirectURISecure(ctx context.Context, uri *url.URL) bool {
	return !(uri.Scheme == consts.SchemeHTTP && !IsLocalhost(uri))
}

// IsRedirectURISecureStrict is stricter than IsRedirectURISecure and it does not allow custom-scheme
// URLs because they can be hijacked for native apps. Use claimed HTTPS redirects instead.
// See discussion in https://github.com/ory/fosite/pull/489.
func IsRedirectURISecureStrict(uri *url.URL) bool {
	return uri.Scheme == consts.SchemeHTTPS || (uri.Scheme == consts.SchemeHTTP && IsLocalhost(uri))
}

func IsLocalhost(uri *url.URL) bool {
	hostname := uri.Hostname()

	return strings.HasSuffix(hostname, ".localhost") || hostname == "localhost" || isLoopbackAddress(uri)
}

// MatchRedirectURIWithClientRedirectURIs if the given uri is a registered redirect uri. Does not perform
// uri validation.
//
// Considered specifications
//
//   - https://datatracker.ietf.org/doc/html/rfc6749#section-3.1.2.3
//     If multiple redirection URIs have been registered, if only part of
//     the redirection URI has been registered, or if no redirection URI has
//     been registered, the client MUST include a redirection URI with the
//     authorization request using the "redirect_uri" request parameter.
//
//     When a redirection URI is included in an authorization request, the
//     authorization server MUST compare and match the value received
//     against at least one of the registered redirection URIs (or URI
//     components) as defined in [RFC3986] Section 6, if any redirection
//     URIs were registered.  If the client registration included the full
//     redirection URI, the authorization server MUST compare the two URIs
//     using simple string comparison as defined in [RFC3986] Section 6.2.1.
//
// * https://datatracker.ietf.org/doc/html/rfc6819#section-4.4.1.7
//   - The authorization server may also enforce the usage and validation
//     of pre-registered redirect URIs (see Section 5.2.3.5).  This will
//     allow for early recognition of authorization "code" disclosure to
//     counterfeit clients.
//   - The attacker will need to use another redirect URI for its
//     authorization process rather than the target web site because it
//     needs to intercept the flow.  So, if the authorization server
//     associates the authorization "code" with the redirect URI of a
//     particular end-user authorization and validates this redirect URI
//     with the redirect URI passed to the token's endpoint, such an
//     attack is detected (see Section 5.2.4.5).
func MatchRedirectURIWithClientRedirectURIs(raw string, client Client) (*url.URL, error) {
	strategy := GetClientRedirectURIComparisonStrategy(client)

	if raw == "" && len(client.GetRedirectURIs()) == 1 {
		if redirectURIFromClient, err := url.Parse(client.GetRedirectURIs()[0]); err == nil && IsValidRedirectURI(redirectURIFromClient) {
			// If no redirect_uri was given and the client has exactly one valid redirect_uri registered, use that instead.
			return redirectURIFromClient, nil
		}

		return nil, errorsx.WithStack(ErrInvalidRequest.WithHint("The 'redirect_uri' parameter does not match any of the OAuth 2.0 Client's pre-registered 'redirect_uris'.").WithDebugf("The 'redirect_uris' registered with OAuth 2.0 Client with id '%s' did not match 'redirect_uri' value '%s' because the only registered 'redirect_uri' is not a valid value.", client.GetID(), raw))
	} else if redirectTo, ok := IsMatchingRedirectURI(raw, client.GetRedirectURIs(), strategy); raw != "" && ok {
		// If a redirect_uri was given and the clients knows it (simple string comparison!)
		// return it.
		if parsed, err := url.Parse(redirectTo); err == nil && IsValidRedirectURI(parsed) {
			// If no redirect_uri was given and the client has exactly one valid redirect_uri registered, use that instead
			return parsed, nil
		}
	}

	return nil, errorsx.WithStack(ErrInvalidRequest.WithHint("The 'redirect_uri' parameter does not match any of the OAuth 2.0 Client's pre-registered 'redirect_uris'.").WithDebugf("The 'redirect_uris' registered with OAuth 2.0 Client with id '%s' did not match 'redirect_uri' value '%s'.", client.GetID(), raw))
}

// IsMatchingRedirectURI matches a requested redirect URI against a pool of registered client URIs.
//
// Test a given redirect URI against a pool of URIs provided by a registered client.
// If the OAuth 2.0 Client has loopback URIs registered either an IPv4 URI http://127.0.0.1 or
// an IPv6 URI http://[::1] a client is allowed to request a dynamic port and the server MUST accept
// it as a valid redirection uri.
//
// https://datatracker.ietf.org/doc/html/rfc8252#section-7.3
// Native apps that are able to open a port on the loopback network
// interface without needing special permissions (typically, those on
// desktop operating systems) can use the loopback interface to receive
// the OAuth redirect.
//
// Loopback redirect URIs use the "http" scheme and are constructed with
// the loopback IP literal and whatever port the client is listening on.
func IsMatchingRedirectURI(needle string, haystack []string, strategy URIComparisonStrategy) (uri string, ok bool) {
	var (
		requested, registered *url.URL
		err                   error
	)

	if requested, err = url.Parse(needle); err != nil {
		return "", false
	}

	if strategy.UseSimpleStringComparison() {
		for _, raw := range haystack {
			if raw == needle {
				return needle, true
			} else if isMatchingRawLoopbackURI(requested, raw) {
				return needle, true
			}
		}
	} else {
		for _, raw := range haystack {
			if registered, err = url.Parse(raw); err != nil {
				continue
			}

			if strategy.Compare(&uriPair{uri: requested, registeredURI: registered}) {
				return needle, true
			} else if isMatchingLoopbackURI(requested, registered) {
				return needle, true
			}
		}
	}

	return "", false
}

type RedirectURICustomComparisonClient interface {
	GetRedirectURIComparisonStrategy() URIComparisonStrategy
}

func GetClientRedirectURIComparisonStrategy(client Client) (strategy URIComparisonStrategy) {
	if ucsClient, ok := client.(RedirectURICustomComparisonClient); ok {
		strategy = ucsClient.GetRedirectURIComparisonStrategy()
	}

	if strategy == nil {
		return &BestPracticeURIComparisonStrategy{}
	}

	return strategy
}

type uriPair struct {
	uri           *url.URL
	registeredURI *url.URL
}

// URIComparisonStrategy is used to compare URIs.
type URIComparisonStrategy interface {
	Compare(pair *uriPair) bool
	UseSimpleStringComparison() bool
}

// BestPracticeURIComparisonStrategy is used to compare URIs. This comparison strategy only matches based on exact
// simple string comparison.
type BestPracticeURIComparisonStrategy struct{}

func (BestPracticeURIComparisonStrategy) Compare(pair *uriPair) bool {
	return pair.uri.String() == pair.registeredURI.String()
}

func (BestPracticeURIComparisonStrategy) UseSimpleStringComparison() bool {
	return true
}

// OriginURIComparisonStrategy is used to compare URIs. When the registered URI is a Origin URI (only scheme and host),
// the comparison is truthy when the scheme and host parts are the same.
type OriginURIComparisonStrategy struct{}

func (OriginURIComparisonStrategy) Compare(pair *uriPair) bool {
	if !isBareOriginURI(pair.registeredURI) {
		return pair.uri.String() == pair.registeredURI.String()
	}

	if isLoopbackAddress(pair.uri) && isLoopbackAddress(pair.registeredURI) {
		return pair.uri.Scheme == pair.registeredURI.Scheme && pair.uri.Hostname() == pair.registeredURI.Hostname()
	}

	return pair.uri.Scheme == pair.registeredURI.Scheme && pair.uri.Host == pair.registeredURI.Host
}

func (OriginURIComparisonStrategy) UseSimpleStringComparison() bool {
	return false
}

func isBareOriginURI(uri *url.URL) bool {
	return uri.Scheme != "" && uri.Host != "" && uri.Path == "" && uri.RawQuery == "" && uri.RawFragment == "" && uri.Fragment == "" && uri.Opaque == "" && uri.User == nil
}

func isMatchingRawLoopbackURI(requested *url.URL, registeredURI string) bool {
	if requested == nil {
		return false
	}

	registered, err := url.Parse(registeredURI)
	if err != nil {
		return false
	}

	return isMatchingLoopbackURI(requested, registered)
}

func isMatchingLoopbackURI(requested, registered *url.URL) bool {
	// Native apps that are able to open a port on the loopback network
	// interface without needing special permissions (typically, those on
	// desktop operating systems) can use the loopback interface to receive
	// the OAuth redirect.
	//
	// Loopback redirect URIs use the "http" scheme and are constructed with
	// the loopback IP literal and whatever port the client is listening on.
	//
	// Source: https://datatracker.ietf.org/doc/html/rfc8252#section-7.3
	if requested.Scheme != consts.SchemeHTTP || registered.Scheme != consts.SchemeHTTP {
		return false
	}

	if !isLoopbackAddress(requested) {
		return false
	}

	if !isLoopbackAddress(registered) {
		return false
	}

	if registered.Hostname() != requested.Hostname() {
		return false
	}

	if registered.Path != requested.Path {
		return false
	}

	if registered.RawQuery != requested.RawQuery {
		return false
	}

	return true
}

// Determines if the provided address is either an IPv4 loopback or an IPv6 loopback.
func isLoopbackAddress(uri *url.URL) bool {
	if uri == nil {
		return false
	}

	ip := net.ParseIP(uri.Hostname())

	return ip != nil && ip.IsLoopback()
}
