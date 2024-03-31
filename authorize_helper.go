// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"html/template"
	"io"
	"net"
	"net/url"
	"strings"

	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/errorsx"
	"authelia.com/provider/oauth2/internal/urls"
)

var DefaultFormPostTemplate = template.Must(template.New("form_post").Parse(`<html>
   <head>
      <title>Submit This Form</title>
   </head>
   <body onload="javascript:document.forms[0].submit()">
      <form method="post" action="{{ .RedirURL }}">
         {{ range $key,$value := .Parameters }}
            {{ range $parameter:= $value }}
		      <input type="hidden" name="{{ $key }}" value="{{ $parameter }}"/>
            {{ end }}
         {{ end }}
      </form>
   </body>
</html>`))

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
func MatchRedirectURIWithClientRedirectURIs(rawurl string, client Client) (*url.URL, error) {
	if rawurl == "" && len(client.GetRedirectURIs()) == 1 {
		if redirectURIFromClient, err := url.Parse(client.GetRedirectURIs()[0]); err == nil && IsValidRedirectURI(redirectURIFromClient) {
			// If no redirect_uri was given and the client has exactly one valid redirect_uri registered, use that instead
			return redirectURIFromClient, nil
		}
	} else if redirectTo, ok := IsMatchingRedirectURI(rawurl, client.GetRedirectURIs()); rawurl != "" && ok {
		// If a redirect_uri was given and the clients knows it (simple string comparison!)
		// return it.
		if parsed, err := url.Parse(redirectTo); err == nil && IsValidRedirectURI(parsed) {
			// If no redirect_uri was given and the client has exactly one valid redirect_uri registered, use that instead
			return parsed, nil
		}
	}

	return nil, errorsx.WithStack(ErrInvalidRequest.WithHint("The 'redirect_uri' parameter does not match any of the OAuth 2.0 Client's pre-registered 'redirect_uris'.").WithDebugf("The 'redirect_uris' registered with OAuth 2.0 Client with id '%s' match 'redirect_uri' value '%s'.", client.GetID(), rawurl))
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
func IsMatchingRedirectURI(uri string, haystack []string) (string, bool) {
	requested, _ := url.Parse(uri)

	for _, b := range haystack {
		if b == uri {
			return b, true
		} else if isMatchingAsLoopback(requested, b) {
			// We have to return the requested URL here because otherwise the port might get lost (see isMatchingAsLoopback)
			// description.
			return uri, true
		}
	}
	return "", false
}

func isMatchingAsLoopback(requested *url.URL, registeredURI string) bool {
	if requested == nil {
		return false
	}

	registered, err := url.Parse(registeredURI)
	if err != nil {
		return false
	}

	// Native apps that are able to open a port on the loopback network
	// interface without needing special permissions (typically, those on
	// desktop operating systems) can use the loopback interface to receive
	// the OAuth redirect.
	//
	// Loopback redirect URIs use the "http" scheme and are constructed with
	// the loopback IP literal and whatever port the client is listening on.
	//
	// Source: https://datatracker.ietf.org/doc/html/rfc8252#section-7.3
	if requested.Scheme == "http" &&
		isLoopbackAddress(requested) &&
		registered.Hostname() == requested.Hostname() &&
		// The port is skipped here - see codedoc above!
		registered.Path == requested.Path &&
		registered.RawQuery == requested.RawQuery {
		return true
	}

	return false
}

// Check if address is either an IPv4 loopback or an IPv6 loopback-
// An optional port is ignored
func isLoopbackAddress(uri *url.URL) bool {
	if uri == nil {
		return false
	}

	return net.ParseIP(uri.Hostname()).IsLoopback()
}

// IsValidRedirectURI validates a redirect_uri as specified in:
//
// * https://datatracker.ietf.org/doc/html/rfc6749#section-3.1.2
//   - The redirection endpoint URI MUST be an absolute URI as defined by [RFC3986] Section 4.3.
//   - The endpoint URI MUST NOT include a fragment component.
//   - https://datatracker.ietf.org/doc/html/rfc3986#section-4.3
//     absolute-URI  = scheme ":" hier-part [ "?" query ]
//   - https://datatracker.ietf.org/doc/html/rfc6819#section-5.1.1
func IsValidRedirectURI(redirectURI *url.URL) bool {
	// We need to explicitly check for a scheme
	if !urls.IsRequestURL(redirectURI.String()) {
		return false
	}

	if redirectURI.Fragment != "" {
		// "The endpoint URI MUST NOT include a fragment component."
		return false
	}

	return true
}

func IsRedirectURISecure(ctx context.Context, redirectURI *url.URL) bool {
	return !(redirectURI.Scheme == consts.SchemeHTTP && !IsLocalhost(redirectURI))
}

// IsRedirectURISecureStrict is stricter than IsRedirectURISecure and it does not allow custom-scheme
// URLs because they can be hijacked for native apps. Use claimed HTTPS redirects instead.
// See discussion in https://github.com/ory/fosite/pull/489.
func IsRedirectURISecureStrict(redirectURI *url.URL) bool {
	return redirectURI.Scheme == consts.SchemeHTTPS || (redirectURI.Scheme == consts.SchemeHTTP && IsLocalhost(redirectURI))
}

func IsLocalhost(redirectURI *url.URL) bool {
	hn := redirectURI.Hostname()

	return strings.HasSuffix(hn, ".localhost") || hn == "localhost" || isLoopbackAddress(redirectURI)
}

type FormPostResponseWriter func(wr io.Writer, template *template.Template, redirectURL string, parameters url.Values)

func DefaultFormPostResponseWriter(rw io.Writer, template *template.Template, redirectURL string, parameters url.Values) {
	_ = template.Execute(rw, struct {
		RedirURL   string
		Parameters url.Values
	}{
		RedirURL:   redirectURL,
		Parameters: parameters,
	})
}

func GetPostFormHTMLTemplate(ctx context.Context, c FormPostHTMLTemplateProvider) *template.Template {
	if t := c.GetFormPostHTMLTemplate(ctx); t != nil {
		return t
	}

	return DefaultFormPostTemplate
}
