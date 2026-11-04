// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package cimd

import (
	"context"
	"net"
	"net/url"
	"strings"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/x/errorsx"
)

// RedirectURISameOriginValidator is an oauth2.ClientRegistrationValidator for Config.Validators which requires every
// 'redirect_uris' value of a Client ID Metadata Document to have the scheme, host and port of its 'client_id'. The
// port is compared as written, so an explicit default port does not match an omitted one. A document with the
// 'native' 'application_type' may also use loopback interface redirection with the 'http' scheme and the loopback IP
// literal 127.0.0.1 or [::1], whose port is not compared at the authorization endpoint.
//
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-03#section-4.2
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-03#section-10.2
// See: https://datatracker.ietf.org/doc/html/rfc8252#section-7.3
// See: https://datatracker.ietf.org/doc/html/rfc9700#section-2.1
type RedirectURISameOriginValidator struct{}

// ValidateClientRegistrationMetadata implements oauth2.ClientRegistrationValidator.
func (RedirectURISameOriginValidator) ValidateClientRegistrationMetadata(ctx context.Context, client oauth2.Client, metadata *oauth2.ClientRegistrationMetadata) (err error) {
	id, _ := metadata.Extra[memberClientID].(string)

	origin, perr := url.Parse(id)
	if id == "" || perr != nil || origin.Scheme == "" || origin.Host == "" {
		return errorsx.WithStack(oauth2.ErrInvalidRedirectURI.WithHint("The 'redirect_uris' could not be compared with the 'client_id' as it is not a URL."))
	}

	for _, raw := range metadata.RedirectURIs {
		parsed, perr := url.Parse(raw)

		if perr == nil && metadata.ApplicationType == consts.ApplicationTypeNative && isLoopbackRedirectURI(parsed) {
			continue
		}

		if perr != nil || parsed.Scheme != origin.Scheme || !strings.EqualFold(parsed.Host, origin.Host) {
			return errorsx.WithStack(oauth2.ErrInvalidRedirectURI.WithHintf("The 'redirect_uris' value '%s' does not have the same origin as the 'client_id'.", raw))
		}
	}

	return nil
}

func isLoopbackRedirectURI(uri *url.URL) (loopback bool) {
	if uri.Scheme != consts.SchemeHTTP || uri.User != nil || uri.Opaque != "" {
		return false
	}

	ip := net.ParseIP(uri.Hostname())

	return ip != nil && (ip.Equal(net.IPv4(127, 0, 0, 1)) || ip.Equal(net.IPv6loopback))
}

var _ oauth2.ClientRegistrationValidator = RedirectURISameOriginValidator{}
