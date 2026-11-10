// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"authelia.com/provider/oauth2/internal/consts"
)

const (
	// WellKnownOAuthAuthorizationServerSuffix is the well-known URI suffix of the authorization server metadata.
	//
	// See: https://datatracker.ietf.org/doc/html/rfc8414#section-3
	WellKnownOAuthAuthorizationServerSuffix = consts.WellKnownOAuthAuthorizationServerSuffix

	// WellKnownOpenIDConfigurationSuffix is the well-known URI suffix of the OpenID Provider Configuration.
	//
	// See: https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationRequest
	WellKnownOpenIDConfigurationSuffix = consts.WellKnownOpenIDConfigurationSuffix
)

// WriteDiscoveryResponse writes a discovery metadata document as a 200 JSON response, or a 500 without a body when it
// cannot be marshalled. Caching headers are left to the caller.
//
// See: https://datatracker.ietf.org/doc/html/rfc8414#section-3.2
func (f *Fosite) WriteDiscoveryResponse(_ context.Context, rw http.ResponseWriter, metadata any) {
	body, err := json.Marshal(metadata)
	if err != nil {
		rw.WriteHeader(http.StatusInternalServerError)

		return
	}

	rw.Header().Set(consts.HeaderContentType, "application/json;charset=UTF-8")
	rw.WriteHeader(http.StatusOK)

	_, _ = rw.Write(body)
}

// WellKnownURLInsert returns the well-known URL of the issuer with the suffix inserted between the host and the path of
// the issuer.
//
// See: https://datatracker.ietf.org/doc/html/rfc8414#section-3.1
func WellKnownURLInsert(issuer, suffix string) (location string, err error) {
	var u *url.URL

	if u, err = parseWellKnownIssuer(issuer); err != nil {
		return "", err
	}

	return u.Scheme + "://" + u.Host + "/.well-known/" + suffix + u.EscapedPath(), nil
}

// WellKnownURLAppend returns the well-known URL of the issuer with the suffix appended to the issuer.
//
// See: https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationRequest
func WellKnownURLAppend(issuer, suffix string) (location string, err error) {
	var u *url.URL

	if u, err = parseWellKnownIssuer(issuer); err != nil {
		return "", err
	}

	return u.Scheme + "://" + u.Host + u.EscapedPath() + "/.well-known/" + suffix, nil
}

func parseWellKnownIssuer(issuer string) (u *url.URL, err error) {
	if u, err = url.Parse(strings.TrimSuffix(issuer, "/")); err != nil {
		return nil, fmt.Errorf("the issuer '%s' is not a valid URL: %w", issuer, err)
	}

	if u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("the issuer '%s' must be an absolute URL", issuer)
	}

	if u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(issuer, "#") {
		return nil, fmt.Errorf("the issuer '%s' must not have a query or fragment component", issuer)
	}

	return u, nil
}
