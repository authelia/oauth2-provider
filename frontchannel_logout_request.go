// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"net/url"

	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/x/errorsx"
)

// FrontChannelLogoutRequester is a request to build the front-channel logout URIs of the Relying Parties
// participating in a session.
//
// The caller supplies the clients: this library does not track which clients participated in a session.
//
// See: https://openid.net/specs/openid-connect-frontchannel-1_0.html
type FrontChannelLogoutRequester interface {
	// GetSessionID returns the 'sid' query parameter value, empty if absent. It must be the 'sid' claim of the ID
	// Tokens issued for the session.
	GetSessionID() (sid string)

	// GetClients returns the clients to notify.
	GetClients() (clients []Client)
}

// NewFrontChannelLogoutRequest returns a FrontChannelLogoutRequest.
func NewFrontChannelLogoutRequest(sid string, clients []Client) (request *FrontChannelLogoutRequest) {
	return &FrontChannelLogoutRequest{
		SessionID: sid,
		Clients:   clients,
	}
}

// FrontChannelLogoutRequest is an implementation of FrontChannelLogoutRequester.
type FrontChannelLogoutRequest struct {
	SessionID string
	Clients   []Client
}

// GetSessionID returns the session identifier of the session being ended.
func (r *FrontChannelLogoutRequest) GetSessionID() (sid string) {
	return r.SessionID
}

// GetClients returns the clients to notify.
func (r *FrontChannelLogoutRequest) GetClients() (clients []Client) {
	return r.Clients
}

// FrontChannelLogoutResult is the front-channel logout URI of a single Relying Party.
//
// A result is reported for every client supplied, in the order supplied, including clients that were skipped.
type FrontChannelLogoutResult struct {
	// ClientID is the identifier of the client this result concerns.
	ClientID string

	// Skipped is true when the client was ineligible and no URI was built.
	Skipped bool

	// Reason explains why the client was skipped. Empty when Skipped is false.
	Reason string

	// URI is the URI to render as the source of an iframe. Empty when Skipped is true. It is not HTML escaped.
	URI string
}

// NewFrontChannelLogoutURI returns the registered 'frontchannel_logout_uri' with the 'iss' and 'sid' query parameters
// added. The existing query component is retained as registered. If either parameter is included both MUST be, so an
// empty issuer or session identifier is an error.
//
// The registered URI must be an absolute 'https' or 'http' URI with a host, without a fragment, and without an 'iss'
// or 'sid' query parameter of its own.
//
// See: https://openid.net/specs/openid-connect-frontchannel-1_0.html#RPLogout
func NewFrontChannelLogoutURI(uri, issuer, sid string) (location string, err error) {
	if issuer == "" || sid == "" {
		return "", errorsx.WithStack(ErrInvalidRequest.WithHint("The 'iss' and 'sid' parameters must both be included in a front-channel logout URI."))
	}

	parsed, reason := parseFrontChannelLogoutURI(uri)
	if reason != "" {
		return "", errorsx.WithStack(ErrInvalidRequest.WithHint(reason))
	}

	return frontChannelLogoutSessionURI(parsed, issuer, sid), nil
}

func frontChannelLogoutSessionURI(uri *url.URL, issuer, sid string) (location string) {
	query := url.Values{consts.FormParameterIssuer: []string{issuer}}.Encode() + "&" + url.Values{consts.ClaimSessionID: []string{sid}}.Encode()

	location = uri.String()

	switch {
	case uri.RawQuery != "":
		return location + "&" + query
	case uri.ForceQuery:
		return location + query
	default:
		return location + "?" + query
	}
}

func parseFrontChannelLogoutURI(raw string) (uri *url.URL, reason string) {
	var err error

	if uri, err = url.Parse(raw); err != nil || uri.Hostname() == "" || (uri.Scheme != consts.SchemeHTTPS && uri.Scheme != consts.SchemeHTTP) {
		return nil, "The OAuth 2.0 Client has a registered 'frontchannel_logout_uri' which is not an absolute 'https' or 'http' URI."
	}

	if uri.Fragment != "" {
		return nil, "The OAuth 2.0 Client has a registered 'frontchannel_logout_uri' which contains a fragment component."
	}

	query := uri.Query()

	if query.Has(consts.FormParameterIssuer) || query.Has(consts.ClaimSessionID) {
		return nil, "The OAuth 2.0 Client has a registered 'frontchannel_logout_uri' which contains the 'iss' or 'sid' query parameter."
	}

	uri.Fragment, uri.RawFragment = "", ""

	return uri, ""
}

func frontChannelLogoutURI(client Client, issuer, sid string) (location string, reason string) {
	c, ok := client.(FrontChannelLogoutClient)
	if !ok {
		return "", "The OAuth 2.0 Client does not support OpenID Connect Front-Channel Logout."
	}

	raw := c.GetFrontChannelLogoutURI()
	if raw == "" {
		return "", "The OAuth 2.0 Client does not have a registered 'frontchannel_logout_uri'."
	}

	var uri *url.URL

	if uri, reason = parseFrontChannelLogoutURI(raw); reason != "" {
		return "", reason
	}

	// The 'http' scheme is only permitted when the Client Type is confidential.
	if uri.Scheme == consts.SchemeHTTP && c.IsPublic() {
		return "", "The OAuth 2.0 Client is a public client and has a registered 'frontchannel_logout_uri' which does not use the 'https' scheme."
	}

	if !c.GetFrontChannelLogoutSessionRequired() {
		return uri.String(), ""
	}

	switch {
	case sid == "":
		return "", "The OAuth 2.0 Client requires the 'sid' parameter but no session identifier was supplied."
	case issuer == "":
		return "", "The OAuth 2.0 Client requires the 'iss' parameter but no issuer is configured."
	}

	return frontChannelLogoutSessionURI(uri, issuer, sid), ""
}

var (
	_ FrontChannelLogoutRequester = (*FrontChannelLogoutRequest)(nil)
)
