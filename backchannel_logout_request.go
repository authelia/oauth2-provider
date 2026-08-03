// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

// BackChannelLogoutRequester is a request to deliver Logout Tokens to the Relying Parties participating in a
// session.
//
// The caller supplies the clients: this library does not track which clients participated in a session.
//
// See: https://openid.net/specs/openid-connect-backchannel-1_0.html
type BackChannelLogoutRequester interface {
	// GetSubject returns the 'sub' claim for the Logout Token, empty if absent.
	GetSubject() (subject string)

	// GetSessionID returns the 'sid' claim for the Logout Token, empty if absent.
	GetSessionID() (sid string)

	// GetClients returns the clients to notify.
	GetClients() (clients []Client)

	// GetExtra returns additional claims to include in every Logout Token.
	GetExtra() (extra map[string]any)
}

// NewBackChannelLogoutRequest returns a BackChannelLogoutRequest with its map fields initialized.
//
// A Logout Token must carry either a subject or a session identifier; supplying neither is an error at send
// time.
func NewBackChannelLogoutRequest(subject, sid string, clients []Client) (request *BackChannelLogoutRequest) {
	return &BackChannelLogoutRequest{
		Subject:   subject,
		SessionID: sid,
		Clients:   clients,
		Extra:     map[string]any{},
	}
}

// BackChannelLogoutRequest is an implementation of BackChannelLogoutRequester.
type BackChannelLogoutRequest struct {
	Subject   string
	SessionID string
	Clients   []Client
	Extra     map[string]any
}

func (r *BackChannelLogoutRequest) GetSubject() (subject string) {
	return r.Subject
}

func (r *BackChannelLogoutRequest) GetSessionID() (sid string) {
	return r.SessionID
}

func (r *BackChannelLogoutRequest) GetClients() (clients []Client) {
	return r.Clients
}

func (r *BackChannelLogoutRequest) GetExtra() (extra map[string]any) {
	return r.Extra
}

// BackChannelLogoutResult is the outcome of delivering a Logout Token to a single Relying Party.
//
// A result is reported for every client supplied, in the order supplied, including clients that were skipped.
type BackChannelLogoutResult struct {
	// ClientID is the identifier of the client this result concerns.
	ClientID string

	// Skipped is true when the client was ineligible and no request was attempted.
	Skipped bool

	// Reason explains why the client was skipped. Empty when Skipped is false.
	Reason string

	// Status is the HTTP status code the Relying Party returned, zero when no response was received.
	Status int

	// Err is the signing or delivery failure for this client, nil on success.
	Err error
}

// Success returns true when the Relying Party acknowledged the Logout Token.
func (r BackChannelLogoutResult) Success() (ok bool) {
	return !r.Skipped && r.Err == nil
}

// backChannelLogoutURI returns the client's back-channel logout URI, or the reason it is ineligible when it has
// none registered or requires a session identifier that was not supplied.
func backChannelLogoutURI(client Client, sid string) (uri string, reason string) {
	c, ok := client.(BackChannelLogoutClient)
	if !ok {
		return "", "The OAuth 2.0 Client does not support OpenID Connect Back-Channel Logout."
	}

	if uri = c.GetBackChannelLogoutURI(); uri == "" {
		return "", "The OAuth 2.0 Client does not have a registered 'backchannel_logout_uri'."
	}

	if c.GetBackChannelLogoutSessionRequired() && sid == "" {
		return "", "The OAuth 2.0 Client requires the 'sid' claim but no session identifier was supplied."
	}

	return uri, ""
}

var (
	_ BackChannelLogoutRequester = (*BackChannelLogoutRequest)(nil)
)
