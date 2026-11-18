// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
)

// BuildFrontChannelLogout returns the front-channel logout URI of each of the supplied clients, as per OpenID Connect
// Front-Channel Logout 1.0. The caller renders each URI as the source of an iframe.
//
// The caller supplies the clients: this library does not track which clients participated in a session, does not end
// any session, and does not render any page. A result is returned for every client supplied, in the order supplied.
//
// The 'iss' and 'sid' query parameters are added only for a client which registered
// 'frontchannel_logout_session_required', and are always added together. The issuer is the configured issuer, which is
// the 'iss' claim of the ID Tokens issued. A client which requires them is skipped when either is unavailable.
//
// See: https://openid.net/specs/openid-connect-frontchannel-1_0.html#RPLogout
// See: https://openid.net/specs/openid-connect-frontchannel-1_0.html#OPLogout
func (f *Fosite) BuildFrontChannelLogout(ctx context.Context, requester FrontChannelLogoutRequester) (results []FrontChannelLogoutResult) {
	clients := requester.GetClients()

	results = make([]FrontChannelLogoutResult, len(clients))

	if len(clients) == 0 {
		return results
	}

	issuer, sid := f.Config.GetIssuer(ctx), requester.GetSessionID()

	for i, client := range clients {
		results[i].ClientID = client.GetID()

		if results[i].URI, results[i].Reason = frontChannelLogoutURI(client, issuer, sid); results[i].Reason != "" {
			results[i].Skipped = true
		}
	}

	return results
}
