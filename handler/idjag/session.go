// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package idjag

import (
	"context"

	"authelia.com/provider/oauth2"
)

// Session is the session interface for ID-JAG token issuance. IDJAGClaims supplies additional claims for the grant,
// and cannot override the registered claims, 'cnf', 'act', 'authorization_details', 'resource' or 'scope'. The
// 'auth_time', 'acr' and 'amr' claims are taken together from a validated ID token or refresh token subject token
// which carries any of them, otherwise from the session ID token claims, and from IDJAGClaims only when neither of
// those carries any of them.
//
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.1
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-6
type Session interface {
	IDJAGClaims(ctx context.Context, relationship *oauth2.IDJAGRelationship) (claims map[string]any)
}

// RedeemSession is the session interface for ID-JAG token redemption. SetIDJAGClaims receives the claims of the grant
// as issued, not what was granted: 'scope', 'resource' and 'authorization_details' may have been narrowed, so they
// must not be copied into tokens as granted values.
//
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-4.4.1
type RedeemSession interface {
	SetIDJAGClaims(claims map[string]any)
}
