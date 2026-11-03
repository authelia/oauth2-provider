// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package idjag

// RedeemSession is the session interface for ID-JAG token redemption. SetIDJAGClaims receives the claims of the grant
// as issued, not what was granted: 'scope', 'resource' and 'authorization_details' may have been narrowed, so they
// must not be copied into tokens as granted values.
//
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-06#section-4.4.1
type RedeemSession interface {
	SetIDJAGClaims(claims map[string]any)
}
