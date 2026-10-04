// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package idjag

import (
	"context"
	"time"

	"authelia.com/provider/oauth2"
)

// IssueStorage is the storage interface for ID-JAG token issuance. The relationship maps the requesting client to its
// client at the Resource Authorization Server, and the subject maps the End-User to the subject identifier the Resource
// Authorization Server knows (Section 5); the tenant claims are taken from the session, see IssueHandler.
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-5
type IssueStorage interface {
	// GetIDJAGRelationship returns oauth2.ErrNotFound when the client has no relationship for the audience;
	// an audience may be the Resource Authorization Server issuer identifier or an implementation-specific alias (§4.3).
	GetIDJAGRelationship(ctx context.Context, request oauth2.AccessRequester, audience string) (relationship *oauth2.IDJAGRelationship, err error)

	// GetIDJAGSubject returns the subject identifier for the End-User of the session that an ID Token issued to the
	// Resource Authorization Server of the relationship would carry, which differs from the session subject when
	// subject identifiers are pairwise (Section 5). It returns oauth2.ErrNotFound when the End-User has none.
	GetIDJAGSubject(ctx context.Context, request oauth2.AccessRequester, relationship *oauth2.IDJAGRelationship) (subject string, err error)
}

// RedeemStorage is the storage interface for ID-JAG token redemption.
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-4.4.1
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.2.2
type RedeemStorage interface {
	GetIDJAGTrustedIssuer(ctx context.Context, issuer string) (trusted *oauth2.IDJAGTrustedIssuer, err error)
	// ResolveIDJAGSubject returns oauth2.ErrNotFound when the subject cannot be resolved; claims are the verified claims
	// of the grant. The 'sub' claim is unique only within its issuer, and within its tenant when the grant has a
	// 'tenant' claim, so the result MUST be scoped by both (Section 3.1).
	ResolveIDJAGSubject(ctx context.Context, client oauth2.Client, claims map[string]any) (subject string, err error)
	IsIDJAGUsed(ctx context.Context, issuer, jti string) (used bool, err error)
	MarkIDJAGUsed(ctx context.Context, issuer, jti string, exp time.Time) (err error)
}
