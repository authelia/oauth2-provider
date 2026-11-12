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
// Authorization Server knows (Section 5).
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-06#section-5
type IssueStorage interface {
	// GetIDJAGRelationship returns oauth2.ErrNotFound when the audience identifies no Resource Authorization Server the
	// IdP Authorization Server has a trust relationship with, which answers invalid_target; an audience may be the
	// Resource Authorization Server issuer identifier or an implementation-specific alias (Section 4.3). It returns
	// oauth2.ErrAccessDenied when the client or End-User is not authorized for a recognized audience (Section 4.3.4).
	GetIDJAGRelationship(ctx context.Context, request oauth2.AccessRequester, audience string) (relationship *oauth2.IDJAGRelationship, err error)

	// GetIDJAGSubject returns the subject identifier for the End-User of the session that an ID Token issued to the
	// Resource Authorization Server of the relationship would carry, which differs from the session subject when
	// subject identifiers are pairwise. It MUST return the same value for an End-User in every grant for the same
	// Resource Authorization Server and 'aud_tenant' regardless of the requesting client (Section 5.2). It returns
	// oauth2.ErrNotFound when the End-User has none, which answers access_denied.
	//
	// The session subject depends on the 'subject_token_type' of the request form: for an ID Token it is the 'sub'
	// claim of the ID Token, which is pairwise for the requesting client when subject identifiers are pairwise, and for
	// a refresh token it is the subject of the session the refresh token was issued for. Both MUST resolve to the same
	// value for the same End-User.
	GetIDJAGSubject(ctx context.Context, request oauth2.AccessRequester, relationship *oauth2.IDJAGRelationship) (subject string, err error)

	// GetIDJAGClaims returns additional claims about the End-User of the session for the grant issued to the Resource
	// Authorization Server of the relationship, such as 'email', 'aud_sub', 'tenant', 'aud_tenant' or 'sub_id', and nil
	// when there are none (Section 3.1). It is called for every grant, so the claims can reflect the current attributes
	// of the End-User (Section 4.3.3), and it MUST return 'tenant' when the issuer is multi-tenant (Section 6). The
	// claims cannot override the registered claims, 'cnf', 'act', 'authorization_details', 'resource' or 'scope', and
	// 'auth_time', 'acr' and 'amr' are used only when neither the subject token nor the session ID token claims carry
	// any of them. An *oauth2.RFC6749Error is returned to the client, and any other error answers server_error.
	GetIDJAGClaims(ctx context.Context, request oauth2.AccessRequester, relationship *oauth2.IDJAGRelationship) (claims map[string]any, err error)
}

// IssueAuthorizationDetailsStorage is an optional extension of IssueStorage which applies the IdP policy to the RFC 9396
// authorization details of each grant. Without it every requested detail of a type the relationship permits is
// granted unchanged.
//
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-06#section-4.3.3
type IssueAuthorizationDetailsStorage interface {
	// GetIDJAGAuthorizationDetails returns the authorization details to grant to the Resource Authorization Server of
	// the relationship. The requested details are those of the request of a type the relationship permits, and are
	// never nil. The IdP MAY modify, filter or omit them, and an empty result grants none. Every granted detail MUST
	// be of a type the relationship permits, or the request answers server_error. An *oauth2.RFC6749Error, such as
	// oauth2.ErrInvalidAuthorizationDetails, is returned to the client, and any other error answers server_error.
	GetIDJAGAuthorizationDetails(ctx context.Context, request oauth2.AccessRequester, relationship *oauth2.IDJAGRelationship, requested oauth2.AuthorizationDetails) (granted oauth2.AuthorizationDetails, err error)
}

// RedeemStorage is the storage interface for ID-JAG token redemption.
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-06#section-4.4.1
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-06#section-3.2.2
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-06#section-9.8
type RedeemStorage interface {
	GetIDJAGTrustedIssuer(ctx context.Context, issuer string) (trusted *oauth2.IDJAGTrustedIssuer, err error)

	// IsIDJAGTenantTrusted reports whether the 'iss' and 'tenant' claims of the grant are trusted together for the
	// recipient tenant, which the 'aud' claim, the 'aud_tenant' claim when present, or the trust relationship with the
	// issuer identifies. It MUST return false when the recipient tenant cannot be determined unambiguously. It is only
	// called for an issuer with IDJAGTrustedIssuer.MultiTenant set; claims are the verified claims of the grant
	// (Section 4.4.1).
	IsIDJAGTenantTrusted(ctx context.Context, claims map[string]any) (trusted bool, err error)

	// IsIDJAGResourceGoverned reports whether the resource is a protected resource this Resource Authorization Server
	// governs for the tenant the 'aud_tenant' claim identifies when present, otherwise for the tenant it associates
	// with the issuer of the grant. Resource identifiers are compared using Simple String Comparison; claims are the
	// verified claims of the grant (Section 4.4.1).
	IsIDJAGResourceGoverned(ctx context.Context, claims map[string]any, resource string) (governed bool, err error)

	// ResolveIDJAGSubject returns oauth2.ErrNotFound when the subject cannot be resolved, which answers invalid_grant,
	// and oauth2.ErrAccessDenied when the End-User is valid but not authorized here, such as having no license or
	// provisioning record (Section 4.4.3); claims are the verified claims of the grant. The 'sub' claim is unique only
	// within its issuer, and within its tenant when the grant has a 'tenant' claim, so the result MUST be scoped by
	// both (Section 3.1), and only within the recipient tenant (Section 4.4.1).
	//
	// An implementation which resolves the subject by the 'sub_id' claim MUST compare every member of the identifier
	// it uses for resolution, and MUST NOT resolve by the 'nameid' member alone unless that is its policy for the SAML
	// issuer. When its policy requires a SAML NameID Subject Identifier, it MUST return oauth2.ErrNotFound when the
	// claim is absent, malformed, of an unsupported format, or not authorized by that policy for the validated issuer
	// of the grant (Section 3.2.2). The 'issuer' member of the claim MUST NOT establish trust: it is used only when
	// configuration associates it with the 'iss' claim of the grant (Section 9.8).
	ResolveIDJAGSubject(ctx context.Context, client oauth2.Client, claims map[string]any) (subject string, err error)
	IsIDJAGUsed(ctx context.Context, issuer, jti string) (used bool, err error)
	MarkIDJAGUsed(ctx context.Context, issuer, jti string, exp time.Time) (err error)
}
