// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

// Package rfc7523 implements the RFC 7523 JWT Profile for OAuth 2.0 Client Authentication and Authorization Grants.
//
// A JWT authorization grant is accepted from a trusted issuer, see oauth2.RFC7523TrustedIssuer, and its subject is
// resolved to a local subject by the Storage, which makes the handler the second trust domain of OAuth Identity and
// Authorization Chaining Across Domains.
//
// See: https://datatracker.ietf.org/doc/html/rfc7523#section-3
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-chaining-17#section-2.4.2
package rfc7523
