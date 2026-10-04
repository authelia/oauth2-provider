// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

// Package idjag implements the Identity Assertion JWT Authorization Grant as defined by
// draft-ietf-oauth-identity-assertion-authz-grant-04. IssueHandler issues grants in the IdP Authorization Server role
// through RFC 8693 token exchange, and RedeemHandler redeems them in the Resource Authorization Server role through
// the RFC 7523 'jwt-bearer' grant, or through the 'jwt-dpop' grant Section 9.8.1.2.1 uses for a DPoP-bound grant.
//
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04
// See: https://datatracker.ietf.org/doc/html/draft-parecki-oauth-jwt-dpop-grant-01
package idjag
