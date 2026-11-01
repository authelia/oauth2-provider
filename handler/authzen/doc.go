// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

// Package authzen implements oauth2.IssuancePolicy with the OpenID AuthZEN Authorization API 1.0 acting as the Policy
// Decision Point, casting the authorization server as the Policy Enforcement Point. It follows Draft 1 of the AuthZEN
// Profile for OAuth 2.0 Token Issuance and the AuthZEN Binding for OAuth 2.0 Token Exchange, which are not final, so
// this package is not covered by any compatibility guarantee.
//
// It narrows an authorization details entry only by dropping it, which is narrower than the reassembly the profile
// describes. It does not apply the 'claims' shaping key, so a response naming a claim in 'crit' is a denial. It rejects
// the 'authorization_details' shaping key as it has no type-specific validators.
//
// See: https://openid.net/specs/authorization-api-1_0.html
// See: https://github.com/openid/authzen/tree/main/profiles/authzen-oauth
package authzen
