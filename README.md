<!--
SPDX-FileCopyrightText: 2026 Authelia

SPDX-License-Identifier: Apache-2.0
-->

# OAuth 2.0 Framework

<p>
  <a href="https://pkg.go.dev/authelia.com/provider/oauth2"><picture><source media="(prefers-color-scheme: dark)" srcset="https://shieldcn.dev/badge/go-reference-blue.svg?logo=go&logoColor=%2300add8&mode=dark&size=sm&variant=outline"><img alt="Go Reference" src="https://shieldcn.dev/badge/go-reference-blue.svg?logo=go&logoColor=%2300add8&mode=light&size=sm&variant=outline"></picture></a>
  <a href="https://github.com/authelia/oauth2-provider/actions/workflows/go.yml"><picture><source media="(prefers-color-scheme: dark)" srcset="https://shieldcn.dev/badge/dynamic/json.svg?url=https%3A%2F%2Fimg.shields.io%2Fgithub%2Factions%2Fworkflow%2Fstatus%2Fauthelia%2Foauth2-provider%2Fgo.yml.json%3Fbranch%3Dmaster&query=%24.message&label=build&logo=githubactions&logoColor=%232088ff&mode=dark&size=sm&variant=outline"><img alt="Build" src="https://shieldcn.dev/badge/dynamic/json.svg?url=https%3A%2F%2Fimg.shields.io%2Fgithub%2Factions%2Fworkflow%2Fstatus%2Fauthelia%2Foauth2-provider%2Fgo.yml.json%3Fbranch%3Dmaster&query=%24.message&label=build&logo=githubactions&logoColor=%232088ff&mode=light&size=sm&variant=outline"></picture></a>
  <a href="https://github.com/authelia/oauth2-provider/tags"><picture><source media="(prefers-color-scheme: dark)" srcset="https://shieldcn.dev/badge/dynamic/json.svg?url=https%3A%2F%2Fimg.shields.io%2Fgithub%2Fv%2Ftag%2Fauthelia%2Foauth2-provider.json%3Fsort%3Dsemver&query=%24.message&label=tag&logo=github&logoColor=%23181717&mode=dark&size=sm&variant=outline"><img alt="GitHub Tag" src="https://shieldcn.dev/badge/dynamic/json.svg?url=https%3A%2F%2Fimg.shields.io%2Fgithub%2Fv%2Ftag%2Fauthelia%2Foauth2-provider.json%3Fsort%3Dsemver&query=%24.message&label=tag&logo=github&logoColor=%23181717&mode=light&size=sm&variant=outline"></picture></a>
  <a href="https://github.com/authelia/oauth2-provider/blob/master/go.mod"><picture><source media="(prefers-color-scheme: dark)" srcset="https://shieldcn.dev/badge/dynamic/json.svg?url=https%3A%2F%2Fimg.shields.io%2Fgithub%2Fgo-mod%2Fgo-version%2Fauthelia%2Foauth2-provider.json&query=%24.message&label=go&logo=go&logoColor=%2300add8&mode=dark&size=sm&variant=outline"><img alt="Go Version" src="https://shieldcn.dev/badge/dynamic/json.svg?url=https%3A%2F%2Fimg.shields.io%2Fgithub%2Fgo-mod%2Fgo-version%2Fauthelia%2Foauth2-provider.json&query=%24.message&label=go&logo=go&logoColor=%2300add8&mode=light&size=sm&variant=outline"></picture></a>
  <a href="https://codecov.io/gh/authelia/oauth2-provider"><picture><source media="(prefers-color-scheme: dark)" srcset="https://shieldcn.dev/badge/dynamic/json.svg?url=https%3A%2F%2Fimg.shields.io%2Fcodecov%2Fc%2Fgithub%2Fauthelia%2Foauth2-provider.json&query=%24.message&label=coverage&logo=codecov&logoColor=%23f01f7a&mode=dark&size=sm&variant=outline"><img alt="Codecov" src="https://shieldcn.dev/badge/dynamic/json.svg?url=https%3A%2F%2Fimg.shields.io%2Fcodecov%2Fc%2Fgithub%2Fauthelia%2Foauth2-provider.json&query=%24.message&label=coverage&logo=codecov&logoColor=%23f01f7a&mode=light&size=sm&variant=outline"></picture></a>
  <a href="https://scorecard.dev/viewer/?uri=github.com/authelia/oauth2-provider"><picture><source media="(prefers-color-scheme: dark)" srcset="https://shieldcn.dev/badge/dynamic/json.svg?url=https%3A%2F%2Fimg.shields.io%2Fossf-scorecard%2Fgithub.com%2Fauthelia%2Foauth2-provider.json&query=%24.message&label=openssf%20scorecard&logo=data%3Aimage%2Fsvg%2Bxml%3Bbase64%2CPHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyMzAgMjMwIiBmaWxsLXJ1bGU9ImV2ZW5vZGQiPjxwYXRoIGQ9Ik0xMTgsMiAxMzIsMiAxNDUsNyAxNTYsMTcgMTYzLDM0IDE2MSw1MiAxNDUsNzcgMTM0LDEwNCAxMjksMTIzIDEzNCwxMjUgMTQ2LDEzOSAxNTksMTQxIDE2MywxMzYgMTY2LDEzNiAxODEsMTQ4IDE5NCwxNTMgMjEyLDE1MyAyMTYsMTUxIDIyMSwxNTMgMjI3LDE4NyAyMjUsMjI5IDI3LDIyOSAyNywyMjQgMzUsMjE2IDI0LDE5NCAyNCwxODUgMjcsMTc5IDU0LDE1MCA3MCwxMzkgODMsMTM0IDg2LDEyNSA5OCwxMTggMTAyLDEwNyAxMjAsNzggMTEyLDc1IDg2LDgyIDYxLDgyIDU2LDc4IDU2LDc1IDYzLDY2IDg4LDQ0IDg4LDMxIDk1LDE2IDEwNSw3IDExOCwyWiIvPjwvc3ZnPg%3D%3D&logoColor=%230f3b63&mode=dark&size=sm&variant=outline"><img alt="OpenSSF Scorecard" src="https://shieldcn.dev/badge/dynamic/json.svg?url=https%3A%2F%2Fimg.shields.io%2Fossf-scorecard%2Fgithub.com%2Fauthelia%2Foauth2-provider.json&query=%24.message&label=openssf%20scorecard&logo=data%3Aimage%2Fsvg%2Bxml%3Bbase64%2CPHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyMzAgMjMwIiBmaWxsLXJ1bGU9ImV2ZW5vZGQiPjxwYXRoIGQ9Ik0xMTgsMiAxMzIsMiAxNDUsNyAxNTYsMTcgMTYzLDM0IDE2MSw1MiAxNDUsNzcgMTM0LDEwNCAxMjksMTIzIDEzNCwxMjUgMTQ2LDEzOSAxNTksMTQxIDE2MywxMzYgMTY2LDEzNiAxODEsMTQ4IDE5NCwxNTMgMjEyLDE1MyAyMTYsMTUxIDIyMSwxNTMgMjI3LDE4NyAyMjUsMjI5IDI3LDIyOSAyNywyMjQgMzUsMjE2IDI0LDE5NCAyNCwxODUgMjcsMTc5IDU0LDE1MCA3MCwxMzkgODMsMTM0IDg2LDEyNSA5OCwxMTggMTAyLDEwNyAxMjAsNzggMTEyLDc1IDg2LDgyIDYxLDgyIDU2LDc4IDU2LDc1IDYzLDY2IDg4LDQ0IDg4LDMxIDk1LDE2IDEwNSw3IDExOCwyWiIvPjwvc3ZnPg%3D%3D&logoColor=%230f3b63&mode=light&size=sm&variant=outline"></picture></a>
  <a href="https://www.apache.org/licenses/LICENSE-2.0"><picture><source media="(prefers-color-scheme: dark)" srcset="https://shieldcn.dev/github/authelia/oauth2-provider/license.svg?logo=apache&logoColor=%23d22128&mode=dark&size=sm&variant=outline"><img alt="License" src="https://shieldcn.dev/github/authelia/oauth2-provider/license.svg?logo=apache&logoColor=%23d22128&mode=light&size=sm&variant=outline"></picture></a>
</p>

<p align="center">
  <img src=".github/assets/gopher.svg" alt="A Go gopher in front of a shield, holding up a golden token key and presenting an ID token badge" width="280">
</p>

This library is the OAuth 2.0 and OpenID Connect 1.0 authorization server framework used by
[Authelia](https://github.com/authelia/authelia). It provides the request parsing, validation, client authentication,
token issuance, and response writing for the authorization, token, introspection, revocation, and related endpoints, and
leaves storage, user authentication, and consent to the implementer through a set of interfaces.

It started as a hard fork of [ORY Fosite](https://github.com/ory/fosite) and has since diverged significantly; see
[Thanks](#thanks) for details.

## Go Version Support Policy

This library officially supports only the latest minor version of go, which is currently **go 1.27**. Older versions of
go are not supported and are not tested. This rule applies at the time of a published release.

This library is intended to be used with [Go Toolchains](https://go.dev/doc/toolchain) as indicated by the `toolchain`
directive in the `go.mod`.

This library handles a critical element of security in dependent projects, so we prefer security over backwards
compatibility wherever the two conflict. Go's own compatibility guarantees usually make upgrading the toolchain
painless.

## Feature Support

Legend: ✅ supported, 🟡 partially supported, ❌ not supported.

The Draft column names the revision implemented for a specification which is still a draft, or the latest revision when
it is not supported. It is empty for a published specification. A draft may change or be replaced before it is
finalized, so support for one may change in any release.

### OAuth 2.0

| Specification                                                                                                                                   | Status | Draft      | Notes                                                                                                           |
| ----------------------------------------------------------------------------------------------------------------------------------------------- | :----: | ---------- | --------------------------------------------------------------------------------------------------------------- |
| [RFC 6749: The OAuth 2.0 Authorization Framework](https://datatracker.ietf.org/doc/html/rfc6749)                                                |   ✅   |            | Authorization Code, Implicit, Client Credentials, Resource Owner Password Credentials, and Refresh Token grants |
| [RFC 6750: Bearer Token Usage](https://datatracker.ietf.org/doc/html/rfc6750)                                                                   |   ✅   |            |                                                                                                                 |
| [RFC 7009: Token Revocation](https://datatracker.ietf.org/doc/html/rfc7009)                                                                     |   ✅   |            | Optional policy to revoke the refresh token alongside an access token                                           |
| [RFC 7521: Assertion Framework for Client Authentication and Authorization Grants](https://datatracker.ietf.org/doc/html/rfc7521)               |   ✅   |            | Through the RFC 7523 JWT profile                                                                                |
| [RFC 7523: JWT Profile for Client Authentication and Authorization Grants](https://datatracker.ietf.org/doc/html/rfc7523)                       |   ✅   |            | `client_secret_jwt`, `private_key_jwt`, and the JWT bearer grant                                                |
| [RFC 7591: Dynamic Client Registration Protocol](https://datatracker.ietf.org/doc/html/rfc7591)                                                 |   ✅   |            | Includes policies from creation tokens                                                                          |
| [RFC 7592: Dynamic Client Registration Management Protocol](https://datatracker.ietf.org/doc/html/rfc7592)                                      |   ✅   |            |                                                                                                                 |
| [RFC 7636: Proof Key for Code Exchange (PKCE)](https://datatracker.ietf.org/doc/html/rfc7636)                                                   |   ✅   |            | Per-client enforcement policy                                                                                   |
| [RFC 7662: Token Introspection](https://datatracker.ietf.org/doc/html/rfc7662)                                                                  |   ✅   |            | Client authentication for the introspection endpoint                                                            |
| [RFC 8252: OAuth 2.0 for Native Apps](https://datatracker.ietf.org/doc/html/rfc8252)                                                            |   🟡   |            | Redirect URI handling for native clients                                                                        |
| [RFC 8628: Device Authorization Grant](https://datatracker.ietf.org/doc/html/rfc8628)                                                           |   ✅   |            |                                                                                                                 |
| [RFC 8693: Token Exchange](https://datatracker.ietf.org/doc/html/rfc8693)                                                                       |   ✅   |            | Access token, refresh token, ID Token, and custom JWT token types                                               |
| [RFC 8705: Mutual-TLS Client Authentication and Certificate-Bound Access Tokens](https://datatracker.ietf.org/doc/html/rfc8705)                 |   ✅   |            | `tls_client_auth` and `self_signed_tls_client_auth`                                                             |
| [RFC 8707: Resource Indicators](https://datatracker.ietf.org/doc/html/rfc8707)                                                                  |   ✅   |            | Exact, prefix, and wildcard matching strategies                                                                 |
| [RFC 9068: JWT Profile for Access Tokens](https://datatracker.ietf.org/doc/html/rfc9068)                                                        |   ✅   |            | Enabled globally or per client                                                                                  |
| [RFC 9101: JWT-Secured Authorization Request (JAR)](https://datatracker.ietf.org/doc/html/rfc9101)                                              |   ✅   |            |                                                                                                                 |
| [RFC 9126: Pushed Authorization Requests (PAR)](https://datatracker.ietf.org/doc/html/rfc9126)                                                  |   ✅   |            | Per-client enforcement policy                                                                                   |
| [RFC 9207: Authorization Server Issuer Identification](https://datatracker.ietf.org/doc/html/rfc9207)                                           |   ✅   |            |                                                                                                                 |
| [RFC 9396: Rich Authorization Requests](https://datatracker.ietf.org/doc/html/rfc9396)                                                          |   ✅   |            |                                                                                                                 |
| [RFC 9449: Demonstrating Proof of Possession (DPoP)](https://datatracker.ietf.org/doc/html/rfc9449)                                             |   ✅   |            |                                                                                                                 |
| [RFC 9470: Step Up Authentication Challenge Protocol](https://datatracker.ietf.org/doc/html/rfc9470)                                            |   🟡   |            | The `insufficient_user_authentication` error, used by ID-JAG                                                    |
| [RFC 9700: Best Current Practice for OAuth 2.0 Security](https://datatracker.ietf.org/doc/html/rfc9700)                                         |   🟡   |            | Includes refresh token replay detection; not assessed as a whole                                                |
| [RFC 9701: JWT Response for Token Introspection](https://datatracker.ietf.org/doc/html/rfc9701)                                                 |   ✅   |            |                                                                                                                 |
| [JWT Secured Authorization Response Mode (JARM)](https://openid.net/specs/oauth-v2-jarm.html)                                                   |   ✅   |            |                                                                                                                 |
| [Multiple Response Type Encoding Practices](https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html)                                 |   ✅   |            | Including the `none` response type                                                                              |
| [Form Post Response Mode](https://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html)                                                   |   ✅   |            | Custom response writer support                                                                                  |
| [Identity Assertion JWT Authorization Grant (ID-JAG)](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-06) |   ✅   | `draft-06` | Issuing and redeeming through RFC 8693 and RFC 7523                                                             |
| [Identity and Authorization Chaining Across Domains](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-chaining-17)               |   🟡   | `draft-17` | Issuing grants in trust domain A; per-client opt-in                                                             |
| [JWT Authorization Grant with DPoP Binding](https://datatracker.ietf.org/doc/html/draft-parecki-oauth-jwt-dpop-grant-02)                        |   ✅   | `draft-02` | Redeeming a DPoP-bound ID-JAG                                                                                   |
| [Updates to JWT Client Authentication and Authorization Grants](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-rfc7523bis-11)           |   🟡   | `draft-11` | Audience requirements for client assertions                                                                     |
| [FAPI 2.0 Security Profile](https://openid.net/specs/fapi-security-profile-2_0-final.html)                                                      |   🟡   |            | Individual requirements such as refresh token rotation policy; not a complete profile                           |
| [FAPI 2.0 Message Signing](https://openid.net/specs/fapi-message-signing-2_0-final.html)                                                        |   🟡   |            | Individual requirements for request objects; not a complete profile                                             |

### OpenID Connect 1.0

| Specification                                                                                                                                            | Status | Draft      | Notes                                                                                                   |
| -------------------------------------------------------------------------------------------------------------------------------------------------------- | :----: | ---------- | ------------------------------------------------------------------------------------------------------- |
| [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)                                                                         |   🟡   |            | Authorization Code, Implicit, and Hybrid flows and the `claims` request parameter; no UserInfo endpoint |
| [OpenID Connect Dynamic Client Registration 1.0](https://openid.net/specs/openid-connect-registration-1_0.html)                                          |   ✅   |            |                                                                                                         |
| [OpenID Connect RP-Initiated Logout 1.0](https://openid.net/specs/openid-connect-rpinitiated-1_0.html)                                                   |   ✅   |            |                                                                                                         |
| [OpenID Connect Back-Channel Logout 1.0](https://openid.net/specs/openid-connect-backchannel-1_0.html)                                                   |   ✅   |            |                                                                                                         |
| [OpenID Connect Core Error Code `unmet_authentication_requirements`](https://openid.net/specs/openid-connect-unmet-authentication-requirements-1_0.html) |   ✅   |            |                                                                                                         |
| [OpenID Connect Key Binding 1.0](https://openid.net/specs/openid-connect-key-binding-1_0.html)                                                           |   ✅   | `draft-03` |                                                                                                         |
| [OpenID Connect UserInfo Verifiable Credentials](https://openid.net/specs/openid-connect-userinfo-vc-1_0.html)                                           |   🟡   | `draft-00` | Issuing the `c_nonce`; no UserInfo endpoint                                                             |

### JOSE

| Specification                                                                                            | Status | Draft | Notes                                                                            |
| -------------------------------------------------------------------------------------------------------- | :----: | ----- | -------------------------------------------------------------------------------- |
| [RFC 7515: JSON Web Signature (JWS)](https://datatracker.ietf.org/doc/html/rfc7515)                      |   ✅   |       |                                                                                  |
| [RFC 7516: JSON Web Encryption (JWE)](https://datatracker.ietf.org/doc/html/rfc7516)                     |   ✅   |       |                                                                                  |
| [RFC 7517: JSON Web Key (JWK)](https://datatracker.ietf.org/doc/html/rfc7517)                            |   ✅   |       |                                                                                  |
| [RFC 7518: JSON Web Algorithms (JWA)](https://datatracker.ietf.org/doc/html/rfc7518)                     |   ✅   |       |                                                                                  |
| [RFC 7519: JSON Web Token (JWT)](https://datatracker.ietf.org/doc/html/rfc7519)                          |   ✅   |       |                                                                                  |
| [RFC 7638: JSON Web Key (JWK) Thumbprint](https://datatracker.ietf.org/doc/html/rfc7638)                 |   ✅   |       |                                                                                  |
| [RFC 7800: Proof-of-Possession Key Semantics for JWTs](https://datatracker.ietf.org/doc/html/rfc7800)    |   ✅   |       | The `cnf` claim                                                                  |
| [RFC 8037: CFRG Elliptic Curve Signatures in JOSE](https://datatracker.ietf.org/doc/html/rfc8037)        |   🟡   |       | Ed25519; no Ed448                                                                |
| [RFC 8725: JSON Web Token Best Current Practices](https://datatracker.ietf.org/doc/html/rfc8725)         |   🟡   |       | Explicit typing and mutually exclusive validation rules; not assessed as a whole |
| [RFC 9493: Subject Identifiers for Security Event Tokens](https://datatracker.ietf.org/doc/html/rfc9493) |   🟡   |       | The `sub_id` claim of ID-JAG                                                     |
| [RFC 9864: Fully-Specified Algorithms for JOSE and COSE](https://datatracker.ietf.org/doc/html/rfc9864)  |   🟡   |       | The `Ed25519` identifier; no `Ed448`                                             |

### Not Yet Supported: Drafts

Drafts adopted by the IETF OAuth Working Group or the OpenID Foundation which are likely to be finalized.

| Specification                                                                                                                        | Status | Draft                 | Notes                                                                       |
| ------------------------------------------------------------------------------------------------------------------------------------ | :----: | --------------------- | --------------------------------------------------------------------------- |
| [The OAuth 2.1 Authorization Framework](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1)                                 |   ❌   | `draft-17`            |                                                                             |
| [Updates to OAuth 2.0 Security Best Current Practice](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics-update) |   ❌   | `draft-03`            |                                                                             |
| [JSON Web Token Best Current Practices](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-rfc8725bis)                           |   ❌   | `draft-10`            | Updates RFC 8725                                                            |
| [OAuth Client ID Metadata Document](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document)              |   ❌   | `draft-02`            | In progress in [#863](https://github.com/authelia/oauth2-provider/pull/863) |
| [Attestation-Based Client Authentication](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-attestation-based-client-auth)      |   ❌   | `draft-12`            |                                                                             |
| [OAuth SPIFFE Client Authentication](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-spiffe-client-auth)                      |   ❌   | `draft-02`            |                                                                             |
| [OAuth 2.0 for First-Party Applications](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-first-party-apps)                    |   ❌   | `draft-04`            |                                                                             |
| [Transaction Tokens](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-transaction-tokens)                                      |   ❌   | `draft-11`            |                                                                             |
| [Refresh Token and Authorization Expiration](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-refresh-token-expiration)        |   ❌   | `draft-03`            |                                                                             |
| [Token Status List (TSL)](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list)                                        |   ❌   | `draft-21`            |                                                                             |
| [SD-JWT-based Verifiable Digital Credentials (SD-JWT VC)](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc)          |   ❌   | `draft-23`            |                                                                             |
| [Deferred Token Response](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-deferred-token-response)                            |   ❌   | `draft-01`            |                                                                             |
| [Delegate SD-JWT](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-delegate-sd-jwt)                                            |   ❌   | `draft-00`            |                                                                             |
| [OAuth 2.0 RAR Metadata and Error Remediation](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-rar-metadata-remediation)      |   ❌   | `draft-00`            |                                                                             |
| [OpenID Connect Advanced Syntax for Claims (ASC) 1.0](https://openid.net/specs/openid-connect-advanced-syntax-for-claims-1_0.html)   |   ❌   | `draft-02`            |                                                                             |
| [OpenID Connect Native SSO for Mobile Apps 1.0](https://openid.net/specs/openid-connect-native-sso-1_0.html)                         |   ❌   | `draft-07`            |                                                                             |
| [Self-Issued OpenID Provider v2](https://openid.net/specs/openid-connect-self-issued-v2-1_0.html)                                    |   ❌   | `draft-13`            |                                                                             |
| [CAEP Interoperability Profile 1.0](https://openid.net/specs/openid-caep-interoperability-profile-1_0-ID1.html)                      |   ❌   | `draft-00`            |                                                                             |
| [Grant Management for OAuth 2.0](https://openid.net/specs/oauth-v2-grant-management-ID1.html)                                        |   ❌   | Implementer's Draft 1 |                                                                             |

### Not Yet Supported: Published

| Specification                                                                                                                                                  | Status | Draft | Notes                                                                       |
| -------------------------------------------------------------------------------------------------------------------------------------------------------------- | :----: | ----- | --------------------------------------------------------------------------- |
| [RFC 8414: Authorization Server Metadata](https://datatracker.ietf.org/doc/html/rfc8414)                                                                       |   ❌   |       | Implementers serve their own metadata document                              |
| [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html)                                                                     |   ❌   |       | Implementers serve their own metadata document                              |
| [RFC 9728: Protected Resource Metadata](https://datatracker.ietf.org/doc/html/rfc9728)                                                                         |   ❌   |       |                                                                             |
| [RFC 9901: Selective Disclosure for JWTs (SD-JWT)](https://datatracker.ietf.org/doc/html/rfc9901)                                                              |   ❌   |       |                                                                             |
| [RFC 10017: OAuth 2.0 for Browser-Based Applications](https://datatracker.ietf.org/doc/html/rfc10017)                                                          |   ❌   |       |                                                                             |
| [RFC 10027: Best Current Practice for Security of Cross-Device Flows](https://datatracker.ietf.org/doc/html/rfc10027)                                          |   ❌   |       |                                                                             |
| [RFC 8417: Security Event Token (SET)](https://datatracker.ietf.org/doc/html/rfc8417)                                                                          |   ❌   |       | In progress in [#901](https://github.com/authelia/oauth2-provider/pull/901) |
| [RFC 8935: Push-Based Security Event Token Delivery](https://datatracker.ietf.org/doc/html/rfc8935)                                                            |   ❌   |       | In progress in [#901](https://github.com/authelia/oauth2-provider/pull/901) |
| [RFC 8936: Poll-Based Security Event Token Delivery](https://datatracker.ietf.org/doc/html/rfc8936)                                                            |   ❌   |       | In progress in [#901](https://github.com/authelia/oauth2-provider/pull/901) |
| [OpenID Shared Signals Framework 1.0](https://openid.net/specs/openid-sharedsignals-framework-1_0.html)                                                        |   ❌   |       | In progress in [#901](https://github.com/authelia/oauth2-provider/pull/901) |
| [OpenID Continuous Access Evaluation Profile 1.0](https://openid.net/specs/openid-caep-1_0.html)                                                               |   ❌   |       |                                                                             |
| [OpenID RISC Profile 1.0](https://openid.net/specs/openid-risc-1_0.html)                                                                                       |   ❌   |       |                                                                             |
| [OpenID Connect Client-Initiated Backchannel Authentication (CIBA)](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html) |   ❌   |       | In progress in [#532](https://github.com/authelia/oauth2-provider/pull/532) |
| [OpenID Connect Front-Channel Logout 1.0](https://openid.net/specs/openid-connect-frontchannel-1_0.html)                                                       |   ❌   |       |                                                                             |
| [OpenID Connect Session Management 1.0](https://openid.net/specs/openid-connect-session-1_0.html)                                                              |   ❌   |       |                                                                             |
| [Initiating User Registration via OpenID Connect 1.0](https://openid.net/specs/openid-connect-prompt-create-1_0.html)                                          |   ❌   |       |                                                                             |
| [OpenID Connect Relying Party Metadata Choices 1.0](https://openid.net/specs/openid-connect-rp-metadata-choices-1_0-final.html)                                |   ❌   |       |                                                                             |
| [OpenID Connect Extended Authentication Profile (EAP) ACR Values 1.0](https://openid.net/specs/openid-connect-eap-acr-values-1_0.html)                         |   ❌   |       |                                                                             |
| [OpenID Connect for Identity Assurance 1.0](https://openid.net/specs/openid-connect-4-identity-assurance-1_0-final.html)                                       |   ❌   |       |                                                                             |
| [OpenID Federation 1.0](https://openid.net/specs/openid-federation-1_0.html)                                                                                   |   ❌   |       |                                                                             |
| [OpenID Federation 1.1](https://openid.net/specs/openid-federation-1_1.html)                                                                                   |   ❌   |       |                                                                             |
| [OpenID Federation for OpenID Connect 1.1](https://openid.net/specs/openid-federation-connect-1_1.html)                                                        |   ❌   |       |                                                                             |
| [OpenID for Verifiable Credential Issuance 1.0](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)                                     |   ❌   |       |                                                                             |
| [OpenID for Verifiable Presentations 1.0](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html)                                                 |   ❌   |       |                                                                             |
| [OpenID4VC High Assurance Interoperability Profile 1.0](https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0-final.html)             |   ❌   |       |                                                                             |

Planned work and notable differences from ORY Fosite are tracked in [TODO.md](TODO.md).

## Thanks

This is a hard fork of [ORY Fosite](https://github.com/ory/fosite) under the [Apache 2.0 License](LICENSE) for the
purpose of performing self-maintenance of this critical Authelia dependency.

We however:

- Acknowledge the amazing hard work of the ORY developers in making such an amazing framework that we can do this with.
- Plan to continue to contribute back to te ORY fosite and related projects.
- Have ensured the licensing is unchanged in this fork of the library.
- Do not have a formal affiliation with ORY and individuals utilizing this library should not allow their usage to be a
  reflection on ORY as this library is not maintained by them.

The mascot is based on the Go gopher, designed by [Renée French](https://reneefrench.blogspot.com/) and licensed under
[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).
