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

| Specification                                                                                                                                   | Status | Draft      | Notes                                                                                                                                                                                       |
| ----------------------------------------------------------------------------------------------------------------------------------------------- | :----: | ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [RFC 6749: The OAuth 2.0 Authorization Framework](https://datatracker.ietf.org/doc/html/rfc6749)                                                |   ✅   |            | Authorization Code, Implicit, Client Credentials, Resource Owner Password Credentials, and Refresh Token grants                                                                             |
| [RFC 6750: Bearer Token Usage](https://datatracker.ietf.org/doc/html/rfc6750)                                                                   |   ✅   |            |                                                                                                                                                                                             |
| [RFC 7009: Token Revocation](https://datatracker.ietf.org/doc/html/rfc7009)                                                                     |   ✅   |            | Optional policy to revoke the refresh token alongside an access token                                                                                                                       |
| [RFC 7521: Assertion Framework for Client Authentication and Authorization Grants](https://datatracker.ietf.org/doc/html/rfc7521)               |   ✅   |            | Through the RFC 7523 JWT profile                                                                                                                                                            |
| [RFC 7523: JWT Profile for Client Authentication and Authorization Grants](https://datatracker.ietf.org/doc/html/rfc7523)                       |   ✅   |            | `client_secret_jwt`, `private_key_jwt`, and the JWT bearer grant                                                                                                                            |
| [RFC 7591: Dynamic Client Registration Protocol](https://datatracker.ietf.org/doc/html/rfc7591)                                                 |   ✅   |            | Includes policies from creation tokens                                                                                                                                                      |
| [RFC 7592: Dynamic Client Registration Management Protocol](https://datatracker.ietf.org/doc/html/rfc7592)                                      |   ✅   |            |                                                                                                                                                                                             |
| [RFC 7636: Proof Key for Code Exchange (PKCE)](https://datatracker.ietf.org/doc/html/rfc7636)                                                   |   ✅   |            | Per-client enforcement policy                                                                                                                                                               |
| [RFC 7662: Token Introspection](https://datatracker.ietf.org/doc/html/rfc7662)                                                                  |   ✅   |            | Client authentication, and per client a restriction to its own tokens or, for a resource server, to its audience                                                                            |
| [RFC 8252: OAuth 2.0 for Native Apps](https://datatracker.ietf.org/doc/html/rfc8252)                                                            |   ✅   |            | Any loopback port for public clients and those whose `application_type` is `native`; private-use URI schemes are checked at registration, and for other clients are left to the application |
| [RFC 8414: Authorization Server Metadata](https://datatracker.ietf.org/doc/html/rfc8414)                                                        |   ✅   |            | Built from the registered handlers and configuration, with optional signed metadata                                                                                                         |
| [RFC 8628: Device Authorization Grant](https://datatracker.ietf.org/doc/html/rfc8628)                                                           |   ✅   |            |                                                                                                                                                                                             |
| [RFC 8693: Token Exchange](https://datatracker.ietf.org/doc/html/rfc8693)                                                                       |   ✅   |            | Access token, refresh token, ID Token, and custom JWT token types                                                                                                                           |
| [RFC 8705: Mutual-TLS Client Authentication and Certificate-Bound Access Tokens](https://datatracker.ietf.org/doc/html/rfc8705)                 |   ✅   |            | `tls_client_auth` and `self_signed_tls_client_auth`                                                                                                                                         |
| [RFC 8707: Resource Indicators](https://datatracker.ietf.org/doc/html/rfc8707)                                                                  |   ✅   |            | Exact, prefix, and wildcard matching strategies                                                                                                                                             |
| [RFC 9068: JWT Profile for Access Tokens](https://datatracker.ietf.org/doc/html/rfc9068)                                                        |   ✅   |            | Enabled globally or per client                                                                                                                                                              |
| [RFC 9101: JWT-Secured Authorization Request (JAR)](https://datatracker.ietf.org/doc/html/rfc9101)                                              |   ✅   |            |                                                                                                                                                                                             |
| [RFC 9126: Pushed Authorization Requests (PAR)](https://datatracker.ietf.org/doc/html/rfc9126)                                                  |   ✅   |            | Per-client enforcement policy                                                                                                                                                               |
| [RFC 9207: Authorization Server Issuer Identification](https://datatracker.ietf.org/doc/html/rfc9207)                                           |   ✅   |            |                                                                                                                                                                                             |
| [RFC 9396: Rich Authorization Requests](https://datatracker.ietf.org/doc/html/rfc9396)                                                          |   ✅   |            |                                                                                                                                                                                             |
| [RFC 9449: Demonstrating Proof of Possession (DPoP)](https://datatracker.ietf.org/doc/html/rfc9449)                                             |   ✅   |            |                                                                                                                                                                                             |
| [RFC 9470: Step Up Authentication Challenge Protocol](https://datatracker.ietf.org/doc/html/rfc9470)                                            |   ✅   |            | Resource server challenges, `acr` and `auth_time` in tokens when `acr_values` and `max_age` require them, opt-in enforcement                                                                |
| [RFC 9700: Best Current Practice for OAuth 2.0 Security](https://datatracker.ietf.org/doc/html/rfc9700)                                         |   ✅   |            | Assessed as a whole; see [Security Considerations](#security-considerations) for the application's part                                                                                     |
| [RFC 9701: JWT Response for Token Introspection](https://datatracker.ietf.org/doc/html/rfc9701)                                                 |   ✅   |            |                                                                                                                                                                                             |
| [RFC 10017: OAuth 2.0 for Browser-Based Applications](https://datatracker.ietf.org/doc/html/rfc10017)                                           |   ✅   |            | Rotating or sender-constrained refresh tokens, with a maximum grant lifespan the application must enable; CORS is left to the application                                                   |
| [RFC 10070: Updates to JWT Client Authentication and Authorization Grants](https://datatracker.ietf.org/doc/html/rfc10070)                      |   ✅   |            | Issuer as the sole client assertion audience, with an opt-out                                                                                                                               |
| [JWT Secured Authorization Response Mode (JARM)](https://openid.net/specs/oauth-v2-jarm.html)                                                   |   ✅   |            |                                                                                                                                                                                             |
| [Multiple Response Type Encoding Practices](https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html)                                 |   ✅   |            | Including the `none` response type                                                                                                                                                          |
| [Form Post Response Mode](https://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html)                                                   |   ✅   |            | Custom response writer support                                                                                                                                                              |
| [Identity Assertion JWT Authorization Grant (ID-JAG)](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-06) |   ✅   | `draft-06` | Issuing and redeeming through RFC 8693 and RFC 7523                                                                                                                                         |
| [Identity and Authorization Chaining Across Domains](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-chaining-17)               |   🟡   | `draft-17` | Issuing grants in trust domain A; per-client opt-in                                                                                                                                         |
| [JWT Authorization Grant with DPoP Binding](https://datatracker.ietf.org/doc/html/draft-parecki-oauth-jwt-dpop-grant-02)                        |   ✅   | `draft-02` | Redeeming a DPoP-bound ID-JAG                                                                                                                                                               |
| [Transaction Tokens](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-transaction-tokens-11)                                              |   ✅   | `draft-11` | Opt-in, including the `self_signed` and `unsigned_json` subject tokens and replacement tokens                                                                                               |
| [OAuth Client ID Metadata Document](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-03)                      |   ✅   | `draft-03` | Opt-in through `Config.ClientIDMetadataDocumentResolver`, with a default resolver in `handler/cimd`                                                                                         |
| [Refresh Token and Authorization Expiration](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-refresh-token-expiration-03)                |   ✅   | `draft-03` | On by default; the authorization expiry is `RefreshTokenMaximumLifespan` or a deadline the application records                                                                              |
| [FAPI 2.0 Security Profile](https://openid.net/specs/fapi-security-profile-2_0-final.html)                                                      |   🟡   |            | Checked by `compose.ValidateFAPI2SecurityProfile`, applied by `compose.ApplyFAPI2SecurityProfile`, or enforced per client                                                                   |
| [FAPI 2.0 Message Signing](https://openid.net/specs/fapi-message-signing-2_0-final.html)                                                        |   ✅   |            | Applied by `compose.ApplyFAPI2MessageSigning` and checked by `compose.ValidateFAPI2MessageSigning`, per part                                                                                |

### OpenID Connect 1.0

| Specification                                                                                                                                            | Status | Draft      | Notes                                                                                                                               |
| -------------------------------------------------------------------------------------------------------------------------------------------------------- | :----: | ---------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)                                                                         |   ✅   |            | Authorization Code, Implicit, and Hybrid flows and the `claims` request parameter; the UserInfo endpoint is left to the application |
| [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html)                                                               |   ✅   |            | Provider metadata; WebFinger issuer discovery is not implemented                                                                    |
| [OpenID Connect Dynamic Client Registration 1.0](https://openid.net/specs/openid-connect-registration-1_0.html)                                          |   ✅   |            |                                                                                                                                     |
| [OpenID Connect RP-Initiated Logout 1.0](https://openid.net/specs/openid-connect-rpinitiated-1_0.html)                                                   |   ✅   |            |                                                                                                                                     |
| [OpenID Connect Back-Channel Logout 1.0](https://openid.net/specs/openid-connect-backchannel-1_0.html)                                                   |   ✅   |            |                                                                                                                                     |
| [OpenID Connect Core Error Code `unmet_authentication_requirements`](https://openid.net/specs/openid-connect-unmet-authentication-requirements-1_0.html) |   ✅   |            |                                                                                                                                     |
| [OpenID Connect Extended Authentication Profile (EAP) ACR Values 1.0](https://openid.net/specs/openid-connect-eap-acr-values-1_0.html)                   |   ✅   |            | The application asserts `phr`, `phrh` and `pop`; constants are provided                                                             |
| [OpenID Connect Key Binding 1.0](https://openid.net/specs/openid-connect-key-binding-1_0.html)                                                           |   ✅   | `draft-03` |                                                                                                                                     |
| [OpenID Connect UserInfo Verifiable Credentials](https://openid.net/specs/openid-connect-userinfo-vc-1_0.html)                                           |   🟡   | `draft-00` | Issuing the `c_nonce` under draft-suffixed names; the Credential Endpoint is left to the application                                |

### JOSE

| Specification                                                                                            | Status | Draft | Notes                                                                                                                         |
| -------------------------------------------------------------------------------------------------------- | :----: | ----- | ----------------------------------------------------------------------------------------------------------------------------- |
| [RFC 7515: JSON Web Signature (JWS)](https://datatracker.ietf.org/doc/html/rfc7515)                      |   ✅   |       |                                                                                                                               |
| [RFC 7516: JSON Web Encryption (JWE)](https://datatracker.ietf.org/doc/html/rfc7516)                     |   ✅   |       |                                                                                                                               |
| [RFC 7517: JSON Web Key (JWK)](https://datatracker.ietf.org/doc/html/rfc7517)                            |   ✅   |       |                                                                                                                               |
| [RFC 7518: JSON Web Algorithms (JWA)](https://datatracker.ietf.org/doc/html/rfc7518)                     |   ✅   |       |                                                                                                                               |
| [RFC 7519: JSON Web Token (JWT)](https://datatracker.ietf.org/doc/html/rfc7519)                          |   ✅   |       |                                                                                                                               |
| [RFC 7638: JSON Web Key (JWK) Thumbprint](https://datatracker.ietf.org/doc/html/rfc7638)                 |   ✅   |       |                                                                                                                               |
| [RFC 7800: Proof-of-Possession Key Semantics for JWTs](https://datatracker.ietf.org/doc/html/rfc7800)    |   ✅   |       | The `cnf` claim                                                                                                               |
| [RFC 8037: CFRG Elliptic Curve Signatures in JOSE](https://datatracker.ietf.org/doc/html/rfc8037)        |   🟡   |       | Ed25519 signatures; no Ed448, and no X25519 or X448 key agreement                                                             |
| [RFC 8725: JSON Web Token Best Current Practices](https://datatracker.ietf.org/doc/html/rfc8725)         |   ✅   |       | Explicit typing and mutually exclusive validation rules; the algorithms, keys and trusted issuers are left to the application |
| [RFC 9493: Subject Identifiers for Security Event Tokens](https://datatracker.ietf.org/doc/html/rfc9493) |   🟡   |       | The `sub_id` claim of ID-JAG and the subject of a Security Event Token                                                        |
| [RFC 9864: Fully-Specified Algorithms for JOSE and COSE](https://datatracker.ietf.org/doc/html/rfc9864)  |   🟡   |       | The `Ed25519` identifier; no `Ed448`                                                                                          |

### Shared Signals

| Specification                                                                                               | Status | Draft      | Notes                                                                                                                                                                                                                         |
| ----------------------------------------------------------------------------------------------------------- | :----: | ---------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [OpenID Shared Signals Framework 1.0](https://openid.net/specs/openid-sharedsignals-framework-1_0.html)     |   🟡   |            | Security Event Token signing, transmitter metadata, stream management, push and poll; subject management not implemented                                                                                                      |
| [OpenID Continuous Access Evaluation Profile 1.0](https://openid.net/specs/openid-caep-1_0.html)            |   ✅   |            | Every event and subject identifier type; when to emit an event is left to the application                                                                                                                                     |
| [CAEP Interoperability Profile 1.0](https://openid.net/specs/openid-caep-interoperability-profile-1_0.html) |   ✅   | `draft-01` | Bearer authorization with `ssf.read` and `ssf.manage`, stream management and verification, push and poll delivery; the `authorization_schemes` and `reason_admin` values and an RS256 signing key are left to the application |
| [RFC 8417: Security Event Token (SET)](https://datatracker.ietf.org/doc/html/rfc8417)                       |   ✅   |            | Claims and signing as profiled by SSF, so `sub`, `exp`, and multiple events are not supported and `toe` is not emitted; delivery is RFC 8935 push or RFC 8936 poll                                                            |
| [RFC 8935: Push-Based Security Event Token Delivery](https://datatracker.ietf.org/doc/html/rfc8935)         |   ✅   |            | Single push attempt with a typed outcome; queueing and retries are left to the application                                                                                                                                    |
| [RFC 8936: Poll-Based Security Event Token Delivery](https://datatracker.ietf.org/doc/html/rfc8936)         |   ✅   |            | Request parsing and response writing; the SET queue, acknowledgements and long polling are left to the application                                                                                                            |

### Model Context Protocol

| Specification                                                                                                                                                                                                         | Status | Draft | Notes                                                                                                                           |
| --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :----: | ----- | ------------------------------------------------------------------------------------------------------------------------------- |
| [MCP Enterprise-Managed Authorization (2026-07-28)](https://github.com/modelcontextprotocol/ext-auth/blob/main/specification/stable/enterprise-managed-authorization/2026-07-28/enterprise-managed-authorization.mdx) |   ✅   |       | The IdP and Resource Authorization Server roles through ID-JAG; the MCP client and MCP server roles are left to the application |

### Not Yet Supported: Drafts

Drafts adopted by the IETF OAuth Working Group or the OpenID Foundation which are likely to be finalized.

| Specification                                                                                                                        | Status | Draft                 | Notes            |
| ------------------------------------------------------------------------------------------------------------------------------------ | :----: | --------------------- | ---------------- |
| [The OAuth 2.1 Authorization Framework](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1)                                 |   ❌   | `draft-17`            |                  |
| [Updates to OAuth 2.0 Security Best Current Practice](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics-update) |   ❌   | `draft-03`            |                  |
| [JSON Web Token Best Current Practices](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-rfc8725bis)                           |   ❌   | `draft-10`            | Updates RFC 8725 |
| [Attestation-Based Client Authentication](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-attestation-based-client-auth)      |   ❌   | `draft-12`            |                  |
| [OAuth SPIFFE Client Authentication](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-spiffe-client-auth)                      |   ❌   | `draft-02`            |                  |
| [OAuth 2.0 for First-Party Applications](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-first-party-apps)                    |   ❌   | `draft-04`            |                  |
| [Token Status List (TSL)](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list)                                        |   ❌   | `draft-21`            |                  |
| [SD-JWT-based Verifiable Digital Credentials (SD-JWT VC)](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc)          |   ❌   | `draft-23`            |                  |
| [Deferred Token Response](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-deferred-token-response)                            |   ❌   | `draft-01`            |                  |
| [Delegate SD-JWT](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-delegate-sd-jwt)                                            |   ❌   | `draft-00`            |                  |
| [OAuth 2.0 RAR Metadata and Error Remediation](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-rar-metadata-remediation)      |   ❌   | `draft-00`            |                  |
| [OpenID Connect Advanced Syntax for Claims (ASC) 1.0](https://openid.net/specs/openid-connect-advanced-syntax-for-claims-1_0.html)   |   ❌   | `draft-02`            |                  |
| [OpenID Connect Native SSO for Mobile Apps 1.0](https://openid.net/specs/openid-connect-native-sso-1_0.html)                         |   ❌   | `draft-07`            |                  |
| [Self-Issued OpenID Provider v2](https://openid.net/specs/openid-connect-self-issued-v2-1_0.html)                                    |   ❌   | `draft-13`            |                  |
| [Grant Management for OAuth 2.0](https://openid.net/specs/oauth-v2-grant-management-ID1.html)                                        |   ❌   | Implementer's Draft 1 |                  |

### Not Yet Supported: Published

| Specification                                                                                                                                                  | Status | Draft | Notes                                                                       |
| -------------------------------------------------------------------------------------------------------------------------------------------------------------- | :----: | ----- | --------------------------------------------------------------------------- |
| [RFC 9728: Protected Resource Metadata](https://datatracker.ietf.org/doc/html/rfc9728)                                                                         |   ❌   |       |                                                                             |
| [RFC 9901: Selective Disclosure for JWTs (SD-JWT)](https://datatracker.ietf.org/doc/html/rfc9901)                                                              |   ❌   |       |                                                                             |
| [RFC 10027: Best Current Practice for Security of Cross-Device Flows](https://datatracker.ietf.org/doc/html/rfc10027)                                          |   ❌   |       |                                                                             |
| [OpenID RISC Profile 1.0](https://openid.net/specs/openid-risc-1_0.html)                                                                                       |   ❌   |       | Events can be sent as raw Security Events                                   |
| [OpenID Connect Client-Initiated Backchannel Authentication (CIBA)](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html) |   ❌   |       | In progress in [#532](https://github.com/authelia/oauth2-provider/pull/532) |
| [OpenID Connect Front-Channel Logout 1.0](https://openid.net/specs/openid-connect-frontchannel-1_0.html)                                                       |   ❌   |       |                                                                             |
| [OpenID Connect Session Management 1.0](https://openid.net/specs/openid-connect-session-1_0.html)                                                              |   ❌   |       |                                                                             |
| [Initiating User Registration via OpenID Connect 1.0](https://openid.net/specs/openid-connect-prompt-create-1_0.html)                                          |   ❌   |       |                                                                             |
| [OpenID Connect Relying Party Metadata Choices 1.0](https://openid.net/specs/openid-connect-rp-metadata-choices-1_0-final.html)                                |   ❌   |       |                                                                             |
| [OpenID Connect for Identity Assurance 1.0](https://openid.net/specs/openid-connect-4-identity-assurance-1_0-final.html)                                       |   ❌   |       |                                                                             |
| [OpenID Federation 1.0](https://openid.net/specs/openid-federation-1_0.html)                                                                                   |   ❌   |       |                                                                             |
| [OpenID Federation 1.1](https://openid.net/specs/openid-federation-1_1.html)                                                                                   |   ❌   |       |                                                                             |
| [OpenID Federation for OpenID Connect 1.1](https://openid.net/specs/openid-federation-connect-1_1.html)                                                        |   ❌   |       |                                                                             |
| [OpenID for Verifiable Credential Issuance 1.0](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)                                     |   ❌   |       |                                                                             |
| [OpenID for Verifiable Presentations 1.0](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html)                                                 |   ❌   |       |                                                                             |
| [OpenID4VC High Assurance Interoperability Profile 1.0](https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0-final.html)             |   ❌   |       |                                                                             |

Planned work and notable differences from ORY Fosite are tracked in [TODO.md](TODO.md).

## Security Considerations

This library implements the protocol endpoints but not the pages that authenticate the user or ask for consent, and it
does not control the HTTP server it runs in. The following requirements of
[RFC 9700: Best Current Practice for OAuth 2.0 Security](https://datatracker.ietf.org/doc/html/rfc9700) are therefore
the responsibility of the application that uses it:

- **Authenticate the user before redirecting**
  ([Section 4.11.2](https://datatracker.ietf.org/doc/html/rfc9700#section-4.11.2)): once the client and redirect URI are
  valid, the library redirects authorization errors to the redirect URI without any user interaction. Authenticate the
  user before calling `NewAuthorizeResponse` or `WriteAuthorizeError` for a request. Silent authentication
  (`prompt=none`) only skips prompting for credentials: respond successfully only when the user already has a session.
  Neither authentication nor consent, including declined consent, makes an attacker-chosen redirect URI trustworthy, so
  only redirect automatically, including a `login_required` or `access_denied` error, to a redirect URI you trust;
  otherwise inform the user and let them decide whether to continue. This matters most when anyone can register a
  client, through Dynamic Client Registration or Client ID Metadata Documents, as the redirect URI is then
  attacker-chosen.
- **Prevent clickjacking** ([Section 4.16](https://datatracker.ietf.org/doc/html/rfc9700#section-4.16)): send
  `Content-Security-Policy: frame-ancestors` (and `X-Frame-Options` for older browsers) on the authorization endpoint,
  the device authorization verification page, and the login, consent and error pages.
- **Suppress the Referer header** ([Section 4.2.4](https://datatracker.ietf.org/doc/html/rfc9700#section-4.2.4)): send
  `Referrer-Policy: no-referrer` on the authorization endpoint and the pages it leads to, and avoid third-party
  resources on them, so authorization codes and state values do not leak to other sites.
- **Do not enable CORS at the authorization endpoint**
  ([Section 2.6](https://datatracker.ietf.org/doc/html/rfc9700#section-2.6)): the client redirects the user agent to it
  rather than calling it. CORS may be enabled for the token, metadata, `jwks_uri` and registration endpoints.
- **Only trust forwarded headers from your own proxy**
  ([Section 4.13](https://datatracker.ietf.org/doc/html/rfc9700#section-4.13)): `RequestURL` rebuilds the request URL
  from the `Host` header and, when the request did not arrive over TLS, the scheme from the first `X-Forwarded-Proto`
  value. It is the DPoP `htu` a proof is compared against, alongside the configured `EndpointURLs`, and the audience
  required of a bearer credential at an endpoint with no configured audience or URL, including the RFC 7592 client
  configuration endpoint when `EndpointURLs.Registration` is empty. When `MTLSClientCertificateHeader` is set, the
  client certificate is read only from that header and is treated as already validated, so the reverse proxy must
  complete the TLS handshake in which the client proves possession of the certificate's private key, and validate the
  certificate as the client's authentication method requires, before forwarding it. No other forwarded header is read,
  and `Issuer` and `EndpointURLs` are used as configured. Have the reverse proxy overwrite, not append to,
  `X-Forwarded-Proto` and the certificate header on every request, make the server unreachable except through it, and
  protect the connection between them with authenticated TLS or an equivalent so it cannot be eavesdropped on, injected
  into, or replayed. Set `EndpointURLs` so audiences do not depend on the request. If the application itself applies
  `Forwarded`, `X-Forwarded-Host` or similar headers to the request, it must do so only for requests from proxies it
  trusts.
- **Revoke tokens when the session ends**
  ([Section 4.14.2](https://datatracker.ietf.org/doc/html/rfc9700#section-4.14.2)): the lifetime of the tokens the
  library issues is not tied to the user's login session, and neither `NewRPInitiatedLogoutRequest` nor
  `SendBackChannelLogout` ends a session or revokes a token. When the user logs out, or the session ends for another
  reason such as a password change, revoke the grants issued during it with `RevokeRefreshToken` and `RevokeAccessToken`
  of the `TokenRevocationStorage` interface in `handler/oauth2`. Both take the request ID, which is the `GetID` of the
  authorization request and is kept by every token issued from it, including rotated refresh tokens, so record it
  against the session when the user grants consent.
  [OpenID Connect Back-Channel Logout 1.0 Section 2.7](https://openid.net/specs/openid-connect-backchannel-1_0.html#BCActions)
  expects refresh tokens issued without `offline_access` to be revoked at logout, and those issued with it normally to
  be kept. [RFC 10017 Section 6.3.2.3](https://datatracker.ietf.org/doc/html/rfc10017#section-6.3.2.3) likewise
  recommends ending the refresh tokens of browser-based clients with the session.

[RFC 10017: OAuth 2.0 for Browser-Based Applications](https://datatracker.ietf.org/doc/html/rfc10017) and
[RFC 8252: OAuth 2.0 for Native Apps](https://datatracker.ietf.org/doc/html/rfc8252) add the following:

- **Send CORS headers for browser-based clients**
  ([RFC 10017 Section 6.3.3.4](https://datatracker.ietf.org/doc/html/rfc10017#section-6.3.3.4)): the library sends no
  CORS headers. A browser-based client calls the token endpoint from its own origin, and may also call the revocation,
  introspection, registration, metadata and `jwks_uri` endpoints, so each of these it uses needs a CORS policy. A
  preflight request carries no client ID, so it can only be checked against every origin you allow. Check the `Origin`
  header against the origins of the authenticated client on the actual request.
- **Do not give browser-based or native apps a static secret**
  ([RFC 10017 Section 6.3.3.1](https://datatracker.ietf.org/doc/html/rfc10017#section-6.3.3.1),
  [RFC 8252 Section 8.5](https://datatracker.ietf.org/doc/html/rfc8252#section-8.5)): a secret shipped in an app's code
  is readable by every user of the app, so it does not authenticate the client. Register these clients as public
  clients, whose `IsPublic` returns true and whose token endpoint authentication method is `none`. A native app may
  still register each installation through Dynamic Client Registration and receive a secret of its own, and a client
  whose `GetApplicationType` of the `ApplicationTypeClient` interface returns `native` may use a registered loopback
  redirect URI on any port ([RFC 8252 Section 7.3](https://datatracker.ietf.org/doc/html/rfc8252#section-7.3)), as a
  public client may.
- **Only skip consent when the client's identity is assured**
  ([RFC 10017 Section 6.3.3.2](https://datatracker.ietf.org/doc/html/rfc10017#section-6.3.3.2),
  [RFC 8252 Section 8.6](https://datatracker.ietf.org/doc/html/rfc8252#section-8.6)): any app can send the client ID of
  a public client. Before approving a public client's authorization request without asking the user, including for a
  client the user approved before, check that the function returned by `GetPublicClientIdentityChecker` of `Config`
  reports the identity as assured. The default, `IsPublicClientIdentityAssured`, accepts only an `https` redirect URI
  outside the loopback interface, which the app's domain controls.

Several RFC 9700 measures are opt-in, or can be weakened, through `Config`. Consider the following:

- `AllowPublicClientsWithoutPKCE` should stay disabled: public clients are then required to use PKCE, which
  [Section 2.1.1](https://datatracker.ietf.org/doc/html/rfc9700#section-2.1.1) mandates. `EnforcePKCE` requires it from
  every client, which is recommended for confidential clients. Clients that do not send a `code_challenge` are rejected.
  A client implementing `ProofKeyCodeExchangeClient` can be enforced individually.
- `EnablePKCEPlainChallengeMethod` should stay disabled: the `plain` method exposes the verifier in the authorization
  request ([Section 2.1.1](https://datatracker.ietf.org/doc/html/rfc9700#section-2.1.1)).
- The RFC 9207 `iss` authorization response parameter, a mix-up defense
  ([Section 4.4.2.1](https://datatracker.ietf.org/doc/html/rfc9700#section-4.4.2.1)), is returned when `Issuer` is set.
  `Compose` and `ComposeAllEnabled` register the `RFC9207ResponseModeParameterHandler` that returns it, which must be
  registered in `ResponseModeParameterHandlers` when composing by other means.
  `DisableAuthorizationServerIdentification` should stay disabled. Clients that do not check it ignore it.
- `JWTSecuredAuthorizeResponseModeStrategy` enables JARM, whose signed authorization responses carry the issuer. Only
  clients that request a JWT response mode are affected. A client whose `GetResponseModes` of the `ResponseModeClient`
  interface returns only JWT response modes must request one, as a request omitting `response_mode` is refused unless
  the client is registered for its default response mode, which
  [FAPI 2.0 Message Signing Section 5.4.1](https://openid.net/specs/fapi-message-signing-2_0-final.html#section-5.4.1)
  requires.
- `AuthorizationSignedResponseAlgValues` and `IntrospectionSignedResponseAlgValues` restrict the algorithms which sign
  JARM and RFC 9701 introspection responses. By default these include the HMAC algorithms keyed by the client secret,
  which provide none of the non-repudiation
  [FAPI 2.0 Message Signing Section 5.2](https://openid.net/specs/fapi-message-signing-2_0-final.html#section-5.2) is
  for. When set, only the listed algorithms are advertised and accepted at registration, a client registered with
  another is refused a signed response, and the first listed algorithm signs for a client registered with none, or RS256
  for introspection when it is listed.
- `DisableRefreshTokenRotation` should stay disabled
  ([Section 4.14.2](https://datatracker.ietf.org/doc/html/rfc9700#section-4.14.2)). It is ignored for a public client
  whose refresh token is not sender-constrained.
- `RefreshTokenMaximumLifespan` limits how long the refresh tokens of a grant can be renewed, counted from the first
  refresh token, however often they are rotated. `RefreshTokenLifespan` then acts as the time a refresh token expires
  after if it is not used, and each rotated refresh token expires at whichever comes first.
  [RFC 10017 Section 6.3.2.3](https://datatracker.ietf.org/doc/html/rfc10017#section-6.3.2.3) requires this for
  browser-based applications when refresh tokens are rotated. Without it, each rotation issues a refresh token with the
  full `RefreshTokenLifespan`, so a client which keeps refreshing keeps its grant indefinitely. A client implementing
  `RefreshTokenMaximumLifespanClient` can set its own, or opt out with a negative duration. The limit is recorded on the
  session, which must implement `ExpiryDeadlineSetterSession` as the default sessions do, otherwise the request fails
  with `server_error`, and a grant issued without one is limited from its next refresh. Token responses carry
  `refresh_token_timeout` and `authorization_expires_in`, refresh token introspection carries the same members, and
  authorization server metadata publishes `refresh_token_expiration_types_supported`
  ([draft-ietf-oauth-refresh-token-expiration](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-refresh-token-expiration-03)).
  `DisableRefreshTokenExpirationParameters` removes all three. An authorization is extended out of band by updating the
  deadline on the persisted session and raising the stored expiry of the grant's current refresh token. With rotation,
  updating the deadline alone only helps a client that refreshes before the old deadline. Without rotation
  (`DisableRefreshTokenRotation`, or a client that disables it) the stored refresh token keeps its issued expiry, so its
  stored expiry must always be raised. An application can record a deadline of its own, such as one the user chose, with
  `ExpiryDeadlineSetterSession`.
- `DPoPEnabled` and `MTLSEnabled` enable sender-constrained tokens
  ([Section 2.2.1](https://datatracker.ietf.org/doc/html/rfc9700#section-2.2.1)) for clients that request them, and
  `DPoPEnforce` and `MTLSEnforce` require them from every client, which then must all support the mechanism. Resource
  servers must also verify the binding.
- `EnforceSenderConstrainedAccessTokens` requires every token request to bind its tokens to a DPoP proof or a mutual-TLS
  client certificate, whichever the client presents, as
  [FAPI 2.0 Security Profile Section 5.3.2.1](https://openid.net/specs/fapi-security-profile-2_0-final.html#section-5.3.2.1)
  requires. Unlike `DPoPEnforce` and `MTLSEnforce`, either method satisfies it, so clients need only support one. A
  request carrying a DPoP proof is bound to it, and otherwise to the client certificate. A client implementing
  `SenderConstrainedAccessTokensClient` can be required individually.
- `DPoPStrictRefreshTokenBinding` and `MTLSStrictRefreshTokenBinding` keep a confidential client's refresh token bound
  to the key or certificate it was issued for, rather than re-binding it on refresh. The client cannot then change its
  key without a new grant. Public clients are always strictly bound.
- `EnforceAuthenticationRequirements` refuses an authorization, or the approval of a device authorization, unless the
  user's authentication meets the requested `max_age` and Authentication Context Class References: the `acr_values`
  parameter or, when a request names none, the client's registered `default_acr_values`. Without it they are only
  requested, and the client must check the `acr` claim it receives. An attacker can alter or remove the requested
  classes in an unsigned request
  ([EAP ACR Values 1.0 Section 4](https://openid.net/specs/openid-connect-eap-acr-values-1_0.html#section-4)), including
  by adding an `acr` claim request with its own values, which replaces the defaults. A client which depends on a class
  should send signed or pushed requests. The application decides which class an authentication meets, such as `phr` for
  a phishing-resistant method.
- `RequirePushedAuthorizationRequests` requires PAR, so the client sends the authorization request, including the
  redirect URI, directly to the authorization server, which authenticates a confidential client
  ([Section 4.1.3](https://datatracker.ietf.org/doc/html/rfc9700#section-4.1.3)). A public client pushes its request
  with the `none` authentication method, so PAR alone does not establish a public client's identity. Every client must
  support PAR. A client implementing `PushedAuthorizationRequestClient` can be required individually.
- `EnableRedirectFragmentGuard` appends `#_` to authorization response redirects in a query response mode, so a browser
  does not carry the request URL's fragment over to the redirect URI
  ([Section 4.1.3](https://datatracker.ietf.org/doc/html/rfc9700#section-4.1.3)).
- `AllowInsecureRedirectURIForPublicClients` should stay disabled: it accepts any redirect URI scheme and host for
  public clients, including `http` ([Section 2.6](https://datatracker.ietf.org/doc/html/rfc9700#section-2.6)).
- `AllowPostLogoutRedirectWithoutIDTokenHint` should stay disabled. The library does not perform the post logout
  redirect: `GetPostLogoutRedirectURI` returns the registered `post_logout_redirect_uri` for the application to redirect
  to. A request with an `id_token_hint` that fails validation is rejected with `invalid_request`. A request without one
  returns no redirect URI, as
  [OpenID Connect RP-Initiated Logout 1.0 Section 3](https://openid.net/specs/openid-connect-rpinitiated-1_0.html#RedirectionAfterLogout)
  permits post logout redirection without an `id_token_hint` only when the OP can confirm the legitimacy of the target
  by other means. Enabling the option returns it in that case as well, so an application that enables it must make that
  confirmation itself before redirecting, or the logout endpoint becomes an open redirector
  ([Section 4.11](https://datatracker.ietf.org/doc/html/rfc9700#section-4.11)).
- Redirect URIs are compared by exact string by default. A client returning `OriginURIComparisonStrategy` from
  `RedirectURICustomComparisonClient` accepts any path on a registered origin, which does not meet
  [Section 2.1](https://datatracker.ietf.org/doc/html/rfc9700#section-2.1).
- `MinParameterEntropy` sets the minimum length of the `state` and `nonce` parameters when present. Setting it to `-1`
  disables the check.
- `RefreshTokenScopes` limits refresh tokens to grants including one of its scopes, `offline` and `offline_access` by
  default, in line with the risk assessment
  [Section 4.14.2](https://datatracker.ietf.org/doc/html/rfc9700#section-4.14.2) asks for. An empty list issues a
  refresh token for every authorization code and device code grant.
- A client implementing `IntrospectionClient` is restricted at the introspection endpoint, so it learns only about the
  tokens it may know about ([RFC 7662 Section 4](https://datatracker.ietf.org/doc/html/rfc7662#section-4)). When its
  `GetIntrospectionPermitted` returns false it learns only about the tokens issued to it. When it returns true the
  client is a resource server, and learns only about the tokens whose audience or resource includes one of the values
  `GetIntrospectionAudience` returns, or its client ID when that is nil, so a token without an audience is visible to no
  resource server. Any other token is reported as inactive. A client not implementing it may introspect any token.
  `EnforceIntrospectionPermission` refuses every caller except a resource server with `request_unauthorized`, as
  [FAPI 2.0 Message Signing Section 6.2](https://openid.net/specs/fapi-message-signing-2_0-final.html#section-6.2)
  requires. With a bearer credential, these checks use the caller's current registration rather than the one recorded
  with the credential.
- `AuthorizeCodeLifespan` should be kept short, as an authorization code only has to survive a single redirect.

For the [FAPI 2.0 Security Profile](https://openid.net/specs/fapi-security-profile-2_0-final.html),
`compose.ApplyFAPI2SecurityProfile` sets the options above that it requires on an `oauth2.Config`, and
`compose.ValidateFAPI2SecurityProfile` checks any `oauth2.Configurator` once the provider is composed, returning every
setting that does not meet the profile and every missing required handler. Of the authorize endpoint handlers it refuses
only `AuthorizeImplicitGrantTypeHandler`, `OpenIDConnectImplicitHandler`, `OpenIDConnectHybridHandler` and
`NoneResponseTypeHandler`; a custom handler is not checked, even one serving a response type other than `code`. It does
not set `Issuer` or enable DPoP or mTLS, and does not check the keys which sign the JWTs the server issues, such as ID
Tokens and JWT access tokens: these must use PS256, ES256 or EdDSA, and a configuration signing with RS256 still passes.
A client implementing `FAPI2SecurityProfileClient` is instead held to the profile at each request, whatever the options:
it must push its authorization requests with a redirect URI, use the `code` response type, PKCE with S256,
`private_key_jwt` or mutual-TLS client authentication, and a permitted algorithm for its client assertions and request
objects. Its access tokens are sender-constrained, its refresh tokens are not rotated, and its authorization codes and
pushed authorization requests are short-lived. The options that apply to every client, such as the RFC 9207 `iss`
parameter and the DPoP proof algorithms, must still meet the profile.

For [FAPI 2.0 Message Signing](https://openid.net/specs/fapi-message-signing-2_0-final.html),
`compose.ApplyFAPI2MessageSigning` sets the options each selected part requires, being signed authorization requests,
signed authorization responses and signed introspection responses, and `compose.ValidateFAPI2MessageSigning` checks them
once the provider is composed. A client is required to use JARM by registering only JWT response modes, and a resource
server is permitted to introspect through `IntrospectionClient`.

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
