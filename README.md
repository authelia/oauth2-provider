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

| Specification                                                                                                                                   | Status | Draft                    | Notes                                                                                                                                                                                                                                                                                                                                               |
| ----------------------------------------------------------------------------------------------------------------------------------------------- | :----: | ------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [RFC 6749: The OAuth 2.0 Authorization Framework](https://datatracker.ietf.org/doc/html/rfc6749)                                                |   ✅   |                          | Authorization Code, Implicit, Client Credentials, Resource Owner Password Credentials, and Refresh Token grants                                                                                                                                                                                                                                     |
| [RFC 6750: Bearer Token Usage](https://datatracker.ietf.org/doc/html/rfc6750)                                                                   |   ✅   |                          |                                                                                                                                                                                                                                                                                                                                                     |
| [RFC 7009: Token Revocation](https://datatracker.ietf.org/doc/html/rfc7009)                                                                     |   ✅   |                          | Optional policy to revoke the refresh token alongside an access token                                                                                                                                                                                                                                                                               |
| [RFC 7521: Assertion Framework for Client Authentication and Authorization Grants](https://datatracker.ietf.org/doc/html/rfc7521)               |   ✅   |                          | Through the RFC 7523 JWT profile                                                                                                                                                                                                                                                                                                                    |
| [RFC 7523: JWT Profile for Client Authentication and Authorization Grants](https://datatracker.ietf.org/doc/html/rfc7523)                       |   ✅   |                          | `client_secret_jwt`, `private_key_jwt`, and the JWT bearer grant                                                                                                                                                                                                                                                                                    |
| [RFC 7591: Dynamic Client Registration Protocol](https://datatracker.ietf.org/doc/html/rfc7591)                                                 |   ✅   |                          | Includes policies from creation tokens                                                                                                                                                                                                                                                                                                              |
| [RFC 7592: Dynamic Client Registration Management Protocol](https://datatracker.ietf.org/doc/html/rfc7592)                                      |   ✅   |                          |                                                                                                                                                                                                                                                                                                                                                     |
| [RFC 7636: Proof Key for Code Exchange (PKCE)](https://datatracker.ietf.org/doc/html/rfc7636)                                                   |   ✅   |                          | Per-client enforcement policy                                                                                                                                                                                                                                                                                                                       |
| [RFC 7662: Token Introspection](https://datatracker.ietf.org/doc/html/rfc7662)                                                                  |   ✅   |                          | Client authentication, and per client a restriction to its own tokens or, for a resource server, to its audience                                                                                                                                                                                                                                    |
| [RFC 8252: OAuth 2.0 for Native Apps](https://datatracker.ietf.org/doc/html/rfc8252)                                                            |   ✅   |                          | Any loopback port for public clients and those whose `application_type` is `native`; private-use URI schemes are checked at registration, and for other clients are left to the application                                                                                                                                                         |
| [RFC 8414: Authorization Server Metadata](https://datatracker.ietf.org/doc/html/rfc8414)                                                        |   ✅   |                          | Built from the registered handlers and configuration, with optional signed metadata                                                                                                                                                                                                                                                                 |
| [RFC 8628: Device Authorization Grant](https://datatracker.ietf.org/doc/html/rfc8628)                                                           |   ✅   |                          |                                                                                                                                                                                                                                                                                                                                                     |
| [RFC 8693: Token Exchange](https://datatracker.ietf.org/doc/html/rfc8693)                                                                       |   ✅   |                          | Access token, refresh token, ID Token, and custom JWT token types                                                                                                                                                                                                                                                                                   |
| [RFC 8705: Mutual-TLS Client Authentication and Certificate-Bound Access Tokens](https://datatracker.ietf.org/doc/html/rfc8705)                 |   ✅   |                          | `tls_client_auth` and `self_signed_tls_client_auth`                                                                                                                                                                                                                                                                                                 |
| [RFC 8707: Resource Indicators](https://datatracker.ietf.org/doc/html/rfc8707)                                                                  |   ✅   |                          | Exact, prefix, and wildcard matching strategies                                                                                                                                                                                                                                                                                                     |
| [RFC 9068: JWT Profile for Access Tokens](https://datatracker.ietf.org/doc/html/rfc9068)                                                        |   ✅   |                          | Enabled globally or per client                                                                                                                                                                                                                                                                                                                      |
| [RFC 9101: JWT-Secured Authorization Request (JAR)](https://datatracker.ietf.org/doc/html/rfc9101)                                              |   ✅   |                          |                                                                                                                                                                                                                                                                                                                                                     |
| [RFC 9126: Pushed Authorization Requests (PAR)](https://datatracker.ietf.org/doc/html/rfc9126)                                                  |   ✅   |                          | Per-client enforcement policy                                                                                                                                                                                                                                                                                                                       |
| [RFC 9207: Authorization Server Issuer Identification](https://datatracker.ietf.org/doc/html/rfc9207)                                           |   ✅   |                          |                                                                                                                                                                                                                                                                                                                                                     |
| [RFC 9396: Rich Authorization Requests](https://datatracker.ietf.org/doc/html/rfc9396)                                                          |   ✅   |                          |                                                                                                                                                                                                                                                                                                                                                     |
| [RFC 9449: Demonstrating Proof of Possession (DPoP)](https://datatracker.ietf.org/doc/html/rfc9449)                                             |   ✅   |                          |                                                                                                                                                                                                                                                                                                                                                     |
| [RFC 9470: Step Up Authentication Challenge Protocol](https://datatracker.ietf.org/doc/html/rfc9470)                                            |   ✅   |                          | Resource server challenges, `acr` and `auth_time` in tokens when `acr_values` and `max_age` require them, opt-in enforcement                                                                                                                                                                                                                        |
| [RFC 9700: Best Current Practice for OAuth 2.0 Security](https://datatracker.ietf.org/doc/html/rfc9700)                                         |   ✅   |                          | Assessed as a whole; see [Security Considerations](#security-considerations) for the application's part                                                                                                                                                                                                                                             |
| [RFC 9701: JWT Response for Token Introspection](https://datatracker.ietf.org/doc/html/rfc9701)                                                 |   ✅   |                          |                                                                                                                                                                                                                                                                                                                                                     |
| [RFC 9728: Protected Resource Metadata](https://datatracker.ietf.org/doc/html/rfc9728)                                                          |   ✅   |                          | The authorization server metadata and, for resources the application hosts, metadata built from the configuration, signing, and the `resource_metadata` challenge parameter, which the introspection, registration and client configuration error writers only carry when the context holds the request; the client role is left to the application |
| [RFC 10017: OAuth 2.0 for Browser-Based Applications](https://datatracker.ietf.org/doc/html/rfc10017)                                           |   ✅   |                          | Rotating or sender-constrained refresh tokens, with a maximum grant lifespan the application must enable; CORS is left to the application                                                                                                                                                                                                           |
| [RFC 10027: Best Current Practice for Security of Cross-Device Flows](https://datatracker.ietf.org/doc/html/rfc10027)                           |   ✅   |                          | Device and CIBA grants: user codes bound to the first subject that presents them, opt-in `verification_uri_complete`, growing `slow_down`, required `binding_message`, cross-device grants only registrable when permitted, and a user code rate limiter hook; proximity and the user experience are left to the application                        |
| [RFC 10070: Updates to JWT Client Authentication and Authorization Grants](https://datatracker.ietf.org/doc/html/rfc10070)                      |   ✅   |                          | Issuer as the sole client assertion audience, with an opt-out                                                                                                                                                                                                                                                                                       |
| [JWT Secured Authorization Response Mode (JARM)](https://openid.net/specs/oauth-v2-jarm.html)                                                   |   ✅   |                          |                                                                                                                                                                                                                                                                                                                                                     |
| [Multiple Response Type Encoding Practices](https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html)                                 |   ✅   |                          | Including the `none` response type                                                                                                                                                                                                                                                                                                                  |
| [Form Post Response Mode](https://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html)                                                   |   ✅   |                          | Custom response writer support                                                                                                                                                                                                                                                                                                                      |
| [The OAuth 2.1 Authorization Framework](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-17)                                         |   ✅   | `draft-17`               | Checked by `compose.ValidateOAuth21Profile` and applied by `compose.ApplyOAuth21Profile`; clients are not checked                                                                                                                                                                                                                                   |
| [Updates to OAuth 2.0 Security Best Current Practice](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics-update-03)         |   ✅   | `draft-03`               | Audience injection countermeasures through RFC 10070; the other sections bind clients and brokers                                                                                                                                                                                                                                                   |
| [Identity Assertion JWT Authorization Grant (ID-JAG)](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-06) |   ✅   | `draft-06`               | Issuing and redeeming through RFC 8693 and RFC 7523                                                                                                                                                                                                                                                                                                 |
| [Identity and Authorization Chaining Across Domains](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-chaining-17)               |   ✅   | `draft-17`               | Issuing grants in trust domain A through RFC 8693 (per-client opt-in) and redeeming them in trust domain B through RFC 7523; subject mapping and claim transcription are the application's                                                                                                                                                          |
| [JWT Authorization Grant with DPoP Binding](https://datatracker.ietf.org/doc/html/draft-parecki-oauth-jwt-dpop-grant-02)                        |   ✅   | `draft-02`               | Redeeming a DPoP-bound ID-JAG                                                                                                                                                                                                                                                                                                                       |
| [Transaction Tokens](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-transaction-tokens-11)                                              |   ✅   | `draft-11`               | Opt-in, including the `self_signed` and `unsigned_json` subject tokens and replacement tokens                                                                                                                                                                                                                                                       |
| [OAuth Client ID Metadata Document](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-03)                      |   ✅   | `draft-03`               | Opt-in through `Config.ClientIDMetadataDocumentResolver`, with a default resolver in `handler/cimd`                                                                                                                                                                                                                                                 |
| [Refresh Token and Authorization Expiration](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-refresh-token-expiration-03)                |   ✅   | `draft-03`               | On by default; the authorization expiry is `RefreshTokenMaximumLifespan` or a deadline the application records                                                                                                                                                                                                                                      |
| [FAPI 2.0 Security Profile](https://openid.net/specs/fapi-security-profile-2_0-final.html)                                                      |   🟡   |                          | Checked by `compose.ValidateFAPI2SecurityProfile`, applied by `compose.ApplyFAPI2SecurityProfile`, or enforced per client                                                                                                                                                                                                                           |
| [FAPI 2.0 Message Signing](https://openid.net/specs/fapi-message-signing-2_0-final.html)                                                        |   ✅   |                          | Applied by `compose.ApplyFAPI2MessageSigning` and checked by `compose.ValidateFAPI2MessageSigning`, per part                                                                                                                                                                                                                                        |
| [FAPI Client Initiated Backchannel Authentication Profile](https://openid.github.io/fapi/fapi-ciba.html)                                        |   ✅   | Editor's copy 2026-11-18 | Applied by `compose.ApplyFAPICIBAProfile` and checked by `compose.ValidateFAPICIBAProfile`, on the FAPI 2.0 Security Profile                                                                                                                                                                                                                        |

### OpenID Connect 1.0

| Specification                                                                                                                                                           | Status | Draft      | Notes                                                                                                                               |
| ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :----: | ---------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)                                                                                        |   ✅   |            | Authorization Code, Implicit, and Hybrid flows and the `claims` request parameter; the UserInfo endpoint is left to the application |
| [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html)                                                                              |   ✅   |            | Provider metadata; WebFinger issuer discovery is not implemented                                                                    |
| [OpenID Connect Dynamic Client Registration 1.0](https://openid.net/specs/openid-connect-registration-1_0.html)                                                         |   ✅   |            |                                                                                                                                     |
| [OpenID Connect RP-Initiated Logout 1.0](https://openid.net/specs/openid-connect-rpinitiated-1_0.html)                                                                  |   ✅   |            |                                                                                                                                     |
| [OpenID Connect Back-Channel Logout 1.0](https://openid.net/specs/openid-connect-backchannel-1_0.html)                                                                  |   ✅   |            |                                                                                                                                     |
| [OpenID Connect Client-Initiated Backchannel Authentication Flow - Core 1.0](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html) |   ✅   |            | Poll, ping and push token delivery; the application resolves the user from the hint and authenticates them                          |
| [OpenID Connect Core Error Code `unmet_authentication_requirements`](https://openid.net/specs/openid-connect-unmet-authentication-requirements-1_0.html)                |   ✅   |            |                                                                                                                                     |
| [OpenID Connect Extended Authentication Profile (EAP) ACR Values 1.0](https://openid.net/specs/openid-connect-eap-acr-values-1_0.html)                                  |   ✅   |            | The application asserts `phr`, `phrh` and `pop`; constants are provided                                                             |
| [Initiating User Registration via OpenID Connect 1.0](https://openid.net/specs/openid-connect-prompt-create-1_0.html)                                                   |   🟡   |            | The `create` prompt is accepted and advertised when listed in `AllowedPrompts`; the registration flow is left to the application    |
| [OpenID Connect Key Binding 1.0](https://openid.net/specs/openid-connect-key-binding-1_0.html)                                                                          |   ✅   | `draft-03` |                                                                                                                                     |
| [OpenID Connect UserInfo Verifiable Credentials](https://openid.net/specs/openid-connect-userinfo-vc-1_0.html)                                                          |   🟡   | `draft-00` | Issuing the `c_nonce` under draft-suffixed names; the Credential Endpoint is left to the application                                |

### JOSE

| Specification                                                                                                 | Status | Draft      | Notes                                                                                                                         |
| ------------------------------------------------------------------------------------------------------------- | :----: | ---------- | ----------------------------------------------------------------------------------------------------------------------------- |
| [RFC 7515: JSON Web Signature (JWS)](https://datatracker.ietf.org/doc/html/rfc7515)                           |   ✅   |            |                                                                                                                               |
| [RFC 7516: JSON Web Encryption (JWE)](https://datatracker.ietf.org/doc/html/rfc7516)                          |   ✅   |            |                                                                                                                               |
| [RFC 7517: JSON Web Key (JWK)](https://datatracker.ietf.org/doc/html/rfc7517)                                 |   ✅   |            |                                                                                                                               |
| [RFC 7518: JSON Web Algorithms (JWA)](https://datatracker.ietf.org/doc/html/rfc7518)                          |   ✅   |            |                                                                                                                               |
| [RFC 7519: JSON Web Token (JWT)](https://datatracker.ietf.org/doc/html/rfc7519)                               |   ✅   |            |                                                                                                                               |
| [RFC 7638: JSON Web Key (JWK) Thumbprint](https://datatracker.ietf.org/doc/html/rfc7638)                      |   ✅   |            |                                                                                                                               |
| [RFC 7800: Proof-of-Possession Key Semantics for JWTs](https://datatracker.ietf.org/doc/html/rfc7800)         |   ✅   |            | The `cnf` claim                                                                                                               |
| [RFC 8037: CFRG Elliptic Curve Signatures in JOSE](https://datatracker.ietf.org/doc/html/rfc8037)             |   🟡   |            | Ed25519 signatures; no Ed448, and no X25519 or X448 key agreement                                                             |
| [RFC 8725: JSON Web Token Best Current Practices](https://datatracker.ietf.org/doc/html/rfc8725)              |   ✅   |            | Explicit typing and mutually exclusive validation rules; the algorithms, keys and trusted issuers are left to the application |
| [JSON Web Token Best Current Practices](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-rfc8725bis-10) |   ✅   | `draft-10` | Updates RFC 8725; compact serialization only, bounded `p2c` and JWE decompression, and a nested JWT must be signed            |
| [RFC 9493: Subject Identifiers for Security Event Tokens](https://datatracker.ietf.org/doc/html/rfc9493)      |   ✅   |            | Every identifier format; the `sub_id` claim of ID-JAG and the subject of a Security Event Token                               |
| [RFC 9864: Fully-Specified Algorithms for JOSE and COSE](https://datatracker.ietf.org/doc/html/rfc9864)       |   🟡   |            | The `Ed25519` identifier; no `Ed448`                                                                                          |

### Shared Signals

| Specification                                                                                               | Status | Draft      | Notes                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| ----------------------------------------------------------------------------------------------------------- | :----: | ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [OpenID Shared Signals Framework 1.0](https://openid.net/specs/openid-sharedsignals-framework-1_0.html)     |   🟡   |            | The Transmitter role: Security Event Token signing, transmitter metadata, stream configuration, status and verification, and push and poll delivery; the subject endpoints, `inactivity_timeout` and asynchronous stream creation are not implemented, and the event queue is left to the application; the Receiver role is in `ssfreceiver`: transmitter metadata discovery, stream management with the subject endpoints, Security Event Token validation and `jti` de-duplication, the verification and stream updated events, and a relay to the streams of the Transmitter role; a token without `sub_id` or with more than one event is refused, and the routes, the storage and acting on an event are left to the application |
| [OpenID Continuous Access Evaluation Profile 1.0](https://openid.net/specs/openid-caep-1_0.html)            |   ✅   |            | Every event and subject identifier type, validated when sent as a raw event as well; when to emit an event is left to the application                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| [OpenID RISC Profile 1.0](https://openid.net/specs/openid-risc-1_0.html)                                    |   ✅   |            | Every event type, validated when sent as a raw event as well; the identifier events require an `email` or `phone_number` subject and the deprecated `sessions-revoked` event is refused by the Transmitter role and accepted by the Receiver role; when to emit an event and the opt-out state are left to the application                                                                                                                                                                                                                                                                                                                                                                                                            |
| [CAEP Interoperability Profile 1.0](https://openid.net/specs/openid-caep-interoperability-profile-1_0.html) |   🟡   | `draft-01` | The Transmitter role, with bearer authorization through `ssf.read` and `ssf.manage`; RS256 signing with an RSA key of at least 2048 bits and the required transmitter metadata are checked only when `SSFConfig.EnforceCAEPInteroperabilityProfile` is enabled, and TLS, the access token lifetime and the `reason_admin` values are left to the application; the Receiver role checks the same signing and transmitter metadata requirements, and refuses the subject requests, only when `ssfreceiver.Config.EnforceCAEPInteroperabilityProfile` is enabled; TLS, certificate revocation and obtaining the access token are left to the application                                                                                 |
| [RFC 8417: Security Event Token (SET)](https://datatracker.ietf.org/doc/html/rfc8417)                       |   ✅   |            | Claims and signing as profiled by SSF, so `sub`, `exp`, and multiple events are not supported and `toe` is not emitted; the default strategy signs, and nests the token in a JWE per client through `security_event_token_encrypted_response_*`; delivery is RFC 8935 push or RFC 8936 poll                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| [RFC 8935: Push-Based Security Event Token Delivery](https://datatracker.ietf.org/doc/html/rfc8935)         |   ✅   |            | Transmitter: single push attempt with a typed outcome, which `PushSecurityEventTokenToStream` withholds on a stream that is paused or disabled; queuing and retries are left to the application; Receiver: `ssfreceiver.Receiver.HandlePush` authorizes the request, validates and acknowledges the token and answers with the error codes; the route is left to the application and the error descriptions are in English only                                                                                                                                                                                                                                                                                                       |
| [RFC 8936: Poll-Based Security Event Token Delivery](https://datatracker.ietf.org/doc/html/rfc8936)         |   ✅   |            | Transmitter: request parsing and response writing; the SET queue, acknowledgements, the `maxEvents` limit and long polling are left to the application; Receiver: `ssfreceiver.Receiver.Poll` makes one request and `ssfreceiver.Poller` long polls with acknowledgements, `setErrs` and backoff; running a poller for each stream is left to the application                                                                                                                                                                                                                                                                                                                                                                         |

### Model Context Protocol

| Specification                                                                                                                                                                                                         | Status | Draft | Notes                                                                                                                                                                                                                                                               |
| --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :----: | ----- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [MCP Authorization (2026-07-28)](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization)                                                                                                        |   ✅   |       | The Authorization Server role, with OAuth 2.1 applied by `compose.ApplyOAuth21Profile`; the Protected Resource Metadata helpers are provided, while serving the metadata at the well-known path and the MCP client and MCP server roles are left to the application |
| [MCP Enterprise-Managed Authorization (2026-07-28)](https://github.com/modelcontextprotocol/ext-auth/blob/main/specification/stable/enterprise-managed-authorization/2026-07-28/enterprise-managed-authorization.mdx) |   ✅   |       | The IdP and Resource Authorization Server roles through ID-JAG; the MCP client and MCP server roles are left to the application                                                                                                                                     |
| [MCP OAuth Client Credentials (2026-07-28)](https://github.com/modelcontextprotocol/ext-auth/blob/main/specification/stable/oauth-client-credentials/2026-07-28/oauth-client-credentials.mdx)                         |   ✅   |       | The Authorization Server role; the MCP client and MCP server roles are left to the application                                                                                                                                                                      |

### Not Yet Supported: Drafts

Drafts adopted by the IETF OAuth Working Group or the OpenID Foundation which are likely to be finalized.

| Specification                                                                                                                      | Status | Draft                 | Notes |
| ---------------------------------------------------------------------------------------------------------------------------------- | :----: | --------------------- | ----- |
| [Attestation-Based Client Authentication](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-attestation-based-client-auth)    |   ❌   | `draft-12`            |       |
| [OAuth SPIFFE Client Authentication](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-spiffe-client-auth)                    |   ❌   | `draft-03`            |       |
| [OAuth 2.0 for First-Party Applications](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-first-party-apps)                  |   ❌   | `draft-04`            |       |
| [Token Status List (TSL)](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list)                                      |   ❌   | `draft-21`            |       |
| [SD-JWT-based Verifiable Digital Credentials (SD-JWT VC)](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc)        |   ❌   | `draft-27`            |       |
| [Deferred Token Response](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-deferred-token-response)                          |   ❌   | `draft-01`            |       |
| [Delegate SD-JWT](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-delegate-sd-jwt)                                          |   ❌   | `draft-00`            |       |
| [OAuth 2.0 RAR Metadata and Error Remediation](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-rar-metadata-remediation)    |   ❌   | `draft-00`            |       |
| [OpenID Connect Advanced Syntax for Claims (ASC) 1.0](https://openid.net/specs/openid-connect-advanced-syntax-for-claims-1_0.html) |   ❌   | `draft-02`            |       |
| [OpenID Connect Native SSO for Mobile Apps 1.0](https://openid.net/specs/openid-connect-native-sso-1_0.html)                       |   ❌   | `draft-07`            |       |
| [Self-Issued OpenID Provider v2](https://openid.net/specs/openid-connect-self-issued-v2-1_0.html)                                  |   ❌   | `draft-13`            |       |
| [Grant Management for OAuth 2.0](https://openid.net/specs/oauth-v2-grant-management-ID1.html)                                      |   ❌   | Implementer's Draft 1 |       |

### Not Yet Supported: Published

| Specification                                                                                                                                      | Status | Draft | Notes |
| -------------------------------------------------------------------------------------------------------------------------------------------------- | :----: | ----- | ----- |
| [RFC 9901: Selective Disclosure for JWTs (SD-JWT)](https://datatracker.ietf.org/doc/html/rfc9901)                                                  |   ❌   |       |       |
| [OpenID Connect Front-Channel Logout 1.0](https://openid.net/specs/openid-connect-frontchannel-1_0.html)                                           |   ❌   |       |       |
| [OpenID Connect Session Management 1.0](https://openid.net/specs/openid-connect-session-1_0.html)                                                  |   ❌   |       |       |
| [OpenID Connect Relying Party Metadata Choices 1.0](https://openid.net/specs/openid-connect-rp-metadata-choices-1_0-final.html)                    |   ❌   |       |       |
| [OpenID Connect for Identity Assurance 1.0](https://openid.net/specs/openid-connect-4-identity-assurance-1_0-final.html)                           |   ❌   |       |       |
| [OpenID Federation 1.0](https://openid.net/specs/openid-federation-1_0.html)                                                                       |   ❌   |       |       |
| [OpenID Federation 1.1](https://openid.net/specs/openid-federation-1_1.html)                                                                       |   ❌   |       |       |
| [OpenID Federation for OpenID Connect 1.1](https://openid.net/specs/openid-federation-connect-1_1.html)                                            |   ❌   |       |       |
| [OpenID for Verifiable Credential Issuance 1.0](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)                         |   ❌   |       |       |
| [OpenID for Verifiable Presentations 1.0](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html)                                     |   ❌   |       |       |
| [OpenID4VC High Assurance Interoperability Profile 1.0](https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0-final.html) |   ❌   |       |       |

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
- **Protect client secrets against brute force**
  ([RFC 6749 Section 2.3.1](https://datatracker.ietf.org/doc/html/rfc6749#section-2.3.1),
  [OAuth 2.1 Section 2.4.1](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-17#section-2.4.1)): the
  authorization server must protect every endpoint which accepts a client secret against brute force attacks, and the
  library does not limit the rate of attempts. A secret is accepted with `client_secret_basic`, `client_secret_post` or
  `client_secret_jwt` at the endpoints served by `NewAccessRequest`, `NewIntrospectionRequest`, `NewRevocationRequest`,
  `NewPushedAuthorizeRequest`, `NewRFC862DeviceAuthorizeRequest` and `NewBackChannelAuthenticationRequest`, each of
  which fails with `invalid_client` when client authentication fails, except that `NewAccessRequest` returns
  `invalid_request` for a grant type no handler supports, even when client authentication fails. Hashing secrets with
  `BCryptClientSecret` slows each guess but does not limit how many are made, so limit the failed attempts per client ID
  and per source address at these endpoints, for example by delaying or refusing further requests and raising an alert.
  Do not lock a client out entirely on failures alone, as anyone who knows its client ID could then deny it service. The
  verification page where a user enters an [RFC 8628](https://datatracker.ietf.org/doc/html/rfc8628#section-5.1) user
  code before `NewRFC8628UserAuthorizeRequest` needs the same protection, as a user code is short enough to be guessed
  without it. `RFC8628UserCodeRateLimiter` is consulted before each user code is looked up, and the error returned for a
  code which is not accepted wraps `ErrUserCodeUnknown`, `ErrUserCodeExpired`, `ErrUserCodeDecided` or
  `ErrUserCodeClaimed` so failed attempts can be counted. No limiter is configured by default.

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
  user's authentication meets the requested Maximum Authentication Age and Authentication Context Class References: the
  `max_age` and `acr_values` parameters or, when a request names none, the client's registered `default_max_age` and
  `default_acr_values`. Without it the classes are only requested, and the client must check the `acr` claim it
  receives. The OpenID Connect handlers hold an ID Token to the Maximum Authentication Age either way, and to the
  client's registered `require_auth_time`; `GetRequestedMaxAge` returns the age which applies to a request. An attacker
  can alter or remove the requested classes in an unsigned request
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
not set `Issuer`, enable DPoP or mTLS, or choose the keys which sign the JWTs the server issues, such as ID Tokens and
JWT access tokens: these must use PS256, ES256 or EdDSA, and the check fails when the JWT strategy reports a signing
algorithm outside them. `RequireStringClientAssertionAudience`, which it sets, refuses a client assertion carrying the
issuer in an `aud` array rather than as a string. It also clears `GrantTypeJWTBearerCanSkipClientAuth` and
`AccessTokenURIQueryParameterEnabled`, so a JWT bearer grant request must authenticate its client and an access token in
the URI query is not accepted. An access token bound to neither a DPoP key nor a client certificate is refused by
`ValidateBearerAuthorization` and the UserInfo endpoint when `EnforceSenderConstrainedAccessTokens` is set. A client
implementing `FAPI2SecurityProfileClient` is instead held to the profile at each request, whatever the options: it must
push its authorization requests with a redirect URI, use the `code` response type, PKCE with S256, `private_key_jwt` or
mutual-TLS client authentication with the issuer as the string `aud` of its client assertions, and a permitted algorithm
for its client assertions, request objects, JWT bearer grant assertions, Identity Assertion JWT Authorization Grants and
DPoP proofs, whose `iat` and `nbf` are accepted between 10 and 60 seconds into the future. It may not use the resource
owner password credentials grant, its authorization responses carry the RFC 9207 `iss` parameter, and a JWT is only
issued to it when signed with a permitted algorithm, so it must register one wherever the default is RS256. Its access
tokens are sender-constrained and refused when presented unbound, its refresh tokens are not rotated, and its
authorization codes and pushed authorization requests are short-lived. What the registered handlers determine, such as
the response types served, must still meet the profile.

For [FAPI 2.0 Message Signing](https://openid.net/specs/fapi-message-signing-2_0-final.html),
`compose.ApplyFAPI2MessageSigning` sets the options each selected part requires, being signed authorization requests,
signed authorization responses and signed introspection responses, and `compose.ValidateFAPI2MessageSigning` checks them
once the provider is composed. A client is required to use JARM by registering only JWT response modes, and a resource
server is permitted to introspect through `IntrospectionClient`.

For [The OAuth 2.1 Authorization Framework](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-17),
`compose.ApplyOAuth21Profile` sets the options above that it requires on an `oauth2.Config`, and
`compose.ValidateOAuth21Profile` checks any `oauth2.Configurator` once the provider is composed, returning every setting
that does not meet it and every missing required handler. It refuses the resource owner password credentials grant and
the authorize endpoint handlers which can issue an access token in the authorization response:
`AuthorizeImplicitGrantTypeHandler`, `OpenIDConnectImplicitHandler`, and `OpenIDConnectHybridHandler`, which serves
`code token` and `code id_token token` as well as `code id_token`. It requires PKCE with S256 from every client, the RFC
9207 `iss` parameter, an authorization code lifetime of at most 10 minutes, `client_secret_post` wherever another client
secret method is accepted at the token endpoint, `TokenRequestRedirectURIOptional` so a PKCE protected token request may
omit `redirect_uri`, access tokens in the URI query ignored, and a `RefreshTokenMaximumLifespan`, which
`compose.ApplyOAuth21Profile` caps at `RefreshTokenLifespan`, so a rotated refresh token never outlives the first. It
does not set `Issuer`, and does not check the clients, such as their redirect URI comparison strategy or their own
lifespans, or a custom `RedirectSecureChecker`.

### Shared Signals Transmitter

The library signs Security Event Tokens, serves the stream configuration, status, verification and poll requests of an
[OpenID Shared Signals Framework 1.0](https://openid.net/specs/openid-sharedsignals-framework-1_0.html) Transmitter, and
makes a single push attempt. It has no queue, no routes and no knowledge of when an event happens, so the following are
the responsibility of the application. The documentation of `SSFConfig` lists them in full and names the method each one
belongs to.

- **Queue and deliver the tokens**: retry a push that `PushSecurityEventTokenToStream` reports as retryable, wait on a
  poll request that does not ask to return immediately, and return no more tokens than its `maxEvents`
  ([RFC 8936 Section 2.2](https://datatracker.ietf.org/doc/html/rfc8936#section-2.2)). Hold the tokens of a paused
  stream, a verification event included, and drop those of a disabled stream. Held events that affect the same subject
  are sent in the order they were generated, or only the last of them when it supersedes the others
  ([SSF Section 8.1.2.1](https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.2.1)).
  `PushSecurityEventTokenToStream` checks the status when it reads the stream and does not stop it changing before the
  request is sent, so coordinate the queue with status changes.
- **Tell the Receiver of a status change it did not request**: send the event from `NewSSFStreamUpdatedEvent` when the
  application pauses, disables or re-enables a stream. None is sent for a change the Receiver made at the status
  endpoint ([SSF Section 8.1.5](https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.5)).
- **Apply policy changes to existing streams**: a stream keeps the events of the policy it was created under until
  `ReconcileSSFStream` is called for it, and its audience until it is created again.
- **Choose the identifiers of each token**: a `jti` that is unique on the stream and reused only to send the same token
  again, and a `txn` that is unique to the underlying event
  ([SSF Section 4.1.9](https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-4.1.9)).
- **Protect the subject**: send a Receiver only the events it is permitted to have, identify the subject in the same way
  for a Receiver every time and in a way that reveals nothing new to it, obtain consent before releasing data the user
  has not consented to release
  ([SSF Section 10](https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-10)), and set
  `security_event_token_encrypted_response_alg` on the client that owns the stream when a token carries personally
  identifiable information that TLS alone does not keep confidential
  ([RFC 8417 Section 5.1](https://datatracker.ietf.org/doc/html/rfc8417#section-5.1)). An encrypted token is refused
  while `EnforceCAEPInteroperabilityProfile` is enabled.
- **Give each Receiver its own stream**: a stream audience with more than one value is for Receivers known to be the
  same entity ([SSF Section 4.1.8](https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-4.1.8)).
- **Secure the transport**: serve the endpoints, and connect to Receivers, over TLS 1.2 or later with certificate
  validation ([RFC 8935 Section 5.3](https://datatracker.ietf.org/doc/html/rfc8935#section-5.3)). An
  `SSFConfig.HTTPClient` with its own transport must keep both.

`SSFConfig.EnforceCAEPInteroperabilityProfile` is disabled by default. When enabled the library refuses a Security Event
Token that is not signed with RS256 by an RSA key of at least 2048 bits, and Transmitter Configuration Metadata without
the members the [CAEP Interoperability Profile](https://openid.net/specs/openid-caep-interoperability-profile-1_0.html)
requires. The rest of the profile is never checked: TLS, an access token lifetime of 60 minutes or less, a `jwks_uri`
that serves the current signing keys, and a non-empty `reason_admin` in each session-revoked, credential-change and
device-compliance-change event.

### Shared Signals Receiver

The `ssfreceiver` package is the Receiver role of the
[OpenID Shared Signals Framework 1.0](https://openid.net/specs/openid-sharedsignals-framework-1_0.html) for an
authorization server. It discovers and validates the Transmitter Configuration Metadata, manages streams at a
Transmitter, validates the Security Event Tokens of a push request or a poll response, hands each event to an
`EventHandler`, and prepares the tokens which relay an event to the streams the authorization server transmits on. It
has no routes, no queue and no OAuth client, so the following are the responsibility of the application. The package
documentation lists them in full, with what is not implemented.

- **Secure the transport**: serve the push endpoint, and connect to a Transmitter, over TLS 1.2 or later with
  certificate validation
  ([CAEP Interoperability Profile Section 2.1](https://openid.net/specs/openid-caep-interoperability-profile-1_0.html#section-2.1)).
  Go does not check certificate revocation, so an application which requires it adds the check to the transport of
  `Config.HTTPClient` and to its server. A `Config.HTTPClient` with a timeout needs one longer than
  `Config.LongPollTimeout`.
- **Authorize the requests**: supply the `Authorizer` and the access tokens behind it. Reading a stream or its status
  asks for `ssf.read`, and every other request, a poll included, for `ssf.manage`. The poll endpoint URL is the one the
  Transmitter supplied in the stream configuration: it must be an `https` URL and the request passes the special-use
  address guard, but its host is not tied to the issuer, and it receives the access token, so create streams only at
  issuers from a trusted list. A custom `Config.JWKSFetcher` applies the special-use address guard and limits forced
  refreshes itself, as a token with an unknown `kid` forces one.
- **Route each push URL**: one URL per stream, with the record looked up from the request URL and passed to
  `Receiver.HandlePush`. The URL is matched as an exact string, so normalize it the same way when creating the stream
  and when routing. A record whose delivery has no method is a push stream. `HandlePush` returns the cause of a 503 and
  the error of a request which is not authorized, for the application to log. A `PushAuthorizer` which could not decide
  returns an error matching `ErrPushAuthorizerUnavailable`, which answers 503 so the Transmitter delivers again.
- **Keep the push secret**: `Delivery.AuthorizationHeader` and `PendingAuthorizationHeader` are stored with the record
  and must be protected at rest. Rotate the secret with `Receiver.ReplaceStream` or `Receiver.UpdateStream`: the new
  secret is stored as the pending one before the request, and a push with either is authorized while one is pending, so
  no push is refused during a rotation. A 200 makes the new secret the only one. An error matching
  `ErrStreamChangeApplied` confirms the Transmitter applied the change, not that the old secret is no longer accepted:
  when the record could not be stored the old secret stays and the new one stays pending, so repeat the same request
  until it returns no error. An error matching `ErrStreamUpdatePending` (a 202) or `ErrTransmitterUnconfirmed` (no
  response), or a `*TransmitterError` of a 5xx or an unexpected 2xx, keeps both, so repeat the same request until it is
  answered with a 200. Any other error withdraws the new secret. A record has one pending secret, so finish a rotation
  before starting another.
- **Persist in the handler and act afterwards**: `HandleSecurityEvent` persists or enqueues the event and returns, and
  the application acts on it, such as ending sessions, after the handler returned
  ([RFC 8935 Section 2](https://datatracker.ietf.org/doc/html/rfc8935#section-2)). The handler must be idempotent on the
  issuer and the `jti`, as a failure before the token is marked as received, or a concurrent delivery, calls it again
  for the same token.
- **Fill in the events of each record**: an event type outside `StreamRecord.EventsDelivered` is acknowledged and
  dropped, so an empty list drops every event but the verification and stream updated events. The status of a record is
  stored and not enforced: a token received on a paused or disabled stream is handled as any other, as the status is the
  duty of the Transmitter
  ([SSF Section 8.1.5](https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.5)).
- **Resolve subjects**: a `SubjectResolver` returns `ErrSubjectUnknown` for a subject it does not know, which
  acknowledges the token without the handler. Any other error, a `*SetError` included, is never reported to the
  Transmitter, which delivers the token again
  ([SSF Section 9.3](https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-9.3)). An empty
  `Config.ProcessedSubjectMembers` means the seven Complex Subject members of SSF Section 3.3. `Receiver.AddSubject`
  refuses a proprietary subject format.
- **Look after the streams**: call `Receiver.Touch` for a push stream more often than its `inactivity_timeout`
  ([SSF Section 8.1.1](https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.1)), request
  verification on a schedule, and alert when a stream stays unverified, paused or disabled. A process which ends during
  `Receiver.CreateStream` leaves a pending record under the issuer and an empty stream ID, which blocks every later
  create for that issuer until it is deleted through the store. The Transmitter may have created the stream before the
  process ended: find it with `Receiver.ListStreams` and remove it with `Receiver.DeleteStream` before the next create,
  as a Transmitter which allows one stream refuses it with `ErrStreamConflict`. A push to a pending record is answered
  with a 503, so a Transmitter which verifies a push stream inside the create request, and requires that push to
  succeed, fails the create. `Receiver.DeleteStream` removes the record on a 404 as well as on a 204. Serialize
  `Receiver.UpdateStream`, `Receiver.ReplaceStream` and `Receiver.ReadStream` for one stream: each stores the whole
  record and the last one wins. Serialize `Receiver.RequestStreamVerification` for one stream as well, as a request
  replaces the `state` of an earlier one.
- **Run the pollers**: one `Poller` per poll stream. Its `Failure` hook is the only sight of an error it retries, such
  as a 401, a 403, a 400 or a 413. Each request has a `maxEvents`, which is `Config.MaxPollSets` unless
  `Poller.MaxEvents` is set.
- **Queue the relayed tokens**: `Relay.Prepare` returns the tokens and never pushes. Queue them in the outbox used for
  the events the application originates, and prepare the event again when they could not be queued, which gives the same
  `jti` and `txn`.
- **Obtain consent before relaying**: nothing is relayed without a `RelayPolicy`. The policy and the
  `RelaySubjectMapper` decide which Receivers learn of an event, on the consent or other basis the application has
  ([SSF Section 10.3](https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-10.3)). The default
  policy drops the reasons of the Transmitter and relays the free-form members it keeps as received: `credential_type`,
  the namespace and levels of an assurance level change, and the principal of a risk level change.
- **Choose the `txn` mode**: per stream by default, which needs a `Relay.TransactionKey` of at least 32 bytes and keeps
  two Receivers from correlating their subjects
  ([SSF Section 10.1](https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-10.1)).
  `Relay.TransactionModeFor` chooses per stream, such as by client. Rotating the key changes the `jti` and the `txn` of
  every later relay to a stream in the per-stream mode; a stream in the propagate mode has a `jti` without a key and the
  `txn` of the event. The relay marker is keyed by `txn`, event type and principal, so the copy of the same event from a
  second upstream Transmitter with the same `txn` is not relayed again. The upstream Transmitters share one `txn` space;
  clear `RelayEvent.Transaction` for a Transmitter whose `txn` values may collide with those of another, which derives
  one from its `iss` and `jti`. A cycle through another relay which derives a new `txn` is not recognized: keep the
  relays acyclic, or use the propagate mode for every relay of a cycle, and set `ExcludeClientIDs` to the client of the
  upstream Transmitter.

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
