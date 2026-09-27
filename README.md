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

### OAuth 2.0

| Specification                                                                                                                   | Status | Notes                                                                                                           |
| ------------------------------------------------------------------------------------------------------------------------------- | :----: | --------------------------------------------------------------------------------------------------------------- |
| [RFC 6749: The OAuth 2.0 Authorization Framework](https://datatracker.ietf.org/doc/html/rfc6749)                                |   ✅   | Authorization Code, Implicit, Client Credentials, Resource Owner Password Credentials, and Refresh Token grants |
| [RFC 6750: Bearer Token Usage](https://datatracker.ietf.org/doc/html/rfc6750)                                                   |   ✅   |                                                                                                                 |
| [RFC 7009: Token Revocation](https://datatracker.ietf.org/doc/html/rfc7009)                                                     |   ✅   | Optional policy to revoke the refresh token alongside an access token                                           |
| [RFC 7523: JWT Profile for Client Authentication and Authorization Grants](https://datatracker.ietf.org/doc/html/rfc7523)       |   ✅   | `client_secret_jwt`, `private_key_jwt`, and the JWT bearer grant                                                |
| [RFC 7591: Dynamic Client Registration Protocol](https://datatracker.ietf.org/doc/html/rfc7591)                                 |   ✅   |                                                                                                                 |
| [RFC 7592: Dynamic Client Registration Management Protocol](https://datatracker.ietf.org/doc/html/rfc7592)                      |   ✅   |                                                                                                                 |
| [RFC 7636: Proof Key for Code Exchange (PKCE)](https://datatracker.ietf.org/doc/html/rfc7636)                                   |   ✅   | Per-client enforcement policy                                                                                   |
| [RFC 7662: Token Introspection](https://datatracker.ietf.org/doc/html/rfc7662)                                                  |   ✅   | Client authentication for the introspection endpoint                                                            |
| [RFC 8628: Device Authorization Grant](https://datatracker.ietf.org/doc/html/rfc8628)                                           |   ✅   |                                                                                                                 |
| [RFC 8693: Token Exchange](https://datatracker.ietf.org/doc/html/rfc8693)                                                       |   ✅   |                                                                                                                 |
| [RFC 8705: Mutual-TLS Client Authentication and Certificate-Bound Access Tokens](https://datatracker.ietf.org/doc/html/rfc8705) |   ✅   | `tls_client_auth` and `self_signed_tls_client_auth`                                                             |
| [RFC 8707: Resource Indicators](https://datatracker.ietf.org/doc/html/rfc8707)                                                  |   ✅   |                                                                                                                 |
| [RFC 9068: JWT Profile for Access Tokens](https://datatracker.ietf.org/doc/html/rfc9068)                                        |   ✅   | Enabled globally or per client                                                                                  |
| [RFC 9101: JWT-Secured Authorization Request (JAR)](https://datatracker.ietf.org/doc/html/rfc9101)                              |   ✅   |                                                                                                                 |
| [RFC 9126: Pushed Authorization Requests (PAR)](https://datatracker.ietf.org/doc/html/rfc9126)                                  |   ✅   | Per-client enforcement policy                                                                                   |
| [RFC 9207: Authorization Server Issuer Identification](https://datatracker.ietf.org/doc/html/rfc9207)                           |   ✅   |                                                                                                                 |
| [RFC 9396: Rich Authorization Requests](https://datatracker.ietf.org/doc/html/rfc9396)                                          |   ❌   |                                                                                                                 |
| [RFC 9449: Demonstrating Proof of Possession (DPoP)](https://datatracker.ietf.org/doc/html/rfc9449)                             |   ✅   |                                                                                                                 |
| [RFC 9701: JWT Response for Token Introspection](https://datatracker.ietf.org/doc/html/rfc9701)                                 |   ✅   |                                                                                                                 |
| [JWT Secured Authorization Response Mode (JARM)](https://openid.net/specs/oauth-v2-jarm.html)                                   |   ✅   |                                                                                                                 |
| [Multiple Response Type Encoding Practices](https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html)                 |   ✅   | Including the `none` response type                                                                              |
| [Form Post Response Mode](https://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html)                                   |   ✅   | Custom response writer support                                                                                  |

### OpenID Connect 1.0

| Specification                                                                                                                          | Status | Notes                                                                                              |
| -------------------------------------------------------------------------------------------------------------------------------------- | :----: | -------------------------------------------------------------------------------------------------- |
| [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)                                                       |   🟡   | Authorization Code, Implicit, and Hybrid flows; no UserInfo endpoint or `claims` request parameter |
| [OpenID Connect Dynamic Client Registration 1.0](https://openid.net/specs/openid-connect-registration-1_0.html)                        |   ✅   |                                                                                                    |
| [OpenID Connect RP-Initiated Logout 1.0](https://openid.net/specs/openid-connect-rpinitiated-1_0.html)                                 |   ✅   |                                                                                                    |
| [OpenID Connect Back-Channel Logout 1.0](https://openid.net/specs/openid-connect-backchannel-1_0.html)                                 |   ✅   |                                                                                                    |
| [OpenID Connect Front-Channel Logout 1.0](https://openid.net/specs/openid-connect-frontchannel-1_0.html)                               |   ❌   |                                                                                                    |
| [OpenID Connect Session Management 1.0](https://openid.net/specs/openid-connect-session-1_0.html)                                      |   ❌   |                                                                                                    |
| [OpenID Connect Key Binding 1.0](https://openid.net/specs/openid-connect-key-binding-1_0.html)                                         |   ✅   |                                                                                                    |
| [OpenID Connect Advanced Syntax for Claims (ASC) 1.0](https://openid.net/specs/openid-connect-advanced-syntax-for-claims-1_0-ID1.html) |   ❌   |                                                                                                    |

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
