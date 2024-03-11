## OAuth 2.0 Framework

This library is the Authelia OAuth 2.0 Framework which is internally used to
deliver OAuth 2.0 and OpenID Connect 1.0 Flows to its users.

## Notable Implemented or Intended Differences

In an effort to assist users who wish to use this library we aim to maintain the
following list of differences:

- [x] Module path changed from `github.com/ory/fosite` to
      `authelia.com/provider/oauth2`.
- Documentation:
  - [ ] Add spec support documentation
- Overhaul testing:
  - [ ] Ensure all tests and subtests are well named
  - [ ] Ensure all tests are simplified where possible
  - [ ] Restore/Implement conformance tests
- Rename interfaces and implementations:
  - [x] `OAuth2Provider` to `Provider`.
  - [ ] `Fosite` to `TBA`.
- [x] Minimum dependency is go version 1.21
- [x] Replace string values with constants where applicable
      <sup>[commit](https://github.com/authelia/oauth2-provider/commit/de536dc0c9cd5f080c387621799e644319587bd0)</sup>
- [ ] Simplify the internal JWT logic to leverage `github.com/golang-jwt/jwt/v5`
      or other such libraries
- [ ] Implement internal JWKS logic
- [x] Higher Debug error information visibility (Debug Field includes the
      complete RFC6749 error with debug information if available)
- Fixes:
  - [x] ~~Basic Scheme Rejects Special Characters~~
        <sup>[commit](https://github.com/authelia/oauth2-provider/commit/2314625eb1f21987a9199fb1cdf6da6cee4df965)</sup>
  - [x] RFC9068 must condition ignored
        <sup>[commit](https://github.com/authelia/oauth2-provider/commit/c6e7a18ee9066b8c17c6f30a180d44507e2e2ff1)</sup>
  - [x] Arguments are treated as case-insensitive
        <sup>[commit](https://github.com/authelia/oauth2-provider/commit/8418ced18790dc885e5baa0733e93410f3a3a994)
  - Refresh Flow:
    - [x] Requested scope ignored
          <sup>[commit](https://github.com/authelia/oauth2-provider/commit/6584d3495422a97ef9aba92e762ffaebce010dd0)</sup>
    - [x] Original request id not set early enough
          <sup>[commit](https://github.com/authelia/oauth2-provider/commit/6584d3495422a97ef9aba92e762ffaebce010dd0)</sup>
  - PKCE Flow:
    - [x] Session generated needlessly
          <sup>[commit](https://github.com/authelia/oauth2-provider/commit/dbdadf5dee92d13683eeacaa198c28d6704ddb1c)</sup>
    - [x] Failure to fetch session causes an error even when not enforced
          <sup>[commit](https://github.com/authelia/oauth2-provider/commit/dbdadf5dee92d13683eeacaa198c28d6704ddb1c)</sup>
  - OpenID Flows:
    - [x] Absence of Redirect URI does not result in an error
          <sup>[commit](https://github.com/authelia/oauth2-provider/commit/f4652d60c850d167da00e2d2fe9096776eff9465)</sup>
  - [ ] Decode id_token_hint with correct signer
  - [x] Write Revocation Response does not correctly error
        <sup>[commit](https://github.com/authelia/oauth2-provider/commit/6dffe2d9bdc3fc974f7c2c865aef2a8b2cb78402)</sup>
  - ~~Invalid Token base 64 error not mapped to RFC~~
  - [ ] Auth Request omitted Response Mode not validated
  - [x] Refresh Grant if Token Invalid/Expired status is not 400
        <sup>[commit](https://github.com/authelia/oauth2-provider/commit/8e58bcae054dffbad1c920e0bbaa022dfac71f66)</sup>
  - [x] Access Token iat and nbf in JWT Profile always original claims
        <sup>[commit](https://github.com/authelia/oauth2-provider/commit/a87d91df762a8fe26282145ba9dace0461f31b4d)</sup>
- Features:
  - [x] Requested Audience Policy (many clients do not support the parameter)
  - PAR Flow:
    - [x] Per-Client Enforcement Policy
  - PKCE Flow:
    - [x] Per-Client Enforcement Policy
  - CoreStrategy:
    - [x] Customizable Token Prefix
          <sup>[commit](https://github.com/authelia/oauth2-provider/commit/4f55dabdf5d87c34053992c3de3fe7b1bf1046f3)</sup>
    - [x] Automatic NewCoreStrategy which provides either:
      - JWT Profile Core Strategy (if a jwt.Signer is provided)
      - HMAC-based Core Strategy
    - [x] JWT Profile Per Client
  - [ ] UserInfo support
  - [x] [RFC8628: OAuth 2.0 Device Authorization Grant](https://datatracker.ietf.org/doc/html/rfc8628)
        support
        <sup>[commit](https://github.com/authelia/oauth2-provider/commit/be088375c5c0077f33976991cfbc056450fd6d58)</sup>
  - [x] [RFC8693: OAuth 2.0 Token Exchange](https://datatracker.ietf.org/doc/html/rfc8693)
        support
        <sup>[commit](https://github.com/authelia/oauth2-provider/commit/add3cbecb9d35e2b7c29426cf5d898c9b1599e3b)</sup>
  - [ ] [RFC8705: OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens](https://datatracker.ietf.org/doc/html/rfc8705)
        support
  - [ ] [RFC9449: OAuth 2.0 Demonstrating Proof of Possession (DPoP)](https://datatracker.ietf.org/doc/html/rfc9449)
        support
  - [ ] [RFC9396: OAuth 2.0 Rich Authorization Requests](https://datatracker.ietf.org/doc/html/rfc9396)
        support
  - [ ] [OpenID Connect Dynamic Client Registration 1.0](https://openid.net/specs/openid-connect-registration-1_0.html)
        support
  - Response Mode Rework:
    - [x] [JWT Secured Authorization Response Mode for OAuth 2.0 (JARM)](https://openid.net/specs/oauth-v2-jarm.html)
          support
          <sup>[commit](https://github.com/authelia/oauth2-provider/commit/2b6436032f041160311645d4e8a8b129f8986a89)</sup>
    - [x] [RFC9207: OAuth 2.0 Authorization Server Issuer Identification](https://datatracker.ietf.org/doc/html/rfc9207)
          support
          <sup>[commit](https://github.com/authelia/oauth2-provider/commit/28cb8cddc09d1dcd4b9ec42870499d8a37223366)</sup>
    - [x] Response Type None
          <sup>[commit](https://github.com/authelia/oauth2-provider/commit/22c6e980c01eff4fb659c2b4a0a9b53d9e93edea)</sup>
  - [x] Revocation Flow per policy can decide to revoke Refresh Tokens on
        request <sup>[commit](e3ffc451f1c7056494f9dc3e51d47e84f12357de)</sup>
  - Client Authentication Rework:
    - [x] General Refactor
    - [x] Prevent Multiple Client Authentication Methods
    - [x] Client Secret Validation Interface
    - [ ] JWE support for Client Authentication and Issuance
  - [x] Testing Package (mocks, etc)
  - [ ] Clock Drift Support
  - [ ] Key Management
  - [ ] Injectable Clock Configurator
  - [x] Support `s_hash`
        <sup>[commit](https://github.com/authelia/oauth2-provider/commit/edbbbe9467c70a2578db4b9af4d6cd319f74886e)</sup>
- Removal of the following dependencies:
  - [x] `go.opentelemetry.io/otel/trace`
  - [x] `github.com/ecordell/optgen`
  - [x] `github.com/asaskevich/govalidator `
  - [x] `github.com/gorilla/websocket`
  - [x] `github.com/magiconair/properties`
  - [x] `github.com/mattn/goveralls`
  - [x] `github.com/oleiade/reflections`
  - [x] `github.com/ory/go-acc`
  - [x] `github.com/ory/go-convenience`
  - [x] `github.com/ory/x`
  - [x] `github.com/gorilla/sessions`
  - [x] `github.com/gobuffalo/packr`
  - [x] `github.com/form3tech-oss/jwt-go`
  - [x] `github.com/dgrijalva/jwt-go`
- Migration of the following dependencies:
  - [x] `github.com/go-jose/go-jose/v3` => `github.com/go-jose/go-jose/v4`
  - [x] `github.com/golang/mock` => `github.com/uber-go/mock`
  - [x] `github.com/cristalhq/jwt/v4` => `github.com/golang-jwt/jwt/v5`

## Thanks

This is a hard fork of [ORY Fosite](https://github.com/ory/fosite) under the
[Apache 2.0 License](LICENSE) for the purpose of performing self-maintenance of
this critical Authelia dependency.

We however:

- Acknowledge the amazing hard work of the ORY developers in making such an
  amazing framework that we can do this with.
- Plan to continue to contribute back to te ORY fosite and related projects.
- Have ensured the licensing is unchanged in this fork of the library.
- Do not have a formal affiliation with ORY and individuals utilizing this
  library should not allow their usage to be a reflection on ORY as this library
  is not maintained by them.
