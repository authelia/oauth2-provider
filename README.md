## Fork

This is a hard fork of [ORY Fosite](https://github.com/ory/fosite) under the
[Apache 2.0 License](LICENSE) for the purpose of performing self-maintenance of
this critical dependency.

We however:

- Acknowledge the amazing hard work of the ORY developers in making such an
  amazing framework that we can do this with.
- Plan to continue to contribute back to te ORY Fosite and related projects.
- Have ensured the licensing is unchanged in this fork of the library.
- Do not have a formal affiliation with ORY and individuals utilizing this
  library should not allow their usage to be a reflection on ORY as this library
  is not maintained by them.

## Notable Implemented or Intended Differences

In an effort to assist users who wish to use this library we aim to maintain the
following list of differences:

- [x] Module path changed from `github.com/ory/fosite` to
      `authelia.com/provider/oauth2`.
- Rename interfaces and implementations:
  - [x] `OAuth2Provider` to `Provider`.
  - [ ] `Fosite` to `TBA`.
- [x] Minimum dependency is go version 1.21.
- Fixes:
  - [x] Basic Scheme Rejects Special Characters
        2314625eb1f21987a9199fb1cdf6da6cee4df965
  - [x] RFC9068 must condition ignored f4652d60c850d167da00e2d2fe9096776eff9465
  - [ ] Refresh Flow ignores requested scope
  - [ ] Refresh Flow does not set original request ID early enough
  - [ ] PKCE Flow session generated needlessly
  - [ ] OpenID Flows ignore empty redirect uri
  - [ ] Decode id_token_hint with correct signer
  - [ ] Write Revocation Response does not correctly error
  - [ ] Invalid Token base 64 error not mapped to RFC
  - [ ] Auth Request omitted Response Mode not validated
  - [ ] Refresh Grant if Token Invalid/Expired status is not 400
  - [ ] Access Token iat in JWT Profile always original iat
- Features:
  - [ ] Customizable Token Prefix
  - [ ] JWE support for Client Authentication and Issuance
  - [ ] JARM support
  - [ ] Revocation Flow per policy can decide to revoke Refresh Tokens on
        request
  - [ ] Response Type None
  - [ ] Client Secret Validation Interface
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
  - [x] `github.com/golang/mock` => `github.com/uber-go/mock`
  - [x] `github.com/cristalhq/jwt/v4` => `github.com/golang-jwt/jwt/v5`

## TODO

- Consolidate JWT and JOSE dependencies
- Remove unecessary dependencies and/or abstract them
- Apply downstream fixes
