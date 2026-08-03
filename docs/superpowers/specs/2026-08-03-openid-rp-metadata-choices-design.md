# OpenID Connect Relying Party Metadata Choices 1.0 — Server Implementation

Status: approved design
Date: 2026-08-03
Spec: <https://openid.net/specs/openid-connect-rp-metadata-choices-1_0-final.html> (Final, 25 March 2026)

## Problem

The RP Metadata Choices specification extends OpenID Connect Dynamic Client Registration 1.0 so a Relying Party can
declare a *set* of supported values for metadata parameters that were previously single-valued. Nineteen new
`*_supported` / `*_values_supported` client metadata parameters are defined. They exist so the OP can pick a value
that works for both parties, which matters most under OpenID Federation Automatic Registration where there is no
registration response to tell the RP what the OP chose.

This library implements the OP side of dynamic client registration (`handler/rfc7591`) and every JWS/JWE flow the
choices apply to, but models each of these parameters as a single string. Today an RP that supports `ES256`, `PS256`
and `RS256` can only say one of them, and if the OP has no key for that one the registration succeeds and every
token the RP receives afterwards is unverifiable.

## Scope

In scope: the wire format, validation, persistence, and algorithm resolution for all nineteen parameters, plus the
one single-valued counterpart this library does not model yet.

Out of scope: OpenID Federation Automatic Registration, CIBA flows (the CIBA parameter is stored and validated but
no flow consumes it), a discovery/`.well-known` document, and the RFC 9068 `access_token_*` parameters, which this
specification does not define choices for.

## The two hard rules from the specification

**Input only.** §2: the parameters defined "MUST only be used as input values to registration requests, and not as
output values in registration responses and read responses. Any output values used related to these multi-valued
input parameters MUST be the associated corresponding single-valued metadata parameter." They are accepted,
validated, and persisted, but `MetadataFromClient` must never emit them.

**Consistency.** For every parameter, "If a *&lt;single-valued&gt;* metadata parameter is also present, its value MUST be
in the list." A violation is a registration error.

Two SHOULDs shape behaviour rather than bind it. §4: an OP "SHOULD NOT consider it an error when it doesn't support"
the single value if it supports one of the array choices, and "SHOULD use one of the choices that it does support, or
reject the registration with the `invalid_client_metadata` error when none of the client-provided values are
supported."

## Resolution order

One rule, applied everywhere a value must be chosen:

1. The preferred single-valued parameter, if present **and** usable (a matching key exists).
2. Otherwise each `*_values_supported` entry, in the order the RP declared them — the RP's array order is its
   preference order.
3. Otherwise `RS256`.

Step 1 deliberately tolerates an unusable preference rather than failing, which is what §4 asks for.

## Parameter map

Nineteen parameters, their counterparts in this codebase, and where each is resolved.

| Array parameter | Single-valued counterpart | Resolution |
| --- | --- | --- |
| `subject_types_supported` | `subject_type` | registration |
| `token_endpoint_auth_methods_supported` | `token_endpoint_auth_method` | registration |
| `id_token_signing_alg_values_supported` | `id_token_signed_response_alg` | signing, issuer JWKS |
| `userinfo_signing_alg_values_supported` | `userinfo_signed_response_alg` | signing, issuer JWKS |
| `authorization_signing_alg_values_supported` | `authorization_signed_response_alg` | signing, issuer JWKS |
| `introspection_signing_alg_values_supported` | `introspection_signed_response_alg` | signing, issuer JWKS |
| `id_token_encryption_alg_values_supported` | `id_token_encrypted_response_alg` | encryption, client JWKS |
| `id_token_encryption_enc_values_supported` | `id_token_encrypted_response_enc` | encryption, client JWKS |
| `userinfo_encryption_alg_values_supported` | `userinfo_encrypted_response_alg` | encryption, client JWKS |
| `userinfo_encryption_enc_values_supported` | `userinfo_encrypted_response_enc` | encryption, client JWKS |
| `authorization_encryption_alg_values_supported` | `authorization_encrypted_response_alg` | encryption, client JWKS |
| `authorization_encryption_enc_values_supported` | `authorization_encrypted_response_enc` | encryption, client JWKS |
| `introspection_encryption_alg_values_supported` | `introspection_encrypted_response_alg` | encryption, client JWKS |
| `introspection_encryption_enc_values_supported` | `introspection_encrypted_response_enc` | encryption, client JWKS |
| `request_object_signing_alg_values_supported` | `request_object_signing_alg` | verification, accept-any |
| `request_object_encryption_alg_values_supported` | `request_object_encryption_alg` | decryption, accept-any |
| `request_object_encryption_enc_values_supported` | `request_object_encryption_enc` | decryption, accept-any |
| `token_endpoint_auth_signing_alg_values_supported` | `token_endpoint_auth_signing_alg` | verification, accept-any |
| `backchannel_authentication_request_signing_alg_values_supported` | `backchannel_authentication_request_signing_alg` | stored only |

Three groups, three mechanisms:

- **OP-produced, OP-signed** (ID Token, UserInfo, JARM, Introspection). The OP holds the signing key, so the choice
  is made against the issuer JWKS at signing time.
- **OP-produced, client-encrypted.** The OP encrypts to the RP's keys, so the choice is made against the client's
  JWKS at encryption time.
- **Client-produced** (Request Objects, client authentication assertions). The RP already made the choice when it
  signed; the OP's job is to accept any algorithm in the declared set, not to negotiate.

`backchannel_authentication_request_signing_alg` does not exist in this library. It is added — metadata field,
client interface, and `DefaultRegisteredClient` field — so the CIBA array has a target, even though no flow consumes
it yet.

`token_endpoint_auth_methods_supported` deserves a note. §3 states the parameter describes the authentication
methods supported at *any* Authorization Server endpoint, and records the working group's position that the
per-endpoint `revocation_endpoint_auth_methods_supported` and `introspection_endpoint_auth_methods_supported`
Authorization Server metadata parameters in RFC 8414 were a mistake; the specification deliberately declines to
create client-metadata equivalents. So the single array also supplies the supported set for this library's
`introspection_endpoint_auth_method`, `revocation_endpoint_auth_method`, and
`pushed_authorization_request_endpoint_auth_method`.

## Design

### Layer 1 — Wire format

`client_registration_metadata.go` gains nineteen `[]string` fields and the
`backchannel_authentication_request_signing_alg` string, each with an `omitempty` JSON tag matching the specification
name exactly. Because `clientRegistrationMetadataFieldNames()` derives its list reflectively from the struct tags,
the new parameters are stripped from `Extra` on decode with no change to the round-trip machinery.

The input-only rule is enforced by omission: `DefaultClientRegistrationStrategy.MetadataFromClient` does not populate
the array fields, so `omitempty` keeps them out of every registration and read response. A test asserts that a
registration carrying all nineteen arrays produces a response body containing none of them.

### Layer 2 — Validation

`handler/rfc7591/validator_local.go` gains `validateAlgorithmChoices`, which performs the network-free checks:

- every array element is a non-empty token, reusing the existing `isToken`;
- when the corresponding single-valued parameter is non-empty it MUST appear in its array, else
  `invalid_client_metadata` — this is the specification's consistency MUST;
- `id_token_signing_alg_values_supported` must not contain `none`, mirroring the existing single-value rule;
- `subject_types_supported` ⊆ {`public`, `pairwise`};
- `token_endpoint_auth_methods_supported` ⊆ the client authentication methods in `internal/consts`.

A new `handler/rfc7591.AlgorithmValidator` holds a `jwt.Issuer` and implements §4's rejection: when the OP supports
none of the client's choices, registration fails with `invalid_client_metadata`. It is a separate type because it
needs the issuer, whereas `LocalValidator` is documented as performing purely local checks with no external
dependency.

It checks only the four OP-signed parameters — `id_token_signing_alg_values_supported`,
`userinfo_signing_alg_values_supported`, `authorization_signing_alg_values_supported`, and
`introspection_signing_alg_values_supported` — against `GetIssuerJWKAlgorithms`, treating the symmetric `HS*`
algorithms as supported when the client will hold a secret. The client-encrypted parameters are excluded because the
relevant keys are the RP's and are not necessarily resolvable at registration time, and the client-produced ones are
excluded because there is nothing to negotiate.

It is wired into the default validator chain, so an unsatisfiable registration fails fast by default. Because the
chain is supplied through `Config.RFC7591ClientRegistrationValidators`, a deployment that wants different behaviour
replaces or drops it — the same seam already used for `SectorIdentifierValidator`.

### Layer 3 — `jwt.Issuer` chooses

The issuer owns key material, so the issuer chooses the algorithm.

```go
type Issuer interface {
	GetIssuerJWK(ctx context.Context, kid, alg, use string) (jwk *jose.JSONWebKey, err error)
	GetIssuerStrictJWK(ctx context.Context, kid, alg, use string) (jwk *jose.JSONWebKey, err error)

	// GetIssuerJWKAlgorithms returns the distinct 'alg' values across the issuer keys with the given use.
	GetIssuerJWKAlgorithms(ctx context.Context, use string) (algs []string)

	// GetIssuerJWKPreferred returns the key for preferred when a matching key exists, otherwise the key for the
	// first usable entry of supported in declared order, otherwise the RS256 key. It returns the existing
	// JWKLookupError when no RS256 key exists either.
	GetIssuerJWKPreferred(ctx context.Context, kid, preferred string, supported []string, use string) (jwk *jose.JSONWebKey, err error)
}
```

`GetIssuerJWKAlgorithms` exists for `AlgorithmValidator`, which needs to test overlap without selecting a key. Both
are implemented on `DefaultIssuer` over the existing `SearchJWKS`.

`jwt.Client` gains `GetSigningAlgValuesSupported()`, `GetEncryptionAlgValuesSupported()`, and
`GetEncryptionEncValuesSupported()`. Each of the six `decorated*Client` wrappers maps them onto the corresponding
`oauth2` client getters, exactly as they already map `GetSigningAlg` and friends.

`DefaultStrategy.Encode` replaces its `GetIssuerJWK` call with `GetIssuerJWKPreferred`. The `HS*` candidates are
handled inside the same candidate walk rather than the current single up-front `IsSignedJWTClientSecretAlgStr`
branch, because a supported set may mix symmetric and asymmetric algorithms and the key source differs per
candidate: symmetric keys are derived from the client secret, asymmetric ones come from the issuer JWKS. Encryption
resolves through the same walk against the client's JWKS via `FindClientPublicJWK`.

### Layer 4 — Verification of client-produced JWTs

Nothing is negotiated here; the RP has already signed. A new `jwt.ValidateAlgorithmAny(algs ...string)` header
validation option accepts a set instead of a single value.

`authorize_request_handler.go` uses the set from `request_object_signing_alg_values_supported` when
`request_object_signing_alg` is absent, and keeps its existing rejection of an `alg` of `none` that was not
explicitly registered. `client_authentication.go`'s endpoint strategies gain a `GetAuthSigningAlgValuesSupported`
counterpart to `GetAuthSigningAlg`, so client assertions verify against the declared set.

### Layer 5 — Client interfaces and persistence

The getters are added directly to the existing interfaces rather than to parallel opt-in ones:

- `IDTokenClient`, `UserInfoClient`, `JARMClient`, `IntrospectionJWTResponseClient`, `JARClient` each gain the three
  getters for their signing/encryption alg/enc arrays.
- `AuthenticationMethodClient` gains `GetTokenEndpointAuthMethodsSupported` and
  `GetTokenEndpointAuthSigningAlgValuesSupported`.
- A new `BackchannelAuthenticationClient` carries `GetBackchannelAuthenticationRequestSigningAlg` and its array,
  because no existing interface covers CIBA at all.

This is a breaking change for downstream implementers of those interfaces and is accepted deliberately: it keeps the
resolution paths free of type assertions and keeps one model of what a client is. In-repo the blast radius is small
— `DefaultJARClient` and `DefaultRegisteredClient` are the only production implementations, plus test fixtures.

`DefaultRegisteredClient` gains the array fields and their getters; `DefaultClientRegistrationStrategy.apply` maps
them; `MetadataFromClient` deliberately does not, per Layer 1.

`subject_type` and `token_endpoint_auth_method` involve no key material. Their supported sets are static in this
library — {`public`, `pairwise`} and the five `internal/consts` client authentication methods — so they are resolved
during registration inside `apply`, which keeps `DefaultClientRegistrationStrategy` zero-value usable as it is today.
When the single value is absent, `apply` takes the first array entry that is a recognized value; when it is present
it is kept, since `LocalValidator` has already established it is a recognized value and a member of the array.

## Error handling

All registration failures use `oauth2.ErrInvalidClientMetadata`, matching the specification and the surrounding
validators, with a hint naming the offending parameter and value. Resolution at signing time cannot fail into a new
error class: the `RS256` fallback terminates the search, and the pre-existing "no issuer key" error covers an issuer
with no usable key at all.

## Testing

- Wire format: decode/encode round trip for all nineteen parameters; each is stripped from `Extra`.
- Input-only rule: a registration supplying all nineteen produces a response body containing none of them, and a
  subsequent RFC 7592 read produces none either.
- Consistency: for each parameter, a single value absent from its array is rejected with `invalid_client_metadata`.
- `AlgorithmValidator`: rejects when there is no overlap, accepts when the preferred value is unsupported but an
  array entry is supported.
- Resolution order, table-driven per group: preferred usable; preferred unusable with array fallback; neither, so
  `RS256`; array containing a symmetric algorithm against a client with and without a usable secret.
- Verification: request objects signed with each declared algorithm are accepted; one outside the set is rejected;
  `none` outside the set is rejected.
- `token_endpoint_auth_methods_supported` feeds the introspection, revocation, and PAR endpoint methods.

## Files

`client_registration_metadata.go`, `client.go`, `client_registered.go`, `authorize_request_handler.go`,
`client_authentication.go`, `token/jwt/client.go`, `token/jwt/issuer.go`, `token/jwt/jwt_strategy.go`,
`token/jwt/validate.go`, `handler/rfc7591/validator_local.go`, `handler/rfc7591/validator_algorithm.go` (new),
`handler/rfc7591/strategy_registration.go`, `internal/consts/client_registration.go`, `compose` wiring for the new
validator, and the corresponding test files.
