<!--
SPDX-FileCopyrightText: 2026 Authelia

SPDX-License-Identifier: Apache-2.0
-->

# Dynamic Client Registration — Known Issues and Review Record

**This is a defect record, not usage documentation.** It exists so the open items below can be fixed and reviewed later.
Consumer-facing documentation for this package does not exist yet and is itself one of the open items (see
[O4](#o4--no-consumer-documentation)).

Status as of 2026-08-02, branch `feat-dynamic-client-registration`, head `e9eb685`. Full suite green
(`go build ./... && go test ./...`).

**Do not treat green tests as evidence that
[O1](#o1--registration-tokens-are-accepted-as-bearer-client-authentication-at-the-introspection-endpoint) is fixed.**
Its tests pass only because `storage.MemoryStore` behaves differently from a real store; see the entry.

## Background

RFC 7591 / RFC 7592 registration tokens are **ordinary access tokens**. What makes one a registration token is its
session: `rfc7591.DefaultSession` (embedding `*hoauth2.JWTSession`) carries a `Kind` — `KindCreate` or `KindManage` —
and a set of `GrantableScopes` acting as a ceiling on what the registered client may be granted. An earlier design used
a dedicated `authelia_dt_`-prefixed token type; that was removed.

- Design: `docs/superpowers/specs/2026-08-02-dcr-registration-session-design.md`
- Plan: `docs/superpowers/plans/2026-08-02-dcr-registration-sessions.md`
- Per-task review ledger: `.superpowers/sdd/2026-08-02-dcr-registration-sessions/progress.md` (git-ignored)

Because registration tokens are now ordinary access tokens in ordinary access token storage, they are reachable by every
code path that consumes access tokens — introspection, revocation, token exchange. That reachability is the root of
[O1](#o1--registration-tokens-are-accepted-as-bearer-client-authentication-at-the-introspection-endpoint) and
[O3](#o3--rfc-8693-accepts-a-registration-token-as-subject_token), and it is the part of the design that received the
least scrutiny before implementation.

---

## Open — must be resolved before merge

### O1 — Registration tokens are accepted as bearer client-authentication at the introspection endpoint

**Severity: Important (security). The attempted fix does not work.**

`Fosite.handleNewIntrospectionRequestClientAuthentication` (`introspection_request_handler.go:137-157`) authenticates
the caller as the client of whatever access token is presented in the `Authorization` header. A **creation token** is
typically minted for a privileged onboarding client, so it becomes a credential that authenticates as that client at
`/introspect`. Under the removed `authelia_dt_` design this was structurally impossible.

A guard was added in `handler/oauth2/introspector.go:106`:

```go
if isClientRegistrationSession(original.GetSession()) {
    return errorsx.WithStack(oauth2.ErrRequestUnauthorized.WithDebug("The token is a client registration token ..."))
}
```

**Why it is ineffective.** `isClientRegistrationSession` type-asserts on `original.GetSession()`. The documented storage
contract (`handler/oauth2/storage.go`) is that the store _hydrates the caller-supplied session_:

1. `introspect.go:54` — `NewAccessRequest(session)`, where `session` is the **deployment's** session type.
2. `handler/oauth2/introspector.go:102` — `c.GetAccessTokenSession(ctx, signature, request.GetSession())` passes that
   deployment session as the hydration target.
3. A conforming store unmarshals the stored data into it and returns a requester carrying it — a type with no
   `IsClientRegistration()` method.
4. The assertion fails, the guard no-ops, and the token is introspected normally.

It appears to work only because `storage.MemoryStore` ignores the session argument entirely (`storage/memory.go:390`,
`func (s *MemoryStore) GetAccessTokenSession(_ context.Context, signature string, _ oauth2.Session)`) and returns the
stored object. **Every test covering this guard uses `MemoryStore` or a gomock store returning a hand-built registration
session, so the whole test set is green against a defect that is live on any JSON- or SQL-backed store.** Reproduced
empirically with a hydrating store: a creation token introspects successfully.

Note the irony worth preserving for whoever fixes this: the design's fail-closed argument (a foreign access token
hydrates into `rfc7591.DefaultSession` and lands on `KindNone`) depends on exactly these hydration semantics. The guard
was written as though the opposite were true.

**What a real fix needs:**

- A discriminator that survives hydration. The session cannot carry it, because at introspection the session type is the
  deployment's. Candidates: key off the persisted granted audience (registration tokens are always audienced to the
  registration endpoint URL or a `registration_client_uri`), or a marker the store cannot drop.
- A test using a **hydrating** store — one that marshals on write and unmarshals into the supplied session on read. A
  `MemoryStore`-based test cannot detect this class of bug and must not be relied on again here.
- Correction of the false claims in [O2](#o2--false-coverage-claims-about-rfc-8693).

### O2 — False coverage claims about RFC 8693

**Severity: Important (misleading documentation).**

Two places assert that the O1 guard also closes RFC 8693 token-exchange reachability:

- `handler/oauth2/introspector.go:65-72` — the `isClientRegistrationSession` doc comment ("nor as an introspectable or
  exchangeable token").
- The Storage section of `docs/superpowers/specs/2026-08-02-dcr-registration-session-design.md`.

Both are wrong. `handler/rfc8693/access_token_type_handler.go:139` calls `GetAccessTokenSession` and
`ValidateAccessToken` directly and never routes through `CoreValidator` (`compose/compose_rfc8693.go:63-71` confirms the
wiring). A future maintainer will read these as covered. Correct or make true.

### O3 — RFC 8693 accepts a registration token as `subject_token`

**Severity: Important (security). Never entered the findings list; discovered during the final re-review.**

`handler/rfc8693/access_token_type_handler.go:124-165` will accept a registration access token as `subject_token`.
Self-exchange is blocked and `GetTokenExchangePermitted` gates the exchange — but **only when the token's client
implements `rfc8693.Client`, which `DefaultRegisteredClient` does not**, so the gate is skipped. The scope check is
vacuous because registration tokens carry no granted scopes, so a scope-less exchange mints a token whose `client_id`
claim is the onboarding client's.

Same vulnerability class as O1, different route. Fixing O1 with a discriminator that lives outside the session would let
the same check be reused here.

### O4 — No consumer documentation

**Severity: Important (usability). Deliberately out of scope for the fix pass; needs an owner.**

`compose/compose_rfc7591.go` registers both handlers, but nothing wires the pieces a deployment must supply. With
`ComposeAllEnabled` alone both endpoints return `ErrServerError` until the consumer does this by hand. That is
fail-closed and therefore safe, but undiscoverable. Nothing documents:

- that `rfc7591.NewDefaultEndpointAuthStrategy(config, store, strategy)` must be assigned to
  `Config.RFC7591ClientRegistrationEndpointAuthStrategy`;
- that `Config.RFC7591ClientRegistrationStrategy` must be set;
- that `rfc7591.NewClientCreationToken` is the only way to mint an initial access token, and issuance policy is the
  deployment's responsibility;
- what `GrantableScopes` means, and that an **empty ceiling rejects every scoped registration**;
- that an unauthenticated registration endpoint enforces no ceiling at all (see
  [Deliberate design decisions](#deliberate-design-decisions)).

The `docs/superpowers/` design and plan documents are process artifacts, not consumer docs.

### O5 — Residuals flagged but not fixed

| Item                                              | Location                                                                               | Note                                                                                                                                                                                                                                                                                                                                                                                                                    |
| ------------------------------------------------- | -------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `NewClientManagementToken` panics on a nil client | `handler/rfc7591/token.go:56`                                                          | Dereferences `client.GetID()` before anything else. A nil client is meaningless there, so this is arguably correct, but a library should not panic.                                                                                                                                                                                                                                                                     |
| Typed-nil client defeats the M9 guard             | `handler/rfc7591/token.go:84-86`                                                       | `(*oauth2.DefaultClient)(nil)` passes `client != nil` and still panics later at `handler/oauth2/revocation.go:59`.                                                                                                                                                                                                                                                                                                      |
| Typed-nil requester defeats the I3 guard          | `rfc7592_client_configuration_request_handler.go:91-92`, `handler/rfc7591/scope.go:30` | Same class: `authenticated == nil` does not catch a typed nil.                                                                                                                                                                                                                                                                                                                                                          |
| `StatelessJWTValidator` cannot see `Kind`         | `handler/oauth2/introspector.go`                                                       | `Kind` is not a JWT claim, so under `EnforceJWTProfileAccessTokens` the stateless validator cannot detect a registration token. Contained while `CoreValidator` is also registered (`introspect.go:57-67` returns on the first non-`ErrUnknownRequest` error) — but that containment is contingent on the O1 guard actually firing, which today it does not.                                                            |
| Inaccurate nil-guard claim                        | `handler/rfc7591/session.go:57-64`                                                     | The new doc says `JWTSession` "guards its getters against a nil receiver"; `GetJWTClaims`, `GetJWTHeader` and `GetExpiresAt` (`handler/oauth2/strategy_jwt_session.go:38,45,66`) do not.                                                                                                                                                                                                                                |
| `&DefaultSession{}` panics                        | `handler/rfc7591/session.go`                                                           | Resolved by documentation, not code — `NewDefaultSession()` is mandatory. A reviewer suggested a third option not taken: embed `hoauth2.JWTSession` **by value**. All its methods are pointer-receiver and promote identically from an addressable `*DefaultSession`, `JWTSessionContainer` stays satisfied, JSON inlining is unchanged — and `&DefaultSession{}` becomes safe with nothing to lapse. Worth revisiting. |

---

## Fixed in the final pass

Commits `4fdeb4a..e9eb685`. Each was verified to fail against the pre-fix code before the fix was accepted, except where
noted.

### C1 — "Never expires" management tokens actually died after ~1 hour

**Was: Critical. Fixed in `2f13708`.**

A zero `RFC7591ClientRegistrationManageTokenLifespan` is documented as "never expires" and was implemented by skipping
`SetExpiresAt`. But `HMACCoreStrategy.ValidateAccessToken` (`handler/oauth2/strategy_hmac.go:81-87`) does not treat a
zero expiry as "no expiry":

```go
if exp.IsZero() && r.GetRequestedAt().Add(s.Config.GetAccessTokenLifespan(ctx)).Before(time.Now().UTC()) {
    return errorsx.WithStack(oauth2.ErrTokenExpired...)
}
```

Zero fell back to `RequestedAt + GetAccessTokenLifespan`, default one hour (`config_default.go:576-581`). Since RFC 7592
provides no re-issue path for a `registration_access_token`, an hour after registration the client could never GET, PUT
or DELETE its own registration again and its `client_id` was burned — unrecoverable, and invisible until it happened.
Behaviour also **diverged by strategy**: under `EnforceJWTProfileAccessTokens` no `exp` claim was emitted and the token
genuinely never expired.

Fixed by substituting `NonExpiringTokenLifespan` (`handler/rfc7591/token.go:31`, a century) for any non-positive
resolved lifespan and calling `SetExpiresAt` unconditionally, so the HMAC fallback cannot fire and both strategies
agree. The substitution sits after `GetEffectiveLifespan`, so a client override of zero also means never.
`GetRFC7591ClientRegistrationManageTokenLifespan` still returns the raw zero, so the config documentation stays true.

**This originated in the design document, not the implementation** — the spec reasoned about how expiry is _set_ but
never about how it is _validated_, and the plan faithfully encoded the wrong model.

The test that should have caught it was hollow: it asserted `GetExpiresAt(oauth2.AccessToken).IsZero()` — the mechanism
— under a comment claiming the token never expires. Replaced with behavioural tests that drive
`AuthenticateClientRegistrationRequest` past a 1ns `AccessTokenLifespan`, on both the opaque and JWT-profile paths, plus
a negative test pinning the fallback so the positive test cannot pass vacuously.

### I4 — Scope ceiling was compared with a client-supplied strategy

**Was: Important (security). Fixed in `efcc85e`. Initially misgraded by the reviewer as inert hardening.**

`oauth2.GetScopeStrategy` (`strategy_scope.go:19-24`) prefers the **client's** strategy over the server's whenever the
client implements `ScopeStrategyProvider`. The two ceiling call sites disagreed about what to pass:

```
handler_registration.go:80    checkGrantableScopes(..., nil,    metadata)   // no client exists yet
handler_configuration.go:118  checkGrantableScopes(..., client, metadata)   // the registered client
```

So on the RFC 7592 update path the function deciding whether a scope was inside the ceiling was supplied by the client
the ceiling exists to constrain. A permissive client strategy makes every membership test succeed, `excess` stays empty,
and the ceiling is bypassed — not narrowed. The client controls its own `PUT` body, so escalation is bounded only by
what the other validators allow.

Exposure is conditional: no client type in this repository implements `ScopeStrategyProvider`, which is why it was first
graded inert. But it is an exported extension point and every client type in this library is consumer-supplied, so a
deployment deriving a scope strategy from client metadata had a live bypass. **Verified live, not theoretical** — with
the client passed, a wrapper client's accept-everything strategy let `profile` past an `{openid}` ceiling.

Fixed by removing the `client` parameter from `checkGrantableScopes` entirely, so the comparison is always
`oauth2.GetScopeStrategy(ctx, config, nil)` and both endpoints agree. Dropping the parameter rather than passing `nil`
twice means a future caller cannot reintroduce it. Regression test:
`TestClientConfigurationHandlerCeilingIgnoresClientScopeStrategy` (`handler_configuration_test.go:343`).

The asymmetry between the two call sites was the tell — a control meaning one thing at registration and another at
update is one nobody had fully reasoned about.

### I3 — Nil dereference on a documented extension point

**Was: Important. Fixed in `110e00f`.**

`rfc7592_client_configuration_request_handler.go:86` did `request.Signature = request.Authenticated.GetID()` and
panicked when an auth strategy returned `(nil, nil)` — which the documented `GetAuthenticatedRequester` contract
permits, and which `handler/rfc7591/scope.go:30` and `handler_configuration.go:136` both already defended against.
`ClientRegistrationEndpointAuthStrategy` is a documented extension point, so a library must not panic on it. Guarded at
`:91-92`; the RFC 7591 sibling only assigns and was correctly left alone. See [O5](#o5--residuals-flagged-but-not-fixed)
for the typed-nil gap that remains.

### Smaller fixes

| Ref | Fix                                                                                                                                                                                             | Commit    |
| --- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------- |
| M1  | `&DefaultSession{}` panics on promoted setters (nil embedded pointer). Resolved by documenting `NewDefaultSession()` as mandatory on the type doc.                                              | `2cdf155` |
| M2  | `handler_configuration.go` read `GrantableScopes` without the `IsClientRegistration()` guard the registration handler had. Made consistent.                                                     | `efcc85e` |
| M3  | `Kind`'s `iota` values are a storage contract (`"client_registration_kind": 2`). Added an append-only warning; made executable by an assertion in M5's test.                                    | `2cdf155` |
| M4  | `PreservesCeilingAcrossRotation` could not distinguish a carried ceiling from the requested scopes — both were `{openid}`. Now ceiling `{openid, profile}` with a PUT requesting only `openid`. | `efcc85e` |
| M5  | Nothing pinned the JSON round trip, on which the entire fail-closed argument rests. Added `TestDefaultSessionJSONRoundTrip`, asserting a foreign session hydrates to `KindNone`.                | `2cdf155` |
| M6  | `"authelia_dt_token"` fixture literal — last live reference to the deleted prefix.                                                                                                              | `a5aabb5` |
| M7  | `strategy_hmac.go` doc named four prefix parts but three token types.                                                                                                                           | `a5aabb5` |
| M9  | `NewClientCreationToken` with a nil client persisted a session that later panicked at `revocation.go:59`.                                                                                       | `2f13708` |
| M10 | `WrongKind` subtest name overstated what it proved (the audience check rejects first). Renamed, with a pointer to the real isolation at `strategy_auth_test.go:258`.                            | `a5aabb5` |

`e9eb685` is prettier formatting of the design document only.

---

## Deferred minors — triaged as ship-as-is

Recorded so a later reviewer does not rediscover them. Each was raised by a per-task review and judged not worth
blocking on.

| Area          | Item                                                                                                                                                                                                             |
| ------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Endpoint auth | The subject-equality check (step 8) has no isolating test — the audience check rejects first. Documented in-code as defence in depth; the audience check is the real control and _is_ isolated.                  |
| Endpoint auth | `strategy_auth_test.go` `mintToken` has dead `subject`/`exp` params and mints a session that can never authenticate. Fine for its two header-shape callers, a trap for future reuse.                             |
| Scope ceiling | No test with 2+ offending scopes proving the hint names all of them. The loop is correct by inspection; the join format is unexercised.                                                                          |
| Scope ceiling | No test for an authenticated requester whose session is not a registration session taking the no-ceiling skip path. The failure mode would be over-restrictive; the permissive direction is covered.             |
| Spec tests    | RFC 7591 §3.1 coverage asserts only bare `require.Error` — the rejection status is pinned nowhere.                                                                                                               |
| Spec tests    | Nothing asserts `client_secret_expires_at` is _absent_ when no secret is issued.                                                                                                                                 |
| Spec tests    | `NotContains(..., "scope")` relies on `omitempty`; the companion `GetScopes()` assertion carries the weight.                                                                                                     |
| Integration   | Steps 5/6 assert 401 status only and do not isolate the Kind gate (isolated at unit level in `strategy_auth_test.go:232,258`).                                                                                   |
| Integration   | "Replacement applied" is asserted from the PUT response body, rendered from the in-memory `patched` object, not a store re-read. `handler_configuration_test.go` does the store re-read.                         |
| Integration   | The `authelia_at_` prefix assertion partly checks the test's own strategy config; a store-namespace assertion would be stronger.                                                                                 |
| Integration   | Local `store` shadows the package-level fixture; endpoint adapters live in the test file rather than `helper_endpoints_test.go`; the mux mounts without `.Methods()`, so 400-on-non-POST and 405 are unasserted. |

**Two closed questions**, recorded so they are not reopened:

- **Three exported aliases were removed** with `handler/rfc7591/strategy.go` — `ClientRegistrationStrategy`,
  `ClientRegistrationValidator`, `ClientRegistrationEndpointAuthStrategy`. Removal confirmed correct: they were pure
  type aliases duplicating names in the root package, saved nobody an import, and **none of this API exists on master**,
  so there is no public surface to break. The plan's stated rationale for deleting the file was factually wrong, but the
  outcome was right.
- **The integration test uses `compose.Compose`, not `ComposeAllEnabled`.** `ComposeAllEnabled` builds a prefix-less
  strategy via `compose.NewOAuth2HMACStrategy` (`compose/compose_strategy.go:34-39`), making the planned `authelia_at_`
  prefix assertion unsatisfiable — the plan was internally inconsistent. No coverage lost:
  `compose/compose_rfc7591_test.go:46-63` independently proves `ComposeAllEnabled` registers both handlers through the
  same panicking factory assertions.

---

## Deliberate design decisions

Not defects. Listed because each reads like one at first glance.

- **An unauthenticated registration endpoint enforces no scope ceiling.** RFC 7591 permits open registration, and such a
  deployment has no creation token to inherit a ceiling from. `handler/rfc7591/scope.go:30` returns early on a nil
  authenticated requester. Deployments wanting a ceiling must require authentication.
- **When registration is unauthenticated, the management token's ceiling becomes the client's own registered scopes**
  (`handler_registration.go:124-128`), so a later PUT still cannot escalate beyond what registration itself granted.
- **An omitted or empty `scope` registers the client with no scopes**, rather than inheriting the full ceiling.
- **`IsClientRegistration()` is derived from `Kind != KindNone`**, not stored separately — one field cannot contradict
  itself the way an independent boolean and kind can.
- **`DefaultSession` embeds `*hoauth2.JWTSession` specifically.** Registration tokens are ordinary access tokens and
  therefore inherit the JWT profile path; `JWTProfileCoreStrategy.GenerateJWT` hard-rejects any session not implementing
  `hoauth2.JWTSessionContainer`, and only `JWTSession` does. Guarded by `TestNewClientManagementTokenUnderJWTProfile`.
- **`DefaultSession.Clone` is overridden.** The embedded `JWTSession.Clone` deep-copies only the embedded value and
  would silently drop `Kind` and `GrantableScopes`.
- **The scope ceiling is a floor on escalation, not a lock.** A client can raise its scopes up to the creation token's
  ceiling by updating itself; it simply cannot exceed it. The design document's phrasing ("a registered client cannot
  escalate its own scopes by updating itself") reads stronger than the behaviour and should be corrected.
