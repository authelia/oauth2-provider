// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

// Package rfc8693_test — spec compliance test suite.
//
// These tests are written to map directly to numbered sections of RFC 8693 (OAuth 2.0 Token Exchange) so that the
// behavior the implementation guarantees can be read out against the spec. Each test name carries the relevant §
// reference and a description; failures should be interpreted as a divergence from that spec section.
//
// https://datatracker.ietf.org/doc/html/rfc8693

package rfc8693_test

import (
	"context"
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/handler/openid"
	. "authelia.com/provider/oauth2/handler/rfc8693"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/token/hmac"
	"authelia.com/provider/oauth2/token/jwt"
)

// =============================================================================
// §4.1 — "act" (Actor) Claim
//
// The act claim MUST identify the actor when delegation occurs; nested act
// claims express a chain of delegation, outermost = most recent actor.
// =============================================================================

// §4.1: Pure impersonation (no actor_token) MUST NOT add an act claim.
func TestSpec_4_1_ActClaim_ImpersonationOmitsActClaim(t *testing.T) {
	cfg := newSpecConfig(t)
	session := newSpecSession("alice")

	require.NoError(t, runGrantHandler(t, cfg, newSpecRequest(t, newConfidentialClient(), session, nil)))

	_, present := session.Extra[consts.ClaimActor]
	assert.False(t, present, "RFC 8693 §4.1: impersonation requests must not produce an 'act' claim")
}

// §4.1: Delegation MUST add an act claim with the actor's identifying claims.
func TestSpec_4_1_ActClaim_DelegationAddsActorSub(t *testing.T) {
	cfg := newSpecConfig(t)
	session := newSpecSession("alice")
	session.SetActorToken(map[string]any{consts.ClaimSubject: "bob"})

	require.NoError(t, runGrantHandler(t, cfg, newSpecRequest(t, newConfidentialClient(), session, nil)))

	act, ok := session.Extra[consts.ClaimActor].(map[string]any)
	require.True(t, ok, "RFC 8693 §4.1: delegation requests must produce an 'act' claim")
	assert.Equal(t, "bob", act[consts.ClaimSubject], "the 'act' claim's 'sub' must come from the actor_token")
}

// §4.1: The act claim should carry every identifying claim of the actor that the AS recognises (sub + client_id).
func TestSpec_4_1_ActClaim_IncludesClientIDWhenPresent(t *testing.T) {
	cfg := newSpecConfig(t)
	session := newSpecSession("alice")
	session.SetActorToken(map[string]any{
		consts.ClaimSubject:          "bob",
		consts.ClaimClientIdentifier: "client-bob",
	})

	require.NoError(t, runGrantHandler(t, cfg, newSpecRequest(t, newConfidentialClient(), session, nil)))

	act, ok := session.Extra[consts.ClaimActor].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "bob", act[consts.ClaimSubject])
	assert.Equal(t, "client-bob", act[consts.ClaimClientIdentifier])
}

// §4.1: "A nested act claim within an act claim MAY be used to express a chain of delegation."
// Outermost = most recent. When the subject_token already carried an act, the new act nests it as act.act.
func TestSpec_4_1_ActClaim_ChainsDelegationViaNestedAct(t *testing.T) {
	cfg := newSpecConfig(t)
	session := newSpecSession("alice")

	// Subject token already carried an act claim (e.g. an earlier delegation step).
	session.SetSubjectToken(map[string]any{
		consts.ClaimSubject: "alice",
		consts.ClaimActor: map[string]any{
			consts.ClaimSubject: "carol",
		},
	})
	session.SetActorToken(map[string]any{consts.ClaimSubject: "bob"})

	require.NoError(t, runGrantHandler(t, cfg, newSpecRequest(t, newConfidentialClient(), session, nil)))

	act, ok := session.Extra[consts.ClaimActor].(map[string]any)
	require.True(t, ok, "delegation must produce an 'act' claim")

	assert.Equal(t, "bob", act[consts.ClaimSubject], "outermost actor must be the most recent (from actor_token)")

	nested, ok := act[consts.ClaimActor].(map[string]any)
	require.True(t, ok, "RFC 8693 §4.1: prior actor must be nested as act.act for the chain of delegation")
	assert.Equal(t, "carol", nested[consts.ClaimSubject], "nested actor must be the prior actor from the subject_token's act claim")
}

// Regression guard for the previous broken implementation: the helper must not mutate any subject_token map members.
func TestSpec_4_1_ActClaim_DoesNotMutateSubjectTokenMap(t *testing.T) {
	cfg := newSpecConfig(t)
	session := newSpecSession("alice")

	priorAct := map[string]any{consts.ClaimSubject: "carol"}
	subject := map[string]any{
		consts.ClaimSubject: "alice",
		consts.ClaimActor:   priorAct,
	}
	session.SetSubjectToken(subject)
	session.SetActorToken(map[string]any{consts.ClaimSubject: "bob"})

	require.NoError(t, runGrantHandler(t, cfg, newSpecRequest(t, newConfidentialClient(), session, nil)))

	// The original subject-token act must be unchanged — building the new act must deep-copy nested maps so it
	// can be mutated/serialized without disturbing the subject_token snapshot.
	assert.Equal(t, map[string]any{consts.ClaimSubject: "carol"}, priorAct,
		"buildActClaim must not mutate the subject_token's act map (deep-copy required)")

	// And the issued act's nested act must be a fresh allocation, not the same map header as priorAct, so
	// downstream mutation of the issued claim cannot corrupt the subject_token snapshot.
	act := session.Extra[consts.ClaimActor].(map[string]any)
	nested := act[consts.ClaimActor].(map[string]any)
	nested["injected"] = true
	assert.NotContains(t, priorAct, "injected", "mutating the issued nested 'act' must not leak into the subject_token's act map")
}

// An actor_token containing no recognised identifying claims must NOT produce a stub/empty act claim.
func TestSpec_4_1_ActClaim_EmptyActorTokenProducesNoActClaim(t *testing.T) {
	cfg := newSpecConfig(t)
	session := newSpecSession("alice")

	session.SetActorToken(map[string]any{"unknown_claim": "value"})

	require.NoError(t, runGrantHandler(t, cfg, newSpecRequest(t, newConfidentialClient(), session, nil)))

	_, present := session.Extra[consts.ClaimActor]
	assert.False(t, present, "an actor_token with no identifying claims must not produce an empty 'act' claim")
}

// §2.1: the issued JWT's 'aud' MUST reflect this exchange's audience/resource parameters, not any audience the
// session happened to carry from a prior flow. This test seeds the session with a pre-existing audience and runs
// a custom-JWT exchange that supplies a different audience via GrantedAudience; the issued JWT's aud must contain
// only the exchange's audience.
func TestSpec_2_1_CustomJWT_AudienceReplacesSessionAudience(t *testing.T) {
	cfg := newSpecConfig(t)

	// Session has a leftover audience from a prior OIDC flow.
	session := &DefaultSession{
		DefaultSession: &openid.DefaultSession{
			Claims: &jwt.IDTokenClaims{
				Subject:  "alice",
				Audience: []string{"https://leftover.example/"},
			},
			Headers: &jwt.Headers{},
			Subject: "alice",
		},
		Extra: map[string]any{},
	}

	store := storage.NewExampleStore()
	jwtStrategy := &jwt.DefaultStrategy{Config: cfg, Issuer: jwt.NewDefaultIssuerRS256Unverified(key)}
	cjt := &CustomJWTTypeHandler{Config: cfg, Strategy: jwtStrategy, Storage: store}

	req := &oauth2.AccessRequest{
		GrantTypes: oauth2.Arguments{consts.GrantTypeOAuthTokenExchange},
		Request: oauth2.Request{
			ID:              uuid.New().String(),
			Client:          store.Clients["my-client"],
			Session:         session,
			GrantedAudience: oauth2.Arguments{"https://exchange-target.example/"},
			Form: url.Values{
				consts.FormParameterGrantType:          {consts.GrantTypeOAuthTokenExchange},
				consts.FormParameterRequestedTokenType: {"urn:spec:jwt"},
				consts.FormParameterSubjectToken:       {"opaque-subject-token"},
				consts.FormParameterSubjectTokenType:   {consts.TokenTypeRFC8693AccessToken},
			},
		},
	}

	resp := oauth2.NewAccessResponse()
	require.NoError(t, cjt.PopulateTokenEndpointResponse(context.Background(), req, resp))

	var rawClaims map[string]any
	_, err := jwt.UnsafeParseSignedAny(resp.AccessToken, &rawClaims)
	require.NoError(t, err)

	aud, ok := rawClaims[consts.ClaimAudience]
	require.True(t, ok, "issued JWT must have an 'aud' claim")
	assert.Equal(t, []any{"https://exchange-target.example/"}, aud,
		"RFC 8693 §2.1: issued aud must reflect the exchange's audience/resource only, not session-derived audiences")
}

// §4.1: The 'act' claim MUST appear in the issued JWT body, not just in internal session state. This test runs a
// full delegation exchange that produces a custom JWT (which is encoded from session.IDTokenClaims), decodes the
// resulting token, and confirms the 'act' claim is at the top level of the JWT's claims map.
func TestSpec_4_1_ActClaim_AppearsInIssuedCustomJWT(t *testing.T) {
	cfg := newSpecConfig(t)
	session := newSpecSession("alice")

	// Seed session with an actor_token as the type handlers would have done during HandleTokenEndpointRequest.
	// This avoids needing to construct a second valid access token just to drive the actor-token validate() path.
	session.SetActorToken(map[string]any{
		consts.ClaimSubject:          "bob",
		consts.ClaimClientIdentifier: "client-bob",
	})

	resp := runCustomJWTExchange(t, cfg, session)

	require.NotEmpty(t, resp.AccessToken, "exchange must produce a custom JWT in access_token")

	// Decode the issued JWT and confirm the 'act' claim is present at the top level.
	var rawClaims map[string]any
	_, err := jwt.UnsafeParseSignedAny(resp.AccessToken, &rawClaims)
	require.NoError(t, err, "issued JWT must be parseable")

	act, ok := rawClaims[consts.ClaimActor].(map[string]any)
	require.True(t, ok, "RFC 8693 §4.1: issued JWT MUST contain the 'act' claim when delegation occurs")
	assert.Equal(t, "bob", act[consts.ClaimSubject], "act.sub must come from the actor_token")
	assert.Equal(t, "client-bob", act[consts.ClaimClientIdentifier], "act.client_id must come from the actor_token when present")
}

// =============================================================================
// §2.2 — Successful Response
//
// REQUIRED:  access_token, issued_token_type, token_type
// REQUIRED conditionally:  scope (when issued differs from requested)
// RECOMMENDED:  expires_in
// =============================================================================

// §2.2: access-token response carries access_token, token_type=Bearer, expires_in, scope, issued_token_type.
func TestSpec_2_2_ResponseShape_AccessToken(t *testing.T) {
	resp := runTokenExchange(t, consts.TokenTypeRFC8693AccessToken)

	assert.NotEmpty(t, resp.AccessToken, "REQUIRED: access_token")
	assert.Equal(t, oauth2.BearerAccessToken, resp.TokenType, "REQUIRED: token_type for OAuth access tokens MUST be 'Bearer'")
	assert.NotNil(t, resp.GetExtra(consts.AccessResponseExpiresIn), "RECOMMENDED: expires_in")
	assert.NotNil(t, resp.GetExtra(consts.AccessResponseScope), "REQUIRED when scope differs from requested: scope (and AS sets unconditionally)")
	assert.Equal(t, consts.TokenTypeRFC8693AccessToken, resp.GetExtra(consts.FormParameterIssuedTokenType), "REQUIRED: issued_token_type")
}

// §2.2: refresh-token response carries access_token (carrying the refresh token), token_type=N_A, expires_in, scope, issued_token_type.
func TestSpec_2_2_ResponseShape_RefreshToken(t *testing.T) {
	resp := runTokenExchange(t, consts.TokenTypeRFC8693RefreshToken)

	assert.NotEmpty(t, resp.AccessToken, "REQUIRED: access_token (refresh token value placed here)")
	assert.Equal(t, oauth2.RFC8693NAToken, resp.TokenType, "REQUIRED: token_type for non-OAuth tokens MUST be 'N_A'")
	assert.NotNil(t, resp.GetExtra(consts.AccessResponseExpiresIn), "RECOMMENDED: expires_in")
	assert.NotNil(t, resp.GetExtra(consts.AccessResponseScope), "REQUIRED when scope differs from requested: scope")
	assert.Equal(t, consts.TokenTypeRFC8693RefreshToken, resp.GetExtra(consts.FormParameterIssuedTokenType), "REQUIRED: issued_token_type")
}

// §2.2: id-token response carries access_token (carrying the id token), token_type=N_A, expires_in, scope, issued_token_type.
func TestSpec_2_2_ResponseShape_IDToken(t *testing.T) {
	resp := runTokenExchange(t, consts.TokenTypeRFC8693IDToken)

	assert.NotEmpty(t, resp.AccessToken, "REQUIRED: access_token (id token value placed here)")
	assert.Equal(t, oauth2.RFC8693NAToken, resp.TokenType, "REQUIRED: token_type for non-OAuth tokens MUST be 'N_A'")
	assert.NotNil(t, resp.GetExtra(consts.AccessResponseExpiresIn), "RECOMMENDED: expires_in")
	assert.NotNil(t, resp.GetExtra(consts.AccessResponseScope), "REQUIRED when scope differs from requested: scope")
	assert.Equal(t, consts.TokenTypeRFC8693IDToken, resp.GetExtra(consts.FormParameterIssuedTokenType), "REQUIRED: issued_token_type")
}

// §2.2: custom-JWT response carries access_token, token_type=N_A, expires_in, scope, issued_token_type set to the
// custom JWT type identifier.
func TestSpec_2_2_ResponseShape_CustomJWT(t *testing.T) {
	resp := runTokenExchange(t, "urn:spec:jwt")

	assert.NotEmpty(t, resp.AccessToken, "REQUIRED: access_token")
	assert.Equal(t, oauth2.RFC8693NAToken, resp.TokenType, "REQUIRED: token_type for non-OAuth tokens MUST be 'N_A'")
	assert.NotNil(t, resp.GetExtra(consts.AccessResponseExpiresIn), "RECOMMENDED: expires_in")
	assert.NotNil(t, resp.GetExtra(consts.AccessResponseScope), "REQUIRED when scope differs from requested: scope")
	assert.Equal(t, "urn:spec:jwt", resp.GetExtra(consts.FormParameterIssuedTokenType), "REQUIRED: issued_token_type")
}

// =============================================================================
// §2.4 — Error Response (uses RFC 6749 §5.2 codes)
//
// The error response uses invalid_grant for grant problems and invalid_target
// for unresolvable audience/resource per RFC 8707 §2.
// =============================================================================

// §5.2 'invalid_grant': self-exchange (client exchanges its own subject token) MUST fail.
func TestSpec_2_4_Errors_SelfExchangeReturnsInvalidGrant(t *testing.T) {
	store := storage.NewExampleStore()
	cfg := newSpecConfig(t)

	coreStrategy := &hoauth2.HMACCoreStrategy{Enigma: &hmac.HMACStrategy{Config: cfg}, Config: cfg}

	handler := &AccessTokenTypeHandler{
		Config:               cfg,
		AccessTokenLifespan:  5 * time.Minute,
		RefreshTokenLifespan: 5 * time.Minute,
		CoreStrategy:         coreStrategy,
		ScopeStrategy:        cfg.ScopeStrategy,
		Storage:              store,
	}

	client := store.Clients["my-client"]
	subjectToken := createAccessToken(context.Background(), coreStrategy, store, client) // same client as the requester

	req := &oauth2.AccessRequest{
		GrantTypes: oauth2.Arguments{consts.GrantTypeOAuthTokenExchange},
		Request: oauth2.Request{
			ID:     uuid.New().String(),
			Client: client,
			Form: url.Values{
				consts.FormParameterGrantType:        {consts.GrantTypeOAuthTokenExchange},
				consts.FormParameterSubjectTokenType: {consts.TokenTypeRFC8693AccessToken},
				consts.FormParameterSubjectToken:     {subjectToken},
			},
			Session: newSpecSession("peter"),
		},
	}

	err := handler.HandleTokenEndpointRequest(context.Background(), req)
	require.Error(t, err)
	assert.ErrorIs(t, err, oauth2.ErrInvalidGrant, "RFC 6749 §5.2: subject token issued to another client MUST yield invalid_grant; self-exchange is the inverse case")
}

// RefreshTokenTypeHandler must refuse to issue a refresh token if the requesting client is not registered for the
// refresh_token grant. AccessTokenTypeHandler silently skips refresh-token issuance in this case; when the client
// EXPLICITLY requests a refresh token via 'requested_token_type', silent downgrade is wrong — refuse with
// unauthorized_client per RFC 6749 §5.2.
func TestSpec_RefreshTokenExchange_RejectsClientWithoutRefreshTokenGrant(t *testing.T) {
	cfg := newSpecConfig(t)
	store := storage.NewExampleStore()
	coreStrategy := &hoauth2.HMACCoreStrategy{Enigma: &hmac.HMACStrategy{Config: cfg}, Config: cfg}

	handler := &RefreshTokenTypeHandler{
		Config:               cfg,
		RefreshTokenLifespan: 5 * time.Minute,
		CoreStrategy:         coreStrategy,
		ScopeStrategy:        cfg.ScopeStrategy,
		Storage:              store,
	}

	clientWithoutRefresh := &oauth2.DefaultClient{
		ID:           "no-refresh-client",
		ClientSecret: oauth2.NewPlainTextClientSecret("secret"),
		GrantTypes:   []string{consts.GrantTypeOAuthTokenExchange}, // no refresh_token
		Scopes:       []string{"openid"},
	}

	req := &oauth2.AccessRequest{
		GrantTypes: oauth2.Arguments{consts.GrantTypeOAuthTokenExchange},
		Request: oauth2.Request{
			ID:     uuid.New().String(),
			Client: clientWithoutRefresh,
			Form: url.Values{
				consts.FormParameterGrantType:          {consts.GrantTypeOAuthTokenExchange},
				consts.FormParameterRequestedTokenType: {consts.TokenTypeRFC8693RefreshToken},
				consts.FormParameterSubjectTokenType:   {consts.TokenTypeRFC8693AccessToken},
				consts.FormParameterSubjectToken:       {"opaque-subject-token"},
			},
			Session: newSpecSession("alice"),
		},
	}

	err := handler.PopulateTokenEndpointResponse(context.Background(), req, oauth2.NewAccessResponse())
	require.Error(t, err)
	assert.ErrorIs(t, err, oauth2.ErrUnauthorizedClient)
}

// RefreshTokenTypeHandler must refuse when configured RefreshTokenScopes are not granted to the session, matching
// the AccessTokenTypeHandler policy but surfaced as an explicit error (rather than a silent skip) because the
// client is requesting THIS token type by name.
func TestSpec_RefreshTokenExchange_RejectsWhenRefreshScopeNotGranted(t *testing.T) {
	cfg := newSpecConfig(t)
	store := storage.NewExampleStore()
	coreStrategy := &hoauth2.HMACCoreStrategy{Enigma: &hmac.HMACStrategy{Config: cfg}, Config: cfg}

	handler := &RefreshTokenTypeHandler{
		Config:               cfg,
		RefreshTokenLifespan: 5 * time.Minute,
		RefreshTokenScopes:   []string{"offline_access"},
		CoreStrategy:         coreStrategy,
		ScopeStrategy:        cfg.ScopeStrategy,
		Storage:              store,
	}

	req := &oauth2.AccessRequest{
		GrantTypes: oauth2.Arguments{consts.GrantTypeOAuthTokenExchange},
		Request: oauth2.Request{
			ID:     uuid.New().String(),
			Client: newConfidentialClientWithRefresh(),
			// No granted scopes — RefreshTokenScopes requirement not satisfied.
			Form: url.Values{
				consts.FormParameterGrantType:          {consts.GrantTypeOAuthTokenExchange},
				consts.FormParameterRequestedTokenType: {consts.TokenTypeRFC8693RefreshToken},
				consts.FormParameterSubjectTokenType:   {consts.TokenTypeRFC8693AccessToken},
				consts.FormParameterSubjectToken:       {"opaque-subject-token"},
			},
			Session: newSpecSession("alice"),
		},
	}

	err := handler.PopulateTokenEndpointResponse(context.Background(), req, oauth2.NewAccessResponse())
	require.Error(t, err)
	assert.ErrorIs(t, err, oauth2.ErrInvalidScope)
}

// §1.1: custom-JWT issuance with no session subject must fail loudly rather than silently substitute the requesting
// client's id as the JWT's 'sub' claim. The subject of the issued token represents the user whose authority is
// being exercised, not the requester.
func TestSpec_2_4_Errors_CustomJWTNoSubjectReturnsServerError(t *testing.T) {
	cfg := newSpecConfig(t)
	store := storage.NewExampleStore()
	jwtStrategy := &jwt.DefaultStrategy{Config: cfg, Issuer: jwt.NewDefaultIssuerRS256Unverified(key)}

	cjt := &CustomJWTTypeHandler{Config: cfg, Strategy: jwtStrategy, Storage: store}

	// Session intentionally has no subject populated — simulates a misconfigured upstream where the subject_token
	// resolution didn't write the subject onto the session.
	session := &DefaultSession{
		DefaultSession: &openid.DefaultSession{Claims: &jwt.IDTokenClaims{}, Headers: &jwt.Headers{}},
		Extra:          map[string]any{},
	}

	req := &oauth2.AccessRequest{
		GrantTypes: oauth2.Arguments{consts.GrantTypeOAuthTokenExchange},
		Request: oauth2.Request{
			ID:     uuid.New().String(),
			Client: store.Clients["my-client"],
			Form: url.Values{
				consts.FormParameterGrantType:          {consts.GrantTypeOAuthTokenExchange},
				consts.FormParameterRequestedTokenType: {"urn:spec:jwt"},
				consts.FormParameterSubjectToken:       {"opaque-subject-token"},
				consts.FormParameterSubjectTokenType:   {consts.TokenTypeRFC8693AccessToken},
			},
			Session: session,
		},
	}

	err := cjt.PopulateTokenEndpointResponse(context.Background(), req, oauth2.NewAccessResponse())
	require.Error(t, err)
	assert.ErrorIs(t, err, oauth2.ErrServerError, "AS MUST NOT silently substitute requester id as the subject of the issued JWT")
}

// §5.2 'invalid_target' (RFC 8707): custom-JWT issuance with no audience source must fail loudly rather than
// silently fall back to the requesting client's id.
func TestSpec_2_4_Errors_CustomJWTUndeterminableAudienceReturnsInvalidTarget(t *testing.T) {
	store := storage.NewExampleStore()
	cfg := newSpecConfig(t)

	// Replace the registered JWT type with one that has NO default audience.
	cfg.RFC8693TokenTypes["urn:spec:jwt"] = &JWTType{
		Name:           "urn:spec:jwt",
		Issuer:         "https://as.example.com",
		JWTIssueConfig: JWTIssueConfig{Expiry: 5 * time.Minute}, // <— no Audience
		JWTValidationConfig: JWTValidationConfig{
			ValidateFunc: jwt.Keyfunc(func(_ *jwt.Token) (any, error) { return key.PublicKey, nil }),
		},
	}

	coreStrategy := &hoauth2.HMACCoreStrategy{Enigma: &hmac.HMACStrategy{Config: cfg}, Config: cfg}
	jwtStrategy := &jwt.DefaultStrategy{Config: cfg, Issuer: jwt.NewDefaultIssuerRS256Unverified(key)}

	cjt := &CustomJWTTypeHandler{Config: cfg, Strategy: jwtStrategy, Storage: store}

	req := &oauth2.AccessRequest{
		GrantTypes: oauth2.Arguments{consts.GrantTypeOAuthTokenExchange},
		Request: oauth2.Request{
			ID:     uuid.New().String(),
			Client: store.Clients["my-client"],
			Form: url.Values{
				consts.FormParameterGrantType:          {consts.GrantTypeOAuthTokenExchange},
				consts.FormParameterRequestedTokenType: {"urn:spec:jwt"},
				consts.FormParameterSubjectTokenType:   {consts.TokenTypeRFC8693AccessToken},
				consts.FormParameterSubjectToken:       {createAccessToken(context.Background(), coreStrategy, store, store.Clients["custom-lifespan-client"])},
			},
			Session: newSpecSession("peter"),
		},
	}

	// Note: the access-token type handler must run first to populate session.SubjectToken; we then drive the
	// custom-JWT issuance directly to exercise the audience-rejection path.
	access := &AccessTokenTypeHandler{
		Config:               cfg,
		AccessTokenLifespan:  5 * time.Minute,
		RefreshTokenLifespan: 5 * time.Minute,
		CoreStrategy:         coreStrategy,
		ScopeStrategy:        cfg.ScopeStrategy,
		Storage:              store,
	}

	require.NoError(t, access.HandleTokenEndpointRequest(context.Background(), req))

	err := cjt.PopulateTokenEndpointResponse(context.Background(), req, oauth2.NewAccessResponse())
	require.Error(t, err)
	assert.ErrorIs(t, err, oauth2.ErrInvalidTarget, "RFC 8707 §2: AS MUST NOT silently substitute requester id when audience is undeterminable")
}

// §5.2 'invalid_grant': public clients MUST NOT be permitted to use the token exchange grant (token exchange
// requires client authentication per §4.4).
func TestSpec_2_4_Errors_PublicClientReturnsInvalidGrant(t *testing.T) {
	cfg := newSpecConfig(t)
	session := newSpecSession("alice")

	publicClient := &oauth2.DefaultClient{
		ID:         "public-client",
		Public:     true,
		GrantTypes: []string{consts.GrantTypeOAuthTokenExchange},
		Scopes:     []string{"openid"},
	}

	err := runGrantHandler(t, cfg, newSpecRequest(t, publicClient, session, nil))
	require.Error(t, err)
	assert.ErrorIs(t, err, oauth2.ErrInvalidGrant)
}

// §2.1: a client without the token-exchange grant_type registered MUST be rejected with unauthorized_client.
func TestSpec_2_1_Errors_ClientWithoutGrantReturnsUnauthorizedClient(t *testing.T) {
	cfg := newSpecConfig(t)
	session := newSpecSession("alice")

	noGrantClient := &oauth2.DefaultClient{
		ID:           "no-grant-client",
		ClientSecret: oauth2.NewPlainTextClientSecret("secret"),
		GrantTypes:   []string{consts.GrantTypeAuthorizationCode}, // <— missing token-exchange
		Scopes:       []string{"openid"},
	}

	err := runGrantHandler(t, cfg, newSpecRequest(t, noGrantClient, session, nil))
	require.Error(t, err)
	assert.ErrorIs(t, err, oauth2.ErrUnauthorizedClient)
}

// =============================================================================
// Test helpers
// =============================================================================

// newSpecConfig builds a Config that registers all four spec token types plus a custom JWT type at "urn:spec:jwt".
// Tests can mutate the returned config to remove a type or tweak defaults.
func newSpecConfig(t *testing.T) *oauth2.Config {
	t.Helper()

	return &oauth2.Config{
		ScopeStrategy:    oauth2.HierarchicScopeStrategy,
		AudienceStrategy: oauth2.DefaultAudienceStrategy,
		GlobalSecret:     []byte("some-secret-thats-random-some-secret-thats-random-"),
		IDTokenLifespan:  10 * time.Minute,
		RFC8693TokenTypes: map[string]oauth2.RFC8693TokenType{
			consts.TokenTypeRFC8693AccessToken:  &DefaultTokenType{Name: consts.TokenTypeRFC8693AccessToken},
			consts.TokenTypeRFC8693RefreshToken: &DefaultTokenType{Name: consts.TokenTypeRFC8693RefreshToken},
			consts.TokenTypeRFC8693IDToken:      &DefaultTokenType{Name: consts.TokenTypeRFC8693IDToken},
			"urn:spec:jwt": &JWTType{
				Name:           "urn:spec:jwt",
				Issuer:         "https://as.example.com",
				JWTIssueConfig: JWTIssueConfig{Audience: []string{"https://api.example.com"}, Expiry: 5 * time.Minute},
				JWTValidationConfig: JWTValidationConfig{
					ValidateFunc: jwt.Keyfunc(func(_ *jwt.Token) (any, error) { return key.PublicKey, nil }),
				},
			},
		},
		DefaultRequestedTokenType: consts.TokenTypeRFC8693AccessToken,
	}
}

// newSpecSession returns a DefaultSession seeded with a subject so the openid.DefaultSession invariants hold.
func newSpecSession(subject string) *DefaultSession {
	return &DefaultSession{
		DefaultSession: &openid.DefaultSession{
			Claims:  &jwt.IDTokenClaims{Subject: subject},
			Headers: &jwt.Headers{},
			Subject: subject,
		},
		Extra: map[string]any{},
	}
}

// newSpecRequest produces a baseline RFC 8693 access request with grant_type and the minimum required form params.
func newSpecRequest(t *testing.T, client oauth2.Client, session *DefaultSession, form url.Values) *oauth2.AccessRequest {
	t.Helper()

	merged := url.Values{
		consts.FormParameterGrantType:        {consts.GrantTypeOAuthTokenExchange},
		consts.FormParameterSubjectToken:     {"opaque-subject-token"},
		consts.FormParameterSubjectTokenType: {consts.TokenTypeRFC8693AccessToken},
	}

	for k, vs := range form {
		merged[k] = vs
	}

	return &oauth2.AccessRequest{
		GrantTypes: oauth2.Arguments{consts.GrantTypeOAuthTokenExchange},
		Request: oauth2.Request{
			ID:      uuid.New().String(),
			Client:  client,
			Form:    merged,
			Session: session,
		},
	}
}

// runGrantHandler runs the TokenExchangeGrantHandler over the request, returning the first error encountered. It
// short-circuits on the HandleTokenEndpointRequest phase to keep tests focused on the grant-handler's contribution
// (the act-claim derivation in PopulateTokenEndpointResponse).
func runGrantHandler(t *testing.T, cfg *oauth2.Config, req *oauth2.AccessRequest) error {
	t.Helper()

	h := &TokenExchangeGrantHandler{
		Config:           cfg,
		ScopeStrategy:    cfg.ScopeStrategy,
		AudienceStrategy: cfg.AudienceStrategy,
		ResourceStrategy: cfg.GetResourceStrategy(context.Background()),
	}

	if err := h.HandleTokenEndpointRequest(context.Background(), req); err != nil {
		return err
	}

	return h.PopulateTokenEndpointResponse(context.Background(), req, oauth2.NewAccessResponse())
}

// runTokenExchange runs the full handler chain for a request that exchanges an access token for the requested type
// and returns the resulting AccessResponse.
func runTokenExchange(t *testing.T, requestedType string) *oauth2.AccessResponse {
	t.Helper()

	store := storage.NewExampleStore()
	cfg := newSpecConfig(t)

	coreStrategy := &hoauth2.HMACCoreStrategy{Enigma: &hmac.HMACStrategy{Config: cfg}, Config: cfg}
	jwtStrategy := &jwt.DefaultStrategy{Config: cfg, Issuer: jwt.NewDefaultIssuerRS256Unverified(key)}

	grant := &TokenExchangeGrantHandler{
		Config:           cfg,
		ScopeStrategy:    cfg.ScopeStrategy,
		AudienceStrategy: cfg.AudienceStrategy,
		ResourceStrategy: cfg.GetResourceStrategy(context.Background()),
	}
	access := &AccessTokenTypeHandler{
		Config:               cfg,
		AccessTokenLifespan:  5 * time.Minute,
		RefreshTokenLifespan: 5 * time.Minute,
		CoreStrategy:         coreStrategy,
		ScopeStrategy:        cfg.ScopeStrategy,
		Storage:              store,
	}
	refresh := &RefreshTokenTypeHandler{
		Config:               cfg,
		RefreshTokenLifespan: 5 * time.Minute,
		CoreStrategy:         coreStrategy,
		ScopeStrategy:        cfg.ScopeStrategy,
		Storage:              store,
	}
	idt := &IDTokenTypeHandler{
		Config:        cfg,
		Strategy:      jwtStrategy,
		IssueStrategy: &openid.DefaultStrategy{Strategy: jwtStrategy, Config: cfg},
		// ValidationStrategy is nil — this test exchanges access_token → id_token, so the validate() path
		// (which only runs for id_token-typed inputs) is not exercised.
		Storage: store,
	}
	cjt := &CustomJWTTypeHandler{
		Config:   cfg,
		Strategy: jwtStrategy,
		Storage:  store,
	}

	handlers := []oauth2.TokenEndpointHandler{grant, access, refresh, idt, cjt}

	req := &oauth2.AccessRequest{
		GrantTypes: oauth2.Arguments{consts.GrantTypeOAuthTokenExchange},
		Request: oauth2.Request{
			ID:     uuid.New().String(),
			Client: store.Clients["my-client"],
			Form: url.Values{
				consts.FormParameterGrantType:          {consts.GrantTypeOAuthTokenExchange},
				consts.FormParameterSubjectTokenType:   {consts.TokenTypeRFC8693AccessToken},
				consts.FormParameterSubjectToken:       {createAccessToken(context.Background(), coreStrategy, store, store.Clients["custom-lifespan-client"])},
				consts.FormParameterRequestedTokenType: {requestedType},
			},
			Session: newSpecSession("peter"),
		},
	}

	ctx := context.Background()
	resp := oauth2.NewAccessResponse()

	for _, h := range handlers {
		if !h.CanHandleTokenEndpointRequest(ctx, req) {
			continue
		}

		if err := h.HandleTokenEndpointRequest(ctx, req); err != nil && !errors.Is(err, oauth2.ErrUnknownRequest) {
			require.NoError(t, err)
		}
	}

	for _, h := range handlers {
		if !h.CanHandleTokenEndpointRequest(ctx, req) {
			continue
		}

		if err := h.PopulateTokenEndpointResponse(ctx, req, resp); err != nil && !errors.Is(err, oauth2.ErrUnknownRequest) {
			require.NoError(t, err)
		}
	}

	return resp
}

// newConfidentialClientWithRefresh returns a confidential client that is allowed both the token-exchange and the
// refresh_token grant types — used in tests that exercise refresh-token-issuance gating.
func newConfidentialClientWithRefresh() *oauth2.DefaultClient {
	return &oauth2.DefaultClient{
		ID:           "exchange-refresh-client",
		ClientSecret: oauth2.NewPlainTextClientSecret("secret"),
		GrantTypes:   []string{consts.GrantTypeOAuthTokenExchange, consts.GrantTypeRefreshToken},
		Scopes:       []string{"openid", "offline_access"},
	}
}

// runCustomJWTExchange drives a token-exchange request that issues a custom JWT, with the session pre-seeded by the
// caller (notably with an actor_token map to exercise the delegation path). The custom-JWT handler is registered
// after the grant handler so the act claim set by the grant handler is in place before issuance runs.
func runCustomJWTExchange(t *testing.T, cfg *oauth2.Config, session *DefaultSession) *oauth2.AccessResponse {
	t.Helper()

	store := storage.NewExampleStore()
	jwtStrategy := &jwt.DefaultStrategy{Config: cfg, Issuer: jwt.NewDefaultIssuerRS256Unverified(key)}

	grant := &TokenExchangeGrantHandler{
		Config:           cfg,
		ScopeStrategy:    cfg.ScopeStrategy,
		AudienceStrategy: cfg.AudienceStrategy,
		ResourceStrategy: cfg.GetResourceStrategy(context.Background()),
	}
	cjt := &CustomJWTTypeHandler{
		Config:   cfg,
		Strategy: jwtStrategy,
		Storage:  store,
	}

	req := &oauth2.AccessRequest{
		GrantTypes: oauth2.Arguments{consts.GrantTypeOAuthTokenExchange},
		Request: oauth2.Request{
			ID:     uuid.New().String(),
			Client: store.Clients["my-client"],
			Form: url.Values{
				consts.FormParameterGrantType:          {consts.GrantTypeOAuthTokenExchange},
				consts.FormParameterSubjectToken:       {"opaque-subject-token"},
				consts.FormParameterSubjectTokenType:   {consts.TokenTypeRFC8693AccessToken},
				consts.FormParameterRequestedTokenType: {"urn:spec:jwt"},
			},
			Session: session,
		},
	}

	ctx := context.Background()
	resp := oauth2.NewAccessResponse()

	require.NoError(t, grant.HandleTokenEndpointRequest(ctx, req))
	require.NoError(t, grant.PopulateTokenEndpointResponse(ctx, req, resp))
	require.NoError(t, cjt.PopulateTokenEndpointResponse(ctx, req, resp))

	return resp
}
