// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

// Package rfc8693_test is a spec compliance test suite. Each test name carries the RFC 8693 § reference it covers.
//
// See: https://datatracker.ietf.org/doc/html/rfc8693
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
	"authelia.com/provider/oauth2/handler/rfc9449"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/token/hmac"
	"authelia.com/provider/oauth2/token/jwt"
)

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
func TestSpec_4_1_ActClaim_ChainsDelegationViaNestedAct(t *testing.T) {
	cfg := newSpecConfig(t)
	session := newSpecSession("alice")

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

	assert.Equal(t, map[string]any{consts.ClaimSubject: "carol"}, priorAct,
		"buildActClaim must not mutate the subject_token's act map (deep-copy required)")

	act := session.Extra[consts.ClaimActor].(map[string]any)
	nested := act[consts.ClaimActor].(map[string]any)
	nested["injected"] = true
	assert.NotContains(t, priorAct, "injected", "mutating the issued nested 'act' must not leak into the subject_token's act map")
}

// §4.1 and §2.2.2: an actor_token that does not identify the actor is unacceptable, as the issued token could not
// express the delegation.
func TestSpec_4_1_ActClaim_ActorTokenWithoutIdentity(t *testing.T) {
	testCases := []struct {
		name    string
		actor   map[string]any
		subject map[string]any
	}{
		{
			name:  "ShouldRejectAnActorTokenWithUnknownClaims",
			actor: map[string]any{"unknown_claim": "value"},
		},
		{
			name:  "ShouldRejectAnActorTokenWithOnlyAnIssuer",
			actor: map[string]any{consts.ClaimIssuer: "https://actor.example.com"},
		},
		{
			name:  "ShouldRejectAnEmptyActorToken",
			actor: map[string]any{},
		},
		{
			name:  "ShouldRejectAnActorTokenWithEmptyIdentifiers",
			actor: map[string]any{consts.ClaimSubject: "", consts.ClaimClientIdentifier: ""},
		},
		{
			name:  "ShouldRejectAnActorTokenWhenTheSubjectTokenHasAPriorActor",
			actor: map[string]any{consts.ClaimIssuer: "https://service77.example.com"},
			subject: map[string]any{
				consts.ClaimSubject: "alice",
				consts.ClaimActor:   map[string]any{consts.ClaimSubject: "carol"},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := newSpecConfig(t)
			session := newSpecSession("alice")

			if tc.subject != nil {
				session.SetSubjectToken(tc.subject)
			}

			session.SetActorToken(tc.actor)

			err := runGrantHandler(t, cfg, newSpecRequest(t, newConfidentialClient(), session, nil))

			require.ErrorIs(t, err, oauth2.ErrInvalidRequest)
			assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The 'actor_token' does not identify the actor as it has neither a 'sub' nor a 'client_id' claim.")

			_, present := session.Extra[consts.ClaimActor]
			assert.False(t, present)
		})
	}
}

// §2.1: the issued JWT's 'aud' MUST reflect this exchange's audience/resource parameters.
func TestSpec_2_1_CustomJWT_AudienceReplacesSessionAudience(t *testing.T) {
	cfg := newSpecConfig(t)

	session := &DefaultSession{
		DefaultSession: &openid.DefaultSession{
			Claims: &jwt.IDTokenClaims{
				Subject:  "alice",
				Audience: []string{"https://leftover.example/"},
			},
			Headers: &jwt.Headers{},
			Subject: "alice",
		},
		SubjectToken: map[string]any{consts.ClaimSubject: "alice"},
		Extra:        map[string]any{},
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

// §4.1: the 'act' claim MUST appear in the issued JWT body.
func TestSpec_4_1_ActClaim_AppearsInIssuedCustomJWT(t *testing.T) {
	cfg := newSpecConfig(t)
	session := newSpecSession("alice")

	session.SetActorToken(map[string]any{
		consts.ClaimSubject:          "bob",
		consts.ClaimClientIdentifier: "client-bob",
	})

	resp := runCustomJWTExchange(t, cfg, session)

	require.NotEmpty(t, resp.AccessToken, "exchange must produce a custom JWT in access_token")

	var rawClaims map[string]any
	_, err := jwt.UnsafeParseSignedAny(resp.AccessToken, &rawClaims)
	require.NoError(t, err, "issued JWT must be parseable")

	act, ok := rawClaims[consts.ClaimActor].(map[string]any)
	require.True(t, ok, "RFC 8693 §4.1: issued JWT MUST contain the 'act' claim when delegation occurs")
	assert.Equal(t, "bob", act[consts.ClaimSubject], "act.sub must come from the actor_token")
	assert.Equal(t, "client-bob", act[consts.ClaimClientIdentifier], "act.client_id must come from the actor_token when present")
}

// §2.2: access-token response carries access_token, token_type=Bearer, expires_in, scope, issued_token_type.
func TestSpec_2_2_ResponseShape_AccessToken(t *testing.T) {
	resp := runTokenExchange(t, consts.TokenTypeRFC8693AccessToken)

	assert.NotEmpty(t, resp.AccessToken, "REQUIRED: access_token")
	assert.Equal(t, oauth2.BearerAccessToken, resp.TokenType, "REQUIRED: token_type for OAuth access tokens MUST be 'Bearer'")
	assert.NotNil(t, resp.GetExtra(consts.AccessResponseExpiresIn), "RECOMMENDED: expires_in")
	assert.NotNil(t, resp.GetExtra(consts.AccessResponseScope), "REQUIRED when scope differs from requested: scope (and AS sets unconditionally)")
	assert.Equal(t, consts.TokenTypeRFC8693AccessToken, resp.GetExtra(consts.FormParameterIssuedTokenType), "REQUIRED: issued_token_type")
}

// §2.2.1: a DPoP bound exchange keeps token_type 'N_A' for an issued token that is not an access token.
func TestSpec_2_2_1_TokenType_DPoPBoundExchange(t *testing.T) {
	testCases := []struct {
		name      string
		requested string
		expected  string
	}{
		{name: "ShouldRelabelAnAccessToken", requested: consts.TokenTypeRFC8693AccessToken, expected: oauth2.DPoPAccessToken},
		{name: "ShouldKeepNotApplicableForARefreshToken", requested: consts.TokenTypeRFC8693RefreshToken, expected: oauth2.RFC8693NAToken},
		{name: "ShouldKeepNotApplicableForAnIDToken", requested: consts.TokenTypeRFC8693IDToken, expected: oauth2.RFC8693NAToken},
		{name: "ShouldKeepNotApplicableForACustomJWT", requested: "urn:spec:jwt", expected: oauth2.RFC8693NAToken},
	}

	binder := &rfc9449.Handler{Config: &oauth2.Config{DPoPEnabled: true}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			resp := runTokenExchange(t, tc.requested)

			session := newSpecSession("peter")
			session.SetDPoPJWKThumbprint("some-thumbprint")

			require.NoError(t, binder.PopulateBoundTokenEndpointResponse(t.Context(), oauth2.NewAccessRequest(session), resp))
			assert.Equal(t, tc.expected, resp.GetTokenType())
		})
	}
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
	subjectToken := createAccessToken(context.Background(), coreStrategy, store, client)

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

// RFC 6749 §5.2 'unauthorized_client': a refresh token is refused for a client not registered for the refresh_token grant.
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
		GrantTypes:   []string{consts.GrantTypeOAuthTokenExchange},
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
				consts.FormParameterSubjectTokenType:   {consts.TokenTypeRFC8693RefreshToken},
				consts.FormParameterSubjectToken:       {"opaque-subject-token"},
			},
			Session: newValidatedSpecSession("alice"),
		},
	}

	err := handler.PopulateTokenEndpointResponse(context.Background(), req, oauth2.NewAccessResponse())
	require.Error(t, err)
	assert.ErrorIs(t, err, oauth2.ErrUnauthorizedClient)
}

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
			Form: url.Values{
				consts.FormParameterGrantType:          {consts.GrantTypeOAuthTokenExchange},
				consts.FormParameterRequestedTokenType: {consts.TokenTypeRFC8693RefreshToken},
				consts.FormParameterSubjectTokenType:   {consts.TokenTypeRFC8693RefreshToken},
				consts.FormParameterSubjectToken:       {"opaque-subject-token"},
			},
			Session: newValidatedSpecSession("alice"),
		},
	}

	err := handler.PopulateTokenEndpointResponse(context.Background(), req, oauth2.NewAccessResponse())
	require.Error(t, err)
	assert.ErrorIs(t, err, oauth2.ErrInvalidScope)
}

// §1.1: custom-JWT issuance with no session subject must fail.
func TestSpec_2_4_Errors_CustomJWTNoSubjectReturnsServerError(t *testing.T) {
	cfg := newSpecConfig(t)
	store := storage.NewExampleStore()
	jwtStrategy := &jwt.DefaultStrategy{Config: cfg, Issuer: jwt.NewDefaultIssuerRS256Unverified(key)}

	cjt := &CustomJWTTypeHandler{Config: cfg, Strategy: jwtStrategy, Storage: store}

	session := &DefaultSession{
		DefaultSession: &openid.DefaultSession{Claims: &jwt.IDTokenClaims{}, Headers: &jwt.Headers{}},
		SubjectToken:   map[string]any{},
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

// §5.2 'invalid_target' (RFC 8707): custom-JWT issuance with no audience source must fail.
func TestSpec_2_4_Errors_CustomJWTUndeterminableAudienceReturnsInvalidTarget(t *testing.T) {
	store := storage.NewExampleStore()
	cfg := newSpecConfig(t)

	cfg.RFC8693TokenTypes["urn:spec:jwt"] = &JWTType{
		Name:           "urn:spec:jwt",
		Issuer:         "https://as.example.com",
		JWTIssueConfig: JWTIssueConfig{Expiry: 5 * time.Minute},
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
		GrantTypes:   []string{consts.GrantTypeAuthorizationCode},
		Scopes:       []string{"openid"},
	}

	err := runGrantHandler(t, cfg, newSpecRequest(t, noGrantClient, session, nil))
	require.Error(t, err)
	assert.ErrorIs(t, err, oauth2.ErrUnauthorizedClient)
}

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

func newValidatedSpecSession(subject string) *DefaultSession {
	session := newSpecSession(subject)
	session.SetSubjectToken(map[string]any{consts.ClaimSubject: subject})

	return session
}

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

func runGrantHandler(t *testing.T, cfg *oauth2.Config, req *oauth2.AccessRequest) error {
	t.Helper()

	h := &TokenExchangeGrantHandler{
		Config:           cfg,
		ScopeStrategy:    cfg.ScopeStrategy,
		AudienceStrategy: cfg.AudienceStrategy,
		ResourceStrategy: cfg.GetResourceStrategy(context.Background()),
	}

	session, _ := req.GetSession().(Session)

	var subjectToken, actorToken map[string]any

	if session != nil {
		subjectToken = session.GetSubjectToken()
		actorToken = session.GetActorToken()
	}

	if err := h.HandleTokenEndpointRequest(context.Background(), req); err != nil {
		return err
	}

	if subjectToken != nil {
		session.SetSubjectToken(subjectToken)
	}

	if actorToken != nil {
		session.SetActorToken(actorToken)
	}

	return h.PopulateTokenEndpointResponse(context.Background(), req, oauth2.NewAccessResponse())
}

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
		Storage:       store,
	}

	cjt := &CustomJWTTypeHandler{
		Config:   cfg,
		Strategy: jwtStrategy,
		Storage:  store,
	}

	handlers := []oauth2.TokenEndpointHandler{grant, access, refresh, idt, cjt}

	subjectTokenType, subjectToken := consts.TokenTypeRFC8693AccessToken, createAccessToken(context.Background(), coreStrategy, store, store.Clients["custom-lifespan-client"])

	// RFC 8693 Section 2.2.1: a refresh token is only issued in exchange for a refresh token. An ID Token is only issued
	// in exchange for an ID Token or a refresh token.
	if requestedType == consts.TokenTypeRFC8693RefreshToken || requestedType == consts.TokenTypeRFC8693IDToken {
		subjectTokenType, subjectToken = consts.TokenTypeRFC8693RefreshToken, createSessionRefreshToken(context.Background(), coreStrategy, &exchangeMemoryStore{store}, store.Clients["custom-lifespan-client"], time.Now().UTC().Add(10*time.Minute))
	}

	req := &oauth2.AccessRequest{
		GrantTypes: oauth2.Arguments{consts.GrantTypeOAuthTokenExchange},
		Request: oauth2.Request{
			ID:     uuid.New().String(),
			Client: store.Clients["my-client"],
			Form: url.Values{
				consts.FormParameterGrantType:          {consts.GrantTypeOAuthTokenExchange},
				consts.FormParameterSubjectTokenType:   {subjectTokenType},
				consts.FormParameterSubjectToken:       {subjectToken},
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

func newConfidentialClientWithRefresh() *oauth2.DefaultClient {
	return &oauth2.DefaultClient{
		ID:           "exchange-refresh-client",
		ClientSecret: oauth2.NewPlainTextClientSecret("secret"),
		GrantTypes:   []string{consts.GrantTypeOAuthTokenExchange, consts.GrantTypeRefreshToken},
		Scopes:       []string{"openid", "offline_access"},
	}
}

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

	subjectToken, actorToken := session.GetSubjectToken(), session.GetActorToken()

	require.NoError(t, grant.HandleTokenEndpointRequest(ctx, req))

	if subjectToken == nil {
		subjectToken = map[string]any{consts.ClaimSubject: session.GetSubject()}
	}

	session.SetSubjectToken(subjectToken)
	session.SetActorToken(actorToken)

	require.NoError(t, grant.PopulateTokenEndpointResponse(ctx, req, resp))
	require.NoError(t, cjt.PopulateTokenEndpointResponse(ctx, req, resp))

	return resp
}
