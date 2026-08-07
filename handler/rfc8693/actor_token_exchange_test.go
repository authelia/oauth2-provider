// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

// These tests cover the differing treatment of the 'subject_token' and 'actor_token' in the handlers that resolve a
// token back to the request it was issued for: AccessTokenTypeHandler and RefreshTokenTypeHandler.
//
// A subject token issued to the requesting client is a self-exchange and is refused. An actor token issued to the
// requesting client identifies that client as the acting party, which per RFC 8693 §2.1 is the ordinary delegation
// case. Appendix A.2 illustrates it, with an actor token holding no scopes of its own.

package rfc8693_test

import (
	"context"
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	. "authelia.com/provider/oauth2/handler/rfc8693"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/token/hmac"
)

// §2.1: an actor token issued to the requesting client is accepted, unlike a subject token.
func TestSpec_2_1_ActorToken_AccessTokenIssuedToRequestingClientIsAccepted(t *testing.T) {
	cfg, store, strategy := newExchangeFixture(t)

	client := store.Clients["my-client"]
	subjectClient := store.Clients["custom-lifespan-client"]

	session := newSpecSession("")
	req := newExchangeRequest(t, client, session, url.Values{
		consts.FormParameterActorTokenType:   {consts.TokenTypeRFC8693AccessToken},
		consts.FormParameterActorToken:       {createExchangeAccessToken(t, strategy, store, client, "bob")},
		consts.FormParameterSubjectTokenType: {consts.TokenTypeRFC8693AccessToken},
		consts.FormParameterSubjectToken:     {createExchangeAccessToken(t, strategy, store, subjectClient, "alice")},
	})

	require.NoError(t, newAccessTokenTypeHandler(cfg, store, strategy).HandleTokenEndpointRequest(context.Background(), req))

	actor := session.GetActorToken()
	require.NotNil(t, actor)
	assert.Equal(t, client.GetID(), actor[consts.ClaimClientIdentifier])

	subject := session.GetSubjectToken()
	require.NotNil(t, subject)
	assert.Equal(t, subjectClient.GetID(), subject[consts.ClaimClientIdentifier])
}

// §2.1: likewise for a refresh token supplied as the 'actor_token'.
func TestSpec_2_1_ActorToken_RefreshTokenIssuedToRequestingClientIsAccepted(t *testing.T) {
	cfg, store, strategy := newExchangeFixture(t)

	client := store.Clients["my-client"]

	session := newSpecSession("alice")
	req := newExchangeRequest(t, client, session, url.Values{
		consts.FormParameterActorTokenType: {consts.TokenTypeRFC8693RefreshToken},
		consts.FormParameterActorToken:     {createExchangeRefreshToken(t, strategy, store, client, "bob")},
		// An access-token subject token keeps this handler's subject branch out of the test.
		consts.FormParameterSubjectTokenType: {consts.TokenTypeRFC8693AccessToken},
		consts.FormParameterSubjectToken:     {"opaque-subject-token"},
	})

	require.NoError(t, newRefreshTokenTypeHandler(cfg, store, strategy).HandleTokenEndpointRequest(context.Background(), req))

	actor := session.GetActorToken()
	require.NotNil(t, actor)
	assert.Equal(t, client.GetID(), actor[consts.ClaimClientIdentifier])
}

// §5.2 'invalid_grant': self-exchange is still refused for a refresh token supplied as the 'subject_token'.
func TestSpec_2_4_Errors_RefreshTokenSelfSubjectExchangeReturnsInvalidGrant(t *testing.T) {
	cfg, store, strategy := newExchangeFixture(t)

	client := store.Clients["my-client"]

	req := newExchangeRequest(t, client, newSpecSession("alice"), url.Values{
		consts.FormParameterSubjectTokenType: {consts.TokenTypeRFC8693RefreshToken},
		consts.FormParameterSubjectToken:     {createExchangeRefreshToken(t, strategy, store, client, "alice")},
	})

	err := newRefreshTokenTypeHandler(cfg, store, strategy).HandleTokenEndpointRequest(context.Background(), req)
	require.Error(t, err)
	assert.ErrorIs(t, err, oauth2.ErrInvalidGrant)
	assert.Contains(t, oauth2.ErrorToDebugRFC6749Error(err).Error(),
		"Clients are not allowed to perform a token exchange on their own tokens.")
}

// A client's own exchange policy is not consulted for its own actor token, otherwise it would have to list itself
// in its own allow-list to perform delegation.
func TestSpec_2_1_ActorToken_SelfIssuedSkipsExchangePolicy(t *testing.T) {
	cfg, store, strategy := newExchangeFixture(t)

	client := &rfc8693Client{DefaultClient: newConfidentialClient(), exchangePermitted: false}

	session := newSpecSession("alice")
	req := newExchangeRequest(t, client, session, url.Values{
		consts.FormParameterActorTokenType:   {consts.TokenTypeRFC8693AccessToken},
		consts.FormParameterActorToken:       {createExchangeAccessToken(t, strategy, store, client, "bob")},
		consts.FormParameterSubjectTokenType: {consts.TokenTypeRFC8693IDToken},
		consts.FormParameterSubjectToken:     {"opaque-subject-token"},
	})

	require.NoError(t, newAccessTokenTypeHandler(cfg, store, strategy).HandleTokenEndpointRequest(context.Background(), req))
	assert.Equal(t, client.GetID(), session.GetActorToken()[consts.ClaimClientIdentifier])
}

// An actor token issued to another client is still gated by that client's exchange policy.
func TestSpec_2_1_ActorToken_ForeignTokenStillGatedByExchangePolicy(t *testing.T) {
	cfg, store, strategy := newExchangeFixture(t)

	actorClient := &rfc8693Client{
		DefaultClient: &oauth2.DefaultClient{
			ID:         "actor-token-client",
			GrantTypes: []string{consts.GrantTypeOAuthTokenExchange},
			Scopes:     []string{consts.ScopeOpenID},
		},
		exchangePermitted: false,
	}

	req := newExchangeRequest(t, newConfidentialClient(), newSpecSession("alice"), url.Values{
		consts.FormParameterActorTokenType:   {consts.TokenTypeRFC8693AccessToken},
		consts.FormParameterActorToken:       {createExchangeAccessToken(t, strategy, store, actorClient, "bob")},
		consts.FormParameterSubjectTokenType: {consts.TokenTypeRFC8693IDToken},
		consts.FormParameterSubjectToken:     {"opaque-subject-token"},
	})

	err := newAccessTokenTypeHandler(cfg, store, strategy).HandleTokenEndpointRequest(context.Background(), req)
	require.Error(t, err)
	assert.ErrorIs(t, err, oauth2.ErrInvalidGrant)
	assert.Contains(t, oauth2.ErrorToDebugRFC6749Error(err).Error(),
		"The OAuth 2.0 client is not permitted to exchange an actor token issued to client actor-token-client")
}

// So is a subject token issued to another client.
func TestSpec_2_1_SubjectToken_ForeignTokenStillGatedByExchangePolicy(t *testing.T) {
	cfg, store, strategy := newExchangeFixture(t)

	subjectClient := &rfc8693Client{
		DefaultClient: &oauth2.DefaultClient{
			ID:         "subject-token-client",
			GrantTypes: []string{consts.GrantTypeOAuthTokenExchange},
			Scopes:     []string{consts.ScopeOpenID},
		},
		exchangePermitted: false,
	}

	req := newExchangeRequest(t, newConfidentialClient(), newSpecSession("alice"), url.Values{
		consts.FormParameterSubjectTokenType: {consts.TokenTypeRFC8693AccessToken},
		consts.FormParameterSubjectToken:     {createExchangeAccessToken(t, strategy, store, subjectClient, "alice")},
	})

	err := newAccessTokenTypeHandler(cfg, store, strategy).HandleTokenEndpointRequest(context.Background(), req)
	require.Error(t, err)
	assert.ErrorIs(t, err, oauth2.ErrInvalidGrant)
	assert.Contains(t, oauth2.ErrorToDebugRFC6749Error(err).Error(),
		"The OAuth 2.0 client is not permitted to exchange a subject token issued to client subject-token-client")
}

// The actor token's granted scopes do not constrain the requested scopes. The actor token in the Appendix A.2
// delegation example carries no scope at all, yet the issued token carries the subject token's scope in full.
func TestSpec_2_1_ActorToken_GrantedScopesDoNotConstrainRequestedScopes(t *testing.T) {
	cfg, store, strategy := newExchangeFixture(t)

	client := store.Clients["my-client"]
	subjectClient := store.Clients["custom-lifespan-client"]

	req := newExchangeRequest(t, client, newSpecSession("alice"), url.Values{
		consts.FormParameterActorTokenType:   {consts.TokenTypeRFC8693AccessToken},
		consts.FormParameterActorToken:       {createExchangeAccessToken(t, strategy, store, client, "bob")},
		consts.FormParameterSubjectTokenType: {consts.TokenTypeRFC8693AccessToken},
		consts.FormParameterSubjectToken:     {createExchangeAccessToken(t, strategy, store, subjectClient, "alice", "photos")},
	})

	req.RequestedScope = oauth2.Arguments{"photos"}

	require.NoError(t, newAccessTokenTypeHandler(cfg, store, strategy).HandleTokenEndpointRequest(context.Background(), req))
}

// §5.2 'invalid_scope': the subject token's granted scopes still bound the requested scopes.
func TestSpec_2_4_Errors_SubjectTokenMissingRequestedScopeReturnsInvalidScope(t *testing.T) {
	cfg, store, strategy := newExchangeFixture(t)

	subjectClient := store.Clients["custom-lifespan-client"]

	req := newExchangeRequest(t, store.Clients["my-client"], newSpecSession("alice"), url.Values{
		consts.FormParameterSubjectTokenType: {consts.TokenTypeRFC8693AccessToken},
		consts.FormParameterSubjectToken:     {createExchangeAccessToken(t, strategy, store, subjectClient, "alice", consts.ScopeOpenID)},
	})

	req.RequestedScope = oauth2.Arguments{"photos"}

	err := newAccessTokenTypeHandler(cfg, store, strategy).HandleTokenEndpointRequest(context.Background(), req)
	require.Error(t, err)
	assert.ErrorIs(t, err, oauth2.ErrInvalidScope)
}

// =============================================================================
// Test helpers
// =============================================================================

// newExchangeFixture returns a spec config, an example store and the HMAC core strategy wired to that config.
func newExchangeFixture(t *testing.T) (cfg *oauth2.Config, store *storage.MemoryStore, strategy hoauth2.CoreStrategy) {
	t.Helper()

	cfg = newSpecConfig(t)
	store = storage.NewExampleStore()

	return cfg, store, &hoauth2.HMACCoreStrategy{Enigma: &hmac.HMACStrategy{Config: cfg}, Config: cfg}
}

func newAccessTokenTypeHandler(cfg *oauth2.Config, store *storage.MemoryStore, strategy hoauth2.CoreStrategy) *AccessTokenTypeHandler {
	return &AccessTokenTypeHandler{
		Config:               cfg,
		AccessTokenLifespan:  5 * time.Minute,
		RefreshTokenLifespan: 5 * time.Minute,
		CoreStrategy:         strategy,
		ScopeStrategy:        cfg.ScopeStrategy,
		Storage:              store,
	}
}

func newRefreshTokenTypeHandler(cfg *oauth2.Config, store *storage.MemoryStore, strategy hoauth2.CoreStrategy) *RefreshTokenTypeHandler {
	return &RefreshTokenTypeHandler{
		Config:               cfg,
		RefreshTokenLifespan: 5 * time.Minute,
		CoreStrategy:         strategy,
		ScopeStrategy:        cfg.ScopeStrategy,
		Storage:              store,
	}
}

// newExchangeRequest builds a token-exchange AccessRequest whose form is the supplied parameters plus grant_type.
func newExchangeRequest(t *testing.T, client oauth2.Client, session *DefaultSession, form url.Values) *oauth2.AccessRequest {
	t.Helper()

	form.Set(consts.FormParameterGrantType, consts.GrantTypeOAuthTokenExchange)

	return &oauth2.AccessRequest{
		GrantTypes: oauth2.Arguments{consts.GrantTypeOAuthTokenExchange},
		Request: oauth2.Request{
			ID:      uuid.New().String(),
			Client:  client,
			Form:    form,
			Session: session,
		},
	}
}

// createExchangeAccessToken issues and stores an access token for client, with the given subject and granted scopes.
func createExchangeAccessToken(t *testing.T, strategy hoauth2.CoreStrategy, store *storage.MemoryStore, client oauth2.Client, subject string, scopes ...string) string {
	t.Helper()

	ctx := context.Background()
	request := newIssuedRequest(client, subject, scopes, oauth2.AccessToken)

	token, signature, err := strategy.GenerateAccessToken(ctx, request)
	require.NoError(t, err)
	require.NoError(t, store.CreateAccessTokenSession(ctx, signature, request.Sanitize(nil)))

	return token
}

// createExchangeRefreshToken issues and stores a refresh token for client, with the given subject and granted scopes.
func createExchangeRefreshToken(t *testing.T, strategy hoauth2.CoreStrategy, store *storage.MemoryStore, client oauth2.Client, subject string, scopes ...string) string {
	t.Helper()

	ctx := context.Background()
	request := newIssuedRequest(client, subject, scopes, oauth2.RefreshToken)

	token, signature, err := strategy.GenerateRefreshToken(ctx, request)
	require.NoError(t, err)
	require.NoError(t, store.CreateRefreshTokenSession(ctx, signature, "", request.Sanitize(nil)))

	return token
}

func newIssuedRequest(client oauth2.Client, subject string, scopes []string, key oauth2.TokenType) *oauth2.AccessRequest {
	return &oauth2.AccessRequest{
		GrantTypes: oauth2.Arguments{consts.GrantTypeAuthorizationCode},
		Request: oauth2.Request{
			ID:           uuid.New().String(),
			Client:       client,
			GrantedScope: scopes,
			Session: &oauth2.DefaultSession{
				Username: subject,
				Subject:  subject,
				ExpiresAt: map[oauth2.TokenType]time.Time{
					key: time.Now().UTC().Add(10 * time.Minute),
				},
			},
		},
	}
}
