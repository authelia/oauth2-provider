// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc8693_test

import (
	"context"
	"net/http"
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
)

func TestRefreshTokenTypeHandlerAppliesTheRefreshTokenGrantChecks(t *testing.T) {
	const (
		hintInvalidToken        = "Token is not valid or has expired."
		keyCorrupt              = "!!!!"
		keyMismatched           = "AAAA"
		hintNoRefreshTokenScope = "The refresh token was not granted scope offline or offline_access and may thus not be used for token exchange."
	)

	offline := []string{consts.ScopeOffline, consts.ScopeOfflineAccess}

	testCases := []struct {
		name               string
		actor              bool
		granted            []string
		refreshTokenScopes []string
		replay             bool
		expired            bool
		key                string
		validateErr        error
		noRevocation       bool
		code               int
		hint               string
		revoked            bool
	}{
		{
			name:               "ShouldRejectASubjectTokenWithoutARefreshTokenScope",
			granted:            []string{consts.ScopeOpenID},
			refreshTokenScopes: offline,
			code:               http.StatusBadRequest,
			hint:               hintNoRefreshTokenScope,
		},
		{
			name:               "ShouldRejectAnActorTokenWithoutARefreshTokenScope",
			actor:              true,
			granted:            []string{consts.ScopeOpenID},
			refreshTokenScopes: offline,
			code:               http.StatusBadRequest,
			hint:               hintNoRefreshTokenScope,
		},
		{
			name:    "ShouldAcceptASubjectTokenWithoutARefreshTokenScopeWhenNoneAreConfigured",
			granted: []string{consts.ScopeOpenID},
		},
		{
			name:    "ShouldAcceptAnActorTokenWithoutARefreshTokenScopeWhenNoneAreConfigured",
			actor:   true,
			granted: []string{consts.ScopeOpenID},
		},
		{
			name:               "ShouldAcceptAnActiveSubjectTokenWithARefreshTokenScope",
			granted:            []string{consts.ScopeOpenID, consts.ScopeOffline},
			refreshTokenScopes: offline,
		},
		{
			name:               "ShouldAcceptAnActiveActorTokenWithARefreshTokenScope",
			actor:              true,
			granted:            []string{consts.ScopeOpenID, consts.ScopeOfflineAccess},
			refreshTokenScopes: offline,
		},
		{
			name:               "ShouldRevokeTheGrantWhenARotatedSubjectTokenIsReplayed",
			granted:            []string{consts.ScopeOpenID, consts.ScopeOffline},
			refreshTokenScopes: offline,
			replay:             true,
			code:               http.StatusBadRequest,
			hint:               hintInvalidToken,
			revoked:            true,
		},
		{
			name:               "ShouldRevokeTheGrantWhenARotatedActorTokenIsReplayed",
			actor:              true,
			granted:            []string{consts.ScopeOpenID, consts.ScopeOffline},
			refreshTokenScopes: offline,
			replay:             true,
			code:               http.StatusBadRequest,
			hint:               hintInvalidToken,
			revoked:            true,
		},
		{
			name:    "ShouldRevokeTheGrantWhenARotatedSubjectTokenIsReplayedWithoutARefreshTokenScope",
			granted: []string{consts.ScopeOpenID},
			replay:  true,
			code:    http.StatusBadRequest,
			hint:    hintInvalidToken,
			revoked: true,
		},
		{
			name:               "ShouldRevokeTheGrantWhenAnExpiredRotatedSubjectTokenIsReplayed",
			granted:            []string{consts.ScopeOpenID, consts.ScopeOffline},
			refreshTokenScopes: offline,
			replay:             true,
			expired:            true,
			code:               http.StatusBadRequest,
			hint:               hintInvalidToken,
			revoked:            true,
		},
		{
			name:               "ShouldNotRevokeTheGrantWhenARotatedSubjectTokenWithACorruptKeyIsReplayed",
			granted:            []string{consts.ScopeOpenID, consts.ScopeOffline},
			refreshTokenScopes: offline,
			replay:             true,
			key:                keyCorrupt,
			code:               http.StatusBadRequest,
			hint:               hintInvalidToken,
		},
		{
			name:               "ShouldNotRevokeTheGrantWhenARotatedActorTokenWithACorruptKeyIsReplayed",
			actor:              true,
			granted:            []string{consts.ScopeOpenID, consts.ScopeOffline},
			refreshTokenScopes: offline,
			replay:             true,
			key:                keyCorrupt,
			code:               http.StatusBadRequest,
			hint:               hintInvalidToken,
		},
		{
			name:               "ShouldNotRevokeTheGrantWhenARotatedSubjectTokenWithAMismatchedKeyIsReplayed",
			granted:            []string{consts.ScopeOpenID, consts.ScopeOffline},
			refreshTokenScopes: offline,
			replay:             true,
			key:                keyMismatched,
			code:               http.StatusBadRequest,
			hint:               hintInvalidToken,
		},
		{
			name:               "ShouldNotRevokeTheGrantWhenARotatedActorTokenWithAMismatchedKeyIsReplayed",
			actor:              true,
			granted:            []string{consts.ScopeOpenID, consts.ScopeOffline},
			refreshTokenScopes: offline,
			replay:             true,
			key:                keyMismatched,
			code:               http.StatusBadRequest,
			hint:               hintInvalidToken,
		},
		{
			name:               "ShouldKeepAServerErrorFromValidatingASubjectToken",
			granted:            []string{consts.ScopeOpenID, consts.ScopeOffline},
			refreshTokenScopes: offline,
			validateErr:        oauth2.ErrServerError,
			code:               http.StatusInternalServerError,
		},
		{
			name:               "ShouldKeepAServerErrorFromValidatingAnActorToken",
			actor:              true,
			granted:            []string{consts.ScopeOpenID, consts.ScopeOffline},
			refreshTokenScopes: offline,
			validateErr:        oauth2.ErrServerError,
			code:               http.StatusInternalServerError,
		},
		{
			name:               "ShouldNotRevokeTheGrantWhenValidatingARotatedSubjectTokenFailsWithAServerError",
			granted:            []string{consts.ScopeOpenID, consts.ScopeOffline},
			refreshTokenScopes: offline,
			replay:             true,
			validateErr:        oauth2.ErrServerError,
			code:               http.StatusInternalServerError,
		},
		{
			name:               "ShouldFailClosedWhenARotatedSubjectTokenIsReplayedWithoutRevocationStorage",
			granted:            []string{consts.ScopeOpenID, consts.ScopeOffline},
			refreshTokenScopes: offline,
			replay:             true,
			noRevocation:       true,
			code:               http.StatusInternalServerError,
		},
	}

	for _, tc := range testCases {
		for _, s := range bindingExchangeStores() {
			t.Run(tc.name+"/"+s.name, func(t *testing.T) {
				ctx := t.Context()
				store := s.newStore()
				config, coreStrategy := newBindingExchangeConfig()

				config.RFC8693TokenTypes[consts.TokenTypeRFC8693RefreshToken] = &DefaultTokenType{Name: consts.TokenTypeRFC8693RefreshToken}

				validator := coreStrategy
				if tc.validateErr != nil {
					validator = &failingRefreshTokenStrategy{CoreStrategy: coreStrategy, err: tc.validateErr}
				}

				handler := &RefreshTokenTypeHandler{
					Config:                 config,
					RefreshTokenLifespan:   5 * time.Minute,
					RefreshTokenScopes:     tc.refreshTokenScopes,
					ScopeStrategy:          config.ScopeStrategy,
					CoreStrategy:           validator,
					Storage:                store,
					TokenRevocationStorage: store,
				}

				if tc.noRevocation {
					handler.TokenRevocationStorage = nil
				}

				client := store.GetClients()["my-client"]

				owner := store.GetClients()["custom-lifespan-client"]
				if tc.actor {
					owner = client
				}

				family := newReuseFamily(ctx, t, coreStrategy, store, owner, tc.granted, tc.replay, tc.expired)

				presented := family.presented
				if tc.key != "" {
					presented = tc.key + presented[len(presented)-len(family.presentedSignature)-1:]
				}

				form := url.Values{consts.FormParameterGrantType: {consts.GrantTypeOAuthTokenExchange}}

				if tc.actor {
					form.Set(consts.FormParameterActorTokenType, consts.TokenTypeRFC8693RefreshToken)
					form.Set(consts.FormParameterActorToken, presented)
					form.Set(consts.FormParameterSubjectTokenType, consts.TokenTypeRFC8693AccessToken)
					form.Set(consts.FormParameterSubjectToken, "opaque-subject-token")
				} else {
					form.Set(consts.FormParameterSubjectTokenType, consts.TokenTypeRFC8693RefreshToken)
					form.Set(consts.FormParameterSubjectToken, presented)
				}

				request := &oauth2.AccessRequest{
					GrantTypes: oauth2.Arguments{consts.GrantTypeOAuthTokenExchange},
					Request: oauth2.Request{
						ID:      uuid.New().String(),
						Client:  client,
						Form:    form,
						Session: newSpecSession(""),
					},
				}

				err := handler.HandleTokenEndpointRequest(ctx, request)

				if tc.code == 0 {
					require.NoError(t, err)
				} else {
					require.Error(t, err)

					rfc := oauth2.ErrorToRFC6749Error(err)

					assert.Equal(t, tc.code, rfc.CodeField)

					if tc.code == http.StatusBadRequest {
						assert.Equal(t, oauth2.ErrInvalidRequest.ErrorField, rfc.ErrorField)
						assert.Equal(t, tc.hint, rfc.HintField)
					}
				}

				_, err = store.GetRefreshTokenSession(ctx, family.currentSignature, &oauth2.DefaultSession{})
				_, aerr := store.GetAccessTokenSession(ctx, family.accessSignature, &oauth2.DefaultSession{})

				if tc.revoked {
					assert.ErrorIs(t, err, oauth2.ErrInactiveToken)
					assert.ErrorIs(t, aerr, oauth2.ErrNotFound)

					_, err = store.GetRefreshTokenSession(ctx, family.presentedSignature, &oauth2.DefaultSession{})
					assert.ErrorIs(t, err, oauth2.ErrNotFound)
				} else {
					assert.NoError(t, err)
					assert.NoError(t, aerr)
				}
			})
		}
	}
}

type failingRefreshTokenStrategy struct {
	hoauth2.CoreStrategy

	err error
}

func (s *failingRefreshTokenStrategy) ValidateRefreshToken(_ context.Context, _ oauth2.Requester, _ string) error {
	return s.err
}

type reuseFamily struct {
	presented          string
	presentedSignature string
	currentSignature   string
	accessSignature    string
}

func newReuseFamily(ctx context.Context, t *testing.T, coreStrategy hoauth2.CoreStrategy, store rfc8693ExchangeStore, client oauth2.Client, granted []string, replay, expired bool) (family reuseFamily) {
	t.Helper()

	subject := "reuse-subject"

	expires := time.Now().UTC().Add(10 * time.Minute)
	if expired {
		expires = time.Now().UTC().Add(-time.Minute)
	}

	request := &oauth2.AccessRequest{
		GrantTypes: oauth2.Arguments{consts.GrantTypeAuthorizationCode},
		Request: oauth2.Request{
			ID:           uuid.New().String(),
			Client:       client,
			GrantedScope: granted,
			Session: &oauth2.DefaultSession{
				Username: subject,
				Subject:  subject,
				ExpiresAt: map[oauth2.TokenType]time.Time{
					oauth2.AccessToken:  time.Now().UTC().Add(10 * time.Minute),
					oauth2.RefreshToken: expires,
				},
			},
		},
	}

	token, signature, err := coreStrategy.GenerateRefreshToken(ctx, request)
	require.NoError(t, err)
	require.NoError(t, store.CreateRefreshTokenSession(ctx, signature, "", request.Sanitize(nil)))

	family.presented, family.presentedSignature, family.currentSignature = token, signature, signature

	if replay {
		require.NoError(t, store.RotateRefreshToken(ctx, request.GetID(), signature))

		_, family.currentSignature, err = coreStrategy.GenerateRefreshToken(ctx, request)
		require.NoError(t, err)
	}

	_, family.accessSignature, err = coreStrategy.GenerateAccessToken(ctx, request)
	require.NoError(t, err)
	require.NoError(t, store.CreateAccessTokenSession(ctx, family.accessSignature, request.Sanitize(nil)))

	if replay {
		require.NoError(t, store.CreateRefreshTokenSession(ctx, family.currentSignature, family.accessSignature, request.Sanitize(nil)))
	}

	return family
}
