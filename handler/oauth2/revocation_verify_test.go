// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/gen"
	"authelia.com/provider/oauth2/storage"
	"authelia.com/provider/oauth2/token/jwt"
	"authelia.com/provider/oauth2/x/errorsx"
)

func TestRevokeTokenVerifiesTheToken(t *testing.T) {
	stores := []struct {
		name string
		new  func() TokenRevocationStorage
	}{
		{"MemoryStore", func() TokenRevocationStorage { return storage.NewMemoryStore() }},
		{"HydratingMemoryStore", func() TokenRevocationStorage { return storage.NewHydratingMemoryStore() }},
	}

	forge := func(prefix string) func(token string) string {
		return func(token string) string {
			_, signature, _ := strings.Cut(token, ".")

			return prefix + "v9E8WquYRq3WmL5xeME65ftCh2SezhVBI9JL7z7NPbM." + signature
		}
	}

	corrupt := func(prefix string) func(token string) string {
		return func(token string) string {
			_, signature, _ := strings.Cut(token, ".")

			return prefix + "!!!." + signature
		}
	}

	testCases := []struct {
		name    string
		access  bool
		expired bool
		token   func(token string) string
		revoked bool
	}{
		{name: "ShouldRevokeAnIntactAccessToken", access: true, revoked: true},
		{name: "ShouldRevokeAnExpiredAccessToken", access: true, expired: true, revoked: true},
		{name: "ShouldIgnoreAForgedAccessToken", access: true, token: forge("authelia_at_")},
		{name: "ShouldIgnoreACorruptAccessToken", access: true, token: corrupt("authelia_at_")},
		{name: "ShouldIgnoreAForgedExpiredAccessToken", access: true, expired: true, token: forge("authelia_at_")},
		{name: "ShouldRevokeAnIntactRefreshToken", revoked: true},
		{name: "ShouldRevokeAnExpiredRefreshToken", expired: true, revoked: true},
		{name: "ShouldIgnoreAForgedRefreshToken", token: forge("authelia_rt_")},
		{name: "ShouldIgnoreACorruptRefreshToken", token: corrupt("authelia_rt_")},
		{name: "ShouldIgnoreAForgedExpiredRefreshToken", expired: true, token: forge("authelia_rt_")},
	}

	for _, s := range stores {
		for _, tc := range testCases {
			for _, hint := range []oauth2.TokenType{oauth2.AccessToken, oauth2.RefreshToken, ""} {
				t.Run(s.name+"/"+tc.name+"/"+string(hint), func(t *testing.T) {
					store := s.new()

					access, refresh, client := newVerifiedRevocationGrant(t, store, tc.expired)

					handler := &TokenRevocationHandler{
						TokenRevocationStorage: store,
						RefreshTokenStrategy:   &hmacshaStrategy,
						AccessTokenStrategy:    &hmacshaStrategy,
						Config:                 &oauth2.Config{},
					}

					token := refresh
					if tc.access {
						token = access
					}

					if tc.token != nil {
						token = tc.token(token)
					}

					require.NoError(t, oauth2.ErrorToDebugRFC6749Error(handler.RevokeToken(t.Context(), token, hint, client)))

					_, errAccess := store.GetAccessTokenSession(t.Context(), hmacshaStrategy.AccessTokenSignature(t.Context(), access), &oauth2.DefaultSession{})
					_, errRefresh := store.GetRefreshTokenSession(t.Context(), hmacshaStrategy.RefreshTokenSignature(t.Context(), refresh), &oauth2.DefaultSession{})

					if tc.revoked {
						assert.Error(t, errAccess)
						assert.ErrorIs(t, errRefresh, oauth2.ErrInactiveToken)
					} else {
						assert.NoError(t, errAccess)
						assert.NoError(t, errRefresh)
					}
				})
			}
		}
	}
}

func TestRevokeTokenVerifiesAJWTProfileAccessToken(t *testing.T) {
	config := &oauth2.Config{
		GlobalSecret:                  []byte("foofoofoofoofoofoofoofoofoofoofoofoo"),
		EnforceJWTProfileAccessTokens: true,
	}

	strategy := &JWTProfileCoreStrategy{
		HMACCoreStrategy: NewHMACCoreStrategy(config, "authelia_%s_"),
		Strategy:         &jwt.DefaultStrategy{Config: config, Issuer: jwt.NewDefaultIssuerRS256Unverified(gen.MustRSAKey())},
		Config:           config,
	}

	testCases := []struct {
		name    string
		request func() *oauth2.Request
		token   func(token string) string
		revoked bool
	}{
		{name: "ShouldRevokeAnIntactToken", request: func() *oauth2.Request { return jwtValidCase(oauth2.AccessToken) }, revoked: true},
		{name: "ShouldRevokeAnExpiredToken", request: func() *oauth2.Request { return jwtExpiredCase(oauth2.AccessToken, time.Unix(1726972738, 0)) }, revoked: true},
		{
			name:    "ShouldIgnoreATokenWithAChangedPayload",
			request: func() *oauth2.Request { return jwtValidCase(oauth2.AccessToken) },
			token: func(token string) string {
				segments := strings.Split(token, ".")

				return segments[0] + ".e30." + segments[2]
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			store := storage.NewMemoryStore()

			request := tc.request()
			request.ID = "req-id"

			access, signature, err := strategy.GenerateAccessToken(t.Context(), request)
			require.NoError(t, err)
			require.NoError(t, store.CreateAccessTokenSession(t.Context(), signature, request))

			handler := &TokenRevocationHandler{
				TokenRevocationStorage: store,
				RefreshTokenStrategy:   strategy,
				AccessTokenStrategy:    strategy,
				Config:                 &oauth2.Config{},
			}

			token := access
			if tc.token != nil {
				token = tc.token(access)
			}

			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(handler.RevokeToken(t.Context(), token, oauth2.AccessToken, request.GetClient())))

			_, err = store.GetAccessTokenSession(t.Context(), signature, nil)

			if tc.revoked {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestRevokeTokenWithoutAHydratedSession(t *testing.T) {
	testCases := []struct {
		name   string
		access bool
	}{
		{name: "ShouldRevokeAnAccessToken", access: true},
		{name: "ShouldRevokeARefreshToken"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			store := storage.NewMemoryStore()

			access, refresh, client := newVerifiedRevocationGrant(t, store, false)

			handler := &TokenRevocationHandler{
				TokenRevocationStorage: &unhydratedRevocationStore{TokenRevocationStorage: store},
				RefreshTokenStrategy:   &hmacshaStrategy,
				AccessTokenStrategy:    &hmacshaStrategy,
				Config:                 &oauth2.Config{},
			}

			token := refresh
			if tc.access {
				token = access
			}

			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(handler.RevokeToken(t.Context(), token, "", client)))

			_, err := store.GetRefreshTokenSession(t.Context(), hmacshaStrategy.RefreshTokenSignature(t.Context(), refresh), nil)
			assert.ErrorIs(t, err, oauth2.ErrInactiveToken)
		})
	}
}

func TestRevokeTokenAnswersAValidationFailure(t *testing.T) {
	failures := []struct {
		name string
		err  error
	}{
		{name: "ShouldAnswerAnUnknownError", err: errors.New("the secret could not be retrieved")},
		{name: "ShouldAnswerAServerError", err: oauth2.ErrServerError.WithDebug("debug")},
		{name: "ShouldAnswerATemporaryFailure", err: oauth2.ErrTemporarilyUnavailable.WithDebug("debug")},
		{name: "ShouldAnswerAMisconfiguration", err: oauth2.ErrMisconfiguration.WithDebug("debug")},
	}

	for _, tc := range failures {
		t.Run(tc.name, func(t *testing.T) {
			t.Run("AccessToken", func(t *testing.T) {
				store := storage.NewMemoryStore()

				access, _, client := newVerifiedRevocationGrant(t, store, false)

				handler := &TokenRevocationHandler{
					TokenRevocationStorage: store,
					RefreshTokenStrategy:   &hmacshaStrategy,
					AccessTokenStrategy:    &failingTokenStrategy{CoreStrategy: &hmacshaStrategy, err: tc.err},
					Config:                 &oauth2.Config{},
				}

				assert.ErrorIs(t, handler.RevokeToken(t.Context(), access, oauth2.AccessToken, client), oauth2.ErrTemporarilyUnavailable)

				_, err := store.GetAccessTokenSession(t.Context(), hmacshaStrategy.AccessTokenSignature(t.Context(), access), &oauth2.DefaultSession{})
				assert.NoError(t, err)
			})

			t.Run("RefreshToken", func(t *testing.T) {
				store := storage.NewMemoryStore()

				_, refresh, client := newVerifiedRevocationGrant(t, store, false)

				handler := &TokenRevocationHandler{
					TokenRevocationStorage: store,
					RefreshTokenStrategy:   &failingTokenStrategy{CoreStrategy: &hmacshaStrategy, err: tc.err},
					AccessTokenStrategy:    &hmacshaStrategy,
					Config:                 &oauth2.Config{},
				}

				assert.ErrorIs(t, handler.RevokeToken(t.Context(), refresh, oauth2.RefreshToken, client), oauth2.ErrTemporarilyUnavailable)

				_, err := store.GetRefreshTokenSession(t.Context(), hmacshaStrategy.RefreshTokenSignature(t.Context(), refresh), &oauth2.DefaultSession{})
				assert.NoError(t, err)
			})

			t.Run("RotatedRefreshToken", func(t *testing.T) {
				store := storage.NewMemoryStore()
				client := &oauth2.DefaultClient{ID: "foo", GrantTypes: oauth2.Arguments{consts.GrantTypeRefreshToken}, Scopes: []string{"foo", consts.ScopeOffline}}

				rotated, _, refresh := newRotatedRefreshToken(t, store, client)

				handler := &TokenRevocationHandler{
					TokenRevocationStorage: store,
					RefreshTokenStrategy:   &failingTokenStrategy{CoreStrategy: &hmacshaStrategy, err: tc.err},
					AccessTokenStrategy:    &hmacshaStrategy,
					Config:                 &oauth2.Config{},
				}

				assert.ErrorIs(t, handler.RevokeToken(t.Context(), rotated, oauth2.RefreshToken, client), oauth2.ErrTemporarilyUnavailable)

				_, err := store.GetRefreshTokenSession(t.Context(), hmacshaStrategy.RefreshTokenSignature(t.Context(), refresh), &oauth2.DefaultSession{})
				assert.NoError(t, err)
			})
		})
	}
}

func TestIsTokenRejection(t *testing.T) {
	testCases := []struct {
		name     string
		err      error
		expected bool
	}{
		{name: "ShouldRejectASignatureMismatch", err: oauth2.ErrTokenSignatureMismatch, expected: true},
		{name: "ShouldRejectAnInvalidFormat", err: oauth2.ErrInvalidTokenFormat.WithDebug("debug"), expected: true},
		{name: "ShouldRejectAnInvalidClaim", err: oauth2.ErrTokenClaim, expected: true},
		{name: "ShouldRejectACorruptToken", err: base64.CorruptInputError(1), expected: true},
		{name: "ShouldNotRejectAServerError", err: oauth2.ErrServerError},
		{name: "ShouldNotRejectATemporaryFailure", err: oauth2.ErrTemporarilyUnavailable},
		{name: "ShouldNotRejectAMisconfiguration", err: oauth2.ErrMisconfiguration},
		{name: "ShouldNotRejectAWrappedServerSideError", err: errorsx.WithStack(oauth2.ErrMisconfiguration.WithDebug("debug"))},
		{name: "ShouldNotRejectAnUnknownError", err: errors.New("unknown")},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, IsTokenRejection(tc.err))
		})
	}
}

type failingTokenStrategy struct {
	CoreStrategy

	err error
}

func (s *failingTokenStrategy) ValidateAccessToken(_ context.Context, _ oauth2.Requester, _ string) error {
	return s.err
}

func (s *failingTokenStrategy) ValidateRefreshToken(_ context.Context, _ oauth2.Requester, _ string) error {
	return s.err
}

type unhydratedRevocationStore struct {
	TokenRevocationStorage
}

func (s *unhydratedRevocationStore) GetAccessTokenSession(ctx context.Context, signature string, session oauth2.Session) (oauth2.Requester, error) {
	request, err := s.TokenRevocationStorage.GetAccessTokenSession(ctx, signature, session)
	if err != nil {
		return nil, err
	}

	return &oauth2.Request{ID: request.GetID(), Client: request.GetClient()}, nil
}

func (s *unhydratedRevocationStore) GetRefreshTokenSession(ctx context.Context, signature string, session oauth2.Session) (oauth2.Requester, error) {
	request, err := s.TokenRevocationStorage.GetRefreshTokenSession(ctx, signature, session)
	if err != nil {
		return nil, err
	}

	return &oauth2.Request{ID: request.GetID(), Client: request.GetClient()}, nil
}

func newVerifiedRevocationGrant(t *testing.T, store TokenRevocationStorage, expired bool) (access, refresh string, client oauth2.Client) {
	t.Helper()

	client = &oauth2.DefaultClient{ID: "foo"}

	expires := time.Now().UTC().Add(time.Hour)
	if expired {
		expires = time.Now().UTC().Add(-time.Hour)
	}

	request := &oauth2.Request{
		ID:          "req-id",
		Client:      client,
		RequestedAt: time.Now().UTC(),
		Session: &oauth2.DefaultSession{ExpiresAt: map[oauth2.TokenType]time.Time{
			oauth2.AccessToken:  expires,
			oauth2.RefreshToken: expires,
		}},
	}

	access, accessSignature, err := hmacshaStrategy.GenerateAccessToken(t.Context(), nil)
	require.NoError(t, err)

	refresh, refreshSignature, err := hmacshaStrategy.GenerateRefreshToken(t.Context(), nil)
	require.NoError(t, err)

	require.NoError(t, store.CreateAccessTokenSession(t.Context(), accessSignature, request))
	require.NoError(t, store.CreateRefreshTokenSession(t.Context(), refreshSignature, accessSignature, request))

	return access, refresh, client
}
