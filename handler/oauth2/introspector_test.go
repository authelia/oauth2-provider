// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"net/http"
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/testing/mock"
	"authelia.com/provider/oauth2/x/errorsx"
)

func TestIntrospectToken(t *testing.T) {
	testCases := []struct {
		name     string
		setup    func(t *testing.T, config *oauth2.Config, r *http.Request, strategy *mock.MockCoreStrategy, store *mock.MockCoreStorage, requester oauth2.AccessRequester)
		hint     oauth2.TokenType
		error    error
		errorStr string
		expected oauth2.TokenUse
	}{
		{
			name: "ShouldFailBecauseNoBearerTokenSet",
			setup: func(t *testing.T, config *oauth2.Config, r *http.Request, strategy *mock.MockCoreStrategy, store *mock.MockCoreStorage, requester oauth2.AccessRequester) {
				r.Header.Set(consts.HeaderAuthorization, oauth2.BearerAccessToken)
			},
			error:    oauth2.ErrRequestUnauthorized,
			errorStr: "The request could not be authorized. Check that you provided valid credentials in the right format. The request either had a malformed Authorization header or didn't include a bearer token.",
		},
		{
			name: "ShouldFailBecauseTokenSessionCantBeFoundAccessTokenHint",
			setup: func(t *testing.T, config *oauth2.Config, r *http.Request, strategy *mock.MockCoreStrategy, store *mock.MockCoreStorage, requester oauth2.AccessRequester) {
				r.Header.Set(consts.HeaderAuthorization, "bearer 1234")

				gomock.InOrder(
					strategy.
						EXPECT().
						AccessTokenSignature(gomock.Eq(t.Context()), gomock.Eq("1234")).
						Return("asdf"),
					store.
						EXPECT().
						GetAccessTokenSession(gomock.Eq(t.Context()), gomock.Eq("asdf"), gomock.Eq(nil)).
						Return(nil, errors.New("Failed to lookup the Access Token Session.")),
					strategy.
						EXPECT().
						RefreshTokenSignature(gomock.Eq(t.Context()), gomock.Eq("1234")).
						Return("asdf"),
					store.
						EXPECT().
						GetRefreshTokenSession(gomock.Eq(t.Context()), gomock.Eq("asdf"), gomock.Eq(nil)).
						Return(nil, errors.New("Failed to lookup the Refresh Token Session.")),
				)
			},
			hint:     oauth2.AccessToken,
			error:    oauth2.ErrRequestUnauthorized,
			errorStr: "The request could not be authorized. Check that you provided valid credentials in the right format. Failed to lookup the Access Token Session.",
		},
		{
			name: "ShouldFailBecauseTokenSessionCantBeFoundRefreshTokenHint",
			setup: func(t *testing.T, config *oauth2.Config, r *http.Request, strategy *mock.MockCoreStrategy, store *mock.MockCoreStorage, requester oauth2.AccessRequester) {
				r.Header.Set(consts.HeaderAuthorization, "bearer 1234")

				gomock.InOrder(
					strategy.
						EXPECT().
						RefreshTokenSignature(gomock.Eq(t.Context()), gomock.Eq("1234")).
						Return("asdf"),
					store.
						EXPECT().
						GetRefreshTokenSession(gomock.Eq(t.Context()), gomock.Eq("asdf"), gomock.Eq(nil)).
						Return(nil, errors.New("Failed to lookup the Refresh Token Session.")),
					strategy.
						EXPECT().
						AccessTokenSignature(gomock.Eq(t.Context()), gomock.Eq("1234")).
						Return("asdf"),
					store.
						EXPECT().
						GetAccessTokenSession(gomock.Eq(t.Context()), gomock.Eq("asdf"), gomock.Eq(nil)).
						Return(nil, errors.New("Failed to lookup the Access Token Session.")),
				)
			},
			hint:     oauth2.RefreshToken,
			error:    oauth2.ErrRequestUnauthorized,
			errorStr: "The request could not be authorized. Check that you provided valid credentials in the right format. Failed to lookup the Refresh Token Session.",
		},
		{
			name: "ShouldFailBecauseValidationFails",
			setup: func(t *testing.T, config *oauth2.Config, r *http.Request, strategy *mock.MockCoreStrategy, store *mock.MockCoreStorage, requester oauth2.AccessRequester) {
				r.Header.Set(consts.HeaderAuthorization, "bearer 1234")

				gomock.InOrder(
					strategy.
						EXPECT().
						AccessTokenSignature(gomock.Eq(t.Context()), gomock.Eq("1234")).
						Return("asdf"),
					store.
						EXPECT().
						GetAccessTokenSession(gomock.Eq(t.Context()), gomock.Eq("asdf"), gomock.Eq(nil)).
						Return(requester, nil),
					strategy.
						EXPECT().
						ValidateAccessToken(gomock.Eq(t.Context()), gomock.Eq(requester), "1234").
						Return(errorsx.WithStack(oauth2.ErrTokenExpired)),
					strategy.
						EXPECT().
						RefreshTokenSignature(gomock.Eq(t.Context()), gomock.Eq("1234")).
						Return("asdf"),
					store.
						EXPECT().
						GetRefreshTokenSession(gomock.Eq(t.Context()), gomock.Eq("asdf"), gomock.Eq(nil)).
						Return(nil, errors.New("Failed to lookup the Refresh Token Session.")),
				)
			},
			error:    oauth2.ErrTokenExpired,
			errorStr: "Token expired. The token expired.",
		},
		{
			name: "ShouldFailBecauseAccessTokenInvalid",
			setup: func(t *testing.T, config *oauth2.Config, r *http.Request, strategy *mock.MockCoreStrategy, store *mock.MockCoreStorage, requester oauth2.AccessRequester) {
				r.Header.Set(consts.HeaderAuthorization, "bearer 1234")

				config.DisableRefreshTokenValidation = true

				gomock.InOrder(
					strategy.
						EXPECT().
						AccessTokenSignature(gomock.Eq(t.Context()), gomock.Eq("1234")).
						Return("asdf"),
					store.
						EXPECT().
						GetAccessTokenSession(gomock.Eq(t.Context()), gomock.Eq("asdf"), gomock.Eq(nil)).
						Return(requester, nil),
					strategy.
						EXPECT().
						ValidateAccessToken(gomock.Eq(t.Context()), gomock.Eq(requester), gomock.Eq("1234")).
						Return(errorsx.WithStack(oauth2.ErrInvalidTokenFormat)),
				)
			},
			error:    oauth2.ErrInvalidTokenFormat,
			errorStr: "Invalid token format. Check that you provided a valid token in the right format.",
		},
		{
			name: "ShouldPass",
			setup: func(t *testing.T, config *oauth2.Config, r *http.Request, strategy *mock.MockCoreStrategy, store *mock.MockCoreStorage, requester oauth2.AccessRequester) {
				r.Header.Set(consts.HeaderAuthorization, "bearer 1234")

				gomock.InOrder(
					strategy.
						EXPECT().
						AccessTokenSignature(gomock.Eq(t.Context()), gomock.Eq("1234")).
						Return("asdf"),
					store.
						EXPECT().
						GetAccessTokenSession(gomock.Eq(t.Context()), gomock.Eq("asdf"), gomock.Eq(nil)).
						Return(requester, nil),
					strategy.
						EXPECT().
						ValidateAccessToken(gomock.Eq(t.Context()), gomock.Eq(requester), gomock.Eq("1234")).
						Return(nil),
				)
			},
			expected: oauth2.AccessToken,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)

			defer ctrl.Finish()

			store := mock.NewMockCoreStorage(ctrl)
			strategy := mock.NewMockCoreStrategy(ctrl)
			requester := oauth2.NewAccessRequest(nil)

			config := &oauth2.Config{}

			validator := &CoreValidator{
				CoreStrategy: strategy,
				CoreStorage:  store,
				Config:       config,
			}

			r := &http.Request{Header: http.Header{}}

			if tc.setup != nil {
				tc.setup(t, config, r, strategy, store, requester)
			}

			hint := tc.hint

			if hint == "" {
				hint = oauth2.AccessToken
			}

			actual, err := validator.IntrospectToken(t.Context(), oauth2.AccessTokenFromRequest(r), hint, requester, []string{})

			if len(tc.errorStr) == 0 {
				require.NoError(t, err)
				require.NotNil(t, actual)

				assert.Equal(t, tc.expected, actual)
			} else {
				assert.EqualError(t, err, tc.error.Error())
				assert.EqualError(t, oauth2.ErrorToDebugRFC6749Error(err), tc.errorStr)
			}
		})
	}
}
