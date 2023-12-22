// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal"
)

func TestRevokeToken(t *testing.T) {
	type testCase struct {
		name      string
		setup     func(t *testing.T, tc testCase, store *internal.MockTokenRevocationStorage, atStrat *internal.MockAccessTokenStrategy, rtStrat *internal.MockRefreshTokenStrategy, ar *internal.MockAccessRequester)
		have      string
		tokenType oauth2.TokenType
		config    *oauth2.Config
		client    oauth2.Client
		expected  error
	}

	testCases := []testCase{
		{
			name:      "ShouldFailWhenTokenWasIssuedToAnotherClient",
			have:      "foo",
			tokenType: oauth2.RefreshToken,
			expected:  oauth2.ErrUnauthorizedClient,
			client:    &oauth2.DefaultClient{ID: "bar"},
			setup: func(t *testing.T, tc testCase, store *internal.MockTokenRevocationStorage, atStrat *internal.MockAccessTokenStrategy, rtStrat *internal.MockRefreshTokenStrategy, ar *internal.MockAccessRequester) {
				gomock.InOrder(
					rtStrat.EXPECT().RefreshTokenSignature(gomock.Any(), tc.have),
					store.EXPECT().GetRefreshTokenSession(gomock.Any(), gomock.Any(), gomock.Any()).Return(ar, nil),
					ar.EXPECT().GetClient().Return(&oauth2.DefaultClient{ID: "foo"}),
				)
			},
		},
		{
			name:      "ShouldPassWhenRefreshDiscoveryPreferenceAndRefreshTokenFound",
			have:      "foo",
			tokenType: oauth2.RefreshToken,
			expected:  nil,
			client:    &oauth2.DefaultClient{ID: "bar"},
			setup: func(t *testing.T, tc testCase, store *internal.MockTokenRevocationStorage, atStrat *internal.MockAccessTokenStrategy, rtStrat *internal.MockRefreshTokenStrategy, ar *internal.MockAccessRequester) {
				gomock.InOrder(
					rtStrat.EXPECT().RefreshTokenSignature(gomock.Any(), tc.have),
					store.EXPECT().GetRefreshTokenSession(gomock.Any(), gomock.Any(), gomock.Any()).Return(ar, nil),
					ar.EXPECT().GetClient().Return(&oauth2.DefaultClient{ID: "bar"}),
					ar.EXPECT().GetID(),
					store.EXPECT().RevokeRefreshToken(gomock.Any(), gomock.Any()),
					store.EXPECT().RevokeAccessToken(gomock.Any(), gomock.Any()),
				)
			},
		},
		{
			name:      "ShouldPassWhenAccessTokenPreferenceAccessTokenFound",
			have:      "foo",
			tokenType: oauth2.AccessToken,
			expected:  nil,
			client:    &oauth2.DefaultClient{ID: "bar"},
			setup: func(t *testing.T, tc testCase, store *internal.MockTokenRevocationStorage, atStrat *internal.MockAccessTokenStrategy, rtStrat *internal.MockRefreshTokenStrategy, ar *internal.MockAccessRequester) {
				gomock.InOrder(
					atStrat.EXPECT().AccessTokenSignature(gomock.Any(), tc.have),
					store.EXPECT().GetAccessTokenSession(gomock.Any(), gomock.Any(), gomock.Any()).Return(ar, nil),
					ar.EXPECT().GetClient().Return(&oauth2.DefaultClient{ID: "bar"}),
					ar.EXPECT().GetID(),
					store.EXPECT().RevokeRefreshToken(gomock.Any(), gomock.Any()),
					store.EXPECT().RevokeAccessToken(gomock.Any(), gomock.Any()),
				)
			},
		},
		{
			name:      "ShouldPassWhenAccessTokenPreferenceAndAccessTokenFound",
			have:      "foo",
			tokenType: oauth2.AccessToken,
			expected:  nil,
			client:    &oauth2.DefaultClient{ID: "bar"},
			setup: func(t *testing.T, tc testCase, store *internal.MockTokenRevocationStorage, atStrat *internal.MockAccessTokenStrategy, rtStrat *internal.MockRefreshTokenStrategy, ar *internal.MockAccessRequester) {
				gomock.InOrder(
					atStrat.EXPECT().AccessTokenSignature(gomock.Any(), tc.have),
					store.EXPECT().GetAccessTokenSession(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, oauth2.ErrNotFound),
					rtStrat.EXPECT().RefreshTokenSignature(gomock.Any(), tc.have),
					store.EXPECT().GetRefreshTokenSession(gomock.Any(), gomock.Any(), gomock.Any()).Return(ar, nil),
					ar.EXPECT().GetClient().Return(&oauth2.DefaultClient{ID: "bar"}),
					ar.EXPECT().GetID(),
					store.EXPECT().RevokeRefreshToken(gomock.Any(), gomock.Any()),
					store.EXPECT().RevokeAccessToken(gomock.Any(), gomock.Any()),
				)
			},
		},
		{
			name:      "ShouldPassExplicitWhenRefreshTokenPreferenceAndAccessTokenFound",
			have:      "foo",
			tokenType: oauth2.RefreshToken,
			expected:  nil,
			config:    &oauth2.Config{RevokeRefreshTokensExplicitly: true},
			client:    &oauth2.DefaultClient{ID: "bar"},
			setup: func(t *testing.T, tc testCase, store *internal.MockTokenRevocationStorage, atStrat *internal.MockAccessTokenStrategy, rtStrat *internal.MockRefreshTokenStrategy, ar *internal.MockAccessRequester) {
				gomock.InOrder(
					rtStrat.EXPECT().RefreshTokenSignature(gomock.Any(), tc.have).Return("example"),
					store.EXPECT().GetRefreshTokenSession(gomock.Any(), gomock.Eq("example"), gomock.Any()).Return(nil, oauth2.ErrNotFound),
					atStrat.EXPECT().AccessTokenSignature(gomock.Any(), tc.have),
					store.EXPECT().GetAccessTokenSession(gomock.Any(), gomock.Any(), gomock.Any()).Return(ar, nil),
					ar.EXPECT().GetClient().Return(&oauth2.DefaultClient{ID: "bar"}),
					ar.EXPECT().GetID(),
					store.EXPECT().RevokeAccessToken(gomock.Any(), gomock.Any()),
				)
			},
		},
		{
			name:      "ShouldPassExplicitWhenAccessTokenPreferenceAndRefreshTokenTokenFound",
			have:      "foo",
			tokenType: oauth2.AccessToken,
			expected:  nil,
			config:    &oauth2.Config{RevokeRefreshTokensExplicitly: true},
			client:    &oauth2.DefaultClient{ID: "bar"},
			setup: func(t *testing.T, tc testCase, store *internal.MockTokenRevocationStorage, atStrat *internal.MockAccessTokenStrategy, rtStrat *internal.MockRefreshTokenStrategy, ar *internal.MockAccessRequester) {
				gomock.InOrder(
					atStrat.EXPECT().AccessTokenSignature(gomock.Any(), tc.have),
					store.EXPECT().GetAccessTokenSession(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, oauth2.ErrNotFound),
					rtStrat.EXPECT().RefreshTokenSignature(gomock.Any(), tc.have),
					store.EXPECT().GetRefreshTokenSession(gomock.Any(), gomock.Any(), gomock.Any()).Return(ar, nil),
					ar.EXPECT().GetClient().Return(&oauth2.DefaultClient{ID: "bar"}),
					ar.EXPECT().GetID(),
					store.EXPECT().RevokeRefreshToken(gomock.Any(), gomock.Any()),
					store.EXPECT().RevokeAccessToken(gomock.Any(), gomock.Any()),
				)
			},
		},
		{
			name:      "ShouldPassExplicitWhenRefreshTokenPreferenceAndRefreshTokenTokenFound",
			have:      "foo",
			tokenType: oauth2.RefreshToken,
			expected:  nil,
			config:    &oauth2.Config{RevokeRefreshTokensExplicitly: true},
			client:    &oauth2.DefaultClient{ID: "bar"},
			setup: func(t *testing.T, tc testCase, store *internal.MockTokenRevocationStorage, atStrat *internal.MockAccessTokenStrategy, rtStrat *internal.MockRefreshTokenStrategy, ar *internal.MockAccessRequester) {
				gomock.InOrder(
					rtStrat.EXPECT().RefreshTokenSignature(gomock.Any(), tc.have),
					store.EXPECT().GetRefreshTokenSession(gomock.Any(), gomock.Any(), gomock.Any()).Return(ar, nil),
					ar.EXPECT().GetClient().Return(&oauth2.DefaultClient{ID: "bar"}),
					ar.EXPECT().GetID(),
					store.EXPECT().RevokeRefreshToken(gomock.Any(), gomock.Any()),
					store.EXPECT().RevokeAccessToken(gomock.Any(), gomock.Any()),
				)
			},
		},
		{
			name:      "ShouldPassExplicitWithExplicitClientWhenRefreshTokenPreferenceAndAccessTokenFound",
			have:      "foo",
			tokenType: oauth2.RefreshToken,
			expected:  nil,
			config:    &oauth2.Config{RevokeRefreshTokensExplicitly: true},
			client:    &ExplicitClient{&oauth2.DefaultClient{ID: "bar"}, false},
			setup: func(t *testing.T, tc testCase, store *internal.MockTokenRevocationStorage, atStrat *internal.MockAccessTokenStrategy, rtStrat *internal.MockRefreshTokenStrategy, ar *internal.MockAccessRequester) {
				gomock.InOrder(
					rtStrat.EXPECT().RefreshTokenSignature(gomock.Any(), tc.have).Return("example"),
					store.EXPECT().GetRefreshTokenSession(gomock.Any(), gomock.Eq("example"), gomock.Any()).Return(nil, oauth2.ErrNotFound),
					atStrat.EXPECT().AccessTokenSignature(gomock.Any(), tc.have),
					store.EXPECT().GetAccessTokenSession(gomock.Any(), gomock.Any(), gomock.Any()).Return(ar, nil),
					ar.EXPECT().GetClient().Return(&oauth2.DefaultClient{ID: "bar"}),
					ar.EXPECT().GetID(),
					store.EXPECT().RevokeAccessToken(gomock.Any(), gomock.Any()),
				)
			},
		},
		{
			name:      "ShouldPassExplicitWithExplicitClientWhenAccessTokenPreferenceAndRefreshTokenTokenFound",
			have:      "foo",
			tokenType: oauth2.AccessToken,
			expected:  nil,
			config:    &oauth2.Config{RevokeRefreshTokensExplicitly: true},
			client:    &ExplicitClient{&oauth2.DefaultClient{ID: "bar"}, false},
			setup: func(t *testing.T, tc testCase, store *internal.MockTokenRevocationStorage, atStrat *internal.MockAccessTokenStrategy, rtStrat *internal.MockRefreshTokenStrategy, ar *internal.MockAccessRequester) {
				gomock.InOrder(
					atStrat.EXPECT().AccessTokenSignature(gomock.Any(), tc.have),
					store.EXPECT().GetAccessTokenSession(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, oauth2.ErrNotFound),
					rtStrat.EXPECT().RefreshTokenSignature(gomock.Any(), tc.have),
					store.EXPECT().GetRefreshTokenSession(gomock.Any(), gomock.Any(), gomock.Any()).Return(ar, nil),
					ar.EXPECT().GetClient().Return(&oauth2.DefaultClient{ID: "bar"}),
					ar.EXPECT().GetID(),
					store.EXPECT().RevokeRefreshToken(gomock.Any(), gomock.Any()),
					store.EXPECT().RevokeAccessToken(gomock.Any(), gomock.Any()),
				)
			},
		},
		{
			name:      "ShouldPassExplicitWithExplicitClientWhenRefreshTokenPreferenceAndRefreshTokenTokenFound",
			have:      "foo",
			tokenType: oauth2.RefreshToken,
			expected:  nil,
			config:    &oauth2.Config{RevokeRefreshTokensExplicitly: true},
			client:    &ExplicitClient{&oauth2.DefaultClient{ID: "bar"}, false},
			setup: func(t *testing.T, tc testCase, store *internal.MockTokenRevocationStorage, atStrat *internal.MockAccessTokenStrategy, rtStrat *internal.MockRefreshTokenStrategy, ar *internal.MockAccessRequester) {
				gomock.InOrder(
					rtStrat.EXPECT().RefreshTokenSignature(gomock.Any(), tc.have),
					store.EXPECT().GetRefreshTokenSession(gomock.Any(), gomock.Any(), gomock.Any()).Return(ar, nil),
					ar.EXPECT().GetClient().Return(&oauth2.DefaultClient{ID: "bar"}),
					ar.EXPECT().GetID(),
					store.EXPECT().RevokeRefreshToken(gomock.Any(), gomock.Any()),
					store.EXPECT().RevokeAccessToken(gomock.Any(), gomock.Any()),
				)
			},
		},
		{
			name:      "ShouldPassExplicitWithExplicitClientEnforceWhenRefreshTokenPreferenceAndAccessTokenFound",
			have:      "foo",
			tokenType: oauth2.RefreshToken,
			expected:  nil,
			config:    &oauth2.Config{RevokeRefreshTokensExplicitly: true, EnforceRevokeFlowRevokeRefreshTokensExplicitClient: true},
			client:    &ExplicitClient{&oauth2.DefaultClient{ID: "bar"}, false},
			setup: func(t *testing.T, tc testCase, store *internal.MockTokenRevocationStorage, atStrat *internal.MockAccessTokenStrategy, rtStrat *internal.MockRefreshTokenStrategy, ar *internal.MockAccessRequester) {
				gomock.InOrder(
					rtStrat.EXPECT().RefreshTokenSignature(gomock.Any(), tc.have).Return("example"),
					store.EXPECT().GetRefreshTokenSession(gomock.Any(), gomock.Eq("example"), gomock.Any()).Return(nil, oauth2.ErrNotFound),
					atStrat.EXPECT().AccessTokenSignature(gomock.Any(), tc.have),
					store.EXPECT().GetAccessTokenSession(gomock.Any(), gomock.Any(), gomock.Any()).Return(ar, nil),
					ar.EXPECT().GetClient().Return(&oauth2.DefaultClient{ID: "bar"}),
					ar.EXPECT().GetID(),
					store.EXPECT().RevokeRefreshToken(gomock.Any(), gomock.Any()),
					store.EXPECT().RevokeAccessToken(gomock.Any(), gomock.Any()),
				)
			},
		},
		{
			name:      "ShouldPassExplicitWithExplicitClientEnforceWhenAccessTokenPreferenceAndRefreshTokenTokenFound",
			have:      "foo",
			tokenType: oauth2.AccessToken,
			expected:  nil,
			config:    &oauth2.Config{RevokeRefreshTokensExplicitly: true, EnforceRevokeFlowRevokeRefreshTokensExplicitClient: true},
			client:    &ExplicitClient{&oauth2.DefaultClient{ID: "bar"}, false},
			setup: func(t *testing.T, tc testCase, store *internal.MockTokenRevocationStorage, atStrat *internal.MockAccessTokenStrategy, rtStrat *internal.MockRefreshTokenStrategy, ar *internal.MockAccessRequester) {
				gomock.InOrder(
					atStrat.EXPECT().AccessTokenSignature(gomock.Any(), tc.have),
					store.EXPECT().GetAccessTokenSession(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, oauth2.ErrNotFound),
					rtStrat.EXPECT().RefreshTokenSignature(gomock.Any(), tc.have),
					store.EXPECT().GetRefreshTokenSession(gomock.Any(), gomock.Any(), gomock.Any()).Return(ar, nil),
					ar.EXPECT().GetClient().Return(&oauth2.DefaultClient{ID: "bar"}),
					ar.EXPECT().GetID(),
					store.EXPECT().RevokeRefreshToken(gomock.Any(), gomock.Any()),
					store.EXPECT().RevokeAccessToken(gomock.Any(), gomock.Any()),
				)
			},
		},
		{
			name:      "ShouldPassExplicitWithExplicitClientEnforceWhenRefreshTokenPreferenceAndRefreshTokenTokenFound",
			have:      "foo",
			tokenType: oauth2.RefreshToken,
			expected:  nil,
			config:    &oauth2.Config{RevokeRefreshTokensExplicitly: true, EnforceRevokeFlowRevokeRefreshTokensExplicitClient: true},
			client:    &ExplicitClient{&oauth2.DefaultClient{ID: "bar"}, false},
			setup: func(t *testing.T, tc testCase, store *internal.MockTokenRevocationStorage, atStrat *internal.MockAccessTokenStrategy, rtStrat *internal.MockRefreshTokenStrategy, ar *internal.MockAccessRequester) {
				gomock.InOrder(
					rtStrat.EXPECT().RefreshTokenSignature(gomock.Any(), tc.have),
					store.EXPECT().GetRefreshTokenSession(gomock.Any(), gomock.Any(), gomock.Any()).Return(ar, nil),
					ar.EXPECT().GetClient().Return(&oauth2.DefaultClient{ID: "bar"}),
					ar.EXPECT().GetID(),
					store.EXPECT().RevokeRefreshToken(gomock.Any(), gomock.Any()),
					store.EXPECT().RevokeAccessToken(gomock.Any(), gomock.Any()),
				)
			},
		},
		{
			name:      "ShouldPassExplicitWithExplicitClientEnforceAndEnabledWhenRefreshTokenPreferenceAndAccessTokenFound",
			have:      "foo",
			tokenType: oauth2.RefreshToken,
			expected:  nil,
			config:    &oauth2.Config{RevokeRefreshTokensExplicitly: true, EnforceRevokeFlowRevokeRefreshTokensExplicitClient: true},
			client:    &ExplicitClient{&oauth2.DefaultClient{ID: "bar"}, true},
			setup: func(t *testing.T, tc testCase, store *internal.MockTokenRevocationStorage, atStrat *internal.MockAccessTokenStrategy, rtStrat *internal.MockRefreshTokenStrategy, ar *internal.MockAccessRequester) {
				gomock.InOrder(
					rtStrat.EXPECT().RefreshTokenSignature(gomock.Any(), tc.have).Return("example"),
					store.EXPECT().GetRefreshTokenSession(gomock.Any(), gomock.Eq("example"), gomock.Any()).Return(nil, oauth2.ErrNotFound),
					atStrat.EXPECT().AccessTokenSignature(gomock.Any(), tc.have),
					store.EXPECT().GetAccessTokenSession(gomock.Any(), gomock.Any(), gomock.Any()).Return(ar, nil),
					ar.EXPECT().GetClient().Return(&oauth2.DefaultClient{ID: "bar"}),
					ar.EXPECT().GetID(),
					store.EXPECT().RevokeAccessToken(gomock.Any(), gomock.Any()),
				)
			},
		},
		{
			name:      "ShouldPassExplicitWithExplicitClientEnforceAndEnabledWhenAccessTokenPreferenceAndRefreshTokenTokenFound",
			have:      "foo",
			tokenType: oauth2.AccessToken,
			expected:  nil,
			config:    &oauth2.Config{RevokeRefreshTokensExplicitly: true, EnforceRevokeFlowRevokeRefreshTokensExplicitClient: true},
			client:    &ExplicitClient{&oauth2.DefaultClient{ID: "bar"}, true},
			setup: func(t *testing.T, tc testCase, store *internal.MockTokenRevocationStorage, atStrat *internal.MockAccessTokenStrategy, rtStrat *internal.MockRefreshTokenStrategy, ar *internal.MockAccessRequester) {
				gomock.InOrder(
					atStrat.EXPECT().AccessTokenSignature(gomock.Any(), tc.have),
					store.EXPECT().GetAccessTokenSession(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, oauth2.ErrNotFound),
					rtStrat.EXPECT().RefreshTokenSignature(gomock.Any(), tc.have),
					store.EXPECT().GetRefreshTokenSession(gomock.Any(), gomock.Any(), gomock.Any()).Return(ar, nil),
					ar.EXPECT().GetClient().Return(&oauth2.DefaultClient{ID: "bar"}),
					ar.EXPECT().GetID(),
					store.EXPECT().RevokeRefreshToken(gomock.Any(), gomock.Any()),
					store.EXPECT().RevokeAccessToken(gomock.Any(), gomock.Any()),
				)
			},
		},
		{
			name:      "ShouldPassExplicitWithExplicitClientEnforceAndEnabledWhenRefreshTokenPreferenceAndRefreshTokenTokenFound",
			have:      "foo",
			tokenType: oauth2.RefreshToken,
			expected:  nil,
			config:    &oauth2.Config{RevokeRefreshTokensExplicitly: true, EnforceRevokeFlowRevokeRefreshTokensExplicitClient: true},
			client:    &ExplicitClient{&oauth2.DefaultClient{ID: "bar"}, true},
			setup: func(t *testing.T, tc testCase, store *internal.MockTokenRevocationStorage, atStrat *internal.MockAccessTokenStrategy, rtStrat *internal.MockRefreshTokenStrategy, ar *internal.MockAccessRequester) {
				gomock.InOrder(
					rtStrat.EXPECT().RefreshTokenSignature(gomock.Any(), tc.have),
					store.EXPECT().GetRefreshTokenSession(gomock.Any(), gomock.Any(), gomock.Any()).Return(ar, nil),
					ar.EXPECT().GetClient().Return(&oauth2.DefaultClient{ID: "bar"}),
					ar.EXPECT().GetID(),
					store.EXPECT().RevokeRefreshToken(gomock.Any(), gomock.Any()),
					store.EXPECT().RevokeAccessToken(gomock.Any(), gomock.Any()),
				)
			},
		},

		{
			name:      "ShouldPassWithRefreshTokenPreferencePreferenceAndRefreshTokenFound",
			have:      "foo",
			tokenType: oauth2.RefreshToken,
			expected:  nil,
			client:    &oauth2.DefaultClient{ID: "bar"},
			setup: func(t *testing.T, tc testCase, store *internal.MockTokenRevocationStorage, atStrat *internal.MockAccessTokenStrategy, rtStrat *internal.MockRefreshTokenStrategy, ar *internal.MockAccessRequester) {
				gomock.InOrder(
					rtStrat.EXPECT().RefreshTokenSignature(gomock.Any(), tc.have),
					store.EXPECT().GetRefreshTokenSession(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, oauth2.ErrNotFound),
					atStrat.EXPECT().AccessTokenSignature(gomock.Any(), tc.have),
					store.EXPECT().GetAccessTokenSession(gomock.Any(), gomock.Any(), gomock.Any()).Return(ar, nil),
					ar.EXPECT().GetClient().Return(&oauth2.DefaultClient{ID: "bar"}),
					ar.EXPECT().GetID(),
					store.EXPECT().RevokeRefreshToken(gomock.Any(), gomock.Any()),
					store.EXPECT().RevokeAccessToken(gomock.Any(), gomock.Any()),
				)
			},
		},
		{
			name:      "ShouldPassWithRefreshTokenPreferencePreferenceAndNoTokenFound",
			have:      "foo",
			tokenType: oauth2.RefreshToken,
			expected:  nil,
			client:    &oauth2.DefaultClient{ID: "bar"},
			setup: func(t *testing.T, tc testCase, store *internal.MockTokenRevocationStorage, atStrat *internal.MockAccessTokenStrategy, rtStrat *internal.MockRefreshTokenStrategy, ar *internal.MockAccessRequester) {
				gomock.InOrder(
					rtStrat.EXPECT().RefreshTokenSignature(gomock.Any(), tc.have),
					store.EXPECT().GetRefreshTokenSession(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, oauth2.ErrNotFound),
					atStrat.EXPECT().AccessTokenSignature(gomock.Any(), tc.have),
					store.EXPECT().GetAccessTokenSession(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, oauth2.ErrNotFound),
				)
			},
		},
		{
			name:      "ShouldPassWithRefreshTokenPreferencePreferenceAndNoTokenFound",
			have:      "foo",
			tokenType: oauth2.AccessToken,
			expected:  nil,
			client:    &oauth2.DefaultClient{ID: "bar"},
			setup: func(t *testing.T, tc testCase, store *internal.MockTokenRevocationStorage, atStrat *internal.MockAccessTokenStrategy, rtStrat *internal.MockRefreshTokenStrategy, ar *internal.MockAccessRequester) {
				gomock.InOrder(
					atStrat.EXPECT().AccessTokenSignature(gomock.Any(), tc.have),
					store.EXPECT().GetAccessTokenSession(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, oauth2.ErrNotFound),
					rtStrat.EXPECT().RefreshTokenSignature(gomock.Any(), tc.have),
					store.EXPECT().GetRefreshTokenSession(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, oauth2.ErrNotFound),
				)
			},
		},
		{
			name:      "ShouldPassWithRefreshTokenPreferencePreferenceAndRefreshTokenFoundButInactive",
			have:      "foo",
			tokenType: oauth2.RefreshToken,
			expected:  nil,
			client:    &oauth2.DefaultClient{ID: "bar"},
			setup: func(t *testing.T, tc testCase, store *internal.MockTokenRevocationStorage, atStrat *internal.MockAccessTokenStrategy, rtStrat *internal.MockRefreshTokenStrategy, ar *internal.MockAccessRequester) {
				gomock.InOrder(
					rtStrat.EXPECT().RefreshTokenSignature(gomock.Any(), tc.have),
					store.EXPECT().GetRefreshTokenSession(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, oauth2.ErrInactiveToken),
					atStrat.EXPECT().AccessTokenSignature(gomock.Any(), tc.have),
					store.EXPECT().GetAccessTokenSession(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, oauth2.ErrNotFound),
				)
			},
		},
		{
			name:      "ShouldPassWithAccessTokenPreferencePreferenceAndRefreshTokenFoundButInactive",
			have:      "foo",
			tokenType: oauth2.AccessToken,
			expected:  nil,
			client:    &oauth2.DefaultClient{ID: "bar"},
			setup: func(t *testing.T, tc testCase, store *internal.MockTokenRevocationStorage, atStrat *internal.MockAccessTokenStrategy, rtStrat *internal.MockRefreshTokenStrategy, ar *internal.MockAccessRequester) {
				gomock.InOrder(
					atStrat.EXPECT().AccessTokenSignature(gomock.Any(), tc.have),
					store.EXPECT().GetAccessTokenSession(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, oauth2.ErrNotFound),
					rtStrat.EXPECT().RefreshTokenSignature(gomock.Any(), tc.have),
					store.EXPECT().GetRefreshTokenSession(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, oauth2.ErrInactiveToken),
				)
			},
		},
		{
			name:      "ShouldFailStoreErrorAccessTokenRetrieval",
			have:      "foo",
			tokenType: oauth2.AccessToken,
			expected:  oauth2.ErrTemporarilyUnavailable,
			client:    &oauth2.DefaultClient{ID: "bar"},
			setup: func(t *testing.T, tc testCase, store *internal.MockTokenRevocationStorage, atStrat *internal.MockAccessTokenStrategy, rtStrat *internal.MockRefreshTokenStrategy, ar *internal.MockAccessRequester) {
				gomock.InOrder(
					atStrat.EXPECT().AccessTokenSignature(gomock.Any(), tc.have),
					store.EXPECT().GetAccessTokenSession(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, fmt.Errorf("random error")),
					rtStrat.EXPECT().RefreshTokenSignature(gomock.Any(), tc.have),
					store.EXPECT().GetRefreshTokenSession(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, oauth2.ErrNotFound),
				)
			},
		},
		{
			name:      "ShouldFailStoreErrorRefreshTokenRetrieval",
			have:      "foo",
			tokenType: oauth2.RefreshToken,
			expected:  oauth2.ErrTemporarilyUnavailable,
			client:    &oauth2.DefaultClient{ID: "bar"},
			setup: func(t *testing.T, tc testCase, store *internal.MockTokenRevocationStorage, atStrat *internal.MockAccessTokenStrategy, rtStrat *internal.MockRefreshTokenStrategy, ar *internal.MockAccessRequester) {
				gomock.InOrder(
					rtStrat.EXPECT().RefreshTokenSignature(gomock.Any(), tc.have),
					store.EXPECT().GetRefreshTokenSession(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, fmt.Errorf("random error")),
					atStrat.EXPECT().AccessTokenSignature(gomock.Any(), tc.have),
					store.EXPECT().GetAccessTokenSession(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, oauth2.ErrNotFound),
				)
			},
		},
		{
			name:      "ShouldFailStoreErrorAccessTokenRevocation",
			have:      "foo",
			tokenType: oauth2.AccessToken,
			expected:  oauth2.ErrTemporarilyUnavailable,
			client:    &oauth2.DefaultClient{ID: "bar"},
			setup: func(t *testing.T, tc testCase, store *internal.MockTokenRevocationStorage, atStrat *internal.MockAccessTokenStrategy, rtStrat *internal.MockRefreshTokenStrategy, ar *internal.MockAccessRequester) {
				gomock.InOrder(
					atStrat.EXPECT().AccessTokenSignature(gomock.Any(), tc.have),
					store.EXPECT().GetAccessTokenSession(gomock.Any(), gomock.Any(), gomock.Any()).Return(ar, nil),
					ar.EXPECT().GetClient().Return(&oauth2.DefaultClient{ID: "bar"}),
					ar.EXPECT().GetID(),
					store.EXPECT().RevokeRefreshToken(gomock.Any(), gomock.Any()).Return(oauth2.ErrNotFound),
					store.EXPECT().RevokeAccessToken(gomock.Any(), gomock.Any()).Return(fmt.Errorf("random error")),
				)
			},
		},
		{
			name:      "ShouldFailStoreErrorRefreshTokenRevocation",
			have:      "foo",
			tokenType: oauth2.RefreshToken,
			expected:  oauth2.ErrTemporarilyUnavailable,
			client:    &oauth2.DefaultClient{ID: "bar"},
			setup: func(t *testing.T, tc testCase, store *internal.MockTokenRevocationStorage, atStrat *internal.MockAccessTokenStrategy, rtStrat *internal.MockRefreshTokenStrategy, ar *internal.MockAccessRequester) {
				gomock.InOrder(
					rtStrat.EXPECT().RefreshTokenSignature(gomock.Any(), tc.have),
					store.EXPECT().GetRefreshTokenSession(gomock.Any(), gomock.Any(), gomock.Any()).Return(ar, nil),
					ar.EXPECT().GetClient().Return(&oauth2.DefaultClient{ID: "bar"}),
					ar.EXPECT().GetID(),
					store.EXPECT().RevokeRefreshToken(gomock.Any(), gomock.Any()).Return(fmt.Errorf("random error")),
					store.EXPECT().RevokeAccessToken(gomock.Any(), gomock.Any()).Return(oauth2.ErrNotFound),
				)
			},
		},
		{

			name:      "ShouldPassRefreshTokenPreferenceRefreshTokenFoundButTokenInactive",
			have:      "foo",
			tokenType: oauth2.RefreshToken,
			expected:  nil,
			client:    &oauth2.DefaultClient{ID: "bar"},
			setup: func(t *testing.T, tc testCase, store *internal.MockTokenRevocationStorage, atStrat *internal.MockAccessTokenStrategy, rtStrat *internal.MockRefreshTokenStrategy, ar *internal.MockAccessRequester) {
				rtStrat.EXPECT().RefreshTokenSignature(gomock.Any(), tc.have)
				store.EXPECT().GetRefreshTokenSession(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, oauth2.ErrInactiveToken)

				atStrat.EXPECT().AccessTokenSignature(gomock.Any(), tc.have)
				store.EXPECT().GetAccessTokenSession(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, oauth2.ErrNotFound)
			},
		},
		{
			name:      "ShouldPassAccessTokenPreferenceRefreshTokenFoundButTokenInactive",
			have:      "foo",
			tokenType: oauth2.AccessToken,
			expected:  nil,
			client:    &oauth2.DefaultClient{ID: "bar"},
			setup: func(t *testing.T, tc testCase, store *internal.MockTokenRevocationStorage, atStrat *internal.MockAccessTokenStrategy, rtStrat *internal.MockRefreshTokenStrategy, ar *internal.MockAccessRequester) {

				atStrat.EXPECT().AccessTokenSignature(gomock.Any(), tc.have)
				store.EXPECT().GetAccessTokenSession(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, oauth2.ErrNotFound)

				rtStrat.EXPECT().RefreshTokenSignature(gomock.Any(), tc.have)
				store.EXPECT().GetRefreshTokenSession(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, oauth2.ErrInactiveToken)
			},
		}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			store := internal.NewMockTokenRevocationStorage(ctrl)
			atStrat := internal.NewMockAccessTokenStrategy(ctrl)
			rtStrat := internal.NewMockRefreshTokenStrategy(ctrl)
			ar := internal.NewMockAccessRequester(ctrl)

			defer ctrl.Finish()

			var config *oauth2.Config

			if tc.config == nil {
				config = &oauth2.Config{
					RevokeRefreshTokensExplicitly: false,
				}
			} else {
				config = tc.config
			}

			h := TokenRevocationHandler{
				TokenRevocationStorage: store,
				RefreshTokenStrategy:   rtStrat,
				AccessTokenStrategy:    atStrat,
				Config:                 config,
			}

			tc.setup(t, tc, store, atStrat, rtStrat, ar)

			err := h.RevokeToken(context.TODO(), tc.have, tc.tokenType, tc.client)

			if tc.expected != nil {
				require.EqualError(t, err, tc.expected.Error())
			} else {
				require.NoError(t, err)
			}
		})
	}
}

type ExplicitClient struct {
	*oauth2.DefaultClient

	RevokeRefreshTokensExplicitly bool
}

func (c *ExplicitClient) GetRevokeRefreshTokensExplicitly(ctx context.Context) bool {
	return c.RevokeRefreshTokensExplicitly
}
