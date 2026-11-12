// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	. "authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/testing/mock"
)

func TestNewAccessResponse(t *testing.T) {
	testCases := []struct {
		name         string
		emptyHandler bool
		mock         func(handler *mock.MockTokenEndpointHandler)
		err          string
		expect       AccessResponder
	}{
		{
			name:         "ShouldFailNoHandlers",
			emptyHandler: true,
			mock:         func(handler *mock.MockTokenEndpointHandler) {},
			err:          "The authorization server encountered an unexpected condition that prevented it from fulfilling the request. An internal server occurred while trying to complete the request. Access token or token type not set by TokenEndpointHandlers.",
		},
		{
			name: "ShouldFailHandlerReturnsError",
			mock: func(handler *mock.MockTokenEndpointHandler) {
				handler.EXPECT().PopulateTokenEndpointResponse(gomock.Any(), gomock.Any(), gomock.Any()).Return(ErrServerError)
			},
			err: "The authorization server encountered an unexpected condition that prevented it from fulfilling the request.",
		},
		{
			name: "ShouldFailHandlerSetsNoToken",
			mock: func(handler *mock.MockTokenEndpointHandler) {
				handler.EXPECT().PopulateTokenEndpointResponse(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
			},
			err: "The authorization server encountered an unexpected condition that prevented it from fulfilling the request. An internal server occurred while trying to complete the request. Access token or token type not set by TokenEndpointHandlers.",
		},
		{
			name: "ShouldFailHandlerSetsOnlyAccessToken",
			mock: func(handler *mock.MockTokenEndpointHandler) {
				handler.EXPECT().PopulateTokenEndpointResponse(gomock.Any(), gomock.Any(), gomock.Any()).Do(func(_ context.Context, _ AccessRequester, responder AccessResponder) {
					responder.SetAccessToken("foo")
				}).Return(nil)
			},
			err: "The authorization server encountered an unexpected condition that prevented it from fulfilling the request. An internal server occurred while trying to complete the request. Access token or token type not set by TokenEndpointHandlers.",
		},
		{
			name: "ShouldContinueWhenHandlerReturnsErrUnknownRequest",
			mock: func(handler *mock.MockTokenEndpointHandler) {
				handler.EXPECT().PopulateTokenEndpointResponse(gomock.Any(), gomock.Any(), gomock.Any()).Return(ErrUnknownRequest)
			},
			err: "The authorization server encountered an unexpected condition that prevented it from fulfilling the request. An internal server occurred while trying to complete the request. Access token or token type not set by TokenEndpointHandlers.",
		},
		{
			name: "ShouldPass",
			mock: func(handler *mock.MockTokenEndpointHandler) {
				handler.EXPECT().PopulateTokenEndpointResponse(gomock.Any(), gomock.Any(), gomock.Any()).Do(func(_ context.Context, _ AccessRequester, responder AccessResponder) {
					responder.SetAccessToken("foo")
					responder.SetTokenType("bar")
				}).Return(nil)
			},
			expect: &AccessResponse{
				Extra:       map[string]any{},
				AccessToken: "foo",
				TokenType:   "bar",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			handler := mock.NewMockTokenEndpointHandler(ctrl)

			config := &Config{}
			if tc.emptyHandler {
				config.TokenEndpointHandlers = TokenEndpointHandlers{}
			} else {
				config.TokenEndpointHandlers = TokenEndpointHandlers{handler}
			}
			provider := &Fosite{Config: config}

			tc.mock(handler)

			actual, err := provider.NewAccessResponse(t.Context(), NewAccessRequest(&DefaultSession{}))

			if tc.err != "" {
				assert.Nil(t, actual)
				assert.EqualError(t, ErrorToDebugRFC6749Error(err), tc.err)

				return
			}

			require.NoError(t, ErrorToDebugRFC6749Error(err))
			assert.Equal(t, tc.expect, actual)
		})
	}
}

func TestNewAccessResponseRefreshTokenExpirationParameters(t *testing.T) {
	now := time.Now().UTC()

	testCases := []struct {
		name      string
		grant     string
		set       func(responder AccessResponder)
		deadline  time.Duration
		disable   bool
		timeout   bool
		authz     bool
		timeoutIs time.Duration
	}{
		{name: "ShouldSetForAnIssuedRefreshToken", grant: "authorization_code", set: func(r AccessResponder) { r.SetExtra("refresh_token", "rt") }, timeout: true, timeoutIs: time.Hour},
		{name: "ShouldSetBothWithADeadline", grant: "authorization_code", set: func(r AccessResponder) { r.SetExtra("refresh_token", "rt") }, deadline: 10 * time.Minute, timeout: true, authz: true, timeoutIs: 10 * time.Minute},
		{name: "ShouldSetForARefreshGrantWithoutANewToken", grant: "refresh_token", set: func(r AccessResponder) {}, timeout: true, timeoutIs: time.Hour},
		{name: "ShouldSetForAnExchangedRefreshToken", grant: "urn:ietf:params:oauth:grant-type:token-exchange", set: func(r AccessResponder) {
			r.SetExtra("issued_token_type", "urn:ietf:params:oauth:token-type:refresh_token")
		}, timeout: true, timeoutIs: time.Hour},
		{name: "ShouldNotSetForClientCredentials", grant: "client_credentials", set: func(r AccessResponder) {
			r.SetExtra("issued_token_type", "urn:ietf:params:oauth:token-type:access_token")
		}},
		{name: "ShouldNotSetWhenDisabledWithARefreshToken", grant: "authorization_code", set: func(r AccessResponder) { r.SetExtra("refresh_token", "rt") }, disable: true},
		{name: "ShouldNotSetWhenDisabledOnTheRefreshGrant", grant: "refresh_token", set: func(r AccessResponder) {}, deadline: time.Minute, disable: true},
		{name: "ShouldNotSetWhenDisabledOnAnExchange", grant: "urn:ietf:params:oauth:grant-type:token-exchange", set: func(r AccessResponder) {
			r.SetExtra("issued_token_type", "urn:ietf:params:oauth:token-type:refresh_token")
		}, disable: true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			handler := mock.NewMockTokenEndpointHandler(ctrl)
			handler.EXPECT().PopulateTokenEndpointResponse(gomock.Any(), gomock.Any(), gomock.Any()).Do(func(_ context.Context, _ AccessRequester, responder AccessResponder) {
				responder.SetAccessToken("foo")
				responder.SetTokenType("bar")
				tc.set(responder)
			}).Return(nil)

			session := &DefaultSession{}
			session.SetExpiresAt(RefreshToken, now.Add(time.Hour))

			if tc.deadline != 0 {
				session.ExpiryDeadline = now.Add(tc.deadline)
			}

			request := NewAccessRequest(session)
			request.GrantTypes = Arguments{tc.grant}

			provider := &Fosite{Config: &Config{
				TokenEndpointHandlers:                   TokenEndpointHandlers{handler},
				DisableRefreshTokenExpirationParameters: tc.disable,
			}}

			actual, err := provider.NewAccessResponse(t.Context(), request)
			require.NoError(t, err)

			timeout, hasTimeout := actual.GetExtra("refresh_token_timeout").(int64)
			_, hasAuthz := actual.GetExtra("authorization_expires_in").(int64)

			assert.Equal(t, tc.timeout, hasTimeout)
			assert.Equal(t, tc.authz, hasAuthz)

			if tc.timeout {
				assert.InDelta(t, tc.timeoutIs.Seconds(), float64(timeout), 2)
			}
		})
	}
}
