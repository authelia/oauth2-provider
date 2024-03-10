// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"

	. "authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/testing/mock"
)

func TestNewRevocationRequest(t *testing.T) {
	ctrl := gomock.NewController(t)
	store := mock.NewMockStorage(ctrl)
	handler := mock.NewMockRevocationHandler(ctrl)
	defer ctrl.Finish()

	client := &DefaultClient{}
	config := &Config{}
	provider := &Fosite{Store: store, Config: config}
	for k, c := range []struct {
		header       http.Header
		form         url.Values
		mock         func()
		method       string
		expectErr    error
		expectStrErr string
		expect       *AccessRequest
		handlers     RevocationHandlers
	}{
		{
			header:       http.Header{},
			expectErr:    ErrInvalidRequest,
			expectStrErr: "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. HTTP method is 'GET' but expected 'POST'.",
			method:       "GET",
			mock:         func() {},
		},
		{
			header:       http.Header{},
			expectErr:    ErrInvalidRequest,
			expectStrErr: "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The POST body can not be empty.",
			method:       "POST",
			mock:         func() {},
		},
		{
			header: http.Header{},
			method: "POST",
			form: url.Values{
				consts.FormParameterToken: {"foo"},
			},
			mock:         func() {},
			expectErr:    ErrInvalidRequest,
			expectStrErr: "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Client Credentials missing or malformed. The Client ID was missing from the request but it is required when there is no client assertion.",
		},
		{
			header: http.Header{
				consts.HeaderAuthorization: {basicAuth("foo", "bar")},
			},
			method: "POST",
			form: url.Values{
				consts.FormParameterToken: {"foo"},
			},
			expectErr:    ErrInvalidClient,
			expectStrErr: "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method).",
			mock: func() {
				store.EXPECT().GetClient(gomock.Any(), gomock.Eq("foo")).Return(nil, errors.New(""))
			},
		},
		{
			header: http.Header{
				consts.HeaderAuthorization: {basicAuth("foo", "bar")},
			},
			method: "POST",
			form: url.Values{
				consts.FormParameterToken: {"foo"},
			},
			expectErr:    ErrInvalidClient,
			expectStrErr: "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method). crypto/bcrypt: hashedPassword is not the hash of the given password",
			mock: func() {
				store.EXPECT().GetClient(gomock.Any(), gomock.Eq("foo")).Return(client, nil)
				client.ClientSecret = testClientSecretFoo
				client.Public = false
			},
		},
		{
			header: http.Header{
				consts.HeaderAuthorization: {basicAuth("foo", "bar")},
			},
			method: "POST",
			form: url.Values{
				consts.FormParameterToken: {"foo"},
			},
			expectErr: nil,
			mock: func() {
				store.EXPECT().GetClient(gomock.Any(), gomock.Eq("foo")).Return(client, nil)
				client.ClientSecret = testClientSecretBar
				client.Public = false
				handler.EXPECT().RevokeToken(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
			},
			handlers: RevocationHandlers{handler},
		},
		{
			header: http.Header{
				consts.HeaderAuthorization: {basicAuth("foo", "bar")},
			},
			method: "POST",
			form: url.Values{
				consts.FormParameterToken:         {"foo"},
				consts.FormParameterTokenTypeHint: {consts.TokenTypeAccessToken},
			},
			expectErr: nil,
			mock: func() {
				store.EXPECT().GetClient(gomock.Any(), gomock.Eq("foo")).Return(client, nil)
				client.ClientSecret = testClientSecretBar
				client.Public = false
				handler.EXPECT().RevokeToken(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
			},
			handlers: RevocationHandlers{handler},
		},
		{
			header: http.Header{
				consts.HeaderAuthorization: {basicAuth("foo", "")},
			},
			method: "POST",
			form: url.Values{
				consts.FormParameterToken:         {"foo"},
				consts.FormParameterTokenTypeHint: {consts.TokenTypeRefreshToken},
			},
			expectErr: nil,
			mock: func() {
				store.EXPECT().GetClient(gomock.Any(), gomock.Eq("foo")).Return(client, nil)
				client.Public = true
				handler.EXPECT().RevokeToken(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
			},
			handlers: RevocationHandlers{handler},
		},
		{
			header: http.Header{
				consts.HeaderAuthorization: {basicAuth("foo", "bar")},
			},
			method: "POST",
			form: url.Values{
				consts.FormParameterToken:         {"foo"},
				consts.FormParameterTokenTypeHint: {consts.TokenTypeRefreshToken},
			},
			expectErr: nil,
			mock: func() {
				store.EXPECT().GetClient(gomock.Any(), gomock.Eq("foo")).Return(client, nil)
				client.ClientSecret = testClientSecretBar
				client.Public = false
				handler.EXPECT().RevokeToken(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
			},
			handlers: RevocationHandlers{handler},
		},
		{
			header: http.Header{
				consts.HeaderAuthorization: {basicAuth("foo", "bar")},
			},
			method: "POST",
			form: url.Values{
				consts.FormParameterToken:         {"foo"},
				consts.FormParameterTokenTypeHint: {"bar"},
			},
			expectErr: nil,
			mock: func() {
				store.EXPECT().GetClient(gomock.Any(), gomock.Eq("foo")).Return(client, nil)
				client.ClientSecret = testClientSecretBar
				client.Public = false
				handler.EXPECT().RevokeToken(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
			},
			handlers: RevocationHandlers{handler},
		},
	} {
		t.Run(fmt.Sprintf("case=%d", k), func(t *testing.T) {
			r := &http.Request{
				Header:   c.header,
				PostForm: c.form,
				Form:     c.form,
				Method:   c.method,
			}
			c.mock()

			config.RevocationHandlers = c.handlers
			err := provider.NewRevocationRequest(context.TODO(), r)

			if c.expectErr != nil {
				assert.EqualError(t, err, c.expectErr.Error())
				assert.EqualError(t, ErrorToDebugRFC6749Error(err), c.expectStrErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestWriteRevocationResponse(t *testing.T) {
	ctrl := gomock.NewController(t)
	store := mock.NewMockStorage(ctrl)
	defer ctrl.Finish()

	config := &Config{}
	provider := &Fosite{Store: store, Config: config}

	testCases := []struct {
		name     string
		have     error
		expected int
	}{
		{
			"ShouldHandleNil",
			nil,
			http.StatusOK,
		},
		{
			"ShouldHandleErrInvalidRequest",
			ErrInvalidRequest,
			-1,
		},
		{
			"ShouldHandleErrInvalidClient",
			ErrInvalidClient,
			-1,
		},
		{
			"ShouldHandleErrInvalidGrant",
			ErrInvalidGrant,
			-1,
		},
		{
			"ShouldHandleErrUnauthorizedClient",
			ErrUnauthorizedClient,
			-1,
		},
		{
			"ShouldHandleErrUnsupportedGrantType",
			ErrUnsupportedGrantType,
			-1,
		},
		{
			"ShouldHandleErrInvalidScope",
			ErrInvalidScope,
			-1,
		},
		{
			"ShouldHandleOtherErrors",
			fmt.Errorf("example"),
			500,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rw := httptest.NewRecorder()

			provider.WriteRevocationResponse(context.Background(), rw, tc.have)

			expected := tc.expected

			var err *RFC6749Error

			if errors.As(tc.have, &err) {
				if expected == -1 {
					expected = err.CodeField
				}
			}

			assert.Equal(t, expected, rw.Code)

			if err != nil {
				assert.Contains(t, rw.Body.String(), err.ErrorField)
				assert.Contains(t, rw.Body.String(), err.HintField)
			}
		})
	}
}
