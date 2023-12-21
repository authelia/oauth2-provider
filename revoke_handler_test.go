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
	"authelia.com/provider/oauth2/internal"
	"authelia.com/provider/oauth2/internal/consts"
)

func TestNewRevocationRequest(t *testing.T) {
	ctrl := gomock.NewController(t)
	store := internal.NewMockStorage(ctrl)
	handler := internal.NewMockRevocationHandler(ctrl)
	hasher := internal.NewMockHasher(ctrl)
	defer ctrl.Finish()

	ctx := gomock.AssignableToTypeOf(context.WithValue(context.TODO(), ContextKey("test"), nil))

	client := &DefaultClient{}
	config := &Config{ClientSecretsHasher: hasher}
	provider := &Fosite{Store: store, Config: config}
	for k, c := range []struct {
		header    http.Header
		form      url.Values
		mock      func()
		method    string
		expectErr error
		expect    *AccessRequest
		handlers  RevocationHandlers
	}{
		{
			header:    http.Header{},
			expectErr: ErrInvalidRequest,
			method:    "GET",
			mock:      func() {},
		},
		{
			header:    http.Header{},
			expectErr: ErrInvalidRequest,
			method:    "POST",
			mock:      func() {},
		},
		{
			header: http.Header{},
			method: "POST",
			form: url.Values{
				consts.FormParameterToken: {"foo"},
			},
			mock:      func() {},
			expectErr: ErrInvalidRequest,
		},
		{
			header: http.Header{
				consts.HeaderAuthorization: {basicAuth("foo", "bar")},
			},
			method: "POST",
			form: url.Values{
				consts.FormParameterToken: {"foo"},
			},
			expectErr: ErrInvalidClient,
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
			expectErr: ErrInvalidClient,
			mock: func() {
				store.EXPECT().GetClient(gomock.Any(), gomock.Eq("foo")).Return(client, nil)
				client.Secret = []byte("foo")
				client.Public = false
				hasher.EXPECT().Compare(ctx, gomock.Eq([]byte("foo")), gomock.Eq([]byte("bar"))).Return(errors.New(""))
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
				client.Secret = []byte("foo")
				client.Public = false
				hasher.EXPECT().Compare(ctx, gomock.Eq([]byte("foo")), gomock.Eq([]byte("bar"))).Return(nil)
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
				client.Secret = []byte("foo")
				client.Public = false
				hasher.EXPECT().Compare(ctx, gomock.Eq([]byte("foo")), gomock.Eq([]byte("bar"))).Return(nil)
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
				client.Secret = []byte("foo")
				client.Public = false
				hasher.EXPECT().Compare(ctx, gomock.Eq([]byte("foo")), gomock.Eq([]byte("bar"))).Return(nil)
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
				client.Secret = []byte("foo")
				client.Public = false
				hasher.EXPECT().Compare(ctx, gomock.Eq([]byte("foo")), gomock.Eq([]byte("bar"))).Return(nil)
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
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestWriteRevocationResponse(t *testing.T) {
	ctrl := gomock.NewController(t)
	store := internal.NewMockStorage(ctrl)
	hasher := internal.NewMockHasher(ctrl)
	defer ctrl.Finish()

	config := &Config{ClientSecretsHasher: hasher}
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
