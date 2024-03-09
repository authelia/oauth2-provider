// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	. "authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal"
	"authelia.com/provider/oauth2/internal/consts"
)

func TestNewAccessRequest(t *testing.T) {
	testCases := []struct {
		name         string
		header       http.Header
		form         url.Values
		mock         func(ctx gomock.Matcher, handler *internal.MockTokenEndpointHandler, store *internal.MockStorage, hasher *internal.MockHasher, client *DefaultClient)
		method       string
		expectErr    error
		expectStrErr string
		expect       func(client *DefaultClient) *AccessRequest
		handlers     func(handler *internal.MockTokenEndpointHandler) TokenEndpointHandlers
	}{
		{
			name:         "ShouldReturnInvalidRequestWhenNoValues",
			header:       http.Header{},
			expectErr:    ErrInvalidRequest,
			expectStrErr: "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The POST body can not be empty.",
			form:         url.Values{},
			method:       "POST",
		},
		{
			name:   "ShouldReturnInvalidRequestWhenOnlyGrantType",
			header: http.Header{},
			method: "POST",
			form: url.Values{
				consts.FormParameterGrantType: {"foo"},
			},
			expectErr:    ErrInvalidRequest,
			expectStrErr: "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Make sure that the various parameters are correct, be aware of case sensitivity and trim your parameters. Make sure that the client you are using has exactly whitelisted the redirect_uri you specified.",
		},
		{
			name:   "ShouldReturnInvalidRequestWhenEmptyClientID",
			header: http.Header{},
			method: "POST",
			form: url.Values{
				consts.FormParameterGrantType: {"foo"},
				consts.FormParameterClientID:  {""},
			},
			expectErr:    ErrInvalidRequest,
			expectStrErr: "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Make sure that the various parameters are correct, be aware of case sensitivity and trim your parameters. Make sure that the client you are using has exactly whitelisted the redirect_uri you specified.",
		},
		{
			name: "ShouldReturnInvalidClientWhenGetClientError",
			header: http.Header{
				consts.HeaderAuthorization: {basicAuth("foo", "bar")},
			},
			method: "POST",
			form: url.Values{
				consts.FormParameterGrantType: {"foo"},
			},
			expectErr:    ErrInvalidClient,
			expectStrErr: "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method).",
			mock: func(ctx gomock.Matcher, handler *internal.MockTokenEndpointHandler, store *internal.MockStorage, hasher *internal.MockHasher, client *DefaultClient) {
				store.EXPECT().GetClient(gomock.Any(), gomock.Eq("foo")).Return(nil, errors.New(""))
			},
			handlers: func(handler *internal.MockTokenEndpointHandler) TokenEndpointHandlers {
				return TokenEndpointHandlers{handler}
			},
		},
		{
			name: "ShouldReturnInvalidRequestWhenInvalidMethod",
			header: http.Header{
				consts.HeaderAuthorization: {basicAuth("foo", "bar")},
			},
			method: "GET",
			form: url.Values{
				consts.FormParameterGrantType: {"foo"},
			},
			expectErr:    ErrInvalidRequest,
			expectStrErr: "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. HTTP method is 'GET', expected 'POST'.",
		},
		{
			name: "ShouldReturnInvalidClientWhenBadClientSecret",
			header: http.Header{
				consts.HeaderAuthorization: {basicAuth("foo", "bar")},
			},
			method: "POST",
			form: url.Values{
				consts.FormParameterGrantType: {"foo"},
			},
			expectErr:    ErrInvalidClient,
			expectStrErr: "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method). crypto/bcrypt: hashedPassword is not the hash of the given password",
			mock: func(ctx gomock.Matcher, handler *internal.MockTokenEndpointHandler, store *internal.MockStorage, hasher *internal.MockHasher, client *DefaultClient) {
				store.EXPECT().GetClient(gomock.Any(), gomock.Eq("foo")).Return(client, nil)
				client.Public = false
				client.ClientSecret = testClientSecretFoo
			},
			handlers: func(handler *internal.MockTokenEndpointHandler) TokenEndpointHandlers {
				return TokenEndpointHandlers{handler}
			},
		},
		{
			name: "ShouldReturnErrorWhenHandleTokenEndpointError",
			header: http.Header{
				consts.HeaderAuthorization: {basicAuth("foo", "foo")},
			},
			method: "POST",
			form: url.Values{
				consts.FormParameterGrantType: {"foo"},
			},
			expectErr:    ErrServerError,
			expectStrErr: "The authorization server encountered an unexpected condition that prevented it from fulfilling the request.",
			mock: func(ctx gomock.Matcher, handler *internal.MockTokenEndpointHandler, store *internal.MockStorage, hasher *internal.MockHasher, client *DefaultClient) {
				store.EXPECT().GetClient(gomock.Any(), gomock.Eq("foo")).Return(client, nil)
				client.Public = false
				client.ClientSecret = testClientSecretFoo
				handler.EXPECT().HandleTokenEndpointRequest(gomock.Any(), gomock.Any()).Return(ErrServerError)
			},
			handlers: func(handler *internal.MockTokenEndpointHandler) TokenEndpointHandlers {
				return TokenEndpointHandlers{handler}
			},
		},
		{
			name: "ShouldHandleConfidentialClientSuccessfully",
			header: http.Header{
				consts.HeaderAuthorization: {basicAuth("foo", "foo")},
			},
			method: "POST",
			form: url.Values{
				consts.FormParameterGrantType: {"foo"},
			},
			mock: func(ctx gomock.Matcher, handler *internal.MockTokenEndpointHandler, store *internal.MockStorage, hasher *internal.MockHasher, client *DefaultClient) {
				store.EXPECT().GetClient(gomock.Any(), gomock.Eq("foo")).Return(client, nil)
				client.Public = false
				client.ClientSecret = testClientSecretFoo
				handler.EXPECT().HandleTokenEndpointRequest(gomock.Any(), gomock.Any()).Return(nil)
			},
			handlers: func(handler *internal.MockTokenEndpointHandler) TokenEndpointHandlers {
				return TokenEndpointHandlers{handler}
			},
			expect: func(client *DefaultClient) *AccessRequest {
				return &AccessRequest{
					GrantTypes: Arguments{"foo"},
					Request: Request{
						Client: client,
					},
				}
			},
		},
		{
			name: "ShouldHandlePublicClientTypeSuccessfully",
			header: http.Header{
				consts.HeaderAuthorization: {basicAuth("foo", "")},
			},
			method: "POST",
			form: url.Values{
				consts.FormParameterGrantType: {"foo"},
			},
			mock: func(ctx gomock.Matcher, handler *internal.MockTokenEndpointHandler, store *internal.MockStorage, hasher *internal.MockHasher, client *DefaultClient) {
				store.EXPECT().GetClient(gomock.Any(), gomock.Eq("foo")).Return(client, nil)
				client.Public = true
				handler.EXPECT().HandleTokenEndpointRequest(gomock.Any(), gomock.Any()).Return(nil)
			},
			handlers: func(handler *internal.MockTokenEndpointHandler) TokenEndpointHandlers {
				return TokenEndpointHandlers{handler}
			},
			expect: func(client *DefaultClient) *AccessRequest {
				return &AccessRequest{
					GrantTypes: Arguments{"foo"},
					Request: Request{
						Client: client,
					},
				}
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			store := internal.NewMockStorage(ctrl)
			handler := internal.NewMockTokenEndpointHandler(ctrl)
			handler.EXPECT().CanHandleTokenEndpointRequest(gomock.Any(), gomock.Any()).Return(true).AnyTimes()
			handler.EXPECT().CanSkipClientAuth(gomock.Any(), gomock.Any()).Return(false).AnyTimes()
			hasher := internal.NewMockHasher(ctrl)
			defer ctrl.Finish()

			ctx := gomock.AssignableToTypeOf(context.WithValue(context.TODO(), ContextKey("test"), nil))

			client := &DefaultClient{}
			config := &Config{AudienceMatchingStrategy: DefaultAudienceMatchingStrategy}
			provider := &Fosite{Store: store, Config: config}

			r := &http.Request{
				Header:   tc.header,
				PostForm: tc.form,
				Form:     tc.form,
				Method:   tc.method,
			}

			if tc.mock != nil {
				tc.mock(ctx, handler, store, hasher, client)
			}

			if tc.handlers != nil {
				config.TokenEndpointHandlers = tc.handlers(handler)
			}

			ar, err := provider.NewAccessRequest(context.TODO(), r, new(DefaultSession))

			if tc.expectErr != nil {
				assert.EqualError(t, err, tc.expectErr.Error())
				assert.EqualError(t, ErrorToDebugRFC6749Error(err), tc.expectStrErr)
			} else {
				require.NoError(t, err)
				AssertObjectKeysEqual(t, tc.expect(client), ar, "GrantTypes", "Client")
				assert.NotNil(t, ar.GetRequestedAt())
			}
		})
	}
}

func TestNewAccessRequestWithoutClientAuth(t *testing.T) {
	ctrl := gomock.NewController(t)
	store := internal.NewMockStorage(ctrl)
	handler := internal.NewMockTokenEndpointHandler(ctrl)
	handler.EXPECT().CanHandleTokenEndpointRequest(gomock.Any(), gomock.Any()).Return(true).AnyTimes()
	handler.EXPECT().CanSkipClientAuth(gomock.Any(), gomock.Any()).Return(true).AnyTimes()
	defer ctrl.Finish()

	client := &DefaultClient{}
	anotherClient := &DefaultClient{ID: "another", ClientSecret: testClientSecretBar}
	config := &Config{AudienceMatchingStrategy: DefaultAudienceMatchingStrategy}
	provider := &Fosite{Store: store, Config: config}
	for k, c := range []struct {
		header    http.Header
		form      url.Values
		mock      func()
		method    string
		expectErr error
		expect    *AccessRequest
		handlers  TokenEndpointHandlers
	}{
		// No grant type -> error
		{
			form: url.Values{},
			mock: func() {
				store.EXPECT().GetClient(gomock.Any(), gomock.Any()).Times(0)
			},
			method:    "POST",
			expectErr: ErrInvalidRequest,
		},
		// No registered handlers -> error
		{
			form: url.Values{
				consts.FormParameterGrantType: {"foo"},
			},
			mock: func() {
				store.EXPECT().GetClient(gomock.Any(), gomock.Any()).Times(0)
			},
			method:    "POST",
			expectErr: ErrInvalidRequest,
			handlers:  TokenEndpointHandlers{},
		},
		// Handler can skip client auth and ignores missing client.
		{
			header: http.Header{
				consts.HeaderAuthorization: {basicAuth("foo", "bar")},
			},
			form: url.Values{
				consts.FormParameterGrantType: {"foo"},
			},
			mock: func() {
				// despite error from storage, we should success, because client auth is not required
				store.EXPECT().GetClient(gomock.Any(), "foo").Return(nil, errors.New("no client")).Times(1)
				handler.EXPECT().HandleTokenEndpointRequest(gomock.Any(), gomock.Any()).Return(nil)
			},
			method: "POST",
			expect: &AccessRequest{
				GrantTypes: Arguments{"foo"},
				Request: Request{
					Client: client,
				},
			},
			handlers: TokenEndpointHandlers{handler},
		},
		// Should pass if no auth is set in the header and can skip!
		{
			form: url.Values{
				consts.FormParameterGrantType: {"foo"},
			},
			mock: func() {
				handler.EXPECT().HandleTokenEndpointRequest(gomock.Any(), gomock.Any()).Return(nil)
			},
			method: "POST",
			expect: &AccessRequest{
				GrantTypes: Arguments{"foo"},
				Request: Request{
					Client: client,
				},
			},
			handlers: TokenEndpointHandlers{handler},
		},
		// Should also pass if client auth is set!
		{
			header: http.Header{
				consts.HeaderAuthorization: {basicAuth("foo", "bar")},
			},
			form: url.Values{
				consts.FormParameterGrantType: {"foo"},
			},
			mock: func() {
				store.EXPECT().GetClient(gomock.Any(), "foo").Return(anotherClient, nil).Times(1)
				handler.EXPECT().HandleTokenEndpointRequest(gomock.Any(), gomock.Any()).Return(nil)
			},
			method: "POST",
			expect: &AccessRequest{
				GrantTypes: Arguments{"foo"},
				Request: Request{
					Client: anotherClient,
				},
			},
			handlers: TokenEndpointHandlers{handler},
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
			ctx := NewContext()
			config.TokenEndpointHandlers = c.handlers
			ar, err := provider.NewAccessRequest(ctx, r, new(DefaultSession))

			if c.expectErr != nil {
				assert.EqualError(t, err, c.expectErr.Error())
			} else {
				require.NoError(t, err)
				AssertObjectKeysEqual(t, c.expect, ar, "GrantTypes", "Client")
				assert.NotNil(t, ar.GetRequestedAt())
			}
		})
	}
}

// In this test case one handler requires client auth and another handler not.
func TestNewAccessRequestWithMixedClientAuth(t *testing.T) {
	ctrl := gomock.NewController(t)
	store := internal.NewMockStorage(ctrl)

	handlerWithClientAuth := internal.NewMockTokenEndpointHandler(ctrl)
	handlerWithClientAuth.EXPECT().CanHandleTokenEndpointRequest(gomock.Any(), gomock.Any()).Return(true).AnyTimes()
	handlerWithClientAuth.EXPECT().CanSkipClientAuth(gomock.Any(), gomock.Any()).Return(false).AnyTimes()

	handlerWithoutClientAuth := internal.NewMockTokenEndpointHandler(ctrl)
	handlerWithoutClientAuth.EXPECT().CanHandleTokenEndpointRequest(gomock.Any(), gomock.Any()).Return(true).AnyTimes()
	handlerWithoutClientAuth.EXPECT().CanSkipClientAuth(gomock.Any(), gomock.Any()).Return(true).AnyTimes()

	defer ctrl.Finish()

	client := &DefaultClient{}
	config := &Config{AudienceMatchingStrategy: DefaultAudienceMatchingStrategy}
	provider := &Fosite{Store: store, Config: config}
	for k, c := range []struct {
		header    http.Header
		form      url.Values
		mock      func()
		method    string
		expectErr error
		expect    *AccessRequest
		handlers  TokenEndpointHandlers
	}{
		{
			header: http.Header{
				consts.HeaderAuthorization: {basicAuth("foo", "bar")},
			},
			form: url.Values{
				consts.FormParameterGrantType: {"foo"},
			},
			mock: func() {
				store.EXPECT().GetClient(gomock.Any(), gomock.Eq("foo")).Return(client, nil)
				client.Public = false
				client.ClientSecret = testClientSecretFoo
				handlerWithoutClientAuth.EXPECT().HandleTokenEndpointRequest(gomock.Any(), gomock.Any()).Return(nil)
			},
			method:    "POST",
			expectErr: ErrInvalidClient,
			handlers:  TokenEndpointHandlers{handlerWithoutClientAuth, handlerWithClientAuth},
		},
		{
			header: http.Header{
				consts.HeaderAuthorization: {basicAuth("foo", "bar")},
			},
			form: url.Values{
				consts.FormParameterGrantType: {"foo"},
			},
			mock: func() {
				store.EXPECT().GetClient(gomock.Any(), gomock.Eq("foo")).Return(client, nil)
				client.Public = false
				client.ClientSecret = testClientSecretBar
				handlerWithoutClientAuth.EXPECT().HandleTokenEndpointRequest(gomock.Any(), gomock.Any()).Return(nil)
				handlerWithClientAuth.EXPECT().HandleTokenEndpointRequest(gomock.Any(), gomock.Any()).Return(nil)
			},
			method: "POST",
			expect: &AccessRequest{
				GrantTypes: Arguments{"foo"},
				Request: Request{
					Client: client,
				},
			},
			handlers: TokenEndpointHandlers{handlerWithoutClientAuth, handlerWithClientAuth},
		},
		{
			header: http.Header{},
			form: url.Values{
				consts.FormParameterGrantType: {"foo"},
			},
			mock: func() {
				store.EXPECT().GetClient(gomock.Any(), gomock.Any()).Times(0)
				handlerWithoutClientAuth.EXPECT().HandleTokenEndpointRequest(gomock.Any(), gomock.Any()).Return(nil)
			},
			method:    "POST",
			expectErr: ErrInvalidRequest,
			handlers:  TokenEndpointHandlers{handlerWithoutClientAuth, handlerWithClientAuth},
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
			config.TokenEndpointHandlers = c.handlers
			ar, err := provider.NewAccessRequest(context.TODO(), r, new(DefaultSession))

			if c.expectErr != nil {
				assert.EqualError(t, err, c.expectErr.Error())
			} else {
				require.NoError(t, err)
				AssertObjectKeysEqual(t, c.expect, ar, "GrantTypes", "Client")
				assert.NotNil(t, ar.GetRequestedAt())
			}
		})
	}
}

//nolint:unparam
func basicAuth(username, password string) string {
	return prefixSchemeBasic + base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", username, password)))
}

const (
	prefixSchemeBasic = "Basic "
)
