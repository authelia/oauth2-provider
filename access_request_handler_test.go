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
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/testing/mock"
)

func TestNewAccessRequest(t *testing.T) {
	testCases := []struct {
		name         string
		header       http.Header
		form         url.Values
		mock         func(ctx gomock.Matcher, handler *mock.MockTokenEndpointHandler, store *mock.MockStorage, client *DefaultClient)
		method       string
		expectErr    error
		expectStrErr string
		expect       func(client *DefaultClient) *AccessRequest
		handlers     func(handler *mock.MockTokenEndpointHandler) TokenEndpointHandlers
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
				consts.FormParameterClientID:  {"bar"},
				consts.FormParameterGrantType: {"foo"},
			},
			mock: func(ctx gomock.Matcher, handler *mock.MockTokenEndpointHandler, store *mock.MockStorage, client *DefaultClient) {
				store.EXPECT().GetClient(ctx, gomock.Eq("bar")).Return(&DefaultClient{ID: "bar"}, nil)
			},
			expectErr:    ErrInvalidRequest,
			expectStrErr: "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Make sure that the various parameters are correct, be aware of case sensitivity and trim your parameters. Make sure that the client you are using has exactly whitelisted the redirect_uri you specified. The client with id 'bar' requested grant type 'foo' which is invalid, unknown, not supported, or not configured to be handled.",
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
			expectStrErr: "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Make sure that the various parameters are correct, be aware of case sensitivity and trim your parameters. Make sure that the client you are using has exactly whitelisted the redirect_uri you specified. The client with id '' requested grant type 'foo' which is invalid, unknown, not supported, or not configured to be handled.",
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
			mock: func(ctx gomock.Matcher, handler *mock.MockTokenEndpointHandler, store *mock.MockStorage, client *DefaultClient) {
				store.EXPECT().GetClient(gomock.Any(), gomock.Eq("foo")).Return(nil, errors.New(""))
			},
			handlers: func(handler *mock.MockTokenEndpointHandler) TokenEndpointHandlers {
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
			mock: func(ctx gomock.Matcher, handler *mock.MockTokenEndpointHandler, store *mock.MockStorage, client *DefaultClient) {
				store.EXPECT().GetClient(gomock.Any(), gomock.Eq("foo")).Return(client, nil)
				client.Public = false
				client.ClientSecret = testClientSecretFoo
			},
			handlers: func(handler *mock.MockTokenEndpointHandler) TokenEndpointHandlers {
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
			mock: func(ctx gomock.Matcher, handler *mock.MockTokenEndpointHandler, store *mock.MockStorage, client *DefaultClient) {
				store.EXPECT().GetClient(gomock.Any(), gomock.Eq("foo")).Return(client, nil)
				client.Public = false
				client.ClientSecret = testClientSecretFoo
				handler.EXPECT().HandleTokenEndpointRequest(gomock.Any(), gomock.Any()).Return(ErrServerError)
			},
			handlers: func(handler *mock.MockTokenEndpointHandler) TokenEndpointHandlers {
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
			mock: func(ctx gomock.Matcher, handler *mock.MockTokenEndpointHandler, store *mock.MockStorage, client *DefaultClient) {
				store.EXPECT().GetClient(gomock.Any(), gomock.Eq("foo")).Return(client, nil)
				client.Public = false
				client.ClientSecret = testClientSecretFoo
				handler.EXPECT().HandleTokenEndpointRequest(gomock.Any(), gomock.Any()).Return(nil)
			},
			handlers: func(handler *mock.MockTokenEndpointHandler) TokenEndpointHandlers {
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
			mock: func(ctx gomock.Matcher, handler *mock.MockTokenEndpointHandler, store *mock.MockStorage, client *DefaultClient) {
				store.EXPECT().GetClient(gomock.Any(), gomock.Eq("foo")).Return(client, nil)
				client.Public = true
				handler.EXPECT().HandleTokenEndpointRequest(gomock.Any(), gomock.Any()).Return(nil)
			},
			handlers: func(handler *mock.MockTokenEndpointHandler) TokenEndpointHandlers {
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
			store := mock.NewMockStorage(ctrl)

			handler := mock.NewMockTokenEndpointHandler(ctrl)
			handler.EXPECT().CanHandleTokenEndpointRequest(gomock.Any(), gomock.Any()).Return(true).AnyTimes()
			handler.EXPECT().CanSkipClientAuth(gomock.Any(), gomock.Any()).Return(false).AnyTimes()
			defer ctrl.Finish()

			ctx := gomock.AssignableToTypeOf(context.WithValue(t.Context(), ContextKey("test"), nil))

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
				tc.mock(ctx, handler, store, client)
			}

			if tc.handlers != nil {
				config.TokenEndpointHandlers = tc.handlers(handler)
			}

			ar, err := provider.NewAccessRequest(t.Context(), r, new(DefaultSession))

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
	client := &DefaultClient{}
	anotherClient := &DefaultClient{ID: "another", ClientSecret: testClientSecretBar}

	testCases := []struct {
		name     string
		header   http.Header
		form     url.Values
		mock     func(store *mock.MockStorage, handler *mock.MockTokenEndpointHandler)
		method   string
		err      string
		expect   *AccessRequest
		handlers TokenEndpointHandlers
	}{
		{
			name: "ShouldFailNoGrantType",
			form: url.Values{},
			mock: func(store *mock.MockStorage, handler *mock.MockTokenEndpointHandler) {
				store.EXPECT().GetClient(gomock.Any(), gomock.Any()).Times(0)
			},
			method: "POST",
			err:    "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The POST body can not be empty.",
		},
		{
			name: "ShouldFailNoRegisteredHandlers",
			form: url.Values{
				consts.FormParameterGrantType: {"foo"},
			},
			mock: func(store *mock.MockStorage, handler *mock.MockTokenEndpointHandler) {
				store.EXPECT().GetClient(gomock.Any(), gomock.Any()).Times(0)
			},
			method:   "POST",
			err:      "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Make sure that the various parameters are correct, be aware of case sensitivity and trim your parameters. Make sure that the client you are using has exactly whitelisted the redirect_uri you specified. The client with id '' requested grant type 'foo' which is invalid, unknown, not supported, or not configured to be handled.",
			handlers: TokenEndpointHandlers{},
		},
		{
			name: "ShouldPassHandlerSkipsClientAuthAndIgnoresMissingClient",
			header: http.Header{
				consts.HeaderAuthorization: {basicAuth("foo", "bar")},
			},
			form: url.Values{
				consts.FormParameterGrantType: {"foo"},
			},
			mock: func(store *mock.MockStorage, handler *mock.MockTokenEndpointHandler) {
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
		},
		{
			name: "ShouldPassNoAuthHeaderCanSkip",
			form: url.Values{
				consts.FormParameterGrantType: {"foo"},
			},
			mock: func(store *mock.MockStorage, handler *mock.MockTokenEndpointHandler) {
				handler.EXPECT().HandleTokenEndpointRequest(gomock.Any(), gomock.Any()).Return(nil)
			},
			method: "POST",
			expect: &AccessRequest{
				GrantTypes: Arguments{"foo"},
				Request: Request{
					Client: client,
				},
			},
		},
		{
			name: "ShouldPassWithClientAuthSet",
			header: http.Header{
				consts.HeaderAuthorization: {basicAuth("foo", "bar")},
			},
			form: url.Values{
				consts.FormParameterGrantType: {"foo"},
			},
			mock: func(store *mock.MockStorage, handler *mock.MockTokenEndpointHandler) {
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
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			store := mock.NewMockStorage(ctrl)
			handler := mock.NewMockTokenEndpointHandler(ctrl)
			handler.EXPECT().CanHandleTokenEndpointRequest(gomock.Any(), gomock.Any()).Return(true).AnyTimes()
			handler.EXPECT().CanSkipClientAuth(gomock.Any(), gomock.Any()).Return(true).AnyTimes()

			config := &Config{AudienceMatchingStrategy: DefaultAudienceMatchingStrategy}
			provider := &Fosite{Store: store, Config: config}

			handlers := tc.handlers
			if handlers == nil {
				handlers = TokenEndpointHandlers{handler}
			}
			config.TokenEndpointHandlers = handlers

			r := &http.Request{
				Header:   tc.header,
				PostForm: tc.form,
				Form:     tc.form,
				Method:   tc.method,
			}
			tc.mock(store, handler)
			ctx := NewContext()
			ar, err := provider.NewAccessRequest(ctx, r, new(DefaultSession))

			if tc.err != "" {
				assert.EqualError(t, ErrorToDebugRFC6749Error(err), tc.err)
			} else {
				require.NoError(t, err)
				AssertObjectKeysEqual(t, tc.expect, ar, "GrantTypes", "Client")
				assert.NotNil(t, ar.GetRequestedAt())
			}
		})
	}
}

// In this test case one handler requires client auth and another handler not.
func TestNewAccessRequestWithMixedClientAuth(t *testing.T) {
	client := &DefaultClient{}

	testCases := []struct {
		name   string
		header http.Header
		form   url.Values
		mock   func(store *mock.MockStorage, handlerWithClientAuth, handlerWithoutClientAuth *mock.MockTokenEndpointHandler)
		method string
		err    string
		expect *AccessRequest
	}{
		{
			name: "ShouldFailWrongClientSecret",
			header: http.Header{
				consts.HeaderAuthorization: {basicAuth("foo", "bar")},
			},
			form: url.Values{
				consts.FormParameterGrantType: {"foo"},
			},
			mock: func(store *mock.MockStorage, handlerWithClientAuth, handlerWithoutClientAuth *mock.MockTokenEndpointHandler) {
				store.EXPECT().GetClient(gomock.Any(), gomock.Eq("foo")).Return(client, nil)
				client.Public = false
				client.ClientSecret = testClientSecretFoo
				handlerWithoutClientAuth.EXPECT().HandleTokenEndpointRequest(gomock.Any(), gomock.Any()).Return(nil)
			},
			method: "POST",
			err:    "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method). crypto/bcrypt: hashedPassword is not the hash of the given password",
		},
		{
			name: "ShouldPassValidClientSecret",
			header: http.Header{
				consts.HeaderAuthorization: {basicAuth("foo", "bar")},
			},
			form: url.Values{
				consts.FormParameterGrantType: {"foo"},
			},
			mock: func(store *mock.MockStorage, handlerWithClientAuth, handlerWithoutClientAuth *mock.MockTokenEndpointHandler) {
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
		},
		{
			name:   "ShouldFailMissingClientAuthHeader",
			header: http.Header{},
			form: url.Values{
				consts.FormParameterGrantType: {"foo"},
			},
			mock: func(store *mock.MockStorage, handlerWithClientAuth, handlerWithoutClientAuth *mock.MockTokenEndpointHandler) {
				store.EXPECT().GetClient(gomock.Any(), gomock.Any()).Times(0)
				handlerWithoutClientAuth.EXPECT().HandleTokenEndpointRequest(gomock.Any(), gomock.Any()).Return(nil)
			},
			method: "POST",
			err:    "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Client Credentials missing or malformed. The Client ID was missing from the request but it is required when there is no client assertion.",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			store := mock.NewMockStorage(ctrl)

			handlerWithClientAuth := mock.NewMockTokenEndpointHandler(ctrl)
			handlerWithClientAuth.EXPECT().CanHandleTokenEndpointRequest(gomock.Any(), gomock.Any()).Return(true).AnyTimes()
			handlerWithClientAuth.EXPECT().CanSkipClientAuth(gomock.Any(), gomock.Any()).Return(false).AnyTimes()

			handlerWithoutClientAuth := mock.NewMockTokenEndpointHandler(ctrl)
			handlerWithoutClientAuth.EXPECT().CanHandleTokenEndpointRequest(gomock.Any(), gomock.Any()).Return(true).AnyTimes()
			handlerWithoutClientAuth.EXPECT().CanSkipClientAuth(gomock.Any(), gomock.Any()).Return(true).AnyTimes()

			config := &Config{
				AudienceMatchingStrategy: DefaultAudienceMatchingStrategy,
				TokenEndpointHandlers:    TokenEndpointHandlers{handlerWithoutClientAuth, handlerWithClientAuth},
			}
			provider := &Fosite{Store: store, Config: config}

			r := &http.Request{
				Header:   tc.header,
				PostForm: tc.form,
				Form:     tc.form,
				Method:   tc.method,
			}
			tc.mock(store, handlerWithClientAuth, handlerWithoutClientAuth)
			ar, err := provider.NewAccessRequest(t.Context(), r, new(DefaultSession))

			if tc.err != "" {
				assert.EqualError(t, ErrorToDebugRFC6749Error(err), tc.err)
			} else {
				require.NoError(t, err)
				AssertObjectKeysEqual(t, tc.expect, ar, "GrantTypes", "Client")
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
