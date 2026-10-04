// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	. "authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal"
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
			method:       http.MethodPost,
		},
		{
			name:   "ShouldReturnInvalidRequestWhenOnlyGrantType",
			header: http.Header{},
			method: http.MethodPost,
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
			method: http.MethodPost,
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
			method: http.MethodPost,
			form: url.Values{
				consts.FormParameterGrantType: {"foo"},
			},
			expectErr:    ErrInvalidClient,
			expectStrErr: "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method). The required credentials were not found, used an unknown method, could not be parsed, were otherwise malformed, or were otherwise incorrect.",
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
			method: http.MethodGet,
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
			method: http.MethodPost,
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
			method: http.MethodPost,
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
			method: http.MethodPost,
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
			method: http.MethodPost,
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
			config := &Config{AudienceStrategy: DefaultAudienceStrategy}
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

			actual, err := provider.NewAccessRequest(t.Context(), r, new(DefaultSession))

			if tc.expectErr != nil {
				assert.EqualError(t, err, tc.expectErr.Error())
				assert.EqualError(t, ErrorToDebugRFC6749Error(err), tc.expectStrErr)

				return
			}

			require.NoError(t, ErrorToDebugRFC6749Error(err))
			AssertObjectKeysEqual(t, tc.expect(client), actual, "GrantTypes", "Client")
			assert.NotNil(t, actual.GetRequestedAt())
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
			method: http.MethodPost,
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
			method:   http.MethodPost,
			err:      "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Make sure that the various parameters are correct, be aware of case sensitivity and trim your parameters. Make sure that the client you are using has exactly whitelisted the redirect_uri you specified. The client with id '' requested grant type 'foo' which is invalid, unknown, not supported, or not configured to be handled.",
			handlers: TokenEndpointHandlers{},
		},
		{
			name: "ShouldFailHandlerSkipsClientAuthWithPresentedCredentialsForMissingClient",
			header: http.Header{
				consts.HeaderAuthorization: {basicAuth("foo", "bar")},
			},
			form: url.Values{
				consts.FormParameterGrantType: {"foo"},
			},
			mock: func(store *mock.MockStorage, handler *mock.MockTokenEndpointHandler) {
				store.EXPECT().GetClient(gomock.Any(), "foo").Return(nil, errors.New("no client")).Times(1)
			},
			method: http.MethodPost,
			err:    "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method). The required credentials were not found, used an unknown method, could not be parsed, were otherwise malformed, or were otherwise incorrect. no client",
		},
		{
			name: "ShouldFailHandlerSkipsClientAuthWithPresentedFormCredentials",
			form: url.Values{
				consts.FormParameterGrantType:    {"foo"},
				consts.FormParameterClientID:     {"another"},
				consts.FormParameterClientSecret: {"wrong"},
			},
			mock: func(store *mock.MockStorage, handler *mock.MockTokenEndpointHandler) {
				store.EXPECT().GetClient(gomock.Any(), "another").Return(anotherClient, nil).Times(1)
			},
			method: http.MethodPost,
			err:    "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method). crypto/bcrypt: hashedPassword is not the hash of the given password",
		},
		{
			name: "ShouldPassHandlerSkipsClientAuthWithOnlyAClientIdentifier",
			form: url.Values{
				consts.FormParameterGrantType: {"foo"},
				consts.FormParameterClientID:  {"another"},
			},
			mock: func(store *mock.MockStorage, handler *mock.MockTokenEndpointHandler) {
				store.EXPECT().GetClient(gomock.Any(), "another").Return(anotherClient, nil).Times(1)
				handler.EXPECT().HandleTokenEndpointRequest(gomock.Any(), gomock.Any()).Return(nil)
			},
			method: http.MethodPost,
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
			method: http.MethodPost,
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
			method: http.MethodPost,
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

			config := &Config{AudienceStrategy: DefaultAudienceStrategy}
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
			actual, err := provider.NewAccessRequest(ctx, r, new(DefaultSession))

			if tc.err != "" {
				assert.EqualError(t, ErrorToDebugRFC6749Error(err), tc.err)

				return
			}

			require.NoError(t, ErrorToDebugRFC6749Error(err))
			AssertObjectKeysEqual(t, tc.expect, actual, "GrantTypes", "Client")
			assert.NotNil(t, actual.GetRequestedAt())
		})
	}
}

func TestNewAccessRequestEdgeCases(t *testing.T) {
	testCases := []struct {
		name     string
		req      func() *http.Request
		session  Session
		expected string
		strict   bool
	}{
		{
			name: "ShouldFailMalformedMultipartBody",
			req: func() *http.Request {
				return &http.Request{
					Method: http.MethodPost,
					Header: http.Header{consts.HeaderContentType: {"multipart/form-data; boundary=foo"}},
					Body:   io.NopCloser(strings.NewReader("not a real multipart body")),
				}
			},
			session:  new(DefaultSession),
			expected: "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Unable to parse HTTP body, make sure to send a properly formatted form request body. multipart: NextPart: EOF",
		},
		{
			name: "ShouldFailWhenSessionIsNil",
			req: func() *http.Request {
				form := url.Values{consts.FormParameterGrantType: {"foo"}}
				return &http.Request{
					Method:   http.MethodPost,
					Header:   http.Header{},
					PostForm: form,
					Form:     form,
				}
			},
			session:  nil,
			expected: "Session must not be nil",
			strict:   true,
		},
		{
			name: "ShouldFailWhenGrantTypeMissing",
			req: func() *http.Request {
				form := url.Values{consts.FormParameterClientID: {"bar"}}
				return &http.Request{
					Method:   http.MethodPost,
					Header:   http.Header{},
					PostForm: form,
					Form:     form,
				}
			},
			session:  new(DefaultSession),
			expected: "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Request parameter 'grant_type' is missing",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			provider := &Fosite{
				Store: mock.NewMockStorage(gomock.NewController(t)),
				Config: &Config{
					AudienceStrategy: DefaultAudienceStrategy,
				},
			}

			_, err := provider.NewAccessRequest(t.Context(), tc.req(), tc.session)

			if tc.strict {
				assert.EqualError(t, err, tc.expected)

				return
			}

			assert.EqualError(t, ErrorToDebugRFC6749Error(err), tc.expected)
		})
	}
}

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
			},
			method: http.MethodPost,
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
			method: http.MethodPost,
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
			method: http.MethodPost,
			err:    "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method). The required credentials were not found, used an unknown method, could not be parsed, were otherwise malformed, or were otherwise incorrect. The Client ID was missing from the request but it is required when there is no client assertion.",
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
				AudienceStrategy:      DefaultAudienceStrategy,
				TokenEndpointHandlers: TokenEndpointHandlers{handlerWithoutClientAuth, handlerWithClientAuth},
			}
			provider := &Fosite{Store: store, Config: config}

			r := &http.Request{
				Header:   tc.header,
				PostForm: tc.form,
				Form:     tc.form,
				Method:   tc.method,
			}
			tc.mock(store, handlerWithClientAuth, handlerWithoutClientAuth)

			actual, err := provider.NewAccessRequest(t.Context(), r, new(DefaultSession))

			if tc.err != "" {
				assert.EqualError(t, ErrorToDebugRFC6749Error(err), tc.err)

				return
			}

			require.NoError(t, ErrorToDebugRFC6749Error(err))
			AssertObjectKeysEqual(t, tc.expect, actual, "GrantTypes", "Client")
			assert.NotNil(t, actual.GetRequestedAt())
		})
	}
}

func TestNewAccessRequestAuthorizationDetails(t *testing.T) {
	client := &DefaultClient{ID: "foo", ClientSecret: testClientSecretBar}

	handlers := []AuthorizationDetailsTypeHandler{internal.PaymentInitiationTypeHandler{}}

	testCases := []struct {
		name          string
		handlers      []AuthorizationDetailsTypeHandler
		grantType     string
		raw           string
		omit          bool
		expectErr     error
		expectHint    string
		expectDetails AuthorizationDetails
		rejectedEarly bool
		accepts       *bool
		max           int
	}{
		{
			name:       "ShouldRejectRefreshOverDefaultMaximum",
			handlers:   handlers,
			grantType:  consts.GrantTypeRefreshToken,
			raw:        newRARDetailsJSON(33),
			expectErr:  ErrInvalidAuthorizationDetails,
			expectHint: testRARHintMaxObjectsDefault,
		},
		{
			name:       "ShouldRejectCodeOverConfiguredMaximum",
			handlers:   handlers,
			grantType:  consts.GrantTypeAuthorizationCode,
			raw:        newRARDetailsJSON(2),
			max:        1,
			expectErr:  ErrInvalidAuthorizationDetails,
			expectHint: "The 'authorization_details' parameter must not contain more than 1 authorization details objects.",
		},
		{
			name:          "ShouldAcceptCodeAtConfiguredMaximum",
			handlers:      handlers,
			grantType:     consts.GrantTypeAuthorizationCode,
			raw:           newRARDetailsJSON(2),
			max:           2,
			expectDetails: newRARDetails(2),
		},
		{
			name:      "ShouldIgnoreAtTokenEndpointWhenDisabled",
			grantType: consts.GrantTypeAuthorizationCode,
			raw:       testRARMalformedJSON,
		},
		{
			name:          "ShouldParseForAuthorizationCode",
			handlers:      handlers,
			grantType:     consts.GrantTypeAuthorizationCode,
			raw:           testRARDetailsJSON,
			expectDetails: AuthorizationDetails{{Type: internal.AuthorizationDetailsTypePaymentInitiation, Actions: []string{testRARActionInitiate}}},
		},
		{
			name:          "ShouldParseForRefreshToken",
			handlers:      handlers,
			grantType:     consts.GrantTypeRefreshToken,
			raw:           testRARDetailsJSON,
			expectDetails: AuthorizationDetails{{Type: internal.AuthorizationDetailsTypePaymentInitiation, Actions: []string{testRARActionInitiate}}},
		},
		{
			name:      "ShouldTreatEmptyAsAbsent",
			handlers:  handlers,
			grantType: consts.GrantTypeRefreshToken,
			raw:       "",
		},
		{
			name:      "ShouldRejectMalformed",
			handlers:  handlers,
			grantType: consts.GrantTypeAuthorizationCode,
			raw:       "{}",
			expectErr: ErrInvalidAuthorizationDetails,
		},
		{
			name:          "ShouldRejectClientCredentials",
			handlers:      handlers,
			grantType:     consts.GrantTypeClientCredentials,
			raw:           testRARDetailsJSON,
			expectErr:     ErrInvalidAuthorizationDetails,
			expectHint:    testRARHintClientCredentials,
			rejectedEarly: true,
		},
		{
			name:          "ShouldParseForAcceptingHandler",
			handlers:      handlers,
			grantType:     consts.GrantTypeClientCredentials,
			raw:           testRARDetailsJSON,
			accepts:       new(true),
			expectDetails: AuthorizationDetails{{Type: internal.AuthorizationDetailsTypePaymentInitiation, Actions: []string{testRARActionInitiate}}},
		},
		{
			name:          "ShouldRejectForDecliningHandler",
			handlers:      handlers,
			grantType:     consts.GrantTypeClientCredentials,
			raw:           testRARDetailsJSON,
			accepts:       new(false),
			expectErr:     ErrInvalidAuthorizationDetails,
			expectHint:    testRARHintClientCredentials,
			rejectedEarly: true,
		},
		{
			name:      "ShouldAllowClientCredentialsWithoutParameter",
			handlers:  handlers,
			grantType: consts.GrantTypeClientCredentials,
			omit:      true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			store := mock.NewMockStorage(ctrl)
			handler := mock.NewMockTokenEndpointHandler(ctrl)

			form := url.Values{
				consts.FormParameterGrantType: {tc.grantType},
			}

			if !tc.omit {
				form.Set(consts.FormParameterAuthorizationDetails, tc.raw)
			}

			var loader TokenEndpointHandler = handler

			if tc.accepts != nil {
				loader = &authorizationDetailsTokenEndpointHandler{MockTokenEndpointHandler: handler, accepts: *tc.accepts}
			}

			if tc.rejectedEarly {
				handler.EXPECT().CanHandleTokenEndpointRequest(gomock.Any(), gomock.Any()).Return(true).AnyTimes()
				handler.EXPECT().HandleTokenEndpointRequest(gomock.Any(), gomock.Any()).Times(0)
			} else {
				store.EXPECT().GetClient(gomock.Any(), "foo").Return(client, nil)
				handler.EXPECT().CanHandleTokenEndpointRequest(gomock.Any(), gomock.Any()).Return(true).AnyTimes()
				handler.EXPECT().CanSkipClientAuth(gomock.Any(), gomock.Any()).Return(false).AnyTimes()

				if tc.expectErr == nil {
					handler.EXPECT().HandleTokenEndpointRequest(gomock.Any(), gomock.Any()).Return(nil)
				} else {
					handler.EXPECT().HandleTokenEndpointRequest(gomock.Any(), gomock.Any()).Times(0)
				}
			}

			config := &Config{
				AudienceStrategy:                 DefaultAudienceStrategy,
				AuthorizationDetailsTypeHandlers: tc.handlers,
				AuthorizationDetailsMaxObjects:   tc.max,
				TokenEndpointHandlers:            TokenEndpointHandlers{loader},
			}
			provider := &Fosite{Store: store, Config: config}

			r := &http.Request{
				Header:   http.Header{consts.HeaderAuthorization: {basicAuth("foo", "bar")}},
				PostForm: form,
				Form:     form,
				Method:   http.MethodPost,
			}

			actual, err := provider.NewAccessRequest(t.Context(), r, new(DefaultSession))

			if tc.expectErr != nil {
				assert.EqualError(t, err, tc.expectErr.Error())

				if tc.expectHint != "" {
					assert.Equal(t, tc.expectHint, ErrorToRFC6749Error(err).HintField)
				}

				return
			}

			require.NoError(t, ErrorToDebugRFC6749Error(err))
			assert.Equal(t, tc.expectDetails, actual.GetRequestedAuthorizationDetails())
		})
	}
}

type authorizationDetailsTokenEndpointHandler struct {
	*mock.MockTokenEndpointHandler

	accepts bool
}

func (h *authorizationDetailsTokenEndpointHandler) CanHandleAuthorizationDetails(_ context.Context, _ AccessRequester) bool {
	return h.accepts
}

//nolint:unparam
func basicAuth(username, password string) string {
	return prefixSchemeBasic + base64.StdEncoding.EncodeToString(fmt.Appendf(nil, "%s:%s", username, password))
}

const (
	prefixSchemeBasic = "Basic "
)
