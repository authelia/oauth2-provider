// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	. "authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/testing/mock"
)

// Should pass
//
//   - https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#Terminology
//     The OAuth 2.0 specification allows for registration of space-separated response_type parameter values.
//     If a Response Type contains one of more space characters (%20), it is compared as a space-delimited list of
//     values in which the order of values does not matter.
func TestNewPushedAuthorizeRequest(t *testing.T) {
	redir, _ := url.Parse("https://foo.bar/cb")
	specialCharRedir, _ := url.Parse("web+application://callback")

	testCases := []struct {
		name   string
		r      *http.Request
		query  url.Values
		err    string
		mock   func(store *mock.MockStorage)
		expect *AuthorizeRequest
	}{
		{
			name: "ShouldFailEmptyRequest",
			r: &http.Request{
				Method: "POST",
			},
			err:  "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method). The requested OAuth 2.0 Client could not be authenticated. The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Client Credentials missing or malformed. The Client ID was missing from the request but it is required when there is no client assertion.",
			mock: func(store *mock.MockStorage) {},
		},
		{
			name:  "ShouldFailInvalidRedirectURI",
			query: url.Values{consts.FormParameterRedirectURI: []string{"invalid"}},
			err:   "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method). The requested OAuth 2.0 Client could not be authenticated. The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Client Credentials missing or malformed. The Client ID was missing from the request but it is required when there is no client assertion.",
			mock:  func(store *mock.MockStorage) {},
		},
		{
			name:  "ShouldFailInvalidClient",
			query: url.Values{consts.FormParameterRedirectURI: []string{"https://foo.bar/cb"}},
			err:   "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method). The requested OAuth 2.0 Client could not be authenticated. The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Client Credentials missing or malformed. The Client ID was missing from the request but it is required when there is no client assertion.",
			mock:  func(store *mock.MockStorage) {},
		},
		{
			name: "ShouldFailClientAndRequestRedirectsMismatchMissing",
			query: url.Values{
				consts.FormParameterClientID:     []string{"1234"},
				consts.FormParameterClientSecret: []string{"1234"},
			},
			err: "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The 'redirect_uri' parameter does not match any of the OAuth 2.0 Client's pre-registered 'redirect_uris'. The 'redirect_uris' registered with OAuth 2.0 Client with id '' did not match 'redirect_uri' value '' because the only registered 'redirect_uri' is not a valid value.",
			mock: func(store *mock.MockStorage) {
				store.EXPECT().GetClient(gomock.Any(), "1234").Return(&DefaultClient{RedirectURIs: []string{"invalid"}, Scopes: []string{}, ClientSecret: testClientSecret1234}, nil).MaxTimes(2)
			},
		},
		{
			name: "ShouldFailClientAndRequestRedirectsMismatchEmpty",
			query: url.Values{
				consts.FormParameterRedirectURI:  []string{""},
				consts.FormParameterClientID:     []string{"1234"},
				consts.FormParameterClientSecret: []string{"1234"},
			},
			err: "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The 'redirect_uri' parameter does not match any of the OAuth 2.0 Client's pre-registered 'redirect_uris'. The 'redirect_uris' registered with OAuth 2.0 Client with id '' did not match 'redirect_uri' value '' because the only registered 'redirect_uri' is not a valid value.",
			mock: func(store *mock.MockStorage) {
				store.EXPECT().GetClient(gomock.Any(), "1234").Return(&DefaultClient{RedirectURIs: []string{"invalid"}, Scopes: []string{}, ClientSecret: testClientSecret1234}, nil).MaxTimes(2)
			},
		},
		{
			name: "ShouldFailClientAndRequestRedirectsMismatchValue",
			query: url.Values{
				consts.FormParameterRedirectURI:  []string{"https://foo.bar/cb"},
				consts.FormParameterClientID:     []string{"1234"},
				consts.FormParameterClientSecret: []string{"1234"},
			},
			err: "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The 'redirect_uri' parameter does not match any of the OAuth 2.0 Client's pre-registered 'redirect_uris'. The 'redirect_uris' registered with OAuth 2.0 Client with id '' did not match 'redirect_uri' value 'https://foo.bar/cb'.",
			mock: func(store *mock.MockStorage) {
				store.EXPECT().GetClient(gomock.Any(), "1234").Return(&DefaultClient{RedirectURIs: []string{"invalid"}, Scopes: []string{}, ClientSecret: testClientSecret1234}, nil).MaxTimes(2)
			},
		},
		{
			name: "ShouldFailNoState",
			query: url.Values{
				consts.FormParameterRedirectURI:  []string{"https://foo.bar/cb"},
				consts.FormParameterClientID:     []string{"1234"},
				consts.FormParameterClientSecret: []string{"1234"},
				consts.FormParameterResponseType: []string{consts.ResponseTypeAuthorizationCodeFlow},
			},
			err: "The state is missing or does not have enough characters and is therefore considered too weak. Request parameter 'state' must be at least be 8 characters long to ensure sufficient entropy.",
			mock: func(store *mock.MockStorage) {
				store.EXPECT().GetClient(gomock.Any(), "1234").Return(&DefaultClient{RedirectURIs: []string{"https://foo.bar/cb"}, Scopes: []string{}, ClientSecret: testClientSecret1234}, nil).MaxTimes(2)
			},
		},
		{
			name: "ShouldFailShortState",
			query: url.Values{
				consts.FormParameterRedirectURI:  {"https://foo.bar/cb"},
				consts.FormParameterClientID:     {"1234"},
				consts.FormParameterClientSecret: []string{"1234"},
				consts.FormParameterResponseType: {"code"},
				consts.FormParameterState:        {"short"},
			},
			err: "The state is missing or does not have enough characters and is therefore considered too weak. Request parameter 'state' must be at least be 8 characters long to ensure sufficient entropy.",
			mock: func(store *mock.MockStorage) {
				store.EXPECT().GetClient(gomock.Any(), "1234").Return(&DefaultClient{RedirectURIs: []string{"https://foo.bar/cb"}, Scopes: []string{}, ClientSecret: testClientSecret1234}, nil).MaxTimes(2)
			},
		},
		{
			name: "ShouldFailClientWithoutScopeBaz",
			query: url.Values{
				consts.FormParameterRedirectURI:  {"https://foo.bar/cb"},
				consts.FormParameterClientID:     {"1234"},
				consts.FormParameterClientSecret: []string{"1234"},
				consts.FormParameterResponseType: []string{consts.ResponseTypeHybridFlowToken},
				consts.FormParameterState:        {"strong-state"},
				consts.FormParameterScope:        {"foo bar baz"},
			},
			mock: func(store *mock.MockStorage) {
				store.EXPECT().GetClient(gomock.Any(), "1234").Return(&DefaultClient{RedirectURIs: []string{"https://foo.bar/cb"}, Scopes: []string{"foo", "bar"}, ClientSecret: testClientSecret1234}, nil).MaxTimes(2)
			},
			err: "The requested scope is invalid, unknown, or malformed. The OAuth 2.0 Client is not allowed to request scope 'baz'.",
		},
		{
			name: "ShouldFailClientWithoutAudience",
			query: url.Values{
				consts.FormParameterRedirectURI:  {"https://foo.bar/cb"},
				consts.FormParameterClientID:     {"1234"},
				consts.FormParameterClientSecret: []string{"1234"},
				consts.FormParameterResponseType: []string{consts.ResponseTypeHybridFlowToken},
				consts.FormParameterState:        {"strong-state"},
				consts.FormParameterScope:        {"foo bar"},
				consts.FormParameterAudience:     {"https://cloud.authelia.com/api https://www.authelia.com/api"},
			},
			mock: func(store *mock.MockStorage) {
				store.EXPECT().GetClient(gomock.Any(), "1234").Return(&DefaultClient{
					RedirectURIs: []string{"https://foo.bar/cb"}, Scopes: []string{"foo", "bar"},
					Audience:     []string{"https://cloud.authelia.com/api"},
					ClientSecret: testClientSecret1234,
				}, nil).MaxTimes(2)
			},
			err: "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Requested audience 'https://www.authelia.com/api' has not been whitelisted by the OAuth 2.0 Client.",
		},
		{
			name: "ShouldPass",
			query: url.Values{
				consts.FormParameterRedirectURI:  {"https://foo.bar/cb"},
				consts.FormParameterClientID:     {"1234"},
				consts.FormParameterClientSecret: []string{"1234"},
				consts.FormParameterResponseType: []string{consts.ResponseTypeHybridFlowToken},
				consts.FormParameterState:        {"strong-state"},
				consts.FormParameterScope:        {"foo bar"},
				consts.FormParameterAudience:     {"https://cloud.authelia.com/api https://www.authelia.com/api"},
			},
			mock: func(store *mock.MockStorage) {
				store.EXPECT().GetClient(gomock.Any(), "1234").Return(&DefaultClient{
					ResponseTypes: []string{consts.ResponseTypeHybridFlowToken},
					RedirectURIs:  []string{"https://foo.bar/cb"},
					Scopes:        []string{"foo", "bar"},
					Audience:      []string{"https://cloud.authelia.com/api", "https://www.authelia.com/api"},
					ClientSecret:  testClientSecret1234,
				}, nil).MaxTimes(2)
			},
			expect: &AuthorizeRequest{
				RedirectURI:   redir,
				ResponseTypes: []string{"code", "token"},
				State:         "strong-state",
				Request: Request{
					Client: &DefaultClient{
						ResponseTypes: []string{consts.ResponseTypeHybridFlowToken}, RedirectURIs: []string{"https://foo.bar/cb"},
						Scopes:       []string{"foo", "bar"},
						Audience:     []string{"https://cloud.authelia.com/api", "https://www.authelia.com/api"},
						ClientSecret: testClientSecret1234,
					},
					RequestedScope:    []string{"foo", "bar"},
					RequestedAudience: []string{"https://cloud.authelia.com/api", "https://www.authelia.com/api"},
				},
			},
		},
		{
			name: "ShouldPassRepeatedAudienceParameter",
			query: url.Values{
				consts.FormParameterRedirectURI:  {"https://foo.bar/cb"},
				consts.FormParameterClientID:     {"1234"},
				consts.FormParameterClientSecret: []string{"1234"},
				consts.FormParameterResponseType: []string{consts.ResponseTypeHybridFlowToken},
				consts.FormParameterState:        {"strong-state"},
				consts.FormParameterScope:        {"foo bar"},
				consts.FormParameterAudience:     {"https://cloud.authelia.com/api", "https://www.authelia.com/api"},
			},
			mock: func(store *mock.MockStorage) {
				store.EXPECT().GetClient(gomock.Any(), "1234").Return(&DefaultClient{
					ResponseTypes: []string{consts.ResponseTypeHybridFlowToken},
					RedirectURIs:  []string{"https://foo.bar/cb"},
					Scopes:        []string{"foo", "bar"},
					Audience:      []string{"https://cloud.authelia.com/api", "https://www.authelia.com/api"},
					ClientSecret:  testClientSecret1234,
				}, nil).MaxTimes(2)
			},
			expect: &AuthorizeRequest{
				RedirectURI:   redir,
				ResponseTypes: []string{consts.ResponseTypeAuthorizationCodeFlow, consts.ResponseTypeImplicitFlowToken},
				State:         "strong-state",
				Request: Request{
					Client: &DefaultClient{
						ResponseTypes: []string{consts.ResponseTypeHybridFlowToken}, RedirectURIs: []string{"https://foo.bar/cb"},
						Scopes:       []string{"foo", "bar"},
						Audience:     []string{"https://cloud.authelia.com/api", "https://www.authelia.com/api"},
						ClientSecret: testClientSecret1234,
					},
					RequestedScope:    []string{"foo", "bar"},
					RequestedAudience: []string{"https://cloud.authelia.com/api", "https://www.authelia.com/api"},
				},
			},
		},
		{
			name: "ShouldPassRepeatedAudienceParameterWithTrickyValues",
			query: url.Values{
				consts.FormParameterRedirectURI:  {"https://foo.bar/cb"},
				consts.FormParameterClientID:     {"1234"},
				consts.FormParameterClientSecret: []string{"1234"},
				consts.FormParameterResponseType: []string{consts.ResponseTypeHybridFlowToken},
				consts.FormParameterState:        {"strong-state"},
				consts.FormParameterScope:        {"foo bar"},
				consts.FormParameterAudience:     {"test value", ""},
			},
			mock: func(store *mock.MockStorage) {
				store.EXPECT().GetClient(gomock.Any(), "1234").Return(&DefaultClient{
					ResponseTypes: []string{consts.ResponseTypeHybridFlowToken},
					RedirectURIs:  []string{"https://foo.bar/cb"},
					Scopes:        []string{"foo", "bar"},
					Audience:      []string{"test value"},
					ClientSecret:  testClientSecret1234,
				}, nil).MaxTimes(2)
			},
			expect: &AuthorizeRequest{
				RedirectURI:   redir,
				ResponseTypes: []string{consts.ResponseTypeAuthorizationCodeFlow, consts.ResponseTypeImplicitFlowToken},
				State:         "strong-state",
				Request: Request{
					Client: &DefaultClient{
						ResponseTypes: []string{consts.ResponseTypeHybridFlowToken}, RedirectURIs: []string{"https://foo.bar/cb"},
						Scopes:       []string{"foo", "bar"},
						Audience:     []string{"test value"},
						ClientSecret: testClientSecret1234,
					},
					RequestedScope:    []string{"foo", "bar"},
					RequestedAudience: []string{"test value"},
				},
			},
		},
		{
			name: "ShouldPassRedirectURIWithSpecialCharacter",
			query: url.Values{
				consts.FormParameterRedirectURI:  {"web+application://callback"},
				consts.FormParameterClientID:     {"1234"},
				consts.FormParameterClientSecret: []string{"1234"},
				consts.FormParameterResponseType: []string{consts.ResponseTypeHybridFlowToken},
				consts.FormParameterState:        {"strong-state"},
				consts.FormParameterScope:        {"foo bar"},
				consts.FormParameterAudience:     {"https://cloud.authelia.com/api https://www.authelia.com/api"},
			},
			mock: func(store *mock.MockStorage) {
				store.EXPECT().GetClient(gomock.Any(), "1234").Return(&DefaultClient{
					ResponseTypes: []string{consts.ResponseTypeHybridFlowToken},
					RedirectURIs:  []string{"web+application://callback"},
					Scopes:        []string{"foo", "bar"},
					Audience:      []string{"https://cloud.authelia.com/api", "https://www.authelia.com/api"},
					ClientSecret:  testClientSecret1234,
				}, nil).MaxTimes(2)
			},
			expect: &AuthorizeRequest{
				RedirectURI:   specialCharRedir,
				ResponseTypes: []string{consts.ResponseTypeAuthorizationCodeFlow, consts.ResponseTypeImplicitFlowToken},
				State:         "strong-state",
				Request: Request{
					Client: &DefaultClient{
						ResponseTypes: []string{consts.ResponseTypeHybridFlowToken}, RedirectURIs: []string{"web+application://callback"},
						Scopes:       []string{"foo", "bar"},
						Audience:     []string{"https://cloud.authelia.com/api", "https://www.authelia.com/api"},
						ClientSecret: testClientSecret1234,
					},
					RequestedScope:    []string{"foo", "bar"},
					RequestedAudience: []string{"https://cloud.authelia.com/api", "https://www.authelia.com/api"},
				},
			},
		},
		{
			name: "ShouldPassAudienceWithDoubleSpacesBetweenValues",
			query: url.Values{
				consts.FormParameterRedirectURI:  {"https://foo.bar/cb"},
				consts.FormParameterClientID:     {"1234"},
				consts.FormParameterClientSecret: []string{"1234"},
				consts.FormParameterResponseType: []string{consts.ResponseTypeHybridFlowToken},
				consts.FormParameterState:        {"strong-state"},
				consts.FormParameterScope:        {"foo bar"},
				consts.FormParameterAudience:     {"https://cloud.authelia.com/api  https://www.authelia.com/api"},
			},
			mock: func(store *mock.MockStorage) {
				store.EXPECT().GetClient(gomock.Any(), "1234").Return(&DefaultClient{
					ResponseTypes: []string{consts.ResponseTypeHybridFlowToken},
					RedirectURIs:  []string{"https://foo.bar/cb"},
					Scopes:        []string{"foo", "bar"},
					Audience:      []string{"https://cloud.authelia.com/api", "https://www.authelia.com/api"},
					ClientSecret:  testClientSecret1234,
				}, nil).MaxTimes(2)
			},
			expect: &AuthorizeRequest{
				RedirectURI:   redir,
				ResponseTypes: []string{consts.ResponseTypeAuthorizationCodeFlow, consts.ResponseTypeImplicitFlowToken},
				State:         "strong-state",
				Request: Request{
					Client: &DefaultClient{
						ResponseTypes: []string{consts.ResponseTypeHybridFlowToken}, RedirectURIs: []string{"https://foo.bar/cb"},
						Scopes:       []string{"foo", "bar"},
						Audience:     []string{"https://cloud.authelia.com/api", "https://www.authelia.com/api"},
						ClientSecret: testClientSecret1234,
					},
					RequestedScope:    []string{"foo", "bar"},
					RequestedAudience: []string{"https://cloud.authelia.com/api", "https://www.authelia.com/api"},
				},
			},
		},
		{
			name: "ShouldFailUnknownResponseMode",
			query: url.Values{
				consts.FormParameterRedirectURI:  {"https://foo.bar/cb"},
				consts.FormParameterClientID:     {"1234"},
				consts.FormParameterClientSecret: []string{"1234"},
				consts.FormParameterResponseType: []string{consts.ResponseTypeHybridFlowToken},
				consts.FormParameterState:        {"strong-state"},
				consts.FormParameterScope:        {"foo bar"},
				consts.FormParameterResponseMode: {"unknown"},
			},
			mock: func(store *mock.MockStorage) {
				store.EXPECT().GetClient(gomock.Any(), "1234").Return(&DefaultClient{RedirectURIs: []string{"https://foo.bar/cb"}, Scopes: []string{"foo", "bar"}, ResponseTypes: []string{consts.ResponseTypeHybridFlowToken}, ClientSecret: testClientSecret1234}, nil).MaxTimes(2)
			},
			err: "The authorization server does not support obtaining a response using this response mode. Request with unsupported response_mode 'unknown'.",
		},
		{
			name: "ShouldFailResponseModeRequestedButClientDoesNotSupportResponseMode",
			query: url.Values{
				consts.FormParameterRedirectURI:  {"https://foo.bar/cb"},
				consts.FormParameterClientID:     {"1234"},
				consts.FormParameterClientSecret: []string{"1234"},
				consts.FormParameterResponseType: []string{consts.ResponseTypeHybridFlowToken},
				consts.FormParameterState:        {"strong-state"},
				consts.FormParameterScope:        {"foo bar"},
				consts.FormParameterResponseMode: {consts.ResponseModeFormPost},
			},
			mock: func(store *mock.MockStorage) {
				store.EXPECT().GetClient(gomock.Any(), "1234").Return(&DefaultClient{RedirectURIs: []string{"https://foo.bar/cb"}, Scopes: []string{"foo", "bar"}, ResponseTypes: []string{consts.ResponseTypeHybridFlowToken}, ClientSecret: testClientSecret1234}, nil).MaxTimes(2)
			},
			err: "The authorization server does not support obtaining a response using this response mode. The 'response_mode' requested was 'form_post', but the Authorization Server or registered OAuth 2.0 client doesn't allow or support this mode. The registered OAuth 2.0 Client with id '' does not the 'response_mode' type 'form_post', as it's not registered to support any.",
		},
		{
			name: "ShouldFailRequestedResponseModeNotAllowed",
			query: url.Values{
				consts.FormParameterRedirectURI:  {"https://foo.bar/cb"},
				consts.FormParameterClientID:     {"1234"},
				consts.FormParameterClientSecret: []string{"1234"},
				consts.FormParameterResponseType: []string{consts.ResponseTypeHybridFlowToken},
				consts.FormParameterState:        {"strong-state"},
				consts.FormParameterScope:        {"foo bar"},
				consts.FormParameterResponseMode: {consts.ResponseModeFormPost},
			},
			mock: func(store *mock.MockStorage) {
				store.EXPECT().GetClient(gomock.Any(), "1234").Return(&DefaultResponseModeClient{
					DefaultClient: &DefaultClient{
						RedirectURIs:  []string{"https://foo.bar/cb"},
						Scopes:        []string{"foo", "bar"},
						ResponseTypes: []string{consts.ResponseTypeHybridFlowToken},
						ClientSecret:  testClientSecret1234,
					},
					ResponseModes: []ResponseModeType{ResponseModeQuery},
				}, nil).MaxTimes(2)
			},
			err: "The authorization server does not support obtaining a response using this response mode. The 'response_mode' requested was 'form_post', but the Authorization Server or registered OAuth 2.0 client doesn't allow or support this mode. The registered OAuth 2.0 Client with id '' does not the 'response_mode' type 'form_post'.",
		},
		{
			name: "ShouldPassWithResponseModeFormPost",
			query: url.Values{
				consts.FormParameterRedirectURI:  {"https://foo.bar/cb"},
				consts.FormParameterClientID:     {"1234"},
				consts.FormParameterClientSecret: []string{"1234"},
				consts.FormParameterResponseType: []string{consts.ResponseTypeHybridFlowToken},
				consts.FormParameterState:        {"strong-state"},
				consts.FormParameterScope:        {"foo bar"},
				consts.FormParameterResponseMode: {consts.ResponseModeFormPost},
				consts.FormParameterAudience:     {"https://cloud.authelia.com/api https://www.authelia.com/api"},
			},
			mock: func(store *mock.MockStorage) {
				store.EXPECT().GetClient(gomock.Any(), "1234").Return(&DefaultResponseModeClient{
					DefaultClient: &DefaultClient{
						RedirectURIs:  []string{"https://foo.bar/cb"},
						Scopes:        []string{"foo", "bar"},
						ResponseTypes: []string{consts.ResponseTypeHybridFlowToken},
						Audience:      []string{"https://cloud.authelia.com/api", "https://www.authelia.com/api"},
						ClientSecret:  testClientSecret1234,
					},
					ResponseModes: []ResponseModeType{ResponseModeFormPost},
				}, nil).MaxTimes(2)
			},
			expect: &AuthorizeRequest{
				RedirectURI:   redir,
				ResponseTypes: []string{consts.ResponseTypeAuthorizationCodeFlow, consts.ResponseTypeImplicitFlowToken},
				State:         "strong-state",
				Request: Request{
					Client: &DefaultResponseModeClient{
						DefaultClient: &DefaultClient{
							RedirectURIs:  []string{"https://foo.bar/cb"},
							Scopes:        []string{"foo", "bar"},
							ResponseTypes: []string{consts.ResponseTypeHybridFlowToken},
							Audience:      []string{"https://cloud.authelia.com/api", "https://www.authelia.com/api"},
							ClientSecret:  testClientSecret1234,
						},
						ResponseModes: []ResponseModeType{ResponseModeFormPost},
					},
					RequestedScope:    []string{"foo", "bar"},
					RequestedAudience: []string{"https://cloud.authelia.com/api", "https://www.authelia.com/api"},
				},
			},
		},
		{
			name: "ShouldPassWithResponseModeQuery",
			query: url.Values{
				consts.FormParameterRedirectURI:  {"https://foo.bar/cb"},
				consts.FormParameterClientID:     {"1234"},
				consts.FormParameterClientSecret: []string{"1234"},
				consts.FormParameterResponseType: {"code"},
				consts.FormParameterState:        {"strong-state"},
				consts.FormParameterScope:        {"foo bar"},
				consts.FormParameterAudience:     {"https://cloud.authelia.com/api https://www.authelia.com/api"},
			},
			mock: func(store *mock.MockStorage) {
				store.EXPECT().GetClient(gomock.Any(), "1234").Return(&DefaultResponseModeClient{
					DefaultClient: &DefaultClient{
						RedirectURIs:  []string{"https://foo.bar/cb"},
						Scopes:        []string{"foo", "bar"},
						ResponseTypes: []string{consts.ResponseTypeAuthorizationCodeFlow},
						Audience:      []string{"https://cloud.authelia.com/api", "https://www.authelia.com/api"},
						ClientSecret:  testClientSecret1234,
					},
					ResponseModes: []ResponseModeType{ResponseModeQuery},
				}, nil).MaxTimes(2)
			},
			expect: &AuthorizeRequest{
				RedirectURI:   redir,
				ResponseTypes: []string{consts.ResponseTypeAuthorizationCodeFlow},
				State:         "strong-state",
				Request: Request{
					Client: &DefaultResponseModeClient{
						DefaultClient: &DefaultClient{
							RedirectURIs:  []string{"https://foo.bar/cb"},
							Scopes:        []string{"foo", "bar"},
							ResponseTypes: []string{consts.ResponseTypeAuthorizationCodeFlow},
							Audience:      []string{"https://cloud.authelia.com/api", "https://www.authelia.com/api"},
							ClientSecret:  testClientSecret1234,
						},
						ResponseModes: []ResponseModeType{ResponseModeQuery},
					},
					RequestedScope:    []string{"foo", "bar"},
					RequestedAudience: []string{"https://cloud.authelia.com/api", "https://www.authelia.com/api"},
				},
			},
		},
		{
			name: "ShouldPassWithResponseModeFragment",
			query: url.Values{
				consts.FormParameterRedirectURI:  {"https://foo.bar/cb"},
				consts.FormParameterClientID:     {"1234"},
				consts.FormParameterClientSecret: []string{"1234"},
				consts.FormParameterResponseType: []string{consts.ResponseTypeHybridFlowToken},
				consts.FormParameterState:        {"strong-state"},
				consts.FormParameterScope:        {"foo bar"},
				consts.FormParameterAudience:     {"https://cloud.authelia.com/api https://www.authelia.com/api"},
			},
			mock: func(store *mock.MockStorage) {
				store.EXPECT().GetClient(gomock.Any(), "1234").Return(&DefaultResponseModeClient{
					DefaultClient: &DefaultClient{
						RedirectURIs:  []string{"https://foo.bar/cb"},
						Scopes:        []string{"foo", "bar"},
						ResponseTypes: []string{consts.ResponseTypeHybridFlowToken},
						Audience:      []string{"https://cloud.authelia.com/api", "https://www.authelia.com/api"},
						ClientSecret:  testClientSecret1234,
					},
					ResponseModes: []ResponseModeType{ResponseModeFragment},
				}, nil).MaxTimes(2)
			},
			expect: &AuthorizeRequest{
				RedirectURI:   redir,
				ResponseTypes: []string{consts.ResponseTypeAuthorizationCodeFlow, consts.ResponseTypeImplicitFlowToken},
				State:         "strong-state",
				Request: Request{
					Client: &DefaultResponseModeClient{
						DefaultClient: &DefaultClient{
							RedirectURIs:  []string{"https://foo.bar/cb"},
							Scopes:        []string{"foo", "bar"},
							ResponseTypes: []string{consts.ResponseTypeHybridFlowToken},
							Audience:      []string{"https://cloud.authelia.com/api", "https://www.authelia.com/api"},
							ClientSecret:  testClientSecret1234,
						},
						ResponseModes: []ResponseModeType{ResponseModeFragment},
					},
					RequestedScope:    []string{"foo", "bar"},
					RequestedAudience: []string{"https://cloud.authelia.com/api", "https://www.authelia.com/api"},
				},
			},
		},
		{
			name: "ShouldFailRequestURIProvided",
			query: url.Values{
				consts.FormParameterRequestURI:   {"https://foo.bar/ru"},
				consts.FormParameterRedirectURI:  {"https://foo.bar/cb"},
				consts.FormParameterClientID:     {"1234"},
				consts.FormParameterClientSecret: []string{"1234"},
				consts.FormParameterResponseType: []string{consts.ResponseTypeHybridFlowToken},
				consts.FormParameterState:        {"strong-state"},
				consts.FormParameterScope:        {"foo bar"},
				consts.FormParameterResponseMode: {consts.ResponseModeFormPost},
			},
			mock: func(store *mock.MockStorage) {
				store.EXPECT().GetClient(gomock.Any(), "1234").Return(&DefaultClient{RedirectURIs: []string{"https://foo.bar/cb"}, Scopes: []string{"foo", "bar"}, ResponseTypes: []string{consts.ResponseTypeHybridFlowToken}, ClientSecret: testClientSecret1234}, nil).MaxTimes(2)
			},
			err: "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The request must not contain 'request_uri'.",
		},
		{
			name: "ShouldFailInvalidClientCreds",
			query: url.Values{
				consts.FormParameterRequestURI:   {"https://foo.bar/ru"},
				consts.FormParameterRedirectURI:  {"https://foo.bar/cb"},
				consts.FormParameterClientID:     {"1234"},
				consts.FormParameterClientSecret: []string{"4321"},
				consts.FormParameterResponseType: []string{consts.ResponseTypeHybridFlowToken},
				consts.FormParameterState:        {"strong-state"},
				consts.FormParameterScope:        {"foo bar"},
				consts.FormParameterResponseMode: {consts.ResponseModeFormPost},
			},
			mock: func(store *mock.MockStorage) {
				store.EXPECT().GetClient(gomock.Any(), "1234").Return(&DefaultClient{RedirectURIs: []string{"https://foo.bar/cb"}, Scopes: []string{"foo", "bar"}, ResponseTypes: []string{consts.ResponseTypeHybridFlowToken}, ClientSecret: testClientSecret1234}, nil).MaxTimes(2)
			},
			err: "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method). crypto/bcrypt: hashedPassword is not the hash of the given password",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			store := mock.NewMockStorage(ctrl)
			config := &Config{
				ScopeStrategy:            ExactScopeStrategy,
				AudienceMatchingStrategy: DefaultAudienceMatchingStrategy,
			}
			provider := &Fosite{
				Store:  store,
				Config: config,
			}

			ctx := NewContext()

			tc.mock(store)
			r := tc.r
			if r == nil {
				r = &http.Request{
					Header: http.Header{},
					Method: "POST",
				}
				if tc.query != nil {
					r.URL = &url.URL{RawQuery: tc.query.Encode()}
				}
			}

			ar, err := provider.NewPushedAuthorizeRequest(ctx, r)
			if tc.err != "" {
				assert.EqualError(t, ErrorToDebugRFC6749Error(err), tc.err)
				// https://github.com/ory/hydra/issues/1642
				AssertObjectKeysEqual(t, &AuthorizeRequest{State: tc.query.Get("state")}, ar, "State")
			} else {
				require.NoError(t, err)
				AssertObjectKeysEqual(t, tc.expect, ar, "ResponseTypes", "RequestedAudience", "RequestedScope", "Client", "RedirectURI", "State")
				assert.NotNil(t, ar.GetRequestedAt())
			}
		})
	}
}