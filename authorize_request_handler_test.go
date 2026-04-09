// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
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
func TestNewAuthorizeRequest(t *testing.T) {
	redir, _ := url.Parse("https://foo.bar/cb")
	specialCharRedir, _ := url.Parse("web+application://callback")

	testCases := []struct {
		name   string
		config *Config
		r      *http.Request
		query  url.Values
		err    string
		mock   func(store *mock.MockStorage)
		expect *AuthorizeRequest
	}{
		{
			name:   "ShouldFailEmptyRequest",
			config: &Config{ScopeStrategy: ExactScopeStrategy, AudienceMatchingStrategy: DefaultAudienceMatchingStrategy},
			r:      &http.Request{},
			err:    "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method). The requested OAuth 2.0 Client does not exist. foo",
			mock: func(store *mock.MockStorage) {
				store.EXPECT().GetClient(gomock.Any(), gomock.Any()).Return(nil, errors.New("foo"))
			},
		},
		{
			name:   "ShouldFailInvalidRedirectURI",
			config: &Config{ScopeStrategy: ExactScopeStrategy, AudienceMatchingStrategy: DefaultAudienceMatchingStrategy},
			query:  url.Values{consts.FormParameterClientID: []string{"invalid"}},
			err:    "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method). The requested OAuth 2.0 Client does not exist. foo",
			mock: func(store *mock.MockStorage) {
				store.EXPECT().GetClient(gomock.Any(), gomock.Any()).Return(nil, errors.New("foo"))
			},
		},
		{
			name:   "ShouldFailInvalidClient",
			config: &Config{ScopeStrategy: ExactScopeStrategy, AudienceMatchingStrategy: DefaultAudienceMatchingStrategy},
			query:  url.Values{consts.FormParameterClientID: []string{"https://foo.bar/cb"}},
			err:    "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method). The requested OAuth 2.0 Client does not exist. foo",
			mock: func(store *mock.MockStorage) {
				store.EXPECT().GetClient(gomock.Any(), gomock.Any()).Return(nil, errors.New("foo"))
			},
		},
		{
			name:   "ShouldFailClientAndRequestRedirectsMismatchMissing",
			config: &Config{ScopeStrategy: ExactScopeStrategy, AudienceMatchingStrategy: DefaultAudienceMatchingStrategy},
			query: url.Values{
				consts.FormParameterClientID: []string{"1234"},
			},
			err: "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The 'redirect_uri' parameter does not match any of the OAuth 2.0 Client's pre-registered 'redirect_uris'. The 'redirect_uris' registered with OAuth 2.0 Client with id '' did not match 'redirect_uri' value '' because the only registered 'redirect_uri' is not a valid value.",
			mock: func(store *mock.MockStorage) {
				store.EXPECT().GetClient(gomock.Any(), "1234").Return(&DefaultClient{RedirectURIs: []string{"invalid"}, Scopes: []string{}}, nil)
			},
		},
		{
			name:   "ShouldFailClientAndRequestRedirectsMismatchEmpty",
			config: &Config{ScopeStrategy: ExactScopeStrategy, AudienceMatchingStrategy: DefaultAudienceMatchingStrategy},
			query: url.Values{
				consts.FormParameterRedirectURI: []string{""},
				consts.FormParameterClientID:    []string{"1234"},
			},
			err: "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The 'redirect_uri' parameter does not match any of the OAuth 2.0 Client's pre-registered 'redirect_uris'. The 'redirect_uris' registered with OAuth 2.0 Client with id '' did not match 'redirect_uri' value '' because the only registered 'redirect_uri' is not a valid value.",
			mock: func(store *mock.MockStorage) {
				store.EXPECT().GetClient(gomock.Any(), "1234").Return(&DefaultClient{RedirectURIs: []string{"invalid"}, Scopes: []string{}}, nil)
			},
		},
		{
			name:   "ShouldFailClientAndRequestRedirectsMismatchValue",
			config: &Config{ScopeStrategy: ExactScopeStrategy, AudienceMatchingStrategy: DefaultAudienceMatchingStrategy},
			query: url.Values{
				consts.FormParameterRedirectURI: []string{"https://foo.bar/cb"},
				consts.FormParameterClientID:    []string{"1234"},
			},
			err: "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The 'redirect_uri' parameter does not match any of the OAuth 2.0 Client's pre-registered 'redirect_uris'. The 'redirect_uris' registered with OAuth 2.0 Client with id '' did not match 'redirect_uri' value 'https://foo.bar/cb'.",
			mock: func(store *mock.MockStorage) {
				store.EXPECT().GetClient(gomock.Any(), "1234").Return(&DefaultClient{RedirectURIs: []string{"invalid"}, Scopes: []string{}}, nil)
			},
		},
		{
			name:   "ShouldFailNoState",
			config: &Config{ScopeStrategy: ExactScopeStrategy, AudienceMatchingStrategy: DefaultAudienceMatchingStrategy},
			query: url.Values{
				consts.FormParameterRedirectURI:  []string{"https://foo.bar/cb"},
				consts.FormParameterClientID:     []string{"1234"},
				consts.FormParameterResponseType: []string{consts.ResponseTypeAuthorizationCodeFlow},
			},
			err: "The state is missing or does not have enough characters and is therefore considered too weak. Request parameter 'state' must be at least be 8 characters long to ensure sufficient entropy.",
			mock: func(store *mock.MockStorage) {
				store.EXPECT().GetClient(gomock.Any(), "1234").Return(&DefaultClient{RedirectURIs: []string{"https://foo.bar/cb"}, Scopes: []string{}}, nil)
			},
		},
		{
			name:   "ShouldFailShortState",
			config: &Config{ScopeStrategy: ExactScopeStrategy, AudienceMatchingStrategy: DefaultAudienceMatchingStrategy},
			query: url.Values{
				consts.FormParameterRedirectURI:  []string{"https://foo.bar/cb"},
				consts.FormParameterClientID:     []string{"1234"},
				consts.FormParameterResponseType: []string{consts.ResponseTypeAuthorizationCodeFlow},
				consts.FormParameterState:        {"short"},
			},
			err: "The state is missing or does not have enough characters and is therefore considered too weak. Request parameter 'state' must be at least be 8 characters long to ensure sufficient entropy.",
			mock: func(store *mock.MockStorage) {
				store.EXPECT().GetClient(gomock.Any(), "1234").Return(&DefaultClient{RedirectURIs: []string{"https://foo.bar/cb"}, Scopes: []string{}}, nil)
			},
		},
		{
			name:   "ShouldFailClientWithoutScopeBaz",
			config: &Config{ScopeStrategy: ExactScopeStrategy, AudienceMatchingStrategy: DefaultAudienceMatchingStrategy},
			query: url.Values{
				consts.FormParameterRedirectURI:  {"https://foo.bar/cb"},
				consts.FormParameterClientID:     {"1234"},
				consts.FormParameterResponseType: {consts.ResponseTypeHybridFlowToken},
				consts.FormParameterState:        {"strong-state"},
				consts.FormParameterScope:        {"foo bar baz"},
			},
			mock: func(store *mock.MockStorage) {
				store.EXPECT().GetClient(gomock.Any(), "1234").Return(&DefaultClient{RedirectURIs: []string{"https://foo.bar/cb"}, Scopes: []string{"foo", "bar"}}, nil)
			},
			err: "The requested scope is invalid, unknown, or malformed. The OAuth 2.0 Client is not allowed to request scope 'baz'.",
		},
		{
			name:   "ShouldFailClientWithoutAudience",
			config: &Config{ScopeStrategy: ExactScopeStrategy, AudienceMatchingStrategy: DefaultAudienceMatchingStrategy},
			query: url.Values{
				consts.FormParameterRedirectURI:  {"https://foo.bar/cb"},
				consts.FormParameterClientID:     {"1234"},
				consts.FormParameterResponseType: {consts.ResponseTypeHybridFlowToken},
				consts.FormParameterState:        {"strong-state"},
				consts.FormParameterScope:        {"foo bar"},
				consts.FormParameterAudience:     {"https://cloud.authelia.com/api https://www.authelia.com/api"},
			},
			mock: func(store *mock.MockStorage) {
				store.EXPECT().GetClient(gomock.Any(), "1234").Return(&DefaultClient{
					RedirectURIs: []string{"https://foo.bar/cb"}, Scopes: []string{"foo", "bar"},
					Audience: []string{"https://cloud.authelia.com/api"},
				}, nil)
			},
			err: "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Requested audience 'https://www.authelia.com/api' has not been whitelisted by the OAuth 2.0 Client.",
		},
		{
			name:   "ShouldPass",
			config: &Config{ScopeStrategy: ExactScopeStrategy, AudienceMatchingStrategy: DefaultAudienceMatchingStrategy},
			query: url.Values{
				consts.FormParameterRedirectURI:  {"https://foo.bar/cb"},
				consts.FormParameterClientID:     {"1234"},
				consts.FormParameterResponseType: {consts.ResponseTypeHybridFlowToken},
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
				}, nil)
			},
			expect: &AuthorizeRequest{
				RedirectURI:   redir,
				ResponseTypes: []string{consts.ResponseTypeAuthorizationCodeFlow, consts.ResponseTypeImplicitFlowToken},
				State:         "strong-state",
				Request: Request{
					Client: &DefaultClient{
						ResponseTypes: []string{consts.ResponseTypeHybridFlowToken}, RedirectURIs: []string{"https://foo.bar/cb"},
						Scopes:   []string{"foo", "bar"},
						Audience: []string{"https://cloud.authelia.com/api", "https://www.authelia.com/api"},
					},
					RequestedScope:    []string{"foo", "bar"},
					RequestedAudience: []string{"https://cloud.authelia.com/api", "https://www.authelia.com/api"},
				},
			},
		},
		{
			name:   "ShouldPassNoState",
			config: &Config{ScopeStrategy: ExactScopeStrategy, AudienceMatchingStrategy: DefaultAudienceMatchingStrategy, MinParameterEntropy: -1},
			query: url.Values{
				consts.FormParameterRedirectURI:  {"https://foo.bar/cb"},
				consts.FormParameterClientID:     {"1234"},
				consts.FormParameterResponseType: {consts.ResponseTypeHybridFlowToken},
				consts.FormParameterScope:        {"foo bar"},
				consts.FormParameterAudience:     {"https://cloud.authelia.com/api https://www.authelia.com/api"},
			},
			mock: func(store *mock.MockStorage) {
				store.EXPECT().GetClient(gomock.Any(), "1234").Return(&DefaultClient{
					ResponseTypes: []string{consts.ResponseTypeHybridFlowToken},
					RedirectURIs:  []string{"https://foo.bar/cb"},
					Scopes:        []string{"foo", "bar"},
					Audience:      []string{"https://cloud.authelia.com/api", "https://www.authelia.com/api"},
				}, nil)
			},
			expect: &AuthorizeRequest{
				RedirectURI:   redir,
				ResponseTypes: []string{consts.ResponseTypeAuthorizationCodeFlow, consts.ResponseTypeImplicitFlowToken},
				Request: Request{
					Client: &DefaultClient{
						ResponseTypes: []string{consts.ResponseTypeHybridFlowToken}, RedirectURIs: []string{"https://foo.bar/cb"},
						Scopes:   []string{"foo", "bar"},
						Audience: []string{"https://cloud.authelia.com/api", "https://www.authelia.com/api"},
					},
					RequestedScope:    []string{"foo", "bar"},
					RequestedAudience: []string{"https://cloud.authelia.com/api", "https://www.authelia.com/api"},
				},
			},
		},
		{
			name:   "ShouldPassRepeatedAudienceParameter",
			config: &Config{ScopeStrategy: ExactScopeStrategy, AudienceMatchingStrategy: DefaultAudienceMatchingStrategy},
			query: url.Values{
				consts.FormParameterRedirectURI:  {"https://foo.bar/cb"},
				consts.FormParameterClientID:     {"1234"},
				consts.FormParameterResponseType: {consts.ResponseTypeHybridFlowToken},
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
				}, nil)
			},
			expect: &AuthorizeRequest{
				RedirectURI:   redir,
				ResponseTypes: []string{consts.ResponseTypeAuthorizationCodeFlow, consts.ResponseTypeImplicitFlowToken},
				State:         "strong-state",
				Request: Request{
					Client: &DefaultClient{
						ResponseTypes: []string{consts.ResponseTypeHybridFlowToken}, RedirectURIs: []string{"https://foo.bar/cb"},
						Scopes:   []string{"foo", "bar"},
						Audience: []string{"https://cloud.authelia.com/api", "https://www.authelia.com/api"},
					},
					RequestedScope:    []string{"foo", "bar"},
					RequestedAudience: []string{"https://cloud.authelia.com/api", "https://www.authelia.com/api"},
				},
			},
		},
		{
			name:   "ShouldPassRepeatedAudienceParameterWithTrickyValues",
			config: &Config{ScopeStrategy: ExactScopeStrategy, AudienceMatchingStrategy: ExactAudienceMatchingStrategy},
			query: url.Values{
				consts.FormParameterRedirectURI:  {"https://foo.bar/cb"},
				consts.FormParameterClientID:     {"1234"},
				consts.FormParameterResponseType: {consts.ResponseTypeHybridFlowToken},
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
				}, nil)
			},
			expect: &AuthorizeRequest{
				RedirectURI:   redir,
				ResponseTypes: []string{consts.ResponseTypeAuthorizationCodeFlow, consts.ResponseTypeImplicitFlowToken},
				State:         "strong-state",
				Request: Request{
					Client: &DefaultClient{
						ResponseTypes: []string{consts.ResponseTypeHybridFlowToken}, RedirectURIs: []string{"https://foo.bar/cb"},
						Scopes:   []string{"foo", "bar"},
						Audience: []string{"test value"},
					},
					RequestedScope:    []string{"foo", "bar"},
					RequestedAudience: []string{"test value"},
				},
			},
		},
		{
			name:   "ShouldPassRedirectURIWithSpecialCharacter",
			config: &Config{ScopeStrategy: ExactScopeStrategy, AudienceMatchingStrategy: DefaultAudienceMatchingStrategy},
			query: url.Values{
				consts.FormParameterRedirectURI:  {"web+application://callback"},
				consts.FormParameterClientID:     {"1234"},
				consts.FormParameterResponseType: {consts.ResponseTypeHybridFlowToken},
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
				}, nil)
			},
			expect: &AuthorizeRequest{
				RedirectURI:   specialCharRedir,
				ResponseTypes: []string{consts.ResponseTypeAuthorizationCodeFlow, consts.ResponseTypeImplicitFlowToken},
				State:         "strong-state",
				Request: Request{
					Client: &DefaultClient{
						ResponseTypes: []string{consts.ResponseTypeHybridFlowToken}, RedirectURIs: []string{"web+application://callback"},
						Scopes:   []string{"foo", "bar"},
						Audience: []string{"https://cloud.authelia.com/api", "https://www.authelia.com/api"},
					},
					RequestedScope:    []string{"foo", "bar"},
					RequestedAudience: []string{"https://cloud.authelia.com/api", "https://www.authelia.com/api"},
				},
			},
		},
		{
			name:   "ShouldPassAudienceWithDoubleSpacesBetweenValues",
			config: &Config{ScopeStrategy: ExactScopeStrategy, AudienceMatchingStrategy: DefaultAudienceMatchingStrategy},
			query: url.Values{
				consts.FormParameterRedirectURI:  {"https://foo.bar/cb"},
				consts.FormParameterClientID:     {"1234"},
				consts.FormParameterResponseType: {consts.ResponseTypeHybridFlowToken},
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
				}, nil)
			},
			expect: &AuthorizeRequest{
				RedirectURI:   redir,
				ResponseTypes: []string{consts.ResponseTypeAuthorizationCodeFlow, consts.ResponseTypeImplicitFlowToken},
				State:         "strong-state",
				Request: Request{
					Client: &DefaultClient{
						ResponseTypes: []string{consts.ResponseTypeHybridFlowToken}, RedirectURIs: []string{"https://foo.bar/cb"},
						Scopes:   []string{"foo", "bar"},
						Audience: []string{"https://cloud.authelia.com/api", "https://www.authelia.com/api"},
					},
					RequestedScope:    []string{"foo", "bar"},
					RequestedAudience: []string{"https://cloud.authelia.com/api", "https://www.authelia.com/api"},
				},
			},
		},
		{
			name:   "ShouldFailUnknownResponseMode",
			config: &Config{ScopeStrategy: ExactScopeStrategy, AudienceMatchingStrategy: DefaultAudienceMatchingStrategy},
			query: url.Values{
				consts.FormParameterRedirectURI:  {"https://foo.bar/cb"},
				consts.FormParameterClientID:     {"1234"},
				consts.FormParameterResponseType: {consts.ResponseTypeHybridFlowToken},
				consts.FormParameterState:        {"strong-state"},
				consts.FormParameterScope:        {"foo bar"},
				consts.FormParameterResponseMode: {"unknown"},
			},
			mock: func(store *mock.MockStorage) {
				store.EXPECT().GetClient(gomock.Any(), "1234").Return(&DefaultClient{RedirectURIs: []string{"https://foo.bar/cb"}, Scopes: []string{"foo", "bar"}, ResponseTypes: []string{"code token"}}, nil)
			},
			err: "The authorization server does not support obtaining a response using this response mode. Request with unsupported response_mode 'unknown'.",
		},
		{
			name:   "ShouldFailResponseModeRequestedButClientDoesNotSupportResponseMode",
			config: &Config{ScopeStrategy: ExactScopeStrategy, AudienceMatchingStrategy: DefaultAudienceMatchingStrategy},
			query: url.Values{
				consts.FormParameterRedirectURI:  {"https://foo.bar/cb"},
				consts.FormParameterClientID:     {"1234"},
				consts.FormParameterResponseType: {consts.ResponseTypeHybridFlowToken},
				consts.FormParameterState:        {"strong-state"},
				consts.FormParameterScope:        {"foo bar"},
				consts.FormParameterResponseMode: {consts.ResponseModeFormPost},
			},
			mock: func(store *mock.MockStorage) {
				store.EXPECT().GetClient(gomock.Any(), "1234").Return(&DefaultClient{RedirectURIs: []string{"https://foo.bar/cb"}, Scopes: []string{"foo", "bar"}, ResponseTypes: []string{"code token"}}, nil)
			},
			err: "The authorization server does not support obtaining a response using this response mode. The 'response_mode' requested was 'form_post', but the Authorization Server or registered OAuth 2.0 client doesn't allow or support this mode. The registered OAuth 2.0 Client with id '' does not the 'response_mode' type 'form_post', as it's not registered to support any.",
		},
		{
			name:   "ShouldFailRequestedResponseModeNotAllowed",
			config: &Config{ScopeStrategy: ExactScopeStrategy, AudienceMatchingStrategy: DefaultAudienceMatchingStrategy},
			query: url.Values{
				consts.FormParameterRedirectURI:  {"https://foo.bar/cb"},
				consts.FormParameterClientID:     {"1234"},
				consts.FormParameterResponseType: {consts.ResponseTypeHybridFlowToken},
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
					},
					ResponseModes: []ResponseModeType{ResponseModeQuery},
				}, nil)
			},
			err: "The authorization server does not support obtaining a response using this response mode. The 'response_mode' requested was 'form_post', but the Authorization Server or registered OAuth 2.0 client doesn't allow or support this mode. The registered OAuth 2.0 Client with id '' does not the 'response_mode' type 'form_post'.",
		},
		{
			name:   "ShouldPassWithResponseModeFormPost",
			config: &Config{ScopeStrategy: ExactScopeStrategy, AudienceMatchingStrategy: DefaultAudienceMatchingStrategy},
			query: url.Values{
				consts.FormParameterRedirectURI:  {"https://foo.bar/cb"},
				consts.FormParameterClientID:     {"1234"},
				consts.FormParameterResponseType: {consts.ResponseTypeHybridFlowToken},
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
					},
					ResponseModes: []ResponseModeType{ResponseModeFormPost},
				}, nil)
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
						},
						ResponseModes: []ResponseModeType{ResponseModeFormPost},
					},
					RequestedScope:    []string{"foo", "bar"},
					RequestedAudience: []string{"https://cloud.authelia.com/api", "https://www.authelia.com/api"},
				},
			},
		},
		{
			name:   "ShouldPassWithResponseModeQuery",
			config: &Config{ScopeStrategy: ExactScopeStrategy, AudienceMatchingStrategy: DefaultAudienceMatchingStrategy},
			query: url.Values{
				consts.FormParameterRedirectURI:  {"https://foo.bar/cb"},
				consts.FormParameterClientID:     {"1234"},
				consts.FormParameterResponseType: {consts.ResponseTypeAuthorizationCodeFlow},
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
					},
					ResponseModes: []ResponseModeType{ResponseModeQuery},
				}, nil)
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
						},
						ResponseModes: []ResponseModeType{ResponseModeQuery},
					},
					RequestedScope:    []string{"foo", "bar"},
					RequestedAudience: []string{"https://cloud.authelia.com/api", "https://www.authelia.com/api"},
				},
			},
		},
		{
			name:   "ShouldPassWithResponseModeFragment",
			config: &Config{ScopeStrategy: ExactScopeStrategy, AudienceMatchingStrategy: DefaultAudienceMatchingStrategy},
			query: url.Values{
				consts.FormParameterRedirectURI:  {"https://foo.bar/cb"},
				consts.FormParameterClientID:     {"1234"},
				consts.FormParameterResponseType: {consts.ResponseTypeHybridFlowToken},
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
					},
					ResponseModes: []ResponseModeType{ResponseModeFragment},
				}, nil)
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
						},
						ResponseModes: []ResponseModeType{ResponseModeFragment},
					},
					RequestedScope:    []string{"foo", "bar"},
					RequestedAudience: []string{"https://cloud.authelia.com/api", "https://www.authelia.com/api"},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			store := mock.NewMockStorage(ctrl)
			defer ctrl.Finish()

			tc.mock(store)
			if tc.r == nil {
				tc.r = &http.Request{Header: http.Header{}}
				if tc.query != nil {
					tc.r.URL = &url.URL{RawQuery: tc.query.Encode()}
				}
			}

			provider := &Fosite{Store: store, Config: tc.config}
			ar, err := provider.NewAuthorizeRequest(context.Background(), tc.r)
			if tc.err != "" {
				assert.EqualError(t, ErrorToDebugRFC6749Error(err), tc.err)
				AssertObjectKeysEqual(t, &AuthorizeRequest{State: tc.query.Get(consts.FormParameterState)}, ar, "State")
			} else {
				assert.NoError(t, err)
				AssertObjectKeysEqual(t, tc.expect, ar, "ResponseTypes", "RequestedAudience", "RequestedScope", "Client", "RedirectURI", "State")
				assert.NotNil(t, ar.GetRequestedAt())
			}
		})
	}
}
