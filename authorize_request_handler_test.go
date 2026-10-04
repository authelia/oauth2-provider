// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"authelia.com/provider/jose"

	. "authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/testing/mock"
	"authelia.com/provider/oauth2/token/jwt"
)

// See: https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#Terminology
func TestNewAuthorizeRequest(t *testing.T) {
	redir, _ := url.Parse("https://foo.bar/cb")
	specialCharRedir, _ := url.Parse("web+application://callback")

	parClient := &DefaultClient{
		ID:            "1234",
		RedirectURIs:  []string{"https://foo.bar/cb"},
		Scopes:        []string{"foo", "bar"},
		ResponseTypes: []string{consts.ResponseTypeAuthorizationCodeFlow},
		Audience:      []string{"https://cloud.authelia.com/api"},
	}

	newPARSession := func(client Client, session Session) *AuthorizeRequest {
		par := NewAuthorizeRequest()
		par.Client = client
		par.Session = session
		par.State = "strong-enough-state"
		par.RedirectURI = redir
		par.ResponseTypes = []string{consts.ResponseTypeAuthorizationCodeFlow}
		par.RequestedScope = []string{"foo", "bar"}
		par.RequestedAudience = []string{"https://cloud.authelia.com/api"}

		return par
	}

	parClientCurrent := &DefaultClient{
		ID:            "1234",
		RedirectURIs:  []string{"https://foo.bar/cb"},
		Scopes:        []string{"foo", "bar"},
		GrantTypes:    []string{consts.GrantTypeAuthorizationCode},
		ResponseTypes: []string{consts.ResponseTypeAuthorizationCodeFlow},
		Audience:      []string{"https://cloud.authelia.com/api"},
	}

	parSessionValid := &DefaultSession{ExpiresAt: map[TokenType]time.Time{PushedAuthorizeRequestContext: time.Now().Add(time.Hour)}}
	parSessionExpired := &DefaultSession{ExpiresAt: map[TokenType]time.Time{PushedAuthorizeRequestContext: time.Now().Add(-time.Hour)}}

	testCases := []struct {
		name   string
		config *Config
		r      *http.Request
		query  url.Values
		err    string
		mock   func(store *mock.MockStorage)
		par    func(store *mock.MockPARStorage)
		expect *AuthorizeRequest
		form   url.Values
	}{
		{
			name:   "ShouldFailEmptyRequest",
			config: &Config{ScopeStrategy: ExactScopeStrategy, AudienceStrategy: DefaultAudienceStrategy},
			r:      &http.Request{Method: http.MethodGet},
			err:    "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method). The requested OAuth 2.0 Client does not exist. foo",
			mock: func(store *mock.MockStorage) {
				store.EXPECT().GetClient(gomock.Any(), gomock.Any()).Return(nil, errors.New("foo"))
			},
		},
		{
			name:   "ShouldFailInvalidMethodPUT",
			config: &Config{ScopeStrategy: ExactScopeStrategy, AudienceStrategy: DefaultAudienceStrategy},
			r:      &http.Request{Method: http.MethodPut},
			err:    "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. HTTP method is 'PUT', expected 'GET' or 'POST'.",
			mock:   func(store *mock.MockStorage) {},
		},
		{
			name:   "ShouldFailInvalidMethodDELETE",
			config: &Config{ScopeStrategy: ExactScopeStrategy, AudienceStrategy: DefaultAudienceStrategy},
			r:      &http.Request{Method: http.MethodDelete},
			err:    "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. HTTP method is 'DELETE', expected 'GET' or 'POST'.",
			mock:   func(store *mock.MockStorage) {},
		},
		{
			name:   "ShouldFailInvalidRedirectURI",
			config: &Config{ScopeStrategy: ExactScopeStrategy, AudienceStrategy: DefaultAudienceStrategy},
			query:  url.Values{consts.FormParameterClientID: []string{"invalid"}},
			err:    "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method). The requested OAuth 2.0 Client does not exist. foo",
			mock: func(store *mock.MockStorage) {
				store.EXPECT().GetClient(gomock.Any(), gomock.Any()).Return(nil, errors.New("foo"))
			},
		},
		{
			name:   "ShouldFailInvalidClient",
			config: &Config{ScopeStrategy: ExactScopeStrategy, AudienceStrategy: DefaultAudienceStrategy},
			query:  url.Values{consts.FormParameterClientID: []string{"https://foo.bar/cb"}},
			err:    "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method). The requested OAuth 2.0 Client does not exist. foo",
			mock: func(store *mock.MockStorage) {
				store.EXPECT().GetClient(gomock.Any(), gomock.Any()).Return(nil, errors.New("foo"))
			},
		},
		{
			name:   "ShouldFailClientAndRequestRedirectsMismatchMissing",
			config: &Config{ScopeStrategy: ExactScopeStrategy, AudienceStrategy: DefaultAudienceStrategy},
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
			config: &Config{ScopeStrategy: ExactScopeStrategy, AudienceStrategy: DefaultAudienceStrategy},
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
			config: &Config{ScopeStrategy: ExactScopeStrategy, AudienceStrategy: DefaultAudienceStrategy},
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
			config: &Config{ScopeStrategy: ExactScopeStrategy, AudienceStrategy: DefaultAudienceStrategy},
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
			config: &Config{ScopeStrategy: ExactScopeStrategy, AudienceStrategy: DefaultAudienceStrategy},
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
			config: &Config{ScopeStrategy: ExactScopeStrategy, AudienceStrategy: DefaultAudienceStrategy},
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
			config: &Config{ScopeStrategy: ExactScopeStrategy, AudienceStrategy: DefaultAudienceStrategy},
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
			err: "The requested resource is invalid, missing, unknown, or malformed. Ensure the requested resource is an absolute URI without a fragment component that identifies a resource server known to the authorization server and that it is permitted for this client. Requested audience 'https://www.authelia.com/api' has not been whitelisted by the OAuth 2.0 Client.",
		},
		{
			name:   "ShouldPass",
			config: &Config{ScopeStrategy: ExactScopeStrategy, AudienceStrategy: DefaultAudienceStrategy},
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
			config: &Config{ScopeStrategy: ExactScopeStrategy, AudienceStrategy: DefaultAudienceStrategy, MinParameterEntropy: -1},
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
			config: &Config{ScopeStrategy: ExactScopeStrategy, AudienceStrategy: DefaultAudienceStrategy},
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
			config: &Config{ScopeStrategy: ExactScopeStrategy, AudienceStrategy: ExactAudienceStrategy},
			query: url.Values{
				consts.FormParameterRedirectURI:  {"https://foo.bar/cb"},
				consts.FormParameterClientID:     {"1234"},
				consts.FormParameterResponseType: {consts.ResponseTypeHybridFlowToken},
				consts.FormParameterState:        {"strong-state"},
				consts.FormParameterScope:        {"foo bar"},
				consts.FormParameterAudience:     {"https://test/value", ""},
			},
			mock: func(store *mock.MockStorage) {
				store.EXPECT().GetClient(gomock.Any(), "1234").Return(&DefaultClient{
					ResponseTypes: []string{consts.ResponseTypeHybridFlowToken},
					RedirectURIs:  []string{"https://foo.bar/cb"},
					Scopes:        []string{"foo", "bar"},
					Audience:      []string{"https://test/value"},
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
						Audience: []string{"https://test/value"},
					},
					RequestedScope:    []string{"foo", "bar"},
					RequestedAudience: []string{"https://test/value"},
				},
			},
		},
		{
			name:   "ShouldPassRedirectURIWithSpecialCharacter",
			config: &Config{ScopeStrategy: ExactScopeStrategy, AudienceStrategy: DefaultAudienceStrategy},
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
			config: &Config{ScopeStrategy: ExactScopeStrategy, AudienceStrategy: DefaultAudienceStrategy},
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
			config: &Config{ScopeStrategy: ExactScopeStrategy, AudienceStrategy: DefaultAudienceStrategy},
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
			config: &Config{ScopeStrategy: ExactScopeStrategy, AudienceStrategy: DefaultAudienceStrategy},
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
			config: &Config{ScopeStrategy: ExactScopeStrategy, AudienceStrategy: DefaultAudienceStrategy},
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
			config: &Config{ScopeStrategy: ExactScopeStrategy, AudienceStrategy: DefaultAudienceStrategy},
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
			config: &Config{ScopeStrategy: ExactScopeStrategy, AudienceStrategy: DefaultAudienceStrategy},
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
			config: &Config{ScopeStrategy: ExactScopeStrategy, AudienceStrategy: DefaultAudienceStrategy},
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
		{
			name:   "ShouldFailPARStorageNotImplemented",
			config: &Config{ScopeStrategy: ExactScopeStrategy, AudienceStrategy: DefaultAudienceStrategy},
			query: url.Values{
				consts.FormParameterRequestURI: {"urn:ietf:params:oauth:request_uri:storage-unsupported"},
				consts.FormParameterClientID:   {"1234"},
			},
			err:  "The authorization server encountered an unexpected condition that prevented it from fulfilling the request. The OAuth 2.0 provider does not support Pushed Authorization Requests The Pushed Authorization Request storage is not implemented",
			mock: func(store *mock.MockStorage) {},
		},
		{
			name:   "ShouldFailPARRequestURINotFound",
			config: &Config{ScopeStrategy: ExactScopeStrategy, AudienceStrategy: DefaultAudienceStrategy},
			query: url.Values{
				consts.FormParameterRequestURI: {"urn:ietf:params:oauth:request_uri:not-found"},
				consts.FormParameterClientID:   {"1234"},
			},
			err:  "The request_uri in the authorization request returns an error or contains invalid data. The 'request_uri' provided is invalid, expired, or otherwise incorrect. The Pushed Authorization Request session could not be found.",
			mock: func(store *mock.MockStorage) {},
			par: func(store *mock.MockPARStorage) {
				store.EXPECT().GetPARSession(gomock.Any(), "urn:ietf:params:oauth:request_uri:not-found").Return(nil, errors.New("The Pushed Authorization Request session could not be found."))
			},
		},
		{
			name:   "ShouldFailPARSessionNil",
			config: &Config{ScopeStrategy: ExactScopeStrategy, AudienceStrategy: DefaultAudienceStrategy},
			query: url.Values{
				consts.FormParameterRequestURI: {"urn:ietf:params:oauth:request_uri:nil-session"},
				consts.FormParameterClientID:   {"1234"},
			},
			err:  "The authorization server encountered an unexpected condition that prevented it from fulfilling the request. OAuth 2.0 request could not be processed due to an authorization server configuration issue. The Pushed Authorization Request is nil.",
			mock: func(store *mock.MockStorage) {},
			par: func(store *mock.MockPARStorage) {
				store.EXPECT().GetPARSession(gomock.Any(), "urn:ietf:params:oauth:request_uri:nil-session").Return(nil, nil)
			},
		},
		{
			name:   "ShouldFailPARSessionDeleteError",
			config: &Config{ScopeStrategy: ExactScopeStrategy, AudienceStrategy: DefaultAudienceStrategy},
			query: url.Values{
				consts.FormParameterRequestURI: {"urn:ietf:params:oauth:request_uri:delete-error"},
				consts.FormParameterClientID:   {"1234"},
				consts.FormParameterState:      {"strong-enough-state"},
			},
			err: "The authorization server encountered an unexpected condition that prevented it from fulfilling the request. Could not delete the Pushed Authorization Request session.",
			mock: func(store *mock.MockStorage) {
				store.EXPECT().GetClient(gomock.Any(), "1234").Return(parClient, nil)
			},
			par: func(store *mock.MockPARStorage) {
				store.EXPECT().GetPARSession(gomock.Any(), "urn:ietf:params:oauth:request_uri:delete-error").Return(newPARSession(parClient, parSessionValid), nil)
				store.EXPECT().DeletePARSession(gomock.Any(), "urn:ietf:params:oauth:request_uri:delete-error").Return(errors.New("Could not delete the Pushed Authorization Request session."))
			},
		},
		{
			name:   "ShouldFailPARSessionAlreadyRedeemed",
			config: &Config{ScopeStrategy: ExactScopeStrategy, AudienceStrategy: DefaultAudienceStrategy},
			query: url.Values{
				consts.FormParameterRequestURI: {"urn:ietf:params:oauth:request_uri:redeemed"},
				consts.FormParameterClientID:   {"1234"},
				consts.FormParameterState:      {"strong-enough-state"},
			},
			err: "The request_uri in the authorization request returns an error or contains invalid data. The 'request_uri' provided is invalid, expired, or otherwise incorrect. The Pushed Authorization Request session has already been redeemed.",
			mock: func(store *mock.MockStorage) {
				store.EXPECT().GetClient(gomock.Any(), "1234").Return(parClient, nil)
			},
			par: func(store *mock.MockPARStorage) {
				store.EXPECT().GetPARSession(gomock.Any(), "urn:ietf:params:oauth:request_uri:redeemed").Return(newPARSession(parClient, parSessionValid), nil)
				store.EXPECT().DeletePARSession(gomock.Any(), "urn:ietf:params:oauth:request_uri:redeemed").Return(ErrNotFound)
			},
		},
		{
			name:   "ShouldFailPARSessionExpired",
			config: &Config{ScopeStrategy: ExactScopeStrategy, AudienceStrategy: DefaultAudienceStrategy},
			query: url.Values{
				consts.FormParameterRequestURI: {"urn:ietf:params:oauth:request_uri:expired"},
				consts.FormParameterClientID:   {"1234"},
				consts.FormParameterState:      {"strong-enough-state"},
			},
			err: "The request_uri in the authorization request returns an error or contains invalid data. The 'request_uri' provided is invalid, expired, or otherwise incorrect. The Pushed Authorization Request session is expired.",
			mock: func(store *mock.MockStorage) {
				store.EXPECT().GetClient(gomock.Any(), "1234").Return(parClient, nil)
			},
			par: func(store *mock.MockPARStorage) {
				store.EXPECT().GetPARSession(gomock.Any(), "urn:ietf:params:oauth:request_uri:expired").Return(newPARSession(parClient, parSessionExpired), nil)
				store.EXPECT().DeletePARSession(gomock.Any(), "urn:ietf:params:oauth:request_uri:expired").Return(nil)
			},
		},
		{
			name:   "ShouldFailPARClientMismatch",
			config: &Config{ScopeStrategy: ExactScopeStrategy, AudienceStrategy: DefaultAudienceStrategy},
			query: url.Values{
				consts.FormParameterRequestURI: {"urn:ietf:params:oauth:request_uri:client-mismatch"},
				consts.FormParameterClientID:   {"1234"},
				consts.FormParameterState:      {"strong-enough-state"},
			},
			err:  "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The 'client_id' must match the one sent in the pushed authorization request.",
			mock: func(store *mock.MockStorage) {},
			par: func(store *mock.MockPARStorage) {
				store.EXPECT().GetPARSession(gomock.Any(), "urn:ietf:params:oauth:request_uri:client-mismatch").Return(newPARSession(&DefaultClient{ID: "a-different-client"}, parSessionValid), nil)
			},
		},
		{
			name:   "ShouldPassPAR",
			config: &Config{ScopeStrategy: ExactScopeStrategy, AudienceStrategy: DefaultAudienceStrategy},
			query: url.Values{
				consts.FormParameterRequestURI: {"urn:ietf:params:oauth:request_uri:valid"},
				consts.FormParameterClientID:   {"1234"},
			},
			mock: func(store *mock.MockStorage) {
				store.EXPECT().GetClient(gomock.Any(), "1234").Return(parClientCurrent, nil)
			},
			par: func(store *mock.MockPARStorage) {
				store.EXPECT().GetPARSession(gomock.Any(), "urn:ietf:params:oauth:request_uri:valid").Return(newPARSession(parClient, parSessionValid), nil)
				store.EXPECT().DeletePARSession(gomock.Any(), "urn:ietf:params:oauth:request_uri:valid").Return(nil)
			},
			expect: &AuthorizeRequest{
				RedirectURI:   redir,
				ResponseTypes: []string{consts.ResponseTypeAuthorizationCodeFlow},
				State:         "strong-enough-state",
				Request: Request{
					Client:            parClientCurrent,
					RequestedScope:    []string{"foo", "bar"},
					RequestedAudience: []string{"https://cloud.authelia.com/api"},
				},
			},
		},
		{
			name:   "ShouldFailPARClientDeleted",
			config: &Config{ScopeStrategy: ExactScopeStrategy, AudienceStrategy: DefaultAudienceStrategy},
			query: url.Values{
				consts.FormParameterRequestURI: {"urn:ietf:params:oauth:request_uri:valid"},
				consts.FormParameterClientID:   {"1234"},
				consts.FormParameterState:      {"strong-enough-state"},
			},
			err: "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method). The requested OAuth 2.0 Client does not exist. Could not find the requested resource(s).",
			mock: func(store *mock.MockStorage) {
				store.EXPECT().GetClient(gomock.Any(), "1234").Return(nil, ErrNotFound)
			},
			par: func(store *mock.MockPARStorage) {
				store.EXPECT().GetPARSession(gomock.Any(), "urn:ietf:params:oauth:request_uri:valid").Return(newPARSession(parClient, parSessionValid), nil)
			},
		},
		{
			name:   "ShouldFailPARClientNil",
			config: &Config{ScopeStrategy: ExactScopeStrategy, AudienceStrategy: DefaultAudienceStrategy},
			query: url.Values{
				consts.FormParameterRequestURI: {"urn:ietf:params:oauth:request_uri:valid"},
				consts.FormParameterClientID:   {"1234"},
				consts.FormParameterState:      {"strong-enough-state"},
			},
			err: "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method). The requested OAuth 2.0 Client does not exist.",
			mock: func(store *mock.MockStorage) {
				store.EXPECT().GetClient(gomock.Any(), "1234").Return(nil, nil)
			},
			par: func(store *mock.MockPARStorage) {
				store.EXPECT().GetPARSession(gomock.Any(), "urn:ietf:params:oauth:request_uri:valid").Return(newPARSession(parClient, parSessionValid), nil)
			},
		},
		{
			name:   "ShouldFailPARClientRedirectURIRemoved",
			config: &Config{ScopeStrategy: ExactScopeStrategy, AudienceStrategy: DefaultAudienceStrategy},
			query: url.Values{
				consts.FormParameterRequestURI: {"urn:ietf:params:oauth:request_uri:valid"},
				consts.FormParameterClientID:   {"1234"},
				consts.FormParameterState:      {"strong-enough-state"},
			},
			err: "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. The 'redirect_uri' parameter does not match any of the OAuth 2.0 Client's pre-registered 'redirect_uris'. The 'redirect_uris' registered with OAuth 2.0 Client with id '1234' did not match 'redirect_uri' value 'https://foo.bar/cb/removed'.",
			mock: func(store *mock.MockStorage) {
				store.EXPECT().GetClient(gomock.Any(), "1234").Return(parClient, nil)
			},
			par: func(store *mock.MockPARStorage) {
				par := newPARSession(parClient, parSessionValid)
				par.RedirectURI, _ = url.Parse("https://foo.bar/cb/removed")

				store.EXPECT().GetPARSession(gomock.Any(), "urn:ietf:params:oauth:request_uri:valid").Return(par, nil)
				store.EXPECT().DeletePARSession(gomock.Any(), "urn:ietf:params:oauth:request_uri:valid").Return(nil)
			},
		},
		{
			name:   "ShouldFailPARClientScopeRemoved",
			config: &Config{ScopeStrategy: ExactScopeStrategy, AudienceStrategy: DefaultAudienceStrategy},
			query: url.Values{
				consts.FormParameterRequestURI: {"urn:ietf:params:oauth:request_uri:valid"},
				consts.FormParameterClientID:   {"1234"},
				consts.FormParameterState:      {"strong-enough-state"},
			},
			err: "The requested scope is invalid, unknown, or malformed. The OAuth 2.0 Client is not allowed to request scope 'bar'.",
			mock: func(store *mock.MockStorage) {
				store.EXPECT().GetClient(gomock.Any(), "1234").Return(&DefaultClient{ID: "1234", RedirectURIs: []string{"https://foo.bar/cb"}, Scopes: []string{"foo"}, ResponseTypes: []string{consts.ResponseTypeAuthorizationCodeFlow}, Audience: []string{"https://cloud.authelia.com/api"}}, nil)
			},
			par: func(store *mock.MockPARStorage) {
				store.EXPECT().GetPARSession(gomock.Any(), "urn:ietf:params:oauth:request_uri:valid").Return(newPARSession(parClient, parSessionValid), nil)
				store.EXPECT().DeletePARSession(gomock.Any(), "urn:ietf:params:oauth:request_uri:valid").Return(nil)
			},
		},
		{
			name:   "ShouldFailPARClientAudienceRemoved",
			config: &Config{ScopeStrategy: ExactScopeStrategy, AudienceStrategy: DefaultAudienceStrategy},
			query: url.Values{
				consts.FormParameterRequestURI: {"urn:ietf:params:oauth:request_uri:valid"},
				consts.FormParameterClientID:   {"1234"},
				consts.FormParameterState:      {"strong-enough-state"},
			},
			err: "The requested resource is invalid, missing, unknown, or malformed. Ensure the requested resource is an absolute URI without a fragment component that identifies a resource server known to the authorization server and that it is permitted for this client. Requested audience 'https://cloud.authelia.com/api' has not been whitelisted by the OAuth 2.0 Client.",
			mock: func(store *mock.MockStorage) {
				store.EXPECT().GetClient(gomock.Any(), "1234").Return(&DefaultClient{ID: "1234", RedirectURIs: []string{"https://foo.bar/cb"}, Scopes: []string{"foo", "bar"}, ResponseTypes: []string{consts.ResponseTypeAuthorizationCodeFlow}}, nil)
			},
			par: func(store *mock.MockPARStorage) {
				store.EXPECT().GetPARSession(gomock.Any(), "urn:ietf:params:oauth:request_uri:valid").Return(newPARSession(parClient, parSessionValid), nil)
				store.EXPECT().DeletePARSession(gomock.Any(), "urn:ietf:params:oauth:request_uri:valid").Return(nil)
			},
		},
		{
			name:   "ShouldFailPARClientResponseTypeRemoved",
			config: &Config{ScopeStrategy: ExactScopeStrategy, AudienceStrategy: DefaultAudienceStrategy},
			query: url.Values{
				consts.FormParameterRequestURI: {"urn:ietf:params:oauth:request_uri:valid"},
				consts.FormParameterClientID:   {"1234"},
				consts.FormParameterState:      {"strong-enough-state"},
			},
			err: "The authorization server does not support obtaining a token using this method. The client is not allowed to request response_type 'code'.",
			mock: func(store *mock.MockStorage) {
				store.EXPECT().GetClient(gomock.Any(), "1234").Return(&DefaultClient{ID: "1234", RedirectURIs: []string{"https://foo.bar/cb"}, Scopes: []string{"foo", "bar"}, ResponseTypes: []string{consts.ResponseTypeImplicitFlowToken}, Audience: []string{"https://cloud.authelia.com/api"}}, nil)
			},
			par: func(store *mock.MockPARStorage) {
				store.EXPECT().GetPARSession(gomock.Any(), "urn:ietf:params:oauth:request_uri:valid").Return(newPARSession(parClient, parSessionValid), nil)
				store.EXPECT().DeletePARSession(gomock.Any(), "urn:ietf:params:oauth:request_uri:valid").Return(nil)
			},
		},
		{
			name:   "ShouldFailPARClientResponseModeRemoved",
			config: &Config{ScopeStrategy: ExactScopeStrategy, AudienceStrategy: DefaultAudienceStrategy},
			query: url.Values{
				consts.FormParameterRequestURI: {"urn:ietf:params:oauth:request_uri:valid"},
				consts.FormParameterClientID:   {"1234"},
				consts.FormParameterState:      {"strong-enough-state"},
			},
			err: "The authorization server does not support obtaining a response using this response mode. The 'response_mode' requested was 'form_post.jwt', but the Authorization Server or registered OAuth 2.0 client doesn't allow or support this mode. The registered OAuth 2.0 Client with id '1234' does not the 'response_mode' type 'form_post.jwt', as it's not registered to support any.",
			mock: func(store *mock.MockStorage) {
				store.EXPECT().GetClient(gomock.Any(), "1234").Return(parClient, nil)
			},
			par: func(store *mock.MockPARStorage) {
				par := newPARSession(parClient, parSessionValid)
				par.ResponseMode = ResponseModeFormPostJWT
				par.Form = url.Values{consts.FormParameterResponseMode: {consts.ResponseModeFormPostJWT}}

				store.EXPECT().GetPARSession(gomock.Any(), "urn:ietf:params:oauth:request_uri:valid").Return(par, nil)
				store.EXPECT().DeletePARSession(gomock.Any(), "urn:ietf:params:oauth:request_uri:valid").Return(nil)
			},
		},
		{
			name:   "ShouldPassPARClientRefetchDisabled",
			config: &Config{ScopeStrategy: ExactScopeStrategy, AudienceStrategy: DefaultAudienceStrategy, DisablePushedAuthorizationRequestClientRefetch: true},
			query: url.Values{
				consts.FormParameterRequestURI: {"urn:ietf:params:oauth:request_uri:valid"},
				consts.FormParameterClientID:   {"1234"},
			},
			mock: func(store *mock.MockStorage) {},
			par: func(store *mock.MockPARStorage) {
				store.EXPECT().GetPARSession(gomock.Any(), "urn:ietf:params:oauth:request_uri:valid").Return(newPARSession(parClient, parSessionValid), nil)
				store.EXPECT().DeletePARSession(gomock.Any(), "urn:ietf:params:oauth:request_uri:valid").Return(nil)
			},
			expect: &AuthorizeRequest{
				RedirectURI:   redir,
				ResponseTypes: []string{consts.ResponseTypeAuthorizationCodeFlow},
				State:         "strong-enough-state",
				Request: Request{
					Client:            parClient,
					RequestedScope:    []string{"foo", "bar"},
					RequestedAudience: []string{"https://cloud.authelia.com/api"},
				},
			},
		},
		{
			name:   "ShouldPassPARWithOnlyPushedParameters",
			config: &Config{ScopeStrategy: ExactScopeStrategy, AudienceStrategy: DefaultAudienceStrategy},
			query: url.Values{
				consts.FormParameterRequestURI:    {"urn:ietf:params:oauth:request_uri:valid"},
				consts.FormParameterClientID:      {"1234"},
				consts.FormParameterPrompt:        {consts.PromptTypeNone},
				consts.FormParameterCodeChallenge: {"injected-challenge"},
				consts.FormParameterNonce:         {"injected-nonce"},
			},
			mock: func(store *mock.MockStorage) {
				store.EXPECT().GetClient(gomock.Any(), "1234").Return(parClient, nil)
			},
			par: func(store *mock.MockPARStorage) {
				par := newPARSession(parClient, parSessionValid)
				par.Form = url.Values{
					consts.FormParameterClientID: {"1234"},
					consts.FormParameterNonce:    {"pushed-nonce"},
				}

				store.EXPECT().GetPARSession(gomock.Any(), "urn:ietf:params:oauth:request_uri:valid").Return(par, nil)
				store.EXPECT().DeletePARSession(gomock.Any(), "urn:ietf:params:oauth:request_uri:valid").Return(nil)
			},
			expect: &AuthorizeRequest{
				RedirectURI:   redir,
				ResponseTypes: []string{consts.ResponseTypeAuthorizationCodeFlow},
				State:         "strong-enough-state",
				Request: Request{
					Client:            parClient,
					RequestedScope:    []string{"foo", "bar"},
					RequestedAudience: []string{"https://cloud.authelia.com/api"},
				},
			},
			form: url.Values{
				consts.FormParameterRequestURI: {"urn:ietf:params:oauth:request_uri:valid"},
				consts.FormParameterClientID:   {"1234"},
				consts.FormParameterNonce:      {"pushed-nonce"},
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
				tc.r = &http.Request{Header: http.Header{}, Method: http.MethodGet}
				if tc.query != nil {
					tc.r.URL = &url.URL{RawQuery: tc.query.Encode()}
				}
			}

			provider := &Fosite{Store: store, Config: tc.config}

			if tc.par != nil {
				par := mock.NewMockPARStorage(ctrl)
				tc.par(par)
				provider.Store = &parStorage{MockStorage: store, MockPARStorage: par}
			}

			actual, err := provider.NewAuthorizeRequest(context.Background(), tc.r)

			if tc.err != "" {
				assert.EqualError(t, ErrorToDebugRFC6749Error(err), tc.err)
				AssertObjectKeysEqual(t, &AuthorizeRequest{State: tc.query.Get(consts.FormParameterState)}, actual, "State")

				return
			}

			require.NoError(t, ErrorToDebugRFC6749Error(err))
			AssertObjectKeysEqual(t, tc.expect, actual, "ResponseTypes", "RequestedAudience", "RequestedScope", "Client", "RedirectURI", "State")
			assert.NotNil(t, actual.GetRequestedAt())

			if tc.form != nil {
				assert.Equal(t, tc.form, actual.GetRequestForm())
			}
		})
	}
}

func TestNewAuthorizeRequestAuthorizationDetails(t *testing.T) {
	client := &DefaultClient{
		ID:            "1234",
		RedirectURIs:  []string{"https://foo.bar/cb"},
		Scopes:        []string{"foo"},
		ResponseTypes: []string{consts.ResponseTypeAuthorizationCodeFlow},
	}

	restrictedClient := &internal.AuthorizationDetailsClient{
		DefaultClient:             client,
		AuthorizationDetailsTypes: []string{},
	}

	handlers := []AuthorizationDetailsTypeHandler{internal.PaymentInitiationTypeHandler{}}

	testCases := []struct {
		name     string
		handlers []AuthorizationDetailsTypeHandler
		max      int
		client   Client
		raw      string
		err      error
		expect   AuthorizationDetails
	}{
		{
			name:     "ShouldAcceptDefaultMaximumObjects",
			handlers: handlers,
			client:   client,
			raw:      newRARDetailsJSON(32),
			expect:   newRARDetails(32),
		},
		{
			name:     "ShouldRejectMoreObjectsThanDefaultMaximum",
			handlers: handlers,
			client:   client,
			raw:      newRARDetailsJSON(33),
			err:      ErrInvalidAuthorizationDetails,
		},
		{
			name:     "ShouldRejectMoreObjectsThanConfiguredMaximum",
			handlers: handlers,
			max:      1,
			client:   client,
			raw:      newRARDetailsJSON(2),
			err:      ErrInvalidAuthorizationDetails,
		},
		{
			name:   "ShouldIgnoreWhenDisabled",
			client: client,
			raw:    testRARMalformedJSON,
		},
		{
			name:     "ShouldParse",
			handlers: handlers,
			client:   client,
			raw:      testRARDetailsJSON,
			expect:   AuthorizationDetails{{Type: internal.AuthorizationDetailsTypePaymentInitiation, Actions: []string{testRARActionInitiate}}},
		},
		{
			name:     "ShouldRejectUnknownType",
			handlers: handlers,
			client:   client,
			raw:      `[{"type":"x"}]`,
			err:      ErrInvalidAuthorizationDetails,
		},
		{
			name:     "ShouldRejectDisallowedForClient",
			handlers: handlers,
			client:   restrictedClient,
			raw:      testRARDetailsJSON,
			err:      ErrInvalidAuthorizationDetails,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			store := mock.NewMockStorage(ctrl)
			store.EXPECT().GetClient(gomock.Any(), "1234").Return(tc.client, nil)

			config := &Config{ScopeStrategy: ExactScopeStrategy, AudienceStrategy: DefaultAudienceStrategy, AuthorizationDetailsTypeHandlers: tc.handlers, AuthorizationDetailsMaxObjects: tc.max}
			provider := &Fosite{Store: store, Config: config}

			r := &http.Request{
				Method: http.MethodGet,
				Header: http.Header{},
				Form: url.Values{
					consts.FormParameterClientID:             {"1234"},
					consts.FormParameterRedirectURI:          {"https://foo.bar/cb"},
					consts.FormParameterResponseType:         {consts.ResponseTypeAuthorizationCodeFlow},
					consts.FormParameterState:                {"strong-state"},
					consts.FormParameterScope:                {"foo"},
					consts.FormParameterAuthorizationDetails: {tc.raw},
				},
			}

			ar, err := provider.NewAuthorizeRequest(context.Background(), r)

			if tc.err != nil {
				require.Error(t, err)
				assert.ErrorIs(t, err, tc.err)

				return
			}

			require.NoError(t, ErrorToDebugRFC6749Error(err))
			assert.Equal(t, tc.expect, ar.GetRequestedAuthorizationDetails())
		})
	}
}

func TestNewAuthorizeRequestAuthorizationDetailsFromRequestObject(t *testing.T) {
	keyRSA, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	jwkPrivateSigRSA := jose.JSONWebKey{Key: keyRSA, KeyID: testRARKeyID, Algorithm: string(jose.RS256), Use: consts.JSONWebTokenUseSignature}
	jwkPublicSigRSA := jose.JSONWebKey{Key: keyRSA.Public(), KeyID: testRARKeyID, Algorithm: string(jose.RS256), Use: consts.JSONWebTokenUseSignature}

	client := &DefaultJARClient{
		JSONWebKeys:             &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwkPublicSigRSA}},
		RequestObjectSigningAlg: string(jose.RS256),
		DefaultClient: &DefaultClient{
			ID:            "foo",
			RedirectURIs:  []string{"https://foo.bar/cb"},
			Scopes:        []string{consts.ScopeOpenID},
			ResponseTypes: []string{consts.ResponseTypeAuthorizationCodeFlow},
		},
	}

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	store := mock.NewMockStorage(ctrl)
	store.EXPECT().GetClient(gomock.Any(), "foo").Return(client, nil)

	config := &Config{
		ScopeStrategy:                    ExactScopeStrategy,
		AudienceStrategy:                 DefaultAudienceStrategy,
		IDTokenIssuer:                    testRARIssuer,
		JWKSFetcherStrategy:              NewDefaultJWKSFetcherStrategy(),
		AuthorizationDetailsTypeHandlers: []AuthorizationDetailsTypeHandler{internal.PaymentInitiationTypeHandler{}},
	}

	strategy := &jwt.DefaultStrategy{Config: config, Issuer: jwt.NewDefaultIssuerUnverifiedFromJWKS(&jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwkPrivateSigRSA}})}
	config.JWTStrategy = strategy

	assertion, _, err := strategy.Encode(t.Context(), jwt.MapClaims{
		consts.ClaimIssuer:                       "foo",
		consts.ClaimAudience:                     []string{testRARIssuer},
		consts.FormParameterClientID:             "foo",
		consts.FormParameterResponseType:         consts.ResponseTypeAuthorizationCodeFlow,
		consts.FormParameterScope:                consts.ScopeOpenID,
		consts.FormParameterState:                "strong-enough-state",
		consts.FormParameterRedirectURI:          "https://foo.bar/cb",
		consts.FormParameterAuthorizationDetails: []any{map[string]any{testRARMemberType: internal.AuthorizationDetailsTypePaymentInitiation, testRARMemberActions: []any{testRARActionInitiate}}},
	})
	require.NoError(t, err)

	provider := &Fosite{Store: store, Config: config}

	query := url.Values{
		consts.FormParameterClientID:             {"foo"},
		consts.FormParameterResponseType:         {consts.ResponseTypeAuthorizationCodeFlow},
		consts.FormParameterScope:                {consts.ScopeOpenID},
		consts.FormParameterRequest:              {assertion},
		consts.FormParameterAuthorizationDetails: {`[{"type":"payment_initiation","actions":["status"]}]`},
	}

	r := &http.Request{Header: http.Header{}, Method: http.MethodGet, URL: &url.URL{RawQuery: query.Encode()}}

	ar, err := provider.NewAuthorizeRequest(context.Background(), r)
	require.NoError(t, ErrorToDebugRFC6749Error(err))

	details := ar.GetRequestedAuthorizationDetails()
	require.Len(t, details, 1)
	assert.Equal(t, internal.AuthorizationDetailsTypePaymentInitiation, details[0].Type)
	assert.Equal(t, []string{testRARActionInitiate}, details[0].Actions)
}

func TestAuthorizeRequestFromPARRevalidatesAuthorizationDetails(t *testing.T) {
	const requestURI = "urn:ietf:params:oauth:request_uri:rar"

	redir, _ := url.Parse("https://foo.bar/cb")

	newPARSessionWithDetails := func(client Client) *AuthorizeRequest {
		par := NewAuthorizeRequest()
		par.Client = client
		par.Session = &DefaultSession{ExpiresAt: map[TokenType]time.Time{PushedAuthorizeRequestContext: time.Now().Add(time.Hour)}}
		par.State = "strong-enough-state"
		par.RedirectURI = redir
		par.ResponseTypes = []string{consts.ResponseTypeAuthorizationCodeFlow}
		par.RequestedScope = []string{"foo"}
		par.SetRequestedAuthorizationDetails(AuthorizationDetails{{Type: internal.AuthorizationDetailsTypePaymentInitiation, Actions: []string{testRARActionInitiate}}})

		return par
	}

	testCases := []struct {
		name  string
		types []string
		err   bool
	}{
		{name: "ShouldRejectWhenNoLongerAllowed", types: []string{}, err: true},
		{name: "ShouldPassWhenAllowed", types: []string{internal.AuthorizationDetailsTypePaymentInitiation}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			client := &internal.AuthorizationDetailsClient{
				DefaultClient: &DefaultClient{
					ID:            testRARClientID,
					RedirectURIs:  []string{"https://foo.bar/cb"},
					Scopes:        []string{"foo"},
					ResponseTypes: []string{consts.ResponseTypeAuthorizationCodeFlow},
				},
				AuthorizationDetailsTypes: tc.types,
			}

			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockStorage := mock.NewMockStorage(ctrl)
			mockStorage.EXPECT().GetClient(gomock.Any(), testRARClientID).Return(client, nil)

			mockPAR := mock.NewMockPARStorage(ctrl)
			mockPAR.EXPECT().GetPARSession(gomock.Any(), requestURI).Return(newPARSessionWithDetails(client), nil)
			mockPAR.EXPECT().DeletePARSession(gomock.Any(), requestURI).Return(nil)

			config := &Config{
				ScopeStrategy:                    ExactScopeStrategy,
				AudienceStrategy:                 DefaultAudienceStrategy,
				AuthorizationDetailsTypeHandlers: []AuthorizationDetailsTypeHandler{internal.PaymentInitiationTypeHandler{}},
			}
			provider := &Fosite{Store: &parStorage{MockStorage: mockStorage, MockPARStorage: mockPAR}, Config: config}

			query := url.Values{
				consts.FormParameterRequestURI: {requestURI},
				consts.FormParameterClientID:   {testRARClientID},
			}

			r := &http.Request{Header: http.Header{}, Method: http.MethodGet, URL: &url.URL{RawQuery: query.Encode()}}

			ar, err := provider.NewAuthorizeRequest(context.Background(), r)

			if tc.err {
				require.Error(t, err)
				assert.ErrorIs(t, err, ErrInvalidAuthorizationDetails)

				return
			}

			require.NoError(t, ErrorToDebugRFC6749Error(err))
			assert.Equal(t, AuthorizationDetails{{Type: internal.AuthorizationDetailsTypePaymentInitiation, Actions: []string{testRARActionInitiate}}}, ar.GetRequestedAuthorizationDetails())
		})
	}
}

func TestNewAuthorizeRequestEarlyErrorResponseMode(t *testing.T) {
	testCases := []struct {
		name         string
		responseType string
		registered   string
		scope        string
		fragment     bool
	}{
		{
			name:         "ShouldWriteInvalidScopeInQueryForCode",
			responseType: consts.ResponseTypeAuthorizationCodeFlow,
			scope:        "bar",
		},
		{
			name:         "ShouldWriteInvalidScopeInFragmentForToken",
			responseType: consts.ResponseTypeImplicitFlowToken,
			scope:        "bar",
			fragment:     true,
		},
		{
			name:         "ShouldWriteInvalidScopeInFragmentForIDToken",
			responseType: consts.ResponseTypeImplicitFlowIDToken,
			scope:        "openid bar",
			fragment:     true,
		},
		{
			name:         "ShouldWriteInvalidScopeInFragmentForHybrid",
			responseType: consts.ResponseTypeHybridFlowIDToken,
			scope:        "openid baz",
			fragment:     true,
		},
		{
			name:         "ShouldWriteUnsupportedResponseTypeInFragmentForToken",
			responseType: "token unknown",
			registered:   consts.ResponseTypeImplicitFlowToken,
			scope:        "foo",
			fragment:     true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			store := mock.NewMockStorage(ctrl)

			registered := tc.registered
			if registered == "" {
				registered = tc.responseType
			}

			client := &DefaultClient{
				ID:            "1234",
				RedirectURIs:  []string{"https://foo.bar/cb"},
				Scopes:        []string{consts.ScopeOpenID, "foo"},
				ResponseTypes: []string{registered},
			}

			store.EXPECT().GetClient(gomock.Any(), "1234").Return(client, nil)

			query := url.Values{
				consts.FormParameterClientID:     []string{"1234"},
				consts.FormParameterRedirectURI:  []string{"https://foo.bar/cb"},
				consts.FormParameterResponseType: []string{tc.responseType},
				consts.FormParameterScope:        []string{tc.scope},
				consts.FormParameterState:        []string{"strong-enough-state"},
				consts.FormParameterNonce:        []string{"strong-enough-nonce"},
			}

			provider := &Fosite{Store: store, Config: &Config{ScopeStrategy: ExactScopeStrategy, AudienceStrategy: DefaultAudienceStrategy}}

			r := &http.Request{Header: http.Header{}, Method: http.MethodGet, URL: &url.URL{RawQuery: query.Encode()}}

			requester, err := provider.NewAuthorizeRequest(context.Background(), r)
			require.Error(t, err)

			rw := httptest.NewRecorder()

			provider.WriteAuthorizeError(context.Background(), rw, requester, err)

			require.Equal(t, http.StatusSeeOther, rw.Code)

			location, err := url.Parse(rw.Header().Get(consts.HeaderLocation))
			require.NoError(t, err)

			var values url.Values

			if tc.fragment {
				assert.Empty(t, location.RawQuery)

				values, err = url.ParseQuery(location.Fragment)
				require.NoError(t, err)
			} else {
				assert.Empty(t, location.Fragment)

				values = location.Query()
			}

			assert.NotEmpty(t, values.Get(consts.FormParameterError))
			assert.Equal(t, "strong-enough-state", values.Get(consts.FormParameterState))
		})
	}
}

type parStorage struct {
	*mock.MockStorage
	*mock.MockPARStorage
}
