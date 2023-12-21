// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"fmt"
	"net/http"
	"net/url"
	"runtime/debug"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	. "authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal"
	"authelia.com/provider/oauth2/internal/consts"
)

// Should pass
//
//   - https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#Terminology
//     The OAuth 2.0 specification allows for registration of space-separated response_type parameter values.
//     If a Response Type contains one of more space characters (%20), it is compared as a space-delimited list of
//     values in which the order of values does not matter.
func TestNewPushedAuthorizeRequest(t *testing.T) {
	ctrl := gomock.NewController(t)
	store := internal.NewMockStorage(ctrl)
	hasher := internal.NewMockHasher(ctrl)
	defer ctrl.Finish()

	config := &Config{
		ScopeStrategy:            ExactScopeStrategy,
		AudienceMatchingStrategy: DefaultAudienceMatchingStrategy,
		ClientSecretsHasher:      hasher,
	}

	provider := &Fosite{
		Store:  store,
		Config: config,
	}

	ctx := NewContext()

	redir, _ := url.Parse("https://foo.bar/cb")
	specialCharRedir, _ := url.Parse("web+application://callback")
	for _, c := range []struct {
		desc          string
		provider      *Fosite
		r             *http.Request
		query         url.Values
		expectedError error
		mock          func()
		expect        *AuthorizeRequest
	}{
		/* empty request */
		{
			desc:     "empty request fails",
			provider: provider,
			r: &http.Request{
				Method: "POST",
			},
			expectedError: ErrInvalidClient,
			mock:          func() {},
		},
		/* invalid redirect uri */
		{
			desc:          "invalid redirect uri fails",
			provider:      provider,
			query:         url.Values{"redirect_uri": []string{"invalid"}},
			expectedError: ErrInvalidClient,
			mock:          func() {},
		},
		/* invalid client */
		{
			desc:          "invalid client fails",
			provider:      provider,
			query:         url.Values{consts.FormParameterRedirectURI: []string{"https://foo.bar/cb"}},
			expectedError: ErrInvalidClient,
			mock:          func() {},
		},
		/* redirect client mismatch */
		{
			desc:     "client and request redirects mismatch",
			provider: provider,
			query: url.Values{
				consts.FormParameterClientID:     []string{"1234"},
				consts.FormParameterClientSecret: []string{"1234"},
			},
			expectedError: ErrInvalidRequest,
			mock: func() {
				store.EXPECT().GetClient(gomock.Any(), "1234").Return(&DefaultClient{RedirectURIs: []string{"invalid"}, Scopes: []string{}, Secret: []byte("1234")}, nil).MaxTimes(2)
				hasher.EXPECT().Compare(ctx, gomock.Eq([]byte("1234")), gomock.Eq([]byte("1234"))).Return(nil)
			},
		},
		/* redirect client mismatch */
		{
			desc:     "client and request redirects mismatch",
			provider: provider,
			query: url.Values{
				consts.FormParameterRedirectURI:  []string{""},
				consts.FormParameterClientID:     []string{"1234"},
				consts.FormParameterClientSecret: []string{"1234"},
			},
			expectedError: ErrInvalidRequest,
			mock: func() {
				store.EXPECT().GetClient(gomock.Any(), "1234").Return(&DefaultClient{RedirectURIs: []string{"invalid"}, Scopes: []string{}, Secret: []byte("1234")}, nil).MaxTimes(2)
				hasher.EXPECT().Compare(ctx, gomock.Eq([]byte("1234")), gomock.Eq([]byte("1234"))).Return(nil)
			},
		},
		/* redirect client mismatch */
		{
			desc:     "client and request redirects mismatch",
			provider: provider,
			query: url.Values{
				consts.FormParameterRedirectURI:  []string{"https://foo.bar/cb"},
				consts.FormParameterClientID:     []string{"1234"},
				consts.FormParameterClientSecret: []string{"1234"},
			},
			expectedError: ErrInvalidRequest,
			mock: func() {
				store.EXPECT().GetClient(gomock.Any(), "1234").Return(&DefaultClient{RedirectURIs: []string{"invalid"}, Scopes: []string{}, Secret: []byte("1234")}, nil).MaxTimes(2)
				hasher.EXPECT().Compare(ctx, gomock.Eq([]byte("1234")), gomock.Eq([]byte("1234"))).Return(nil)
			},
		},
		/* no state */
		{
			desc:     "no state",
			provider: provider,
			query: url.Values{
				consts.FormParameterRedirectURI:  []string{"https://foo.bar/cb"},
				consts.FormParameterClientID:     []string{"1234"},
				consts.FormParameterClientSecret: []string{"1234"},
				consts.FormParameterResponseType: []string{consts.ResponseTypeAuthorizationCodeFlow},
			},
			expectedError: ErrInvalidState,
			mock: func() {
				store.EXPECT().GetClient(gomock.Any(), "1234").Return(&DefaultClient{RedirectURIs: []string{"https://foo.bar/cb"}, Scopes: []string{}, Secret: []byte("1234")}, nil).MaxTimes(2)
				hasher.EXPECT().Compare(ctx, gomock.Eq([]byte("1234")), gomock.Eq([]byte("1234"))).Return(nil)
			},
		},
		/* short state */
		{
			desc:     "short state",
			provider: provider,
			query: url.Values{
				consts.FormParameterRedirectURI:  {"https://foo.bar/cb"},
				consts.FormParameterClientID:     {"1234"},
				consts.FormParameterClientSecret: []string{"1234"},
				consts.FormParameterResponseType: {"code"},
				consts.FormParameterState:        {"short"},
			},
			expectedError: ErrInvalidState,
			mock: func() {
				store.EXPECT().GetClient(gomock.Any(), "1234").Return(&DefaultClient{RedirectURIs: []string{"https://foo.bar/cb"}, Scopes: []string{}, Secret: []byte("1234")}, nil).MaxTimes(2)
				hasher.EXPECT().Compare(ctx, gomock.Eq([]byte("1234")), gomock.Eq([]byte("1234"))).Return(nil)
			},
		},
		/* fails because scope not given */
		{
			desc:     "should fail because client does not have scope baz",
			provider: provider,
			query: url.Values{
				consts.FormParameterRedirectURI:  {"https://foo.bar/cb"},
				consts.FormParameterClientID:     {"1234"},
				consts.FormParameterClientSecret: []string{"1234"},
				consts.FormParameterResponseType: []string{consts.ResponseTypeHybridFlowToken},
				consts.FormParameterState:        {"strong-state"},
				consts.FormParameterScope:        {"foo bar baz"},
			},
			mock: func() {
				store.EXPECT().GetClient(gomock.Any(), "1234").Return(&DefaultClient{RedirectURIs: []string{"https://foo.bar/cb"}, Scopes: []string{"foo", "bar"}, Secret: []byte("1234")}, nil).MaxTimes(2)
				hasher.EXPECT().Compare(ctx, gomock.Eq([]byte("1234")), gomock.Eq([]byte("1234"))).Return(nil)
			},
			expectedError: ErrInvalidScope,
		},
		/* fails because scope not given */
		{
			desc:     "should fail because client does not have scope baz",
			provider: provider,
			query: url.Values{
				consts.FormParameterRedirectURI:  {"https://foo.bar/cb"},
				consts.FormParameterClientID:     {"1234"},
				consts.FormParameterClientSecret: []string{"1234"},
				consts.FormParameterResponseType: []string{consts.ResponseTypeHybridFlowToken},
				consts.FormParameterState:        {"strong-state"},
				consts.FormParameterScope:        {"foo bar"},
				consts.FormParameterAudience:     {"https://cloud.authelia.com/api https://www.authelia.com/api"},
			},
			mock: func() {
				store.EXPECT().GetClient(gomock.Any(), "1234").Return(&DefaultClient{
					RedirectURIs: []string{"https://foo.bar/cb"}, Scopes: []string{"foo", "bar"},
					Audience: []string{"https://cloud.authelia.com/api"},
					Secret:   []byte("1234"),
				}, nil).MaxTimes(2)
				hasher.EXPECT().Compare(ctx, gomock.Eq([]byte("1234")), gomock.Eq([]byte("1234"))).Return(nil)
			},
			expectedError: ErrInvalidRequest,
		},
		/* success case */
		{
			desc:     "should pass",
			provider: provider,
			query: url.Values{
				consts.FormParameterRedirectURI:  {"https://foo.bar/cb"},
				consts.FormParameterClientID:     {"1234"},
				consts.FormParameterClientSecret: []string{"1234"},
				consts.FormParameterResponseType: []string{consts.ResponseTypeHybridFlowToken},
				consts.FormParameterState:        {"strong-state"},
				consts.FormParameterScope:        {"foo bar"},
				consts.FormParameterAudience:     {"https://cloud.authelia.com/api https://www.authelia.com/api"},
			},
			mock: func() {
				store.EXPECT().GetClient(gomock.Any(), "1234").Return(&DefaultClient{
					ResponseTypes: []string{consts.ResponseTypeHybridFlowToken},
					RedirectURIs:  []string{"https://foo.bar/cb"},
					Scopes:        []string{"foo", "bar"},
					Audience:      []string{"https://cloud.authelia.com/api", "https://www.authelia.com/api"},
					Secret:        []byte("1234"),
				}, nil).MaxTimes(2)
				hasher.EXPECT().Compare(ctx, gomock.Eq([]byte("1234")), gomock.Eq([]byte("1234"))).Return(nil)
			},
			expect: &AuthorizeRequest{
				RedirectURI:   redir,
				ResponseTypes: []string{"code", "token"},
				State:         "strong-state",
				Request: Request{
					Client: &DefaultClient{
						ResponseTypes: []string{consts.ResponseTypeHybridFlowToken}, RedirectURIs: []string{"https://foo.bar/cb"},
						Scopes:   []string{"foo", "bar"},
						Audience: []string{"https://cloud.authelia.com/api", "https://www.authelia.com/api"},
						Secret:   []byte("1234"),
					},
					RequestedScope:    []string{"foo", "bar"},
					RequestedAudience: []string{"https://cloud.authelia.com/api", "https://www.authelia.com/api"},
				},
			},
		},
		/* repeated audience parameter */
		{
			desc:     "repeated audience parameter",
			provider: provider,
			query: url.Values{
				consts.FormParameterRedirectURI:  {"https://foo.bar/cb"},
				consts.FormParameterClientID:     {"1234"},
				consts.FormParameterClientSecret: []string{"1234"},
				consts.FormParameterResponseType: []string{consts.ResponseTypeHybridFlowToken},
				consts.FormParameterState:        {"strong-state"},
				consts.FormParameterScope:        {"foo bar"},
				consts.FormParameterAudience:     {"https://cloud.authelia.com/api", "https://www.authelia.com/api"},
			},
			mock: func() {
				store.EXPECT().GetClient(gomock.Any(), "1234").Return(&DefaultClient{
					ResponseTypes: []string{consts.ResponseTypeHybridFlowToken},
					RedirectURIs:  []string{"https://foo.bar/cb"},
					Scopes:        []string{"foo", "bar"},
					Audience:      []string{"https://cloud.authelia.com/api", "https://www.authelia.com/api"},
					Secret:        []byte("1234"),
				}, nil).MaxTimes(2)
				hasher.EXPECT().Compare(ctx, gomock.Eq([]byte("1234")), gomock.Eq([]byte("1234"))).Return(nil)
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
						Secret:   []byte("1234"),
					},
					RequestedScope:    []string{"foo", "bar"},
					RequestedAudience: []string{"https://cloud.authelia.com/api", "https://www.authelia.com/api"},
				},
			},
		},
		/* repeated audience parameter with tricky values */
		{
			desc:     "repeated audience parameter with tricky values",
			provider: provider,
			query: url.Values{
				consts.FormParameterRedirectURI:  {"https://foo.bar/cb"},
				consts.FormParameterClientID:     {"1234"},
				consts.FormParameterClientSecret: []string{"1234"},
				consts.FormParameterResponseType: []string{consts.ResponseTypeHybridFlowToken},
				consts.FormParameterState:        {"strong-state"},
				consts.FormParameterScope:        {"foo bar"},
				consts.FormParameterAudience:     {"test value", ""},
			},
			mock: func() {
				store.EXPECT().GetClient(gomock.Any(), "1234").Return(&DefaultClient{
					ResponseTypes: []string{consts.ResponseTypeHybridFlowToken},
					RedirectURIs:  []string{"https://foo.bar/cb"},
					Scopes:        []string{"foo", "bar"},
					Audience:      []string{"test value"},
					Secret:        []byte("1234"),
				}, nil).MaxTimes(2)
				hasher.EXPECT().Compare(ctx, gomock.Eq([]byte("1234")), gomock.Eq([]byte("1234"))).Return(nil)
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
						Secret:   []byte("1234"),
					},
					RequestedScope:    []string{"foo", "bar"},
					RequestedAudience: []string{"test value"},
				},
			},
		},
		/* redirect_uri with special character in protocol*/
		{
			desc:     "redirect_uri with special character",
			provider: provider,
			query: url.Values{
				consts.FormParameterRedirectURI:  {"web+application://callback"},
				consts.FormParameterClientID:     {"1234"},
				consts.FormParameterClientSecret: []string{"1234"},
				consts.FormParameterResponseType: []string{consts.ResponseTypeHybridFlowToken},
				consts.FormParameterState:        {"strong-state"},
				consts.FormParameterScope:        {"foo bar"},
				consts.FormParameterAudience:     {"https://cloud.authelia.com/api https://www.authelia.com/api"},
			},
			mock: func() {
				store.EXPECT().GetClient(gomock.Any(), "1234").Return(&DefaultClient{
					ResponseTypes: []string{consts.ResponseTypeHybridFlowToken},
					RedirectURIs:  []string{"web+application://callback"},
					Scopes:        []string{"foo", "bar"},
					Audience:      []string{"https://cloud.authelia.com/api", "https://www.authelia.com/api"},
					Secret:        []byte("1234"),
				}, nil).MaxTimes(2)
				hasher.EXPECT().Compare(ctx, gomock.Eq([]byte("1234")), gomock.Eq([]byte("1234"))).Return(nil)
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
						Secret:   []byte("1234"),
					},
					RequestedScope:    []string{"foo", "bar"},
					RequestedAudience: []string{"https://cloud.authelia.com/api", "https://www.authelia.com/api"},
				},
			},
		},
		/* audience with double spaces between values */
		{
			desc:     "audience with double spaces between values",
			provider: provider,
			query: url.Values{
				consts.FormParameterRedirectURI:  {"https://foo.bar/cb"},
				consts.FormParameterClientID:     {"1234"},
				consts.FormParameterClientSecret: []string{"1234"},
				consts.FormParameterResponseType: []string{consts.ResponseTypeHybridFlowToken},
				consts.FormParameterState:        {"strong-state"},
				consts.FormParameterScope:        {"foo bar"},
				consts.FormParameterAudience:     {"https://cloud.authelia.com/api  https://www.authelia.com/api"},
			},
			mock: func() {
				store.EXPECT().GetClient(gomock.Any(), "1234").Return(&DefaultClient{
					ResponseTypes: []string{consts.ResponseTypeHybridFlowToken},
					RedirectURIs:  []string{"https://foo.bar/cb"},
					Scopes:        []string{"foo", "bar"},
					Audience:      []string{"https://cloud.authelia.com/api", "https://www.authelia.com/api"},
					Secret:        []byte("1234"),
				}, nil).MaxTimes(2)
				hasher.EXPECT().Compare(ctx, gomock.Eq([]byte("1234")), gomock.Eq([]byte("1234"))).Return(nil)
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
						Secret:   []byte("1234"),
					},
					RequestedScope:    []string{"foo", "bar"},
					RequestedAudience: []string{"https://cloud.authelia.com/api", "https://www.authelia.com/api"},
				},
			},
		},
		/* fails because unknown response_mode*/
		{
			desc:     "should fail because unknown response_mode",
			provider: provider,
			query: url.Values{
				consts.FormParameterRedirectURI:  {"https://foo.bar/cb"},
				consts.FormParameterClientID:     {"1234"},
				consts.FormParameterClientSecret: []string{"1234"},
				consts.FormParameterResponseType: []string{consts.ResponseTypeHybridFlowToken},
				consts.FormParameterState:        {"strong-state"},
				consts.FormParameterScope:        {"foo bar"},
				consts.FormParameterResponseMode: {"unknown"},
			},
			mock: func() {
				store.EXPECT().GetClient(gomock.Any(), "1234").Return(&DefaultClient{RedirectURIs: []string{"https://foo.bar/cb"}, Scopes: []string{"foo", "bar"}, ResponseTypes: []string{consts.ResponseTypeHybridFlowToken}, Secret: []byte("1234")}, nil).MaxTimes(2)
				hasher.EXPECT().Compare(ctx, gomock.Eq([]byte("1234")), gomock.Eq([]byte("1234"))).Return(nil)
			},
			expectedError: ErrUnsupportedResponseMode,
		},
		/* fails because response_mode is requested but the OAuth 2.0 client doesn't support response mode */
		{
			desc:     "should fail because response_mode is requested but the OAuth 2.0 client doesn't support response mode",
			provider: provider,
			query: url.Values{
				consts.FormParameterRedirectURI:  {"https://foo.bar/cb"},
				consts.FormParameterClientID:     {"1234"},
				consts.FormParameterClientSecret: []string{"1234"},
				consts.FormParameterResponseType: []string{consts.ResponseTypeHybridFlowToken},
				consts.FormParameterState:        {"strong-state"},
				consts.FormParameterScope:        {"foo bar"},
				consts.FormParameterResponseMode: {consts.ResponseModeFormPost},
			},
			mock: func() {
				store.EXPECT().GetClient(gomock.Any(), "1234").Return(&DefaultClient{RedirectURIs: []string{"https://foo.bar/cb"}, Scopes: []string{"foo", "bar"}, ResponseTypes: []string{consts.ResponseTypeHybridFlowToken}, Secret: []byte("1234")}, nil).MaxTimes(2)
				hasher.EXPECT().Compare(ctx, gomock.Eq([]byte("1234")), gomock.Eq([]byte("1234"))).Return(nil)
			},
			expectedError: ErrUnsupportedResponseMode,
		},
		/* fails because requested response mode is not allowed */
		{
			desc:     "should fail because requested response mode is not allowed",
			provider: provider,
			query: url.Values{
				consts.FormParameterRedirectURI:  {"https://foo.bar/cb"},
				consts.FormParameterClientID:     {"1234"},
				consts.FormParameterClientSecret: []string{"1234"},
				consts.FormParameterResponseType: []string{consts.ResponseTypeHybridFlowToken},
				consts.FormParameterState:        {"strong-state"},
				consts.FormParameterScope:        {"foo bar"},
				consts.FormParameterResponseMode: {consts.ResponseModeFormPost},
			},
			mock: func() {
				store.EXPECT().GetClient(gomock.Any(), "1234").Return(&DefaultResponseModeClient{
					DefaultClient: &DefaultClient{
						RedirectURIs:  []string{"https://foo.bar/cb"},
						Scopes:        []string{"foo", "bar"},
						ResponseTypes: []string{consts.ResponseTypeHybridFlowToken},
						Secret:        []byte("1234"),
					},
					ResponseModes: []ResponseModeType{ResponseModeQuery},
				}, nil).MaxTimes(2)
				hasher.EXPECT().Compare(ctx, gomock.Eq([]byte("1234")), gomock.Eq([]byte("1234"))).Return(nil)
			},
			expectedError: ErrUnsupportedResponseMode,
		},
		/* success with response mode */
		{
			desc:     "success with response mode",
			provider: provider,
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
			mock: func() {
				store.EXPECT().GetClient(gomock.Any(), "1234").Return(&DefaultResponseModeClient{
					DefaultClient: &DefaultClient{
						RedirectURIs:  []string{"https://foo.bar/cb"},
						Scopes:        []string{"foo", "bar"},
						ResponseTypes: []string{consts.ResponseTypeHybridFlowToken},
						Audience:      []string{"https://cloud.authelia.com/api", "https://www.authelia.com/api"},
						Secret:        []byte("1234"),
					},
					ResponseModes: []ResponseModeType{ResponseModeFormPost},
				}, nil).MaxTimes(2)
				hasher.EXPECT().Compare(ctx, gomock.Eq([]byte("1234")), gomock.Eq([]byte("1234"))).Return(nil)
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
							Secret:        []byte("1234"),
						},
						ResponseModes: []ResponseModeType{ResponseModeFormPost},
					},
					RequestedScope:    []string{"foo", "bar"},
					RequestedAudience: []string{"https://cloud.authelia.com/api", "https://www.authelia.com/api"},
				},
			},
		},
		/* determine correct response mode if default */
		{
			desc:     "success with response mode",
			provider: provider,
			query: url.Values{
				consts.FormParameterRedirectURI:  {"https://foo.bar/cb"},
				consts.FormParameterClientID:     {"1234"},
				consts.FormParameterClientSecret: []string{"1234"},
				consts.FormParameterResponseType: {"code"},
				consts.FormParameterState:        {"strong-state"},
				consts.FormParameterScope:        {"foo bar"},
				consts.FormParameterAudience:     {"https://cloud.authelia.com/api https://www.authelia.com/api"},
			},
			mock: func() {
				store.EXPECT().GetClient(gomock.Any(), "1234").Return(&DefaultResponseModeClient{
					DefaultClient: &DefaultClient{
						RedirectURIs:  []string{"https://foo.bar/cb"},
						Scopes:        []string{"foo", "bar"},
						ResponseTypes: []string{consts.ResponseTypeAuthorizationCodeFlow},
						Audience:      []string{"https://cloud.authelia.com/api", "https://www.authelia.com/api"},
						Secret:        []byte("1234"),
					},
					ResponseModes: []ResponseModeType{ResponseModeQuery},
				}, nil).MaxTimes(2)
				hasher.EXPECT().Compare(ctx, gomock.Eq([]byte("1234")), gomock.Eq([]byte("1234"))).Return(nil)
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
							Secret:        []byte("1234"),
						},
						ResponseModes: []ResponseModeType{ResponseModeQuery},
					},
					RequestedScope:    []string{"foo", "bar"},
					RequestedAudience: []string{"https://cloud.authelia.com/api", "https://www.authelia.com/api"},
				},
			},
		},
		/* determine correct response mode if default */
		{
			desc:     "success with response mode",
			provider: provider,
			query: url.Values{
				consts.FormParameterRedirectURI:  {"https://foo.bar/cb"},
				consts.FormParameterClientID:     {"1234"},
				consts.FormParameterClientSecret: []string{"1234"},
				consts.FormParameterResponseType: []string{consts.ResponseTypeHybridFlowToken},
				consts.FormParameterState:        {"strong-state"},
				consts.FormParameterScope:        {"foo bar"},
				consts.FormParameterAudience:     {"https://cloud.authelia.com/api https://www.authelia.com/api"},
			},
			mock: func() {
				store.EXPECT().GetClient(gomock.Any(), "1234").Return(&DefaultResponseModeClient{
					DefaultClient: &DefaultClient{
						RedirectURIs:  []string{"https://foo.bar/cb"},
						Scopes:        []string{"foo", "bar"},
						ResponseTypes: []string{consts.ResponseTypeHybridFlowToken},
						Audience:      []string{"https://cloud.authelia.com/api", "https://www.authelia.com/api"},
						Secret:        []byte("1234"),
					},
					ResponseModes: []ResponseModeType{ResponseModeFragment},
				}, nil).MaxTimes(2)
				hasher.EXPECT().Compare(ctx, gomock.Eq([]byte("1234")), gomock.Eq([]byte("1234"))).Return(nil)
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
							Secret:        []byte("1234"),
						},
						ResponseModes: []ResponseModeType{ResponseModeFragment},
					},
					RequestedScope:    []string{"foo", "bar"},
					RequestedAudience: []string{"https://cloud.authelia.com/api", "https://www.authelia.com/api"},
				},
			},
		},
		/* fails because request_uri is included */
		{
			desc:     "should fail because request_uri is provided in the request",
			provider: provider,
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
			mock: func() {
				store.EXPECT().GetClient(gomock.Any(), "1234").Return(&DefaultClient{RedirectURIs: []string{"https://foo.bar/cb"}, Scopes: []string{"foo", "bar"}, ResponseTypes: []string{consts.ResponseTypeHybridFlowToken}, Secret: []byte("1234")}, nil).MaxTimes(2)
				hasher.EXPECT().Compare(ctx, gomock.Eq([]byte("1234")), gomock.Eq([]byte("1234"))).Return(nil)
			},
			expectedError: ErrInvalidRequest.WithHint("The request must not contain 'request_uri'."),
		},
		/* fails because of invalid client credentials */
		{
			desc:     "should fail because of invalid client creds",
			provider: provider,
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
			mock: func() {
				store.EXPECT().GetClient(gomock.Any(), "1234").Return(&DefaultClient{RedirectURIs: []string{"https://foo.bar/cb"}, Scopes: []string{"foo", "bar"}, ResponseTypes: []string{consts.ResponseTypeHybridFlowToken}, Secret: []byte("1234")}, nil).MaxTimes(2)
				hasher.EXPECT().Compare(ctx, gomock.Eq([]byte("1234")), gomock.Eq([]byte("4321"))).Return(fmt.Errorf("invalid hash"))
			},
			expectedError: ErrInvalidClient,
		},
	} {
		t.Run(fmt.Sprintf("case=%s", c.desc), func(t *testing.T) {
			ctx := NewContext()

			c.mock()
			if c.r == nil {
				c.r = &http.Request{
					Header: http.Header{},
					Method: "POST",
				}
				if c.query != nil {
					c.r.URL = &url.URL{RawQuery: c.query.Encode()}
				}
			}

			ar, err := c.provider.NewPushedAuthorizeRequest(ctx, c.r)
			if c.expectedError != nil {
				assert.EqualError(t, err, c.expectedError.Error(), "Stack: %s", string(debug.Stack()))
				// https://github.com/ory/hydra/issues/1642
				AssertObjectKeysEqual(t, &AuthorizeRequest{State: c.query.Get("state")}, ar, "State")
			} else {
				require.NoError(t, err)
				AssertObjectKeysEqual(t, c.expect, ar, "ResponseTypes", "RequestedAudience", "RequestedScope", "Client", "RedirectURI", "State")
				assert.NotNil(t, ar.GetRequestedAt())
			}
		})
	}
}
