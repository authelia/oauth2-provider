// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	. "authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/handler/pkce"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/testing/mock"
)

// OAuth 2.1 Section 4.1.1: the request is validated before the resource owner is authenticated.
func TestNewAuthorizeRequestRunsAuthorizeRequestValidators(t *testing.T) {
	const challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

	testCases := []struct {
		name     string
		public   bool
		grants   []string
		types    string
		params   url.Values
		fragment bool
		expected *RFC6749Error
	}{
		{
			name:     "ShouldRejectPublicClientWithoutCodeChallenge",
			public:   true,
			types:    consts.ResponseTypeAuthorizationCodeFlow,
			expected: ErrInvalidRequest,
		},
		{
			name:     "ShouldRejectUnknownCodeChallengeMethod",
			types:    consts.ResponseTypeAuthorizationCodeFlow,
			params:   url.Values{consts.FormParameterCodeChallenge: {challenge}, consts.FormParameterCodeChallengeMethod: {"bogus"}},
			expected: ErrInvalidRequest,
		},
		{
			name:     "ShouldRejectMalformedCodeChallenge",
			types:    consts.ResponseTypeAuthorizationCodeFlow,
			params:   url.Values{consts.FormParameterCodeChallenge: {strings.Repeat("a", 42)}, consts.FormParameterCodeChallengeMethod: {consts.PKCEChallengeMethodSHA256}},
			expected: ErrInvalidRequest,
		},
		{
			name:     "ShouldRejectCodeChallengeMethodWithoutCodeChallenge",
			types:    consts.ResponseTypeAuthorizationCodeFlow,
			params:   url.Values{consts.FormParameterCodeChallengeMethod: {consts.PKCEChallengeMethodSHA256}},
			expected: ErrInvalidRequest,
		},
		{
			name:     "ShouldRejectImplicitTokenFromClientWithoutImplicitGrant",
			grants:   []string{consts.GrantTypeAuthorizationCode},
			types:    consts.ResponseTypeImplicitFlowToken,
			fragment: true,
			expected: ErrUnauthorizedClient,
		},
		{
			name:   "ShouldAcceptPublicClientWithCodeChallenge",
			public: true,
			types:  consts.ResponseTypeAuthorizationCodeFlow,
			params: url.Values{consts.FormParameterCodeChallenge: {challenge}, consts.FormParameterCodeChallengeMethod: {consts.PKCEChallengeMethodSHA256}},
		},
		{
			name:  "ShouldAcceptConfidentialClientWithoutCodeChallenge",
			types: consts.ResponseTypeAuthorizationCodeFlow,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			store := mock.NewMockStorage(ctrl)

			grants := tc.grants
			if grants == nil {
				grants = []string{consts.GrantTypeAuthorizationCode, consts.GrantTypeImplicit}
			}

			client := &DefaultClient{
				ID:            "1234",
				Public:        tc.public,
				RedirectURIs:  []string{"https://foo.bar/cb"},
				Scopes:        []string{"foo"},
				GrantTypes:    grants,
				ResponseTypes: []string{tc.types},
			}

			store.EXPECT().GetClient(gomock.Any(), "1234").Return(client, nil)

			query := url.Values{
				consts.FormParameterClientID:     {"1234"},
				consts.FormParameterRedirectURI:  {"https://foo.bar/cb"},
				consts.FormParameterResponseType: {tc.types},
				consts.FormParameterScope:        {"foo"},
				consts.FormParameterState:        {"strong-enough-state"},
			}

			for key, values := range tc.params {
				query[key] = values
			}

			provider := &Fosite{Store: store, Config: newAuthorizeRequestValidatorsConfig()}

			r := &http.Request{Header: http.Header{}, Method: http.MethodGet, URL: &url.URL{RawQuery: query.Encode()}}

			requester, err := provider.NewAuthorizeRequest(context.Background(), r)

			if tc.expected == nil {
				require.NoError(t, ErrorToDebugRFC6749Error(err))

				return
			}

			require.Error(t, err)
			assert.ErrorIs(t, err, tc.expected)

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

			assert.Equal(t, tc.expected.ErrorField, values.Get(consts.FormParameterError))
			assert.Equal(t, "strong-enough-state", values.Get(consts.FormParameterState))
		})
	}
}

func TestNewAuthorizeRequestRunsBindingHandlerValidators(t *testing.T) {
	testCases := []struct {
		name     string
		binding  *recordingAuthorizeRequestValidator
		endpoint *recordingAuthorizeRequestValidator
		expected error
	}{
		{
			name:     "ShouldRejectWhenBindingHandlerRejects",
			binding:  &recordingAuthorizeRequestValidator{err: ErrInvalidDPoPProof},
			endpoint: &recordingAuthorizeRequestValidator{},
			expected: ErrInvalidDPoPProof,
		},
		{
			name:     "ShouldRejectWhenEndpointHandlerRejects",
			binding:  &recordingAuthorizeRequestValidator{},
			endpoint: &recordingAuthorizeRequestValidator{err: ErrAccessDenied},
			expected: ErrAccessDenied,
		},
		{
			name:     "ShouldAcceptWhenNoHandlerRejects",
			binding:  &recordingAuthorizeRequestValidator{},
			endpoint: &recordingAuthorizeRequestValidator{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			store := mock.NewMockStorage(ctrl)

			client := &DefaultClient{
				ID:            "1234",
				RedirectURIs:  []string{"https://foo.bar/cb"},
				Scopes:        []string{"foo"},
				ResponseTypes: []string{consts.ResponseTypeAuthorizationCodeFlow},
			}

			store.EXPECT().GetClient(gomock.Any(), "1234").Return(client, nil)

			query := url.Values{
				consts.FormParameterClientID:     {"1234"},
				consts.FormParameterRedirectURI:  {"https://foo.bar/cb"},
				consts.FormParameterResponseType: {consts.ResponseTypeAuthorizationCodeFlow},
				consts.FormParameterScope:        {"foo"},
				consts.FormParameterState:        {"strong-enough-state"},
			}

			config := &Config{
				ScopeStrategy:                    ExactScopeStrategy,
				AudienceStrategy:                 DefaultAudienceStrategy,
				AuthorizeEndpointBindingHandlers: AuthorizeEndpointBindingHandlers{tc.binding},
				AuthorizeEndpointHandlers:        AuthorizeEndpointHandlers{tc.endpoint},
			}

			provider := &Fosite{Store: store, Config: config}

			r := &http.Request{Header: http.Header{}, Method: http.MethodGet, URL: &url.URL{RawQuery: query.Encode()}}

			_, err := provider.NewAuthorizeRequest(context.Background(), r)

			assert.Equal(t, 1, tc.binding.validated)
			assert.Zero(t, tc.binding.handled)
			assert.Zero(t, tc.endpoint.handled)

			if tc.expected == nil {
				require.NoError(t, ErrorToDebugRFC6749Error(err))
				assert.Equal(t, 1, tc.endpoint.validated)

				return
			}

			assert.ErrorIs(t, err, tc.expected)
		})
	}
}

func TestAuthorizeRequestFromPARRunsAuthorizeRequestValidators(t *testing.T) {
	const requestURI = "urn:ietf:params:oauth:request_uri:pkce"

	redir, _ := url.Parse("https://foo.bar/cb")

	testCases := []struct {
		name     string
		form     url.Values
		expected error
	}{
		{
			name:     "ShouldRejectPublicClientWithoutCodeChallenge",
			form:     url.Values{},
			expected: ErrInvalidRequest,
		},
		{
			name: "ShouldAcceptPublicClientWithCodeChallenge",
			form: url.Values{
				consts.FormParameterCodeChallenge:       {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"},
				consts.FormParameterCodeChallengeMethod: {consts.PKCEChallengeMethodSHA256},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			client := &DefaultClient{
				ID:            "1234",
				Public:        true,
				RedirectURIs:  []string{"https://foo.bar/cb"},
				Scopes:        []string{"foo"},
				GrantTypes:    []string{consts.GrantTypeAuthorizationCode},
				ResponseTypes: []string{consts.ResponseTypeAuthorizationCodeFlow},
			}

			par := NewAuthorizeRequest()
			par.Client = client
			par.Session = &DefaultSession{ExpiresAt: map[TokenType]time.Time{PushedAuthorizeRequestContext: time.Now().Add(time.Hour)}}
			par.State = "strong-enough-state"
			par.RedirectURI = redir
			par.ResponseTypes = []string{consts.ResponseTypeAuthorizationCodeFlow}
			par.RequestedScope = []string{"foo"}
			par.Form = tc.form

			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockStorage := mock.NewMockStorage(ctrl)
			mockStorage.EXPECT().GetClient(gomock.Any(), "1234").Return(client, nil)

			mockPAR := mock.NewMockPARStorage(ctrl)
			mockPAR.EXPECT().GetPARSession(gomock.Any(), requestURI).Return(par, nil)
			mockPAR.EXPECT().DeletePARSession(gomock.Any(), requestURI).Return(nil)

			provider := &Fosite{Store: &parStorage{MockStorage: mockStorage, MockPARStorage: mockPAR}, Config: newAuthorizeRequestValidatorsConfig()}

			query := url.Values{
				consts.FormParameterRequestURI: {requestURI},
				consts.FormParameterClientID:   {"1234"},
			}

			r := &http.Request{Header: http.Header{}, Method: http.MethodGet, URL: &url.URL{RawQuery: query.Encode()}}

			_, err := provider.NewAuthorizeRequest(context.Background(), r)

			if tc.expected == nil {
				require.NoError(t, ErrorToDebugRFC6749Error(err))

				return
			}

			assert.ErrorIs(t, err, tc.expected)
		})
	}
}

func newAuthorizeRequestValidatorsConfig() *Config {
	config := &Config{
		ScopeStrategy:    ExactScopeStrategy,
		AudienceStrategy: DefaultAudienceStrategy,
	}

	config.AuthorizeEndpointHandlers = AuthorizeEndpointHandlers{
		&hoauth2.AuthorizeImplicitGrantTypeHandler{Config: config},
		&pkce.Handler{Config: config},
	}

	return config
}

type recordingAuthorizeRequestValidator struct {
	err       error
	validated int
	handled   int
}

func (h *recordingAuthorizeRequestValidator) ValidateAuthorizeRequest(_ context.Context, _ AuthorizeRequester) (err error) {
	h.validated++

	return h.err
}

func (h *recordingAuthorizeRequestValidator) BindAuthorizeRequest(_ context.Context, _ AuthorizeRequester) (err error) {
	h.handled++

	return nil
}

func (h *recordingAuthorizeRequestValidator) HandleAuthorizeEndpointRequest(_ context.Context, _ AuthorizeRequester, _ AuthorizeResponder) (err error) {
	h.handled++

	return nil
}

func (h *recordingAuthorizeRequestValidator) ResponseTypesSupported(_ context.Context) (types []string) {
	return nil
}

func (h *recordingAuthorizeRequestValidator) GrantTypesSupported(_ context.Context) (types []string) {
	return nil
}

func (h *recordingAuthorizeRequestValidator) CodeChallengeMethodsSupported(_ context.Context) (methods []string) {
	return nil
}

func (h *recordingAuthorizeRequestValidator) IDTokenSigningAlgValuesSupported(_ context.Context) (algs []string) {
	return nil
}
