// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"context"
	"net/url"
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	. "authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/testing/mock"
	"authelia.com/provider/oauth2/token/jwt"
	"authelia.com/provider/oauth2/x/errorsx"
)

func TestNewAuthorizeResponse(t *testing.T) {
	handlerErr := errors.New("handler failed")

	testCases := []struct {
		name     string
		handlers int
		mock     func(handlers []*mock.MockAuthorizeEndpointHandler, ar *mock.MockAuthorizeRequester)
		expected string
	}{
		{
			name:     "ShouldFailWhenHandlerReturnsError",
			handlers: 1,
			mock: func(handlers []*mock.MockAuthorizeEndpointHandler, ar *mock.MockAuthorizeRequester) {
				ar.EXPECT().SetSession(gomock.Eq(new(DefaultSession)))
				handlers[0].EXPECT().HandleAuthorizeEndpointRequest(gomock.Any(), gomock.Eq(ar), gomock.Any()).Return(handlerErr)
			},
			expected: "handler failed",
		},
		{
			name:     "ShouldFailWhenHandlerReturnsRFC6749Error",
			handlers: 1,
			mock: func(handlers []*mock.MockAuthorizeEndpointHandler, ar *mock.MockAuthorizeRequester) {
				ar.EXPECT().SetSession(gomock.Eq(new(DefaultSession)))
				handlers[0].EXPECT().HandleAuthorizeEndpointRequest(gomock.Any(), gomock.Eq(ar), gomock.Any()).Return(errorsx.WithStack(ErrInvalidRequest.WithHint("Authorize endpoint request was invalid.")))
			},
			expected: "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Authorize endpoint request was invalid.",
		},
		{
			name:     "ShouldPassWithSingleHandler",
			handlers: 1,
			mock: func(handlers []*mock.MockAuthorizeEndpointHandler, ar *mock.MockAuthorizeRequester) {
				ar.EXPECT().SetSession(gomock.Eq(new(DefaultSession)))
				handlers[0].EXPECT().HandleAuthorizeEndpointRequest(gomock.Any(), gomock.Eq(ar), gomock.Any()).Return(nil)
				ar.EXPECT().DidHandleAllResponseTypes().Return(true)
				ar.EXPECT().GetDefaultResponseMode().Return(ResponseModeFragment)
				ar.EXPECT().GetResponseMode().Return(ResponseModeDefault)
			},
		},
		{
			name:     "ShouldPassWithMultipleHandlers",
			handlers: 2,
			mock: func(handlers []*mock.MockAuthorizeEndpointHandler, ar *mock.MockAuthorizeRequester) {
				ar.EXPECT().SetSession(gomock.Eq(new(DefaultSession)))
				handlers[0].EXPECT().HandleAuthorizeEndpointRequest(gomock.Any(), gomock.Eq(ar), gomock.Any()).Return(nil)
				handlers[1].EXPECT().HandleAuthorizeEndpointRequest(gomock.Any(), gomock.Eq(ar), gomock.Any()).Return(nil)
				ar.EXPECT().DidHandleAllResponseTypes().Return(true)
				ar.EXPECT().GetDefaultResponseMode().Return(ResponseModeFragment)
				ar.EXPECT().GetResponseMode().Return(ResponseModeDefault)
			},
		},
		{
			name:     "ShouldFailWhenSecondHandlerReturnsError",
			handlers: 2,
			mock: func(handlers []*mock.MockAuthorizeEndpointHandler, ar *mock.MockAuthorizeRequester) {
				ar.EXPECT().SetSession(gomock.Eq(new(DefaultSession)))
				handlers[0].EXPECT().HandleAuthorizeEndpointRequest(gomock.Any(), gomock.Eq(ar), gomock.Any()).Return(nil)
				handlers[1].EXPECT().HandleAuthorizeEndpointRequest(gomock.Any(), gomock.Eq(ar), gomock.Any()).Return(handlerErr)
			},
			expected: "handler failed",
		},
		{
			name:     "ShouldFailWhenNotAllResponseTypesHandled",
			handlers: 1,
			mock: func(handlers []*mock.MockAuthorizeEndpointHandler, ar *mock.MockAuthorizeRequester) {
				ar.EXPECT().SetSession(gomock.Eq(new(DefaultSession)))
				handlers[0].EXPECT().HandleAuthorizeEndpointRequest(gomock.Any(), gomock.Eq(ar), gomock.Any()).Return(nil)
				ar.EXPECT().DidHandleAllResponseTypes().Return(false)
			},
			expected: "The authorization server does not support obtaining a token using this method.",
		},
		{
			name:     "ShouldFailWhenInsecureQueryModeForFragmentDefault",
			handlers: 2,
			mock: func(handlers []*mock.MockAuthorizeEndpointHandler, ar *mock.MockAuthorizeRequester) {
				ar.EXPECT().SetSession(gomock.Eq(new(DefaultSession)))
				handlers[0].EXPECT().HandleAuthorizeEndpointRequest(gomock.Any(), gomock.Eq(ar), gomock.Any()).Return(nil)
				handlers[1].EXPECT().HandleAuthorizeEndpointRequest(gomock.Any(), gomock.Eq(ar), gomock.Any()).Return(nil)
				ar.EXPECT().DidHandleAllResponseTypes().Return(true)
				ar.EXPECT().GetDefaultResponseMode().Return(ResponseModeFragment)
				ar.EXPECT().GetResponseMode().Return(ResponseModeQuery)
				ar.EXPECT().GetResponseTypes().Return(Arguments{"token", "code"})
			},
			expected: "The authorization server does not support obtaining a response using this response mode. Insecure response_mode 'query' for the response_type '[token code]'.",
		},
		{
			name:     "ShouldFailWhenUnencryptedQueryJWTModeForFragmentDefault",
			handlers: 1,
			mock: func(handlers []*mock.MockAuthorizeEndpointHandler, ar *mock.MockAuthorizeRequester) {
				ar.EXPECT().SetSession(gomock.Eq(new(DefaultSession)))
				handlers[0].EXPECT().HandleAuthorizeEndpointRequest(gomock.Any(), gomock.Eq(ar), gomock.Any()).Return(nil)
				ar.EXPECT().DidHandleAllResponseTypes().Return(true)
				ar.EXPECT().GetDefaultResponseMode().Return(ResponseModeFragment)
				ar.EXPECT().GetResponseMode().Return(ResponseModeQueryJWT)
				ar.EXPECT().GetClient().Return(&DefaultRegisteredClient{DefaultClient: &DefaultClient{ID: "client"}, AuthorizationSignedResponseAlg: "RS256"})
				ar.EXPECT().GetResponseTypes().Return(Arguments{"token", "code"})
			},
			expected: "The authorization server does not support obtaining a response using this response mode. Insecure response_mode 'query.jwt' for the response_type '[token code]' unless the authorization response is encrypted.",
		},
		{
			name:     "ShouldFailWhenNoneEncryptedQueryJWTModeForFragmentDefault",
			handlers: 1,
			mock: func(handlers []*mock.MockAuthorizeEndpointHandler, ar *mock.MockAuthorizeRequester) {
				ar.EXPECT().SetSession(gomock.Eq(new(DefaultSession)))
				handlers[0].EXPECT().HandleAuthorizeEndpointRequest(gomock.Any(), gomock.Eq(ar), gomock.Any()).Return(nil)
				ar.EXPECT().DidHandleAllResponseTypes().Return(true)
				ar.EXPECT().GetDefaultResponseMode().Return(ResponseModeFragment)
				ar.EXPECT().GetResponseMode().Return(ResponseModeQueryJWT)
				ar.EXPECT().GetClient().Return(&DefaultRegisteredClient{DefaultClient: &DefaultClient{ID: "client"}, AuthorizationSignedResponseAlg: "RS256", AuthorizationEncryptedResponseAlg: consts.JSONWebTokenAlgNone})
				ar.EXPECT().GetResponseTypes().Return(Arguments{"token", "code"})
			},
			expected: "The authorization server does not support obtaining a response using this response mode. Insecure response_mode 'query.jwt' for the response_type '[token code]' unless the authorization response is encrypted.",
		},
		{
			name:     "ShouldPassWithEncryptedQueryJWTModeForFragmentDefault",
			handlers: 1,
			mock: func(handlers []*mock.MockAuthorizeEndpointHandler, ar *mock.MockAuthorizeRequester) {
				ar.EXPECT().SetSession(gomock.Eq(new(DefaultSession)))
				handlers[0].EXPECT().HandleAuthorizeEndpointRequest(gomock.Any(), gomock.Eq(ar), gomock.Any()).Return(nil)
				ar.EXPECT().DidHandleAllResponseTypes().Return(true)
				ar.EXPECT().GetDefaultResponseMode().Return(ResponseModeFragment)
				ar.EXPECT().GetResponseMode().Return(ResponseModeQueryJWT)
				ar.EXPECT().GetClient().Return(&DefaultRegisteredClient{DefaultClient: &DefaultClient{ID: "client"}, AuthorizationSignedResponseAlg: "RS256", AuthorizationEncryptedResponseAlg: "RSA-OAEP-256"})
			},
		},
		{
			name:     "ShouldPassWithQueryJWTModeForQueryDefault",
			handlers: 1,
			mock: func(handlers []*mock.MockAuthorizeEndpointHandler, ar *mock.MockAuthorizeRequester) {
				ar.EXPECT().SetSession(gomock.Eq(new(DefaultSession)))
				handlers[0].EXPECT().HandleAuthorizeEndpointRequest(gomock.Any(), gomock.Eq(ar), gomock.Any()).Return(nil)
				ar.EXPECT().DidHandleAllResponseTypes().Return(true)
				ar.EXPECT().GetDefaultResponseMode().Return(ResponseModeQuery)
				ar.EXPECT().GetResponseMode().Return(ResponseModeQueryJWT).AnyTimes()
				ar.EXPECT().GetClient().Return(&DefaultRegisteredClient{DefaultClient: &DefaultClient{ID: "client"}}).AnyTimes()
				ar.EXPECT().GetResponseTypes().Return(Arguments{"code"}).AnyTimes()
			},
		},
		{
			name:     "ShouldPassWithNoHandlers",
			handlers: 0,
			mock: func(handlers []*mock.MockAuthorizeEndpointHandler, ar *mock.MockAuthorizeRequester) {
				ar.EXPECT().SetSession(gomock.Eq(new(DefaultSession)))
				ar.EXPECT().DidHandleAllResponseTypes().Return(true)
				ar.EXPECT().GetDefaultResponseMode().Return(ResponseModeFragment)
				ar.EXPECT().GetResponseMode().Return(ResponseModeDefault)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			ar := mock.NewMockAuthorizeRequester(ctrl)

			handlers := make([]*mock.MockAuthorizeEndpointHandler, tc.handlers)
			endpointHandlers := make(AuthorizeEndpointHandlers, tc.handlers)
			for i := 0; i < tc.handlers; i++ {
				handlers[i] = mock.NewMockAuthorizeEndpointHandler(ctrl)
				endpointHandlers[i] = handlers[i]
			}

			provider := &Fosite{Config: &Config{
				AuthorizeEndpointHandlers: endpointHandlers,
			}}

			tc.mock(handlers, ar)

			actual, err := provider.NewAuthorizeResponse(context.Background(), ar, new(DefaultSession))

			if tc.expected != "" {
				assert.Nil(t, actual)
				assert.EqualError(t, ErrorToDebugRFC6749Error(err), tc.expected)

				return
			}

			require.NoError(t, ErrorToDebugRFC6749Error(err))
			require.NotNil(t, actual)
		})
	}
}

func TestNewAuthorizeResponseEnforcesAuthenticationRequirements(t *testing.T) {
	now := time.Now().UTC()

	testCases := []struct {
		name     string
		enforce  bool
		form     url.Values
		defaults []string
		claims   *ClaimsRequest
		session  Session
		expected error
	}{
		{name: "ShouldPassWhenNotEnforced", form: url.Values{"acr_values": {"gold"}, "max_age": {"0"}}, session: newACRValuesSession("bronze", now.Add(-time.Hour))},
		{name: "ShouldPassWhenNotRequested", enforce: true, session: newACRValuesSession("bronze", time.Time{})},
		{name: "ShouldPassWhenARequestedValueIsMet", enforce: true, form: url.Values{"acr_values": {"gold silver"}}, session: newACRValuesSession("silver", time.Time{})},
		{name: "ShouldFailWhenNoRequestedValueIsMet", enforce: true, form: url.Values{"acr_values": {"gold silver"}}, session: newACRValuesSession("bronze", time.Time{}), expected: ErrUnmetAuthenticationRequirements},
		{name: "ShouldFailWhenTheSessionHasNoACR", enforce: true, form: url.Values{"acr_values": {"gold"}}, session: newACRValuesSession("", time.Time{}), expected: ErrUnmetAuthenticationRequirements},
		{name: "ShouldFailWhenTheSessionCannotRecordAnACR", enforce: true, form: url.Values{"acr_values": {"gold"}}, session: &DefaultSession{}, expected: ErrUnmetAuthenticationRequirements},
		{name: "ShouldPassWhenTheAuthenticationIsRecentEnough", enforce: true, form: url.Values{"max_age": {"300"}}, session: newACRValuesSession("", now.Add(-time.Minute))},
		{name: "ShouldFailWhenTheAuthenticationIsTooOld", enforce: true, form: url.Values{"max_age": {"300"}}, session: newACRValuesSession("", now.Add(-time.Hour)), expected: ErrUnmetAuthenticationRequirements},
		{name: "ShouldFailWhenTheSessionHasNoAuthenticationTime", enforce: true, form: url.Values{"max_age": {"300"}}, session: newACRValuesSession("", time.Time{}), expected: ErrUnmetAuthenticationRequirements},
		{name: "ShouldFailWhenMaxAgeIsNotAnInteger", enforce: true, form: url.Values{"max_age": {"soon"}}, session: newACRValuesSession("", now), expected: ErrInvalidRequest},
		{name: "ShouldFailWhenMaxAgeIsNegative", enforce: true, form: url.Values{"max_age": {"-1"}}, session: newACRValuesSession("", now), expected: ErrInvalidRequest},
		{name: "ShouldFailWhenOnlyMaxAgeIsMet", enforce: true, form: url.Values{"acr_values": {"gold"}, "max_age": {"300"}}, session: newACRValuesSession("bronze", now), expected: ErrUnmetAuthenticationRequirements},
		{name: "ShouldPassWhenBothAreMet", enforce: true, form: url.Values{"acr_values": {"gold"}, "max_age": {"300"}}, session: newACRValuesSession("gold", now)},
		{name: "ShouldPassWhenADefaultValueIsMet", enforce: true, defaults: []string{"gold", "silver"}, session: newACRValuesSession("silver", time.Time{})},
		{name: "ShouldFailWhenNoDefaultValueIsMet", enforce: true, defaults: []string{"gold", "silver"}, session: newACRValuesSession("bronze", time.Time{}), expected: ErrUnmetAuthenticationRequirements},
		{name: "ShouldPassWhenTheDefaultsAreNotEnforced", defaults: []string{"gold"}, session: newACRValuesSession("bronze", time.Time{})},
		{name: "ShouldPreferTheRequestedValuesOverTheDefaults", enforce: true, form: url.Values{"acr_values": {"bronze"}}, defaults: []string{"gold"}, session: newACRValuesSession("bronze", time.Time{})},
		{name: "ShouldIgnoreTheDefaultsWhenTheIDTokenACRClaimIsRequestedWithValues", enforce: true, defaults: []string{"gold"}, claims: &ClaimsRequest{IDToken: map[string]*ClaimRequest{"acr": {Values: []any{"bronze"}}}}, session: newACRValuesSession("bronze", time.Time{})},
		{name: "ShouldIgnoreTheDefaultsWhenTheUserInfoACRClaimIsRequestedWithAValue", enforce: true, defaults: []string{"gold"}, claims: &ClaimsRequest{UserInfo: map[string]*ClaimRequest{"acr": {Value: "bronze"}}}, session: newACRValuesSession("bronze", time.Time{})},
		{name: "ShouldApplyTheDefaultsWhenTheACRClaimIsRequestedWithoutValues", enforce: true, defaults: []string{"gold"}, claims: &ClaimsRequest{IDToken: map[string]*ClaimRequest{"acr": nil}, UserInfo: map[string]*ClaimRequest{"acr": {Essential: true}}}, session: newACRValuesSession("bronze", time.Time{}), expected: ErrUnmetAuthenticationRequirements},
		{name: "ShouldApplyTheDefaultsWhenOtherClaimsAreRequested", enforce: true, defaults: []string{"gold"}, claims: &ClaimsRequest{IDToken: map[string]*ClaimRequest{"email": nil}}, session: newACRValuesSession("bronze", time.Time{}), expected: ErrUnmetAuthenticationRequirements},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			handler := &acrValuesHandler{}

			provider := &Fosite{Config: &Config{EnforceAuthenticationRequirements: tc.enforce, AuthorizeEndpointHandlers: AuthorizeEndpointHandlers{handler}}}

			request := NewAuthorizeRequest()
			request.RequestedAt = now
			request.ResponseTypes = Arguments{consts.ResponseTypeAuthorizationCodeFlow}
			request.Client = &DefaultRegisteredClient{DefaultClient: &DefaultClient{ID: "foo"}, DefaultACRValues: tc.defaults}
			request.SetClaims(tc.claims)

			for key, values := range tc.form {
				request.Form[key] = values
			}

			_, err := provider.NewAuthorizeResponse(context.Background(), request, tc.session)

			if tc.expected != nil {
				require.ErrorIs(t, err, tc.expected)
				assert.False(t, handler.called)

				return
			}

			require.NoError(t, err)
			assert.True(t, handler.called)
		})
	}
}

func newACRValuesSession(acr string, authTime time.Time) *acrValuesSession {
	session := &acrValuesSession{DefaultSession: &DefaultSession{}, acr: acr}

	if !authTime.IsZero() {
		session.authTime = jwt.NewNumericDate(authTime)
	}

	return session
}

type acrValuesSession struct {
	*DefaultSession

	acr      string
	authTime *jwt.NumericDate
}

func (s *acrValuesSession) IDTokenClaims() *jwt.IDTokenClaims {
	return &jwt.IDTokenClaims{AuthenticationContextClassReference: s.acr, AuthTime: s.authTime}
}

type acrValuesHandler struct {
	called bool
}

func (h *acrValuesHandler) HandleAuthorizeEndpointRequest(_ context.Context, request AuthorizeRequester, _ AuthorizeResponder) error {
	h.called = true

	request.SetResponseTypeHandled(consts.ResponseTypeAuthorizationCodeFlow)

	return nil
}

func (h *acrValuesHandler) ResponseTypesSupported(_ context.Context) []string {
	return []string{consts.ResponseTypeAuthorizationCodeFlow}
}

func (h *acrValuesHandler) GrantTypesSupported(_ context.Context) []string { return nil }

func (h *acrValuesHandler) CodeChallengeMethodsSupported(_ context.Context) []string { return nil }

func (h *acrValuesHandler) IDTokenSigningAlgValuesSupported(_ context.Context) []string { return nil }
