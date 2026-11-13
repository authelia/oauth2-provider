// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	. "authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestApplyAuthenticationContext(t *testing.T) {
	authTime := time.Unix(1646340198, 0).UTC()

	login := &jwt.IDTokenClaims{AuthTime: jwt.NewNumericDate(authTime), AuthenticationContextClassReference: "myACR", AuthenticationMethodsReferences: []string{"mfa"}}

	all := []string{consts.ClaimAuthenticationTime, consts.ClaimAuthenticationContextClassReference, consts.ClaimAuthenticationMethodsReference}

	testCases := []struct {
		name      string
		session   Session
		recipient Client
		claims    map[string]any
		expected  map[string]any
	}{
		{
			name:      "ShouldAddNothingByDefault",
			session:   &testLoginSession{DefaultSession: &DefaultSession{}, login: login},
			recipient: &DefaultClient{ID: "client"},
			claims:    map[string]any{},
			expected:  map[string]any{},
		},
		{
			name:     "ShouldAddTheACRRequiredByACRValues",
			session:  &testLoginSession{DefaultSession: &DefaultSession{}, login: login, requested: []string{consts.ClaimAuthenticationContextClassReference}},
			claims:   map[string]any{},
			expected: map[string]any{consts.ClaimAuthenticationContextClassReference: "myACR"},
		},
		{
			name:     "ShouldAddTheAuthTimeRequiredByMaxAge",
			session:  &testLoginSession{DefaultSession: &DefaultSession{}, login: login, requested: []string{consts.ClaimAuthenticationTime}},
			claims:   map[string]any{},
			expected: map[string]any{consts.ClaimAuthenticationTime: authTime.Unix()},
		},
		{
			name:      "ShouldAddTheClaimsTheRecipientLists",
			session:   &testLoginSession{DefaultSession: &DefaultSession{}, login: login},
			recipient: &testAuthenticationContextClient{DefaultClient: &DefaultClient{ID: "client"}, claims: []string{consts.ClaimAuthenticationMethodsReference}},
			claims:    map[string]any{},
			expected:  map[string]any{consts.ClaimAuthenticationMethodsReference: []string{"mfa"}},
		},
		{
			name:      "ShouldAddTheRequiredAndRecipientClaims",
			session:   &testLoginSession{DefaultSession: &DefaultSession{}, login: login, requested: []string{consts.ClaimAuthenticationContextClassReference}},
			recipient: &testAuthenticationContextClient{DefaultClient: &DefaultClient{ID: "client"}, claims: []string{consts.ClaimAuthenticationTime}},
			claims:    map[string]any{},
			expected:  map[string]any{consts.ClaimAuthenticationTime: authTime.Unix(), consts.ClaimAuthenticationContextClassReference: "myACR"},
		},
		{
			name:      "ShouldKeepClaimsAlreadyPresent",
			session:   &testLoginSession{DefaultSession: &DefaultSession{}, login: login},
			recipient: &testAuthenticationContextClient{DefaultClient: &DefaultClient{ID: "client"}, claims: all},
			claims:    map[string]any{consts.ClaimAuthenticationContextClassReference: "extra"},
			expected:  map[string]any{consts.ClaimAuthenticationTime: authTime.Unix(), consts.ClaimAuthenticationContextClassReference: "extra", consts.ClaimAuthenticationMethodsReference: []string{"mfa"}},
		},
		{
			name:      "ShouldKeepClaimsAlreadyPresentWhenNotConveyed",
			session:   &testLoginSession{DefaultSession: &DefaultSession{}, login: login},
			recipient: &DefaultClient{ID: "client"},
			claims:    map[string]any{consts.ClaimAuthenticationMethodsReference: []string{"extra"}},
			expected:  map[string]any{consts.ClaimAuthenticationMethodsReference: []string{"extra"}},
		},
		{
			name:      "ShouldAddNothingForAnEmptyLogin",
			session:   &testLoginSession{DefaultSession: &DefaultSession{}, login: &jwt.IDTokenClaims{}, requested: all},
			recipient: &testAuthenticationContextClient{DefaultClient: &DefaultClient{ID: "client"}, claims: all},
			claims:    map[string]any{},
			expected:  map[string]any{},
		},
		{
			name:      "ShouldAddNothingForASessionWithoutALogin",
			session:   &DefaultSession{},
			recipient: &testAuthenticationContextClient{DefaultClient: &DefaultClient{ID: "client"}, claims: all},
			claims:    map[string]any{},
			expected:  map[string]any{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ApplyAuthenticationContext(tc.claims, tc.session, tc.recipient)

			assert.Equal(t, tc.expected, tc.claims)
		})
	}
}

func TestRecordAuthenticationContextRequirements(t *testing.T) {
	testCases := []struct {
		name     string
		form     url.Values
		client   Client
		prior    []string
		expected []string
	}{
		{
			name:     "ShouldRecordNothingWithoutRequirements",
			form:     url.Values{},
			expected: nil,
		},
		{
			name:     "ShouldRecordTheACRForACRValues",
			form:     url.Values{consts.FormParameterAuthenticationContextClassReferenceValues: {"myACR"}},
			expected: []string{consts.ClaimAuthenticationContextClassReference},
		},
		{
			name:     "ShouldRecordTheAuthTimeForMaxAge",
			form:     url.Values{consts.FormParameterMaximumAge: {"0"}},
			expected: []string{consts.ClaimAuthenticationTime},
		},
		{
			name:     "ShouldRecordBoth",
			form:     url.Values{consts.FormParameterAuthenticationContextClassReferenceValues: {"myACR"}, consts.FormParameterMaximumAge: {"300"}},
			expected: []string{consts.ClaimAuthenticationContextClassReference, consts.ClaimAuthenticationTime},
		},
		{
			name:     "ShouldIgnoreEmptyACRValues",
			form:     url.Values{consts.FormParameterAuthenticationContextClassReferenceValues: {""}},
			expected: nil,
		},
		{
			name:     "ShouldRecordTheACRForDefaultACRValues",
			form:     url.Values{},
			client:   &DefaultRegisteredClient{DefaultACRValues: []string{"phr"}},
			expected: []string{consts.ClaimAuthenticationContextClassReference},
		},
		{
			name:     "ShouldReplaceAPriorRecord",
			form:     url.Values{},
			prior:    []string{consts.ClaimAuthenticationTime},
			expected: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			session := &testLoginSession{DefaultSession: &DefaultSession{}, requested: tc.prior}

			request := NewAuthorizeRequest()
			request.Form = tc.form
			request.Client = tc.client

			RecordAuthenticationContextRequirements(request, session)

			assert.Equal(t, tc.expected, GetRequestedAuthenticationContextClaims(session))
		})
	}

	t.Run("ShouldIgnoreASessionWhichDoesNotRecordThem", func(t *testing.T) {
		request := NewAuthorizeRequest()
		request.Form = url.Values{consts.FormParameterMaximumAge: {"0"}}

		assert.NotPanics(t, func() { RecordAuthenticationContextRequirements(request, &DefaultSession{}) })
		assert.Nil(t, GetRequestedAuthenticationContextClaims(&DefaultSession{}))
	})
}

func TestNewAuthorizeResponseRecordsAuthenticationContextRequirements(t *testing.T) {
	session := &testLoginSession{DefaultSession: &DefaultSession{}, login: &jwt.IDTokenClaims{}}

	provider := &Fosite{Config: &Config{AuthorizeEndpointHandlers: AuthorizeEndpointHandlers{&acrValuesHandler{}}}}

	request := NewAuthorizeRequest()
	request.ResponseTypes = Arguments{consts.ResponseTypeAuthorizationCodeFlow}
	request.Form = url.Values{consts.FormParameterAuthenticationContextClassReferenceValues: {"gold"}, consts.FormParameterMaximumAge: {"300"}}

	_, err := provider.NewAuthorizeResponse(context.Background(), request, session)
	require.NoError(t, err)

	// RFC 9470 Section 5.
	assert.Equal(t, []string{consts.ClaimAuthenticationContextClassReference, consts.ClaimAuthenticationTime}, session.requested)
}

func TestNewRFC8628UserAuthorizeResponseRecordsAuthenticationContextRequirements(t *testing.T) {
	session := &testLoginSession{DefaultSession: &DefaultSession{}, login: &jwt.IDTokenClaims{}}

	provider := &Fosite{Config: &Config{RFC8628UserAuthorizeEndpointHandlers: RFC8628UserAuthorizeEndpointHandlers{&deviceDecisionHandler{}}}}

	request := NewDeviceAuthorizeRequest()
	request.Session = &DefaultSession{}
	request.Form = url.Values{consts.FormParameterMaximumAge: {"300"}}
	request.SetStatus(DeviceAuthorizeStatusApproved)

	_, err := provider.NewRFC8628UserAuthorizeResponse(context.Background(), request, session)
	require.NoError(t, err)

	// RFC 9470 Section 5.
	assert.Equal(t, []string{consts.ClaimAuthenticationTime}, session.requested)
}

func TestWriteIntrospectionResponseAuthenticationContext(t *testing.T) {
	login := &jwt.IDTokenClaims{AuthTime: jwt.NewNumericDate(time.Unix(1646340198, 0)), AuthenticationContextClassReference: "myACR", AuthenticationMethodsReferences: []string{"mfa"}}

	testCases := []struct {
		name      string
		requested []string
		caller    Client
		expected  map[string]any
	}{
		{
			name:     "ShouldOmitTheAuthenticationContextByDefault",
			caller:   &DefaultClient{ID: "rs"},
			expected: map[string]any{},
		},
		{
			name:      "ShouldIncludeTheAuthenticationContextTheRequestRequired",
			requested: []string{consts.ClaimAuthenticationTime, consts.ClaimAuthenticationContextClassReference},
			caller:    &DefaultClient{ID: "rs"},
			expected:  map[string]any{consts.ClaimAuthenticationTime: float64(1646340198), consts.ClaimAuthenticationContextClassReference: "myACR"},
		},
		{
			name:     "ShouldIncludeTheAuthenticationContextTheCallerLists",
			caller:   &testAuthenticationContextClient{DefaultClient: &DefaultClient{ID: "rs"}, claims: []string{consts.ClaimAuthenticationMethodsReference}},
			expected: map[string]any{consts.ClaimAuthenticationMethodsReference: []any{"mfa"}},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			session := &testLoginSession{
				DefaultSession: &DefaultSession{Subject: "someone@example.net"},
				login:          login,
				requested:      tc.requested,
			}

			ar := NewAccessRequest(session)
			ar.Client = &DefaultClient{ID: "s6BhdRkqt3"}

			rw := httptest.NewRecorder()

			(&Fosite{Config: &Config{}}).WriteIntrospectionResponse(context.Background(), rw, &IntrospectionResponse{
				Client:          tc.caller,
				Active:          true,
				TokenUse:        AccessToken,
				AccessRequester: ar,
			})

			require.Equal(t, http.StatusOK, rw.Code)

			params := map[string]any{}
			require.NoError(t, json.NewDecoder(rw.Body).Decode(&params))

			actual := map[string]any{}

			for _, claim := range []string{consts.ClaimAuthenticationTime, consts.ClaimAuthenticationContextClassReference, consts.ClaimAuthenticationMethodsReference} {
				if value, ok := params[claim]; ok {
					actual[claim] = value
				}
			}

			assert.Equal(t, tc.expected, actual)
		})
	}
}

type testLoginSession struct {
	*DefaultSession

	login     *jwt.IDTokenClaims
	requested []string
}

func (s *testLoginSession) IDTokenClaims() *jwt.IDTokenClaims {
	return s.login
}

func (s *testLoginSession) SetRequestedAuthenticationContextClaims(claims []string) {
	s.requested = claims
}

func (s *testLoginSession) GetRequestedAuthenticationContextClaims() []string {
	return s.requested
}

type testAuthenticationContextClient struct {
	*DefaultClient

	claims []string
}

func (c *testAuthenticationContextClient) GetAuthenticationContextClaims() []string {
	return c.claims
}
