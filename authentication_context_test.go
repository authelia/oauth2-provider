// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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

	testCases := []struct {
		name     string
		session  Session
		claims   map[string]any
		expected map[string]any
	}{
		{
			name:     "ShouldAddTheAuthenticationContext",
			session:  &testLoginSession{DefaultSession: &DefaultSession{}, login: login},
			claims:   map[string]any{},
			expected: map[string]any{consts.ClaimAuthenticationTime: authTime.Unix(), consts.ClaimAuthenticationContextClassReference: "myACR", consts.ClaimAuthenticationMethodsReference: []string{"mfa"}},
		},
		{
			name:     "ShouldKeepClaimsAlreadyPresent",
			session:  &testLoginSession{DefaultSession: &DefaultSession{}, login: login},
			claims:   map[string]any{consts.ClaimAuthenticationContextClassReference: "extra"},
			expected: map[string]any{consts.ClaimAuthenticationTime: authTime.Unix(), consts.ClaimAuthenticationContextClassReference: "extra", consts.ClaimAuthenticationMethodsReference: []string{"mfa"}},
		},
		{
			name:     "ShouldAddNothingForAnEmptyLogin",
			session:  &testLoginSession{DefaultSession: &DefaultSession{}, login: &jwt.IDTokenClaims{}},
			claims:   map[string]any{},
			expected: map[string]any{},
		},
		{
			name:     "ShouldAddNothingForASessionWithoutALogin",
			session:  &DefaultSession{},
			claims:   map[string]any{},
			expected: map[string]any{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ApplyAuthenticationContext(tc.claims, tc.session)

			assert.Equal(t, tc.expected, tc.claims)
		})
	}
}

func TestWriteIntrospectionResponseAuthenticationContext(t *testing.T) {
	session := &testLoginSession{
		DefaultSession: &DefaultSession{Subject: "someone@example.net"},
		login:          &jwt.IDTokenClaims{AuthTime: jwt.NewNumericDate(time.Unix(1646340198, 0)), AuthenticationContextClassReference: "myACR"},
	}

	ar := NewAccessRequest(session)
	ar.Client = &DefaultClient{ID: "s6BhdRkqt3"}

	rw := httptest.NewRecorder()

	(&Fosite{Config: &Config{}}).WriteIntrospectionResponse(context.Background(), rw, &IntrospectionResponse{
		Active:          true,
		TokenUse:        AccessToken,
		AccessRequester: ar,
	})

	require.Equal(t, http.StatusOK, rw.Code)

	params := map[string]any{}
	require.NoError(t, json.NewDecoder(rw.Body).Decode(&params))

	// RFC 9470 Section 6.2.
	assert.Equal(t, float64(1646340198), params[consts.ClaimAuthenticationTime])
	assert.Equal(t, "myACR", params[consts.ClaimAuthenticationContextClassReference])
}

type testLoginSession struct {
	*DefaultSession

	login *jwt.IDTokenClaims
}

func (s *testLoginSession) IDTokenClaims() *jwt.IDTokenClaims {
	return s.login
}
