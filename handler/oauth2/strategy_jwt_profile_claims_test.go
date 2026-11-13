// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/gen"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestJWTProfileAccessTokenRequiredClaims(t *testing.T) {
	const (
		api      = "https://api.example.com"
		fallback = "https://default.example.com"
		client   = "jwt-client"
	)

	testCases := []struct {
		name     string
		defaults []string
		grant    string
		audience []string
		resource []string
		claims   string
		session  string
		aud      []any
		sub      string
		granted  []string
		err      string
	}{
		{name: "ShouldUseTheGrantedAudience", defaults: []string{fallback}, grant: consts.GrantTypeAuthorizationCode, audience: []string{api}, session: "alice", aud: []any{api}, sub: "alice", granted: []string{api}},
		{name: "ShouldUseAGrantedResource", defaults: []string{fallback}, grant: consts.GrantTypeAuthorizationCode, resource: []string{api}, session: "alice", aud: []any{api}, sub: "alice", granted: []string{}},
		{name: "ShouldUseTheDefaultAudienceAndRecordItAsGranted", defaults: []string{fallback}, grant: consts.GrantTypeAuthorizationCode, session: "alice", aud: []any{fallback}, sub: "alice", granted: []string{fallback}},
		{name: "ShouldIgnoreAnEmptyDefaultAudienceValue", defaults: []string{"", fallback}, grant: consts.GrantTypeAuthorizationCode, session: "alice", aud: []any{fallback}, sub: "alice", granted: []string{fallback}},
		{name: "ShouldRefuseWithOnlyEmptyDefaultAudienceValues", defaults: []string{"", ""}, grant: consts.GrantTypeAuthorizationCode, session: "alice", err: "requires an 'aud' claim"},
		{name: "ShouldRefuseWithoutAnAudienceOrDefault", grant: consts.GrantTypeAuthorizationCode, session: "alice", err: "requires an 'aud' claim"},
		{name: "ShouldPreferTheClaimsSubject", grant: consts.GrantTypeAuthorizationCode, audience: []string{api}, claims: "from-claims", session: "alice", aud: []any{api}, sub: "from-claims", granted: []string{api}},
		{name: "ShouldUseTheClientForAClientCredentialsGrant", grant: consts.GrantTypeClientCredentials, audience: []string{api}, aud: []any{api}, sub: client, granted: []string{api}},
		{name: "ShouldPreferASessionSubjectForAClientCredentialsGrant", grant: consts.GrantTypeClientCredentials, audience: []string{api}, session: "service", aud: []any{api}, sub: "service", granted: []string{api}},
		{name: "ShouldRefuseWithoutASubjectForAResourceOwnerGrant", grant: consts.GrantTypeAuthorizationCode, audience: []string{api}, err: "requires a 'sub' claim"},
		{name: "ShouldRefuseWithoutASubjectForARefreshGrant", grant: consts.GrantTypeRefreshToken, audience: []string{api}, err: "requires a 'sub' claim"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := &oauth2.Config{
				EnforceJWTProfileAccessTokens:        true,
				Issuer:                               "https://as.example.com",
				GlobalSecret:                         []byte("foofoofoofoofoofoofoofoofoofoofoo"),
				JWTProfileAccessTokenDefaultAudience: tc.defaults,
			}

			strategy := &JWTProfileCoreStrategy{
				HMACCoreStrategy: NewHMACCoreStrategy(config, "authelia_%s_"),
				Strategy:         &jwt.DefaultStrategy{Config: config, Issuer: jwt.NewDefaultIssuerRS256Unverified(gen.MustRSAKey())},
				Config:           config,
			}

			session := &JWTSession{Subject: tc.session, JWTClaims: &jwt.JWTClaims{Subject: tc.claims}}
			session.SetExpiresAt(oauth2.AccessToken, time.Now().UTC().Add(time.Hour))

			request := oauth2.NewAccessRequest(session)
			request.GrantTypes = oauth2.Arguments{tc.grant}
			request.Client = &oauth2.DefaultClient{ID: client}

			for _, value := range tc.audience {
				request.GrantAudience(value)
			}

			for _, value := range tc.resource {
				request.GrantResource(value)
			}

			token, _, err := strategy.GenerateAccessToken(context.Background(), request)

			if tc.err != "" {
				assert.ErrorIs(t, err, oauth2.ErrServerError)
				assert.ErrorContains(t, oauth2.ErrorToDebugRFC6749Error(err), tc.err)

				return
			}

			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

			payload, err := base64.RawURLEncoding.DecodeString(strings.Split(token, ".")[1])
			require.NoError(t, err)

			var claims map[string]any

			require.NoError(t, json.Unmarshal(payload, &claims))

			assert.Equal(t, tc.aud, claims[consts.ClaimAudience])
			assert.Equal(t, tc.sub, claims[consts.ClaimSubject])
			assert.Equal(t, oauth2.Arguments(tc.granted), request.GetGrantedAudience())
		})
	}
}

func TestJWTProfileAccessTokenAuthenticationContext(t *testing.T) {
	authTime := time.Now().Add(-time.Hour).Truncate(time.Second)

	testCases := []struct {
		name      string
		extra     map[string]any
		requested []string
		client    oauth2.Client
		expected  map[string]any
	}{
		{
			name:     "ShouldOmitTheAuthenticationContextByDefault",
			client:   &oauth2.DefaultClient{ID: "jwt-client"},
			expected: map[string]any{},
		},
		{
			name:      "ShouldIncludeTheAuthenticationContextTheRequestRequired",
			requested: []string{consts.ClaimAuthenticationTime, consts.ClaimAuthenticationContextClassReference},
			client:    &oauth2.DefaultClient{ID: "jwt-client"},
			expected:  map[string]any{consts.ClaimAuthenticationTime: float64(authTime.Unix()), consts.ClaimAuthenticationContextClassReference: "gold"},
		},
		{
			name:     "ShouldIncludeTheAuthenticationContextTheClientLists",
			client:   &authenticationContextClient{DefaultClient: &oauth2.DefaultClient{ID: "jwt-client"}, claims: []string{consts.ClaimAuthenticationMethodsReference}},
			expected: map[string]any{consts.ClaimAuthenticationMethodsReference: []any{"mfa"}},
		},
		{
			name:      "ShouldPreferTheSessionClaims",
			extra:     map[string]any{consts.ClaimAuthenticationContextClassReference: "silver"},
			requested: []string{consts.ClaimAuthenticationContextClassReference},
			client:    &oauth2.DefaultClient{ID: "jwt-client"},
			expected:  map[string]any{consts.ClaimAuthenticationContextClassReference: "silver"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := &oauth2.Config{
				EnforceJWTProfileAccessTokens:        true,
				Issuer:                               "https://as.example.com",
				GlobalSecret:                         []byte("foofoofoofoofoofoofoofoofoofoofoo"),
				JWTProfileAccessTokenDefaultAudience: []string{"https://api.example.com"},
			}

			strategy := &JWTProfileCoreStrategy{
				HMACCoreStrategy: NewHMACCoreStrategy(config, "authelia_%s_"),
				Strategy:         &jwt.DefaultStrategy{Config: config, Issuer: jwt.NewDefaultIssuerRS256Unverified(gen.MustRSAKey())},
				Config:           config,
			}

			session := &loginJWTSession{
				JWTSession: &JWTSession{Subject: "alice", JWTClaims: &jwt.JWTClaims{Extra: tc.extra}},
				login:      &jwt.IDTokenClaims{AuthTime: jwt.NewNumericDate(authTime), AuthenticationContextClassReference: "gold", AuthenticationMethodsReferences: []string{"mfa"}},
				requested:  tc.requested,
			}
			session.SetExpiresAt(oauth2.AccessToken, time.Now().UTC().Add(time.Hour))

			request := oauth2.NewAccessRequest(session)
			request.GrantTypes = oauth2.Arguments{consts.GrantTypeAuthorizationCode}
			request.Client = tc.client

			token, _, err := strategy.GenerateAccessToken(context.Background(), request)
			require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

			payload, err := base64.RawURLEncoding.DecodeString(strings.Split(token, ".")[1])
			require.NoError(t, err)

			var claims map[string]any

			require.NoError(t, json.Unmarshal(payload, &claims))

			actual := map[string]any{}

			for _, claim := range []string{consts.ClaimAuthenticationTime, consts.ClaimAuthenticationContextClassReference, consts.ClaimAuthenticationMethodsReference} {
				if value, ok := claims[claim]; ok {
					actual[claim] = value
				}
			}

			// RFC 9068 Section 2.2.1 and RFC 9470 Section 6.1.
			assert.Equal(t, tc.expected, actual)
		})
	}
}

type loginJWTSession struct {
	*JWTSession

	login     *jwt.IDTokenClaims
	requested []string
}

func (s *loginJWTSession) IDTokenClaims() *jwt.IDTokenClaims {
	return s.login
}

func (s *loginJWTSession) SetRequestedAuthenticationContextClaims(claims []string) {
	s.requested = claims
}

func (s *loginJWTSession) GetRequestedAuthenticationContextClaims() []string {
	return s.requested
}

type authenticationContextClient struct {
	*oauth2.DefaultClient

	claims []string
}

func (c *authenticationContextClient) GetAuthenticationContextClaims() []string {
	return c.claims
}
