// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/jose"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/token/jwt"
)

var errSSFSign = errors.New("sign failed")

type ssfTestStrategy struct {
	claims *jwt.SecurityEventTokenClaims
	token  string
	err    error
}

func (s *ssfTestStrategy) GenerateSecurityEventToken(ctx context.Context, claims *jwt.SecurityEventTokenClaims) (token string, err error) {
	s.claims = claims

	return s.token, s.err
}

func ssfTestToken(typ string) string {
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": typ})

	return base64.RawURLEncoding.EncodeToString(header) + ".e30.sig"
}

func TestGenerateSecurityEventToken(t *testing.T) {
	subject, err := jwt.NewSubjectIdentifierOpaque("abc")
	require.NoError(t, err)

	event := jwt.RawSecurityEvent{URI: "https://schemas.openid.net/secevent/risc/event-type/account-disabled", Claims: map[string]any{}}

	good := &oauth2.SSFStream{Issuer: "https://tx.example.com", Audience: []string{"rx"}}

	testCases := []struct {
		name    string
		config  *oauth2.SSFConfig
		stream  *oauth2.SSFStream
		subject *jwt.SubjectIdentifier
		event   jwt.SecurityEvent
		err     string
	}{
		{name: "ShouldFailNilConfig", config: nil, stream: good, subject: subject, event: event, err: "server_error"},
		{name: "ShouldFailNilStrategy", config: &oauth2.SSFConfig{Issuer: "https://tx.example.com"}, stream: good, subject: subject, event: event, err: "server_error"},
		{name: "ShouldFailNilStream", config: &oauth2.SSFConfig{TokenStrategy: &ssfTestStrategy{}}, subject: subject, event: event, err: "server_error"},
		{name: "ShouldFailEmptyAudience", config: &oauth2.SSFConfig{TokenStrategy: &ssfTestStrategy{}}, stream: &oauth2.SSFStream{Issuer: "https://tx.example.com"}, subject: subject, event: event, err: "server_error"},
		{name: "ShouldFailEmptyIssuer", config: &oauth2.SSFConfig{TokenStrategy: &ssfTestStrategy{}}, stream: &oauth2.SSFStream{Audience: []string{"rx"}}, subject: subject, event: event, err: "server_error"},
		{name: "ShouldFailNilEvent", config: &oauth2.SSFConfig{TokenStrategy: &ssfTestStrategy{}}, stream: good, subject: subject, err: "server_error"},
		{name: "ShouldWrapStrategyError", config: &oauth2.SSFConfig{TokenStrategy: &ssfTestStrategy{err: errSSFSign}}, stream: good, subject: subject, event: event, err: "server_error"},
		{name: "ShouldGenerate", config: &oauth2.SSFConfig{TokenStrategy: &ssfTestStrategy{token: ssfTestToken(jwt.JSONWebTokenTypeSecurityEventToken)}}, stream: good, subject: subject, event: event},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			f := &oauth2.Fosite{Config: &oauth2.Config{SSF: tc.config}}

			token, jti, err := f.GenerateSecurityEventToken(t.Context(), tc.stream, tc.subject, tc.event, "", "txn-1")

			if tc.err != "" {
				require.Error(t, err)
				assert.ErrorIs(t, err, oauth2.ErrServerError)
				assert.Empty(t, token)
				assert.Empty(t, jti)

				if tc.name == "ShouldWrapStrategyError" {
					assert.ErrorIs(t, err, errSSFSign)

					return
				}

				if tc.config != nil && tc.config.TokenStrategy != nil {
					assert.Nil(t, tc.config.TokenStrategy.(*ssfTestStrategy).claims, "the strategy must not be called")
				}

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.config.TokenStrategy.(*ssfTestStrategy).token, token)

			claims := tc.config.TokenStrategy.(*ssfTestStrategy).claims
			require.NotNil(t, claims)
			assert.Equal(t, "https://tx.example.com", claims.Issuer)
			assert.Equal(t, []string{"rx"}, claims.Audience)
			assert.Equal(t, "txn-1", claims.Transaction)
			assert.NotEmpty(t, jti)
			assert.Equal(t, claims.JTI, jti)
		})
	}
}

func TestGenerateSecurityEventTokenJTI(t *testing.T) {
	subject, err := jwt.NewSubjectIdentifierOpaque("abc")
	require.NoError(t, err)

	event := jwt.CAEPSessionRevoked{}
	stream := &oauth2.SSFStream{Issuer: "https://tx.example.com", Audience: []string{"rx"}}
	strategy := &ssfTestStrategy{token: ssfTestToken(jwt.JSONWebTokenTypeSecurityEventToken)}
	f := &oauth2.Fosite{Config: &oauth2.Config{SSF: &oauth2.SSFConfig{TokenStrategy: strategy}}}

	_, jti, err := f.GenerateSecurityEventToken(t.Context(), stream, subject, event, "retry-1", "")
	require.NoError(t, err)
	assert.Equal(t, "retry-1", jti)
	assert.Equal(t, "retry-1", strategy.claims.JTI)

	_, first, err := f.GenerateSecurityEventToken(t.Context(), stream, subject, event, "", "")
	require.NoError(t, err)

	_, second, err := f.GenerateSecurityEventToken(t.Context(), stream, subject, event, "", "")
	require.NoError(t, err)

	assert.NotEmpty(t, first)
	assert.NotEqual(t, first, second)
}

func TestGenerateSecurityEventTokenType(t *testing.T) {
	subject, err := jwt.NewSubjectIdentifierOpaque("abc")
	require.NoError(t, err)

	stream := &oauth2.SSFStream{Issuer: "https://tx.example.com", Audience: []string{"rx"}}

	testCases := []struct {
		name  string
		token string
		ok    bool
	}{
		{name: "ShouldAcceptExact", token: ssfTestToken("secevent+jwt"), ok: true},
		{name: "ShouldAcceptApplicationPrefix", token: ssfTestToken("application/secevent+jwt"), ok: true},
		{name: "ShouldAcceptOtherCase", token: ssfTestToken("SecEvent+JWT"), ok: true},
		{name: "ShouldRefuseJWT", token: ssfTestToken("JWT")},
		{name: "ShouldRefuseLogoutToken", token: ssfTestToken(jwt.JSONWebTokenTypeLogoutToken)},
		{name: "ShouldRefuseMissingType", token: base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256"}`)) + ".e30.sig"},
		{name: "ShouldRefuseNonJSONHeader", token: base64.RawURLEncoding.EncodeToString([]byte(`nope`)) + ".e30.sig"},
		{name: "ShouldRefuseNonBase64Header", token: "!!.e30.sig"},
		{name: "ShouldRefuseEmpty", token: ""},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			f := &oauth2.Fosite{Config: &oauth2.Config{SSF: &oauth2.SSFConfig{TokenStrategy: &ssfTestStrategy{token: tc.token}}}}

			token, jti, err := f.GenerateSecurityEventToken(t.Context(), stream, subject, jwt.CAEPSessionRevoked{}, "", "")

			if tc.ok {
				require.NoError(t, err)
				assert.Equal(t, tc.token, token)

				return
			}

			require.ErrorIs(t, err, oauth2.ErrServerError)
			assert.Empty(t, token)
			assert.Empty(t, jti)
		})
	}
}

func TestDefaultSecurityEventTokenStrategy(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	jwks := &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: key, KeyID: "k1", Algorithm: string(jose.RS256), Use: jwt.JSONWebTokenUseSignature}}}
	strategy := &oauth2.DefaultSecurityEventTokenStrategy{Strategy: &jwt.DefaultStrategy{Config: &oauth2.Config{}, Issuer: jwt.NewDefaultIssuerUnverifiedFromJWKS(jwks)}}

	f := &oauth2.Fosite{Config: &oauth2.Config{SSF: &oauth2.SSFConfig{TokenStrategy: strategy}}}

	subject, err := jwt.NewSubjectIdentifierEmail("john@example.com")
	require.NoError(t, err)

	stream := &oauth2.SSFStream{Issuer: "https://tx.example.com", Audience: []string{"rx"}}

	token, jti, err := f.GenerateSecurityEventToken(t.Context(), stream, subject, jwt.CAEPSessionRevoked{SecurityEventCommon: jwt.SecurityEventCommon{InitiatingEntity: jwt.SecurityEventInitiatingEntityAdmin}}, "", "txn-1")
	require.NoError(t, err)

	decoded, err := jwt.Parse(token, func(*jwt.Token) (any, error) { return key.Public(), nil })
	require.NoError(t, err)

	assert.Equal(t, jwt.JSONWebTokenTypeSecurityEventToken, decoded.Header[jwt.JSONWebTokenHeaderType])

	claims := decoded.Claims.ToMapClaims()

	assert.Equal(t, jti, claims[jwt.ClaimJWTID])
	assert.Equal(t, "txn-1", claims[jwt.ClaimTransaction])
	assert.Equal(t, "https://tx.example.com", claims[jwt.ClaimIssuer])
	assert.Equal(t, map[string]any{"format": "email", "email": "john@example.com"}, claims[jwt.ClaimSubjectIdentifier])

	events, ok := claims[jwt.ClaimEvents].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, map[string]any{jwt.SecurityEventTypeCAEPSessionRevoked: map[string]any{"initiating_entity": "admin"}}, events)

	t.Run("ShouldFailWithoutStrategy", func(t *testing.T) {
		_, err := (&oauth2.DefaultSecurityEventTokenStrategy{}).GenerateSecurityEventToken(t.Context(), &jwt.SecurityEventTokenClaims{})
		assert.ErrorIs(t, err, oauth2.ErrServerError)
	})
}

func TestConfigGetSSFConfig(t *testing.T) {
	assert.Nil(t, (&oauth2.Config{}).GetSSFConfig(t.Context()))

	c := (&oauth2.Config{SSF: &oauth2.SSFConfig{Issuer: "https://tx.example.com"}}).GetSSFConfig(t.Context())
	require.NotNil(t, c)
	assert.Equal(t, "https://tx.example.com", c.Audience)
	assert.Equal(t, int64(1<<16), c.MaxRequestBytes)

	c = (&oauth2.Config{SSF: &oauth2.SSFConfig{Issuer: "i", Audience: "a", MaxRequestBytes: 10}}).GetSSFConfig(t.Context())
	assert.Equal(t, "a", c.Audience)
	assert.Equal(t, int64(10), c.MaxRequestBytes)
}
