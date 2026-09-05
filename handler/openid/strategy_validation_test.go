// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package openid

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/gen"
	"authelia.com/provider/oauth2/token/jwt"
)

func TestDefaultIDTokenValidationStrategy_GenerateAndValidateRoundTrip(t *testing.T) {
	const (
		issuer  = "https://issuer.example/"
		subject = "alice"
	)

	cfg := &oauth2.Config{
		IDTokenIssuer:       issuer,
		IDTokenLifespan:     5 * time.Minute,
		MinParameterEntropy: 8,
	}

	jwtStrategy := &jwt.DefaultStrategy{
		Config: cfg,
		Issuer: jwt.NewDefaultIssuerRS256Unverified(key),
	}

	issueStrategy := &DefaultStrategy{Strategy: jwtStrategy, Config: cfg}
	validationStrategy := &DefaultIDTokenValidationStrategy{Strategy: jwtStrategy}

	session := &DefaultSession{
		Claims: &jwt.IDTokenClaims{
			Subject:  subject,
			AuthTime: jwt.Now(),
		},
		Headers: &jwt.Headers{},
		Subject: subject,
	}

	req := oauth2.NewAccessRequest(session)
	req.Client = &oauth2.DefaultClient{ID: "test-client"}

	token, err := issueStrategy.GenerateIDToken(t.Context(), cfg.IDTokenLifespan, req)
	require.NoError(t, err)
	require.NotEmpty(t, token)

	claims, err := validationStrategy.ValidateIDToken(t.Context(), req, token)
	require.NoError(t, err)
	require.NotNil(t, claims)

	assert.Equal(t, subject, claims[jwt.ClaimSubject])
	assert.Equal(t, issuer, claims[jwt.ClaimIssuer])
	assert.NotEmpty(t, claims[jwt.ClaimJWTID])
	assert.NotNil(t, claims[jwt.ClaimExpirationTime])
	assert.NotNil(t, claims[jwt.ClaimIssuedAt])
}

func TestDefaultIDTokenValidationStrategy_RejectsTamperedToken(t *testing.T) {
	cfg := &oauth2.Config{
		IDTokenIssuer:       "https://issuer.example/",
		IDTokenLifespan:     5 * time.Minute,
		MinParameterEntropy: 8,
	}

	jwtStrategy := &jwt.DefaultStrategy{
		Config: cfg,
		Issuer: jwt.NewDefaultIssuerRS256Unverified(key),
	}

	issueStrategy := &DefaultStrategy{Strategy: jwtStrategy, Config: cfg}
	validationStrategy := &DefaultIDTokenValidationStrategy{Strategy: jwtStrategy}

	session := &DefaultSession{
		Claims:  &jwt.IDTokenClaims{Subject: "alice", AuthTime: jwt.Now()},
		Headers: &jwt.Headers{},
		Subject: "alice",
	}

	req := oauth2.NewAccessRequest(session)
	req.Client = &oauth2.DefaultClient{ID: "test-client"}

	token, err := issueStrategy.GenerateIDToken(t.Context(), cfg.IDTokenLifespan, req)
	require.NoError(t, err)

	tampered := []byte(token)
	for i, b := range tampered {
		if b == '.' {
			if i+5 < len(tampered) {
				tampered[i+5] ^= 0x01
			}

			break
		}
	}

	_, err = validationStrategy.ValidateIDToken(t.Context(), req, string(tampered))
	require.Error(t, err)
	assert.EqualError(t, err, "go-jose/go-jose: error in cryptographic primitive")
}

func TestDefaultIDTokenValidationStrategy_RejectsTokenSignedWithWrongKey(t *testing.T) {
	cfg := &oauth2.Config{
		IDTokenIssuer:       "https://issuer.example/",
		IDTokenLifespan:     5 * time.Minute,
		MinParameterEntropy: 8,
	}

	wrongKey := gen.MustRSAKey()

	issuingJWT := &jwt.DefaultStrategy{
		Config: cfg,
		Issuer: jwt.NewDefaultIssuerRS256Unverified(wrongKey),
	}
	issueStrategy := &DefaultStrategy{Strategy: issuingJWT, Config: cfg}

	validatingJWT := &jwt.DefaultStrategy{
		Config: cfg,
		Issuer: jwt.NewDefaultIssuerRS256Unverified(key),
	}
	validationStrategy := &DefaultIDTokenValidationStrategy{Strategy: validatingJWT}

	session := &DefaultSession{
		Claims:  &jwt.IDTokenClaims{Subject: "alice", AuthTime: jwt.Now()},
		Headers: &jwt.Headers{},
		Subject: "alice",
	}

	req := oauth2.NewAccessRequest(session)
	req.Client = &oauth2.DefaultClient{ID: "test-client"}

	token, err := issueStrategy.GenerateIDToken(t.Context(), cfg.IDTokenLifespan, req)
	require.NoError(t, err)
	require.NotEmpty(t, token)

	_, err = validationStrategy.ValidateIDToken(t.Context(), req, token)
	require.Error(t, err)
	assert.EqualError(t, err, "go-jose/go-jose: error in cryptographic primitive")
}

func TestDefaultIDTokenValidationStrategy_RejectsExpiredByDefault(t *testing.T) {
	cfg := &oauth2.Config{IDTokenIssuer: "https://issuer.example/", IDTokenLifespan: 5 * time.Minute, MinParameterEntropy: 8}
	jwtStrategy := &jwt.DefaultStrategy{Config: cfg, Issuer: jwt.NewDefaultIssuerRS256Unverified(key)}

	token := newExpiredIDToken(t, cfg, jwtStrategy)

	req := oauth2.NewAccessRequest(&DefaultSession{})
	req.Client = &oauth2.DefaultClient{ID: "test-client"}

	strategy := &DefaultIDTokenValidationStrategy{Strategy: jwtStrategy}

	_, err := strategy.ValidateIDToken(t.Context(), req, token)
	assert.Error(t, err)
	assert.EqualError(t, err, "Token is expired")
}

func TestDefaultIDTokenValidationStrategy_AcceptsExpiredWithOption(t *testing.T) {
	cfg := &oauth2.Config{IDTokenIssuer: "https://issuer.example/", IDTokenLifespan: 5 * time.Minute, MinParameterEntropy: 8}
	jwtStrategy := &jwt.DefaultStrategy{Config: cfg, Issuer: jwt.NewDefaultIssuerRS256Unverified(key)}

	token := newExpiredIDToken(t, cfg, jwtStrategy)

	req := oauth2.NewAccessRequest(&DefaultSession{})
	req.Client = &oauth2.DefaultClient{ID: "test-client"}

	strategy := &DefaultIDTokenValidationStrategy{Strategy: jwtStrategy}

	claims, err := strategy.ValidateIDToken(t.Context(), req, token, oauth2.WithAllowExpired())
	require.NoError(t, err)
	assert.Equal(t, "alice", claims[jwt.ClaimSubject])
}

func TestDefaultIDTokenValidationStrategy_AcceptsUnverifiedWithOption(t *testing.T) {
	cfg := &oauth2.Config{IDTokenIssuer: "https://issuer.example/", IDTokenLifespan: 5 * time.Minute, MinParameterEntropy: 8}

	wrongKey := gen.MustRSAKey()

	issuingJWT := &jwt.DefaultStrategy{Config: cfg, Issuer: jwt.NewDefaultIssuerRS256Unverified(wrongKey)}
	validatingJWT := &jwt.DefaultStrategy{Config: cfg, Issuer: jwt.NewDefaultIssuerRS256Unverified(key)}

	token := newExpiredIDToken(t, cfg, issuingJWT)

	req := oauth2.NewAccessRequest(&DefaultSession{})
	req.Client = &oauth2.DefaultClient{ID: "test-client"}

	strategy := &DefaultIDTokenValidationStrategy{Strategy: validatingJWT}

	t.Run("ShouldRejectWithoutTheOption", func(t *testing.T) {
		_, err := strategy.ValidateIDToken(t.Context(), req, token)

		require.Error(t, err)
		assert.EqualError(t, err, "go-jose/go-jose: error in cryptographic primitive")
	})

	t.Run("ShouldReturnTheUnvalidatedClaimsWithTheOption", func(t *testing.T) {
		claims, err := strategy.ValidateIDToken(t.Context(), req, token, oauth2.WithAllowUnverified())
		require.NoError(t, err)

		assert.Equal(t, "alice", claims[jwt.ClaimSubject])
		assert.EqualError(t, claims.Valid(), "Token is expired")
	})
}

func TestDefaultIDTokenValidationStrategy_AcceptsUnverifiedWithoutRequester(t *testing.T) {
	cfg := &oauth2.Config{IDTokenIssuer: "https://issuer.example/", IDTokenLifespan: 5 * time.Minute, MinParameterEntropy: 8}
	jwtStrategy := &jwt.DefaultStrategy{Config: cfg, Issuer: jwt.NewDefaultIssuerRS256Unverified(key)}

	token := newExpiredIDToken(t, cfg, jwtStrategy)

	strategy := &DefaultIDTokenValidationStrategy{Strategy: jwtStrategy}

	claims, err := strategy.ValidateIDToken(t.Context(), &oauth2.Request{}, token, oauth2.WithAllowUnverified())
	require.NoError(t, err)
	assert.Equal(t, "alice", claims[jwt.ClaimSubject])
}

func newExpiredIDToken(t *testing.T, cfg *oauth2.Config, strategy jwt.Strategy) string {
	t.Helper()

	claims := jwt.MapClaims{
		jwt.ClaimIssuer:         cfg.IDTokenIssuer,
		jwt.ClaimSubject:        "alice",
		jwt.ClaimAudience:       []string{"test-client"},
		jwt.ClaimIssuedAt:       jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
		jwt.ClaimExpirationTime: jwt.NewNumericDate(time.Now().Add(-time.Hour)),
	}

	token, _, err := strategy.Encode(t.Context(), claims)
	require.NoError(t, err)

	return token
}
