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
	require.NoError(t, err, "issuance must succeed when the jwt.Strategy is configured with a usable signing key")
	require.NotEmpty(t, token)

	claims, err := validationStrategy.ValidateIDToken(t.Context(), req, token)
	require.NoError(t, err, "validation must succeed when the issuer key matches the signing key")
	require.NotNil(t, claims)

	assert.Equal(t, subject, claims[jwt.ClaimSubject], "sub claim must round-trip intact")
	assert.Equal(t, issuer, claims[jwt.ClaimIssuer], "iss claim must come from the AS configuration")
	assert.NotEmpty(t, claims[jwt.ClaimJWTID], "jti claim must be auto-populated on issuance")
	assert.NotNil(t, claims[jwt.ClaimExpirationTime], "exp claim must be present so the validator can enforce token lifetime")
	assert.NotNil(t, claims[jwt.ClaimIssuedAt], "iat claim must be present per JWT BCP")
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
	require.Error(t, err, "validation must reject a token whose body has been altered after signing")
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
	require.NoError(t, err, "issuance with the wrong key must succeed; the failure must surface at validation, not issuance")
	require.NotEmpty(t, token)

	_, err = validationStrategy.ValidateIDToken(t.Context(), req, token)
	require.Error(t, err, "validator must reject a token whose signature does not chain to its configured Issuer key")
}

func TestDefaultIDTokenValidationStrategy_RejectsExpiredByDefault(t *testing.T) {
	cfg := &oauth2.Config{IDTokenIssuer: "https://issuer.example/", IDTokenLifespan: 5 * time.Minute, MinParameterEntropy: 8}
	jwtStrategy := &jwt.DefaultStrategy{Config: cfg, Issuer: jwt.NewDefaultIssuerRS256Unverified(key)}

	token := newExpiredIDToken(t, cfg, jwtStrategy)

	req := oauth2.NewAccessRequest(&DefaultSession{})
	req.Client = &oauth2.DefaultClient{ID: "test-client"}

	strategy := &DefaultIDTokenValidationStrategy{Strategy: jwtStrategy}

	_, err := strategy.ValidateIDToken(t.Context(), req, token)
	assert.Error(t, err, "an expired id_token must be rejected when no options are supplied")
}

func TestDefaultIDTokenValidationStrategy_AcceptsExpiredWithOption(t *testing.T) {
	cfg := &oauth2.Config{IDTokenIssuer: "https://issuer.example/", IDTokenLifespan: 5 * time.Minute, MinParameterEntropy: 8}
	jwtStrategy := &jwt.DefaultStrategy{Config: cfg, Issuer: jwt.NewDefaultIssuerRS256Unverified(key)}

	token := newExpiredIDToken(t, cfg, jwtStrategy)

	req := oauth2.NewAccessRequest(&DefaultSession{})
	req.Client = &oauth2.DefaultClient{ID: "test-client"}

	strategy := &DefaultIDTokenValidationStrategy{Strategy: jwtStrategy}

	claims, err := strategy.ValidateIDToken(t.Context(), req, token, oauth2.WithAllowExpired())
	require.NoError(t, err, "WithAllowExpired must permit an expired id_token")
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
