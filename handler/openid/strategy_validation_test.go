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

// TestDefaultIDTokenValidationStrategy_GenerateAndValidateRoundTrip verifies the end-to-end contract that motivated
// the new strategy: an ID token issued by DefaultStrategy (which embeds a jwt.Strategy with a single signing key)
// can be decoded and verified by DefaultIDTokenValidationStrategy when given the same jwt.Strategy. The asymmetric
// signing key is shared by both paths via the jwt.Strategy.Issuer, so the validator resolves the verification key
// from the AS's own issuer JWK set (path 3 of jwt.DefaultStrategy.validate) rather than from the client.
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

	// Single jwt.Strategy backing both issuance and validation — same key everywhere.
	jwtStrategy := &jwt.DefaultStrategy{
		Config: cfg,
		Issuer: jwt.NewDefaultIssuerRS256Unverified(key),
	}

	issueStrategy := &DefaultStrategy{Strategy: jwtStrategy, Config: cfg}
	validationStrategy := &DefaultIDTokenValidationStrategy{Strategy: jwtStrategy}

	// Build a request with the minimum DefaultSession plumbing GenerateIDToken needs.
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

	// Issue: ID token signed with the shared key.
	token, err := issueStrategy.GenerateIDToken(t.Context(), cfg.IDTokenLifespan, req)
	require.NoError(t, err, "issuance must succeed when the jwt.Strategy is configured with a usable signing key")
	require.NotEmpty(t, token)

	// Validate: decoded by the same jwt.Strategy via the new validation strategy.
	claims, err := validationStrategy.ValidateIDToken(t.Context(), req, token)
	require.NoError(t, err, "validation must succeed when the issuer key matches the signing key")
	require.NotNil(t, claims)

	assert.Equal(t, subject, claims[jwt.ClaimSubject], "sub claim must round-trip intact")
	assert.Equal(t, issuer, claims[jwt.ClaimIssuer], "iss claim must come from the AS configuration")
	assert.NotEmpty(t, claims[jwt.ClaimJWTID], "jti claim must be auto-populated on issuance")
	assert.NotNil(t, claims[jwt.ClaimExpirationTime], "exp claim must be present so the validator can enforce token lifetime")
	assert.NotNil(t, claims[jwt.ClaimIssuedAt], "iat claim must be present per JWT BCP")
}

// TestDefaultIDTokenValidationStrategy_RejectsTamperedToken proves the validation strategy actually verifies the
// signature: a token whose payload byte is flipped after signing must be rejected, not accepted with the modified
// claims.
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

	// Tamper: flip a single character in the payload segment (between the two dots).
	tampered := []byte(token)
	for i, b := range tampered {
		if b == '.' {
			// Move past the header dot and flip a payload character.
			if i+5 < len(tampered) {
				tampered[i+5] ^= 0x01
			}

			break
		}
	}

	_, err = validationStrategy.ValidateIDToken(t.Context(), req, string(tampered))
	require.Error(t, err, "validation must reject a token whose body has been altered after signing")
}

// TestDefaultIDTokenValidationStrategy_RejectsTokenSignedWithWrongKey proves the validator's trust anchor is the
// jwt.Strategy's Issuer key, not the bare token signature. A token signed by a different (but otherwise valid) key
// MUST be rejected — the validator must not accept any well-formed JWT that happens to have a valid signature
// under some unrelated key.
func TestDefaultIDTokenValidationStrategy_RejectsTokenSignedWithWrongKey(t *testing.T) {
	cfg := &oauth2.Config{
		IDTokenIssuer:       "https://issuer.example/",
		IDTokenLifespan:     5 * time.Minute,
		MinParameterEntropy: 8,
	}

	// Issuance strategy uses an UNRELATED key. The validator below uses the package-level `key` — distinct from
	// the one signing the token.
	wrongKey := gen.MustRSAKey()

	issuingJWT := &jwt.DefaultStrategy{
		Config: cfg,
		Issuer: jwt.NewDefaultIssuerRS256Unverified(wrongKey),
	}
	issueStrategy := &DefaultStrategy{Strategy: issuingJWT, Config: cfg}

	// Validator pinned to the package-level `key`.
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
	require.NoError(t, err, "issuance with the wrong key must succeed — the failure must surface at validation, not issuance")
	require.NotEmpty(t, token)

	_, err = validationStrategy.ValidateIDToken(t.Context(), req, token)
	require.Error(t, err, "validator must reject a token whose signature does not chain to its configured Issuer key")
}
