// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc8693

import (
	"context"
	"time"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/token/jwt"
)

type JWTType struct {
	Name string `json:"name"`

	// Issuer is the 'iss' claim of an issued JWT and the expected issuer of a validated one. A JWT is not issued when
	// it equals the ID Token issuer, as it would then be accepted as an ID Token.
	Issuer string `json:"iss"`

	JWTValidationConfig `json:"validate"`
	JWTIssueConfig      `json:"issue"`
}

type JWTIssueConfig struct {
	Audience []string `json:"aud"`

	// Expiry is the lifetime of an issued JWT, which never outlives the 'subject_token'. A value that is not positive
	// uses the access token lifespan, or one hour when the configuration does not provide one.
	Expiry time.Duration `json:"exp"`

	// AuthorizationGrant issues the JWT as a JWT authorization grant for an authorization server in another trust
	// domain. The client must opt in with AuthorizationGrantIssuanceClient, the request must identify exactly one target
	// with 'audience' or 'resource', a client may exchange a token issued to itself, and the JWT carries only the 'iss', 'sub', 'aud', 'exp', 'iat', 'jti', 'scope' and 'act' claims.
	// It is signed with the issuer key rather than the ID Token configuration of the client, as the other authorization
	// server must be able to read and verify it. The type cannot be presented as a 'subject_token' or 'actor_token', and
	// no other JWTType may trust the key and issuer of its grants, as a grant could then be exchanged for a new target.
	// Set Expiry to keep grants short-lived, per Section 5.5.
	//
	// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-chaining-17#section-2.3
	AuthorizationGrant bool `json:"authorization_grant"`

	// SigningAlg is the JWS algorithm selecting the issuer key of an AuthorizationGrant. RS256 is used when empty.
	SigningAlg string `json:"signing_alg"`

	// TranscribeClaims adds, changes or removes the claims of an AuthorizationGrant, such as mapping the 'sub' claim to
	// the identifier known to the other trust domain. Changes to 'iss', 'aud', 'exp', 'iat' and 'jti' are discarded, and a
	// 'sub' claim that is not a non-empty string is a server error. A returned error denies the request, and should be
	// an error RFC 8693 Section 2.2.2 defines such as oauth2.ErrInvalidRequest.
	//
	// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-chaining-17#section-2.5
	TranscribeClaims func(ctx context.Context, request oauth2.AccessRequester, claims map[string]any) (err error) `json:"-"`
}

type JWTValidationConfig struct {
	ValidateJTI                bool          `json:"validate_jti"`
	JWTLifetimeToleranceWindow time.Duration `json:"tolerance_window"`
	ValidateFunc               jwt.Keyfunc   `json:"-"`

	// ExpectedAudience is the set of 'aud' claim values accepted in addition to the requesting client's ID, such as
	// this authorization server's own identifier. It does not apply to an Identity Assertion JWT Authorization Grant
	// request, whose audience is always the requesting client.
	ExpectedAudience []string `json:"expected_aud"`

	// Types is the set of permitted 'typ' header values, compared per RFC 8725 Section 3.11. An absent 'typ' is
	// permitted when the set includes 'JWT'. When empty, only 'JWT' or an absent 'typ' is permitted.
	Types []string `json:"types"`
}

// GetName returns the name of the token type.
func (c *JWTType) GetName(ctx context.Context) string {
	return c.Name
}

// GetTypes returns the permitted 'typ' header values.
func (c *JWTType) GetTypes() []string {
	if len(c.Types) == 0 {
		return []string{consts.JSONWebTokenTypeJWT}
	}

	return c.Types
}

// GetType returns the RFC 8693 JWT token type identifier.
func (c *JWTType) GetType(ctx context.Context) string {
	return consts.TokenTypeRFC8693JWT
}
