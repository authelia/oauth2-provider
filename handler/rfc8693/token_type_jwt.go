// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc8693

import (
	"context"
	"time"

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
}

type JWTValidationConfig struct {
	ValidateJTI                bool          `json:"validate_jti"`
	JWTLifetimeToleranceWindow time.Duration `json:"tolerance_window"`
	ValidateFunc               jwt.Keyfunc   `json:"-"`

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
