// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"time"
)

// GetEffectiveLifespan either maps GrantType x TokenType to the client's configured lifespan, or returns the fallback value.
func GetEffectiveLifespan(c Client, gt GrantType, tt TokenType, fallback time.Duration) (lifespan time.Duration) {
	if clc, ok := c.(CustomTokenLifespansClient); ok {
		return clc.GetEffectiveLifespan(gt, tt, fallback)
	}

	return fallback
}

// CustomTokenLifespansClient is a Client with specific lifespans.
type CustomTokenLifespansClient interface {
	// GetEffectiveLifespan either maps GrantType x TokenType to the client's configured lifespan, or returns the fallback value.
	GetEffectiveLifespan(gt GrantType, tt TokenType, fallback time.Duration) (lifespan time.Duration)

	Client
}

// ClientLifespanConfig holds default lifespan configuration for the different
// token types that may be issued for the client. This configuration takes
// precedence over instance-wide default lifespan, but it may be
// overridden by a session's expires_at claim.
//
// The OIDC Hybrid grant type inherits token lifespan configuration from the implicit grant.
type ClientLifespanConfig struct {
	AuthorizationCodeGrantAccessTokenLifespan  *time.Duration `json:"authorization_code_grant_access_token_lifespan"`
	AuthorizationCodeGrantIDTokenLifespan      *time.Duration `json:"authorization_code_grant_id_token_lifespan"`
	AuthorizationCodeGrantRefreshTokenLifespan *time.Duration `json:"authorization_code_grant_refresh_token_lifespan"`
	DeviceCodeGrantAccessTokenLifespan         *time.Duration `json:"device_code_grant_access_token_lifespan"`
	DeviceCodeGrantIDTokenLifespan             *time.Duration `json:"device_code_grant_id_token_lifespan"`
	DeviceCodeGrantRefreshTokenLifespan        *time.Duration `json:"device_code_grant_refresh_token_lifespan"`
	ClientCredentialsGrantAccessTokenLifespan  *time.Duration `json:"client_credentials_grant_access_token_lifespan"`
	ImplicitGrantAccessTokenLifespan           *time.Duration `json:"implicit_grant_access_token_lifespan"`
	ImplicitGrantIDTokenLifespan               *time.Duration `json:"implicit_grant_id_token_lifespan"`
	JwtBearerGrantAccessTokenLifespan          *time.Duration `json:"jwt_bearer_grant_access_token_lifespan"`
	PasswordGrantAccessTokenLifespan           *time.Duration `json:"password_grant_access_token_lifespan"`
	PasswordGrantRefreshTokenLifespan          *time.Duration `json:"password_grant_refresh_token_lifespan"`
	RefreshTokenGrantIDTokenLifespan           *time.Duration `json:"refresh_token_grant_id_token_lifespan"`
	RefreshTokenGrantAccessTokenLifespan       *time.Duration `json:"refresh_token_grant_access_token_lifespan"`
	RefreshTokenGrantRefreshTokenLifespan      *time.Duration `json:"refresh_token_grant_refresh_token_lifespan"`
	// Hybrid grant tokens are not independently configurable, see the comment above.
}

type DefaultClientWithCustomTokenLifespans struct {
	*DefaultClient
	TokenLifespans *ClientLifespanConfig `json:"token_lifespans"`
}

func (c *DefaultClientWithCustomTokenLifespans) GetTokenLifespans() *ClientLifespanConfig {
	return c.TokenLifespans
}

func (c *DefaultClientWithCustomTokenLifespans) SetTokenLifespans(lifespans *ClientLifespanConfig) {
	c.TokenLifespans = lifespans
}

// GetEffectiveLifespan either maps GrantType x TokenType to the client's configured lifespan, or returns the fallback value.
//
// TODO: Refactor time permitting.
//
//nolint:gocyclo
func (c *DefaultClientWithCustomTokenLifespans) GetEffectiveLifespan(gt GrantType, tt TokenType, fallback time.Duration) time.Duration {
	if c.TokenLifespans == nil {
		return fallback
	}
	var cl *time.Duration

	switch gt {
	case GrantTypeAuthorizationCode:
		switch tt {
		case AccessToken:
			cl = c.TokenLifespans.AuthorizationCodeGrantAccessTokenLifespan
		case RefreshToken:
			cl = c.TokenLifespans.AuthorizationCodeGrantRefreshTokenLifespan
		case IDToken:
			cl = c.TokenLifespans.AuthorizationCodeGrantIDTokenLifespan
		}
	case GrantTypeDeviceCode:
		switch tt {
		case AccessToken:
			cl = c.TokenLifespans.DeviceCodeGrantAccessTokenLifespan
		case RefreshToken:
			cl = c.TokenLifespans.DeviceCodeGrantRefreshTokenLifespan
		case IDToken:
			cl = c.TokenLifespans.DeviceCodeGrantIDTokenLifespan
		}
	case GrantTypeClientCredentials:
		if tt == AccessToken {
			cl = c.TokenLifespans.ClientCredentialsGrantAccessTokenLifespan
		}
	case GrantTypeImplicit:
		switch tt {
		case AccessToken:
			cl = c.TokenLifespans.ImplicitGrantAccessTokenLifespan
		case IDToken:
			cl = c.TokenLifespans.ImplicitGrantIDTokenLifespan
		}
	case GrantTypeJWTBearer:
		if tt == AccessToken {
			cl = c.TokenLifespans.JwtBearerGrantAccessTokenLifespan
		}
	case GrantTypePassword:
		switch tt {
		case AccessToken:
			cl = c.TokenLifespans.PasswordGrantAccessTokenLifespan
		case RefreshToken:
			cl = c.TokenLifespans.PasswordGrantRefreshTokenLifespan
		}
	case GrantTypeRefreshToken:
		switch tt {
		case AccessToken:
			cl = c.TokenLifespans.RefreshTokenGrantAccessTokenLifespan
		case RefreshToken:
			cl = c.TokenLifespans.RefreshTokenGrantRefreshTokenLifespan
		case IDToken:
			cl = c.TokenLifespans.RefreshTokenGrantIDTokenLifespan
		}
	}

	if cl == nil {
		return fallback
	}

	return *cl
}
