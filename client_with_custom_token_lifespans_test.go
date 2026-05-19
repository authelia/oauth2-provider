// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestGetEffectiveLifespan(t *testing.T) {
	customLifespan := 36 * time.Hour
	fallback := 42 * time.Minute

	testCases := []struct {
		name     string
		client   Client
		gt       GrantType
		tt       TokenType
		expected time.Duration
	}{
		{
			name:     "ShouldReturnFallbackForNonCustomLifespanClient",
			client:   &DefaultClient{},
			gt:       GrantTypeImplicit,
			tt:       IDToken,
			expected: fallback,
		},
		{
			name: "ShouldDelegateToCustomLifespanClient",
			client: &DefaultClientWithCustomTokenLifespans{
				DefaultClient:  &DefaultClient{},
				TokenLifespans: &ClientLifespanConfig{ImplicitGrantIDTokenLifespan: &customLifespan},
			},
			gt:       GrantTypeImplicit,
			tt:       IDToken,
			expected: customLifespan,
		},
		{
			name: "ShouldReturnFallbackWhenCustomLifespanIsUnset",
			client: &DefaultClientWithCustomTokenLifespans{
				DefaultClient: &DefaultClient{},
			},
			gt:       GrantTypeImplicit,
			tt:       IDToken,
			expected: fallback,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := GetEffectiveLifespan(tc.client, tc.gt, tc.tt, fallback)
			assert.Equal(t, tc.expected, actual)
		})
	}
}

func TestDefaultClientWithCustomTokenLifespansGetters(t *testing.T) {
	testCases := []struct {
		name  string
		check func(t *testing.T)
	}{
		{
			name: "ShouldReturnNilLifespansWhenUnset",
			check: func(t *testing.T) {
				clc := &DefaultClientWithCustomTokenLifespans{DefaultClient: &DefaultClient{}}
				assert.Nil(t, clc.GetTokenLifespans())
			},
		},
		{
			name: "ShouldSetAndReturnLifespans",
			check: func(t *testing.T) {
				clc := &DefaultClientWithCustomTokenLifespans{DefaultClient: &DefaultClient{}}
				ls := &ClientLifespanConfig{}
				clc.SetTokenLifespans(ls)
				assert.Same(t, ls, clc.GetTokenLifespans())
			},
		},
		{
			name: "ShouldSatisfyCustomTokenLifespansClientInterface",
			check: func(t *testing.T) {
				var _ CustomTokenLifespansClient = &DefaultClientWithCustomTokenLifespans{DefaultClient: &DefaultClient{}}
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, tc.check)
	}
}

func TestDefaultClientWithCustomTokenLifespansGetEffectiveLifespan(t *testing.T) {
	customLifespan := 36 * time.Hour
	fallback := 42 * time.Minute

	full := &ClientLifespanConfig{
		AuthorizationCodeGrantAccessTokenLifespan:  &customLifespan,
		AuthorizationCodeGrantIDTokenLifespan:      &customLifespan,
		AuthorizationCodeGrantRefreshTokenLifespan: &customLifespan,
		DeviceCodeGrantAccessTokenLifespan:         &customLifespan,
		DeviceCodeGrantIDTokenLifespan:             &customLifespan,
		DeviceCodeGrantRefreshTokenLifespan:        &customLifespan,
		ClientCredentialsGrantAccessTokenLifespan:  &customLifespan,
		ImplicitGrantAccessTokenLifespan:           &customLifespan,
		ImplicitGrantIDTokenLifespan:               &customLifespan,
		JwtBearerGrantAccessTokenLifespan:          &customLifespan,
		PasswordGrantAccessTokenLifespan:           &customLifespan,
		PasswordGrantRefreshTokenLifespan:          &customLifespan,
		RefreshTokenGrantAccessTokenLifespan:       &customLifespan,
		RefreshTokenGrantRefreshTokenLifespan:      &customLifespan,
		RefreshTokenGrantIDTokenLifespan:           &customLifespan,
	}

	testCases := []struct {
		name     string
		config   *ClientLifespanConfig
		gt       GrantType
		tt       TokenType
		expected time.Duration
	}{
		{
			name:     "ShouldReturnFallbackWhenLifespansNil",
			config:   nil,
			gt:       GrantTypeAuthorizationCode,
			tt:       AccessToken,
			expected: fallback,
		},
		{
			name:     "ShouldReturnCustomForAuthorizationCodeAccessToken",
			config:   full,
			gt:       GrantTypeAuthorizationCode,
			tt:       AccessToken,
			expected: customLifespan,
		},
		{
			name:     "ShouldReturnCustomForAuthorizationCodeRefreshToken",
			config:   full,
			gt:       GrantTypeAuthorizationCode,
			tt:       RefreshToken,
			expected: customLifespan,
		},
		{
			name:     "ShouldReturnCustomForAuthorizationCodeIDToken",
			config:   full,
			gt:       GrantTypeAuthorizationCode,
			tt:       IDToken,
			expected: customLifespan,
		},
		{
			name:     "ShouldReturnCustomForDeviceCodeAccessToken",
			config:   full,
			gt:       GrantTypeDeviceCode,
			tt:       AccessToken,
			expected: customLifespan,
		},
		{
			name:     "ShouldReturnCustomForDeviceCodeRefreshToken",
			config:   full,
			gt:       GrantTypeDeviceCode,
			tt:       RefreshToken,
			expected: customLifespan,
		},
		{
			name:     "ShouldReturnCustomForDeviceCodeIDToken",
			config:   full,
			gt:       GrantTypeDeviceCode,
			tt:       IDToken,
			expected: customLifespan,
		},
		{
			name:     "ShouldReturnCustomForClientCredentialsAccessToken",
			config:   full,
			gt:       GrantTypeClientCredentials,
			tt:       AccessToken,
			expected: customLifespan,
		},
		{
			name:     "ShouldReturnFallbackForClientCredentialsRefreshToken",
			config:   full,
			gt:       GrantTypeClientCredentials,
			tt:       RefreshToken,
			expected: fallback,
		},
		{
			name:     "ShouldReturnCustomForImplicitAccessToken",
			config:   full,
			gt:       GrantTypeImplicit,
			tt:       AccessToken,
			expected: customLifespan,
		},
		{
			name:     "ShouldReturnCustomForImplicitIDToken",
			config:   full,
			gt:       GrantTypeImplicit,
			tt:       IDToken,
			expected: customLifespan,
		},
		{
			name:     "ShouldReturnFallbackForImplicitRefreshToken",
			config:   full,
			gt:       GrantTypeImplicit,
			tt:       RefreshToken,
			expected: fallback,
		},
		{
			name:     "ShouldReturnCustomForJWTBearerAccessToken",
			config:   full,
			gt:       GrantTypeJWTBearer,
			tt:       AccessToken,
			expected: customLifespan,
		},
		{
			name:     "ShouldReturnFallbackForJWTBearerRefreshToken",
			config:   full,
			gt:       GrantTypeJWTBearer,
			tt:       RefreshToken,
			expected: fallback,
		},
		{
			name:     "ShouldReturnCustomForPasswordAccessToken",
			config:   full,
			gt:       GrantTypePassword,
			tt:       AccessToken,
			expected: customLifespan,
		},
		{
			name:     "ShouldReturnCustomForPasswordRefreshToken",
			config:   full,
			gt:       GrantTypePassword,
			tt:       RefreshToken,
			expected: customLifespan,
		},
		{
			name:     "ShouldReturnFallbackForPasswordIDToken",
			config:   full,
			gt:       GrantTypePassword,
			tt:       IDToken,
			expected: fallback,
		},
		{
			name:     "ShouldReturnCustomForRefreshTokenAccessToken",
			config:   full,
			gt:       GrantTypeRefreshToken,
			tt:       AccessToken,
			expected: customLifespan,
		},
		{
			name:     "ShouldReturnCustomForRefreshTokenRefreshToken",
			config:   full,
			gt:       GrantTypeRefreshToken,
			tt:       RefreshToken,
			expected: customLifespan,
		},
		{
			name:     "ShouldReturnCustomForRefreshTokenIDToken",
			config:   full,
			gt:       GrantTypeRefreshToken,
			tt:       IDToken,
			expected: customLifespan,
		},
		{
			name:     "ShouldReturnFallbackForUnknownGrant",
			config:   full,
			gt:       GrantType("unknown"),
			tt:       AccessToken,
			expected: fallback,
		},
		{
			name:     "ShouldReturnFallbackWhenSpecificLifespanIsNil",
			config:   &ClientLifespanConfig{},
			gt:       GrantTypeAuthorizationCode,
			tt:       AccessToken,
			expected: fallback,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			clc := &DefaultClientWithCustomTokenLifespans{
				DefaultClient:  &DefaultClient{},
				TokenLifespans: tc.config,
			}
			actual := clc.GetEffectiveLifespan(tc.gt, tc.tt, fallback)
			assert.Equal(t, tc.expected, actual)
		})
	}
}
