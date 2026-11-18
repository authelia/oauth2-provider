// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsAuthorizationGrantIssuer(t *testing.T) {
	const (
		grantIssuer = "https://as.a.example/auth"
		jwtType     = "urn:ietf:params:oauth:token-type:jwt"
	)

	var absent *grantIssuerTokenType

	testCases := []struct {
		name     string
		types    map[string]RFC8693TokenType
		issuer   string
		expected bool
	}{
		{
			name:     "ShouldMatchAGrantIssuer",
			types:    map[string]RFC8693TokenType{jwtType: &grantIssuerTokenType{issuer: grantIssuer}},
			issuer:   grantIssuer,
			expected: true,
		},
		{
			name:   "ShouldNotMatchAnotherIssuer",
			types:  map[string]RFC8693TokenType{jwtType: &grantIssuerTokenType{issuer: grantIssuer}},
			issuer: "https://as.c.example/auth",
		},
		{
			name:   "ShouldNotMatchATypeThatIssuesNoGrants",
			types:  map[string]RFC8693TokenType{jwtType: &grantIssuerTokenType{}},
			issuer: "",
		},
		{
			name:   "ShouldIgnoreATypeWithoutTheInterface",
			types:  map[string]RFC8693TokenType{jwtType: plainTokenType{}},
			issuer: grantIssuer,
		},
		{
			name:   "ShouldIgnoreANilType",
			types:  map[string]RFC8693TokenType{jwtType: nil, "urn:example:token-type:absent": absent},
			issuer: grantIssuer,
		},
		{
			name:   "ShouldNotMatchWithoutTypes",
			issuer: grantIssuer,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, IsAuthorizationGrantIssuer(t.Context(), tc.types, tc.issuer))
		})
	}
}

type plainTokenType struct{}

func (plainTokenType) GetName(_ context.Context) (name string) {
	return "plain"
}

func (plainTokenType) GetType(_ context.Context) (tokenType string) {
	return "urn:example:token-type:plain"
}

type grantIssuerTokenType struct {
	plainTokenType

	issuer string
}

func (c *grantIssuerTokenType) GetAuthorizationGrantIssuer(_ context.Context) (issuer string) {
	if c == nil {
		return ""
	}

	return c.issuer
}

var _ AuthorizationGrantIssuerProvider = (*grantIssuerTokenType)(nil)
