// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc7523

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"authelia.com/provider/jose/jwt"

	"authelia.com/provider/oauth2"
)

const (
	issuer   = "https://as.example.com"
	tokenURL = "https://as.example.com/token" //nolint:gosec
	mtlsURL  = "https://mtls.as.example.com/token"
	parURL   = "https://as.example.com/par"
	listed   = "https://legacy.example.com"
	other    = "https://other.example.com"
)

func TestAuthorizeJWTGrantAssertionAudience(t *testing.T) {
	urls := oauth2.EndpointURLs{
		Token:                      tokenURL,
		PushedAuthorizationRequest: parURL,
		MutualTLSAliases:           oauth2.RFC8705MutualTLSEndpointAliases{Token: mtlsURL},
	}

	testCases := []struct {
		name   string
		config func(config *oauth2.Config)
		aud    jwt.Audience
		err    error
	}{
		{name: "ShouldAcceptTheIssuer", aud: jwt.Audience{issuer}},
		{name: "ShouldAcceptTheTokenEndpointURL", aud: jwt.Audience{tokenURL}},
		{name: "ShouldAcceptTheMutualTLSTokenEndpointAlias", aud: jwt.Audience{mtlsURL}},
		{name: "ShouldAcceptAConfiguredAudience", aud: jwt.Audience{listed}},
		{name: "ShouldAcceptAnyMatchingValue", aud: jwt.Audience{other, issuer}},
		{name: "ShouldRejectThePushedAuthorizationRequestEndpointURL", aud: jwt.Audience{parURL}, err: oauth2.ErrInvalidGrant},
		{name: "ShouldRejectAnUnknownAudience", aud: jwt.Audience{other}, err: oauth2.ErrInvalidGrant},
		{name: "ShouldRejectAPrefixOfTheIssuer", aud: jwt.Audience{"https://as.example.co"}, err: oauth2.ErrInvalidGrant},
		{name: "ShouldRejectTheIssuerWithATrailingSlash", aud: jwt.Audience{issuer + "/"}, err: oauth2.ErrInvalidGrant},
		{
			name:   "ShouldAcceptTheIssuerWithoutAConfiguredList",
			config: func(config *oauth2.Config) { config.AllowedJWTAssertionAudiences = nil },
			aud:    jwt.Audience{issuer},
		},
		{
			name: "ShouldRejectAnEmptyAudienceWhenTheIssuerIsUnset",
			config: func(config *oauth2.Config) {
				config.Issuer = ""
				config.EndpointURLs = oauth2.EndpointURLs{}
			},
			aud: jwt.Audience{""},
			err: oauth2.ErrInvalidGrant,
		},
		{
			name: "ShouldRejectWhenNoAudienceIsKnown",
			config: func(config *oauth2.Config) {
				config.Issuer = ""
				config.EndpointURLs = oauth2.EndpointURLs{}
				config.AllowedJWTAssertionAudiences = nil
			},
			aud: jwt.Audience{""},
			err: oauth2.ErrServerError,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			f := newJWTBearerFixture(t)

			config := f.handler.Config.(*oauth2.Config)
			config.Issuer = issuer
			config.EndpointURLs = urls
			config.AllowedJWTAssertionAudiences = []string{listed}

			if tc.config != nil {
				tc.config(config)
			}

			f.mockStore.EXPECT().IsRFC7523JWTUsed(gomock.Any(), gomock.Any(), gomock.Any()).Return(false, nil).AnyTimes()

			claims := f.createStandardClaim()
			claims.Audience = tc.aud

			err := f.handler.validateTokenClaims(f.ctx, claims, nil)

			if tc.err == nil {
				require.NoError(t, oauth2.ErrorToDebugRFC6749Error(err))

				return
			}

			assert.ErrorIs(t, err, tc.err)
		})
	}
}

func TestJWTBearerGrantAudiences(t *testing.T) {
	testCases := []struct {
		name     string
		config   *oauth2.Config
		expected []string
	}{
		{name: "ShouldReturnNothingWhenUnconfigured", config: &oauth2.Config{}},
		{
			name: "ShouldOrderTheIssuerThenTheTokenEndpointThenTheList",
			config: &oauth2.Config{
				Issuer: issuer,
				EndpointURLs: oauth2.EndpointURLs{
					Token:            tokenURL,
					MutualTLSAliases: oauth2.RFC8705MutualTLSEndpointAliases{Token: mtlsURL},
				},
				AllowedJWTAssertionAudiences: []string{listed},
			},
			expected: []string{issuer, tokenURL, mtlsURL, listed},
		},
		{
			name: "ShouldOmitEmptyAndDuplicateValues",
			config: &oauth2.Config{
				EndpointURLs:                 oauth2.EndpointURLs{Token: tokenURL},
				AllowedJWTAssertionAudiences: []string{"", tokenURL, listed, listed},
			},
			expected: []string{tokenURL, listed},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, oauth2.JWTBearerGrantAudiences(t.Context(), tc.config))
		})
	}
}
