// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"context"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/handler/idjag"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/handler/openid"
	"authelia.com/provider/oauth2/handler/pkce"
	"authelia.com/provider/oauth2/handler/rfc7523"
	"authelia.com/provider/oauth2/handler/rfc8628"
	"authelia.com/provider/oauth2/handler/rfc8693"
	"authelia.com/provider/oauth2/handler/verifiable"
	"authelia.com/provider/oauth2/internal/consts"
)

func TestCapabilityMethodsAugmentingHandlersReturnNil(t *testing.T) {
	testCases := []struct {
		name       string
		handler    any
		configured []capabilityMethod
		expected   map[capabilityMethod][]string
	}{
		{
			name:       "ShouldReportCapabilitiesForPKCE",
			handler:    &pkce.Handler{},
			configured: []capabilityMethod{capabilityCodeChallengeMethods},
		},
		{
			name:       "ShouldReportCapabilitiesForOpenIDConnectExplicit",
			handler:    &openid.OpenIDConnectExplicitHandler{},
			configured: []capabilityMethod{capabilityIDTokenSigningAlgValues},
		},
		{
			name:       "ShouldReportCapabilitiesForOpenIDConnectImplicit",
			handler:    &openid.OpenIDConnectImplicitHandler{},
			configured: []capabilityMethod{capabilityIDTokenSigningAlgValues},
			expected: map[capabilityMethod][]string{
				capabilityResponseTypes: {consts.ResponseTypeImplicitFlowIDToken, consts.ResponseTypeImplicitFlowBoth},
				capabilityGrantTypes:    {consts.GrantTypeImplicit},
			},
		},
		{
			name:       "ShouldReportCapabilitiesForOpenIDConnectHybrid",
			handler:    &openid.OpenIDConnectHybridHandler{},
			configured: []capabilityMethod{capabilityIDTokenSigningAlgValues},
			expected: map[capabilityMethod][]string{
				capabilityResponseTypes: {
					consts.ResponseTypeHybridFlowIDToken,
					consts.ResponseTypeHybridFlowToken,
					consts.ResponseTypeHybridFlowBoth,
				},
				capabilityGrantTypes: {consts.GrantTypeImplicit},
			},
		},
		{
			name:       "ShouldReportCapabilitiesForOpenIDConnectRefresh",
			handler:    &openid.OpenIDConnectRefreshHandler{},
			configured: []capabilityMethod{capabilityIDTokenSigningAlgValues},
		},
		{
			name:       "ShouldReportCapabilitiesForOpenIDConnectDeviceAuthorize",
			handler:    &openid.OpenIDConnectDeviceAuthorizeHandler{},
			configured: []capabilityMethod{capabilityIDTokenSigningAlgValues},
		},
		{
			name:    "ShouldReportCapabilitiesForVerifiable",
			handler: &verifiable.Handler{},
		},
		{
			name:       "ShouldReportCapabilitiesForIDJAGIssue",
			handler:    &idjag.IssueHandler{},
			configured: []capabilityMethod{capabilityRFC8693TokenTypes},
		},
		{
			name:    "ShouldReportCapabilitiesForIDJAGRedeem",
			handler: &idjag.RedeemHandler{},
			expected: map[capabilityMethod][]string{
				capabilityGrantTypes: {consts.GrantTypeOAuthJWTBearer},
			},
		},
		{
			name:    "ShouldReportCapabilitiesForRFC7523",
			handler: &rfc7523.Handler{},
			expected: map[capabilityMethod][]string{
				capabilityGrantTypes: {consts.GrantTypeOAuthJWTBearer},
			},
		},
		{
			name:    "ShouldReportCapabilitiesForGenericCodeTokenEndpoint",
			handler: &hoauth2.GenericCodeTokenEndpointHandler{},
		},
		{
			name:    "ShouldReportCapabilitiesForDeviceAuthorizeTokenEndpoint",
			handler: &rfc8628.DeviceAuthorizeTokenEndpointHandler{},
			expected: map[capabilityMethod][]string{
				capabilityGrantTypes: {consts.GrantTypeOAuthDeviceCode},
			},
		},
		{
			name:    "ShouldReportCapabilitiesForAuthorizeExplicitGrant",
			handler: &hoauth2.AuthorizeExplicitGrantHandler{},
			expected: map[capabilityMethod][]string{
				capabilityResponseTypes: {consts.ResponseTypeAuthorizationCodeFlow},
				capabilityGrantTypes:    {consts.GrantTypeAuthorizationCode},
			},
		},
		{
			name:    "ShouldReportCapabilitiesForAuthorizeImplicitGrant",
			handler: &hoauth2.AuthorizeImplicitGrantTypeHandler{},
			expected: map[capabilityMethod][]string{
				capabilityResponseTypes: {consts.ResponseTypeImplicitFlowToken},
				capabilityGrantTypes:    {consts.GrantTypeImplicit},
			},
		},
		{
			name:    "ShouldReportCapabilitiesForNoneResponseType",
			handler: &hoauth2.NoneResponseTypeHandler{},
			expected: map[capabilityMethod][]string{
				capabilityResponseTypes: {consts.ResponseTypeNone},
			},
		},
		{
			name:    "ShouldReportCapabilitiesForClientCredentials",
			handler: &hoauth2.ClientCredentialsGrantHandler{},
			expected: map[capabilityMethod][]string{
				capabilityGrantTypes: {consts.GrantTypeClientCredentials},
			},
		},
		{
			name:    "ShouldReportCapabilitiesForRefreshToken",
			handler: &hoauth2.RefreshTokenGrantHandler{},
			expected: map[capabilityMethod][]string{
				capabilityGrantTypes: {consts.GrantTypeRefreshToken},
			},
		},
		{
			name:    "ShouldReportCapabilitiesForTokenExchange",
			handler: &rfc8693.TokenExchangeGrantHandler{},
			expected: map[capabilityMethod][]string{
				capabilityGrantTypes: {consts.GrantTypeOAuthTokenExchange},
			},
		},
		{
			name:    "ShouldReportCapabilitiesForActorTokenValidation",
			handler: &rfc8693.ActorTokenValidationHandler{},
		},
		{
			name:       "ShouldReportCapabilitiesForAccessTokenType",
			handler:    &rfc8693.AccessTokenTypeHandler{},
			configured: []capabilityMethod{capabilityRFC8693TokenTypes},
		},
		{
			name:       "ShouldReportCapabilitiesForRefreshTokenType",
			handler:    &rfc8693.RefreshTokenTypeHandler{},
			configured: []capabilityMethod{capabilityRFC8693TokenTypes},
		},
		{
			name:       "ShouldReportCapabilitiesForIDTokenType",
			handler:    &rfc8693.IDTokenTypeHandler{},
			configured: []capabilityMethod{capabilityRFC8693TokenTypes},
		},
		{
			name:       "ShouldReportCapabilitiesForCustomJWTType",
			handler:    &rfc8693.CustomJWTTypeHandler{},
			configured: []capabilityMethod{capabilityRFC8693TokenTypes},
		},
		{
			name:       "ShouldReportCapabilitiesForTxnTokenType",
			handler:    &rfc8693.TxnTokenTypeHandler{},
			configured: []capabilityMethod{capabilityRFC8693TokenTypes},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()

			check := func(method capabilityMethod, get func(ctx context.Context) []string) {
				if expected, ok := tc.expected[method]; ok {
					assert.Equal(t, expected, get(ctx))

					return
				}

				if slices.Contains(tc.configured, method) {
					return
				}

				assert.Nil(t, get(ctx))
			}

			ah, isAuthorize := tc.handler.(oauth2.AuthorizeEndpointHandler)
			th, isToken := tc.handler.(oauth2.TokenEndpointHandler)

			require.True(t, isAuthorize || isToken)

			if isAuthorize {
				check(capabilityResponseTypes, ah.ResponseTypesSupported)
				check(capabilityGrantTypes, ah.GrantTypesSupported)
				check(capabilityCodeChallengeMethods, ah.CodeChallengeMethodsSupported)
				check(capabilityIDTokenSigningAlgValues, ah.IDTokenSigningAlgValuesSupported)
			}

			if isToken {
				check(capabilityGrantTypes, th.GrantTypesSupported)
				check(capabilityCodeChallengeMethods, th.CodeChallengeMethodsSupported)
				check(capabilityIDTokenSigningAlgValues, th.IDTokenSigningAlgValuesSupported)
				check(capabilityRFC8693TokenTypes, th.RFC8693TokenTypesSupported)
			}
		})
	}
}

type capabilityMethod int

const (
	capabilityResponseTypes capabilityMethod = iota
	capabilityGrantTypes
	capabilityCodeChallengeMethods
	capabilityIDTokenSigningAlgValues
	capabilityRFC8693TokenTypes
)
