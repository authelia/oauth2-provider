// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2/internal/consts"
)

func TestEnforceIssuanceDecisionDeniesWhenNoTokenSurvives(t *testing.T) {
	refreshScopes := Arguments{consts.ScopeOffline, consts.ScopeOfflineAccess}

	testCases := []struct {
		name     string
		tokens   []TokenType
		decision *IssuanceDecision
		denied   bool
	}{
		{name: "ShouldDenyDeniedRefreshOutput", tokens: []TokenType{RefreshToken}, decision: &IssuanceDecision{DeniedTokens: []TokenType{RefreshToken}}, denied: true},
		{name: "ShouldDenyDeniedIDOutput", tokens: []TokenType{IDToken}, decision: &IssuanceDecision{DeniedTokens: []TokenType{IDToken}}, denied: true},
		{name: "ShouldDenyDeniedExchangedOutput", tokens: []TokenType{ExchangedToken}, decision: &IssuanceDecision{DeniedTokens: []TokenType{ExchangedToken}}, denied: true},
		{name: "ShouldDenyRefreshOutputWhenItsScopeIsRemoved", tokens: []TokenType{RefreshToken}, decision: &IssuanceDecision{Scopes: Arguments{"a"}}, denied: true},
		{name: "ShouldDenyIDOutputWhenOpenIDIsRemoved", tokens: []TokenType{IDToken}, decision: &IssuanceDecision{Scopes: Arguments{"a"}}, denied: true},
		{name: "ShouldKeepAccessOutputWhenItsCompanionIsDenied", tokens: []TokenType{AccessToken, RefreshToken}, decision: &IssuanceDecision{DeniedTokens: []TokenType{RefreshToken}}},
		{name: "ShouldKeepRefreshOutputWhenItsScopeSurvives", tokens: []TokenType{RefreshToken}, decision: &IssuanceDecision{Scopes: Arguments{consts.ScopeOfflineAccess}}},
		{name: "ShouldKeepExchangedOutputWhenScopesNarrow", tokens: []TokenType{ExchangedToken}, decision: &IssuanceDecision{Scopes: Arguments{"a"}}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			request := NewAccessRequest(&DefaultSession{})
			request.GrantTypes = Arguments{consts.GrantTypeOAuthTokenExchange}
			request.GrantedScope = Arguments{consts.ScopeOpenID, consts.ScopeOfflineAccess, "a"}

			err := enforceIssuanceDecision(request, tc.tokens, refreshScopes, tc.decision)

			if tc.denied {
				require.ErrorIs(t, err, ErrInvalidTarget)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestEnforceIssuanceDecisionOnlyDeniesTokensOfRemovedScopes(t *testing.T) {
	refreshScopes := Arguments{consts.ScopeOffline, consts.ScopeOfflineAccess}
	decision := &IssuanceDecision{Scopes: Arguments{"a"}}
	request := NewAccessRequest(&DefaultSession{})
	request.GrantedScope = Arguments{"a", "b"}

	require.NoError(t, enforceIssuanceDecision(request, []TokenType{IDToken}, refreshScopes, decision))
	assert.False(t, decision.DeniesToken(IDToken))
	assert.False(t, decision.DeniesToken(RefreshToken))
}

func TestEnforceIssuanceDecisionDoesNotDenyRefreshWithoutRefreshScopes(t *testing.T) {
	decision := &IssuanceDecision{Scopes: Arguments{"a"}}
	request := NewAccessRequest(&DefaultSession{})
	request.GrantedScope = Arguments{"a", "b"}

	require.NoError(t, enforceIssuanceDecision(request, []TokenType{AccessToken, RefreshToken}, nil, decision))
	assert.False(t, decision.DeniesToken(RefreshToken))
}
