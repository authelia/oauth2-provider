// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package rfc8693_test

import (
	"time"

	"authelia.com/provider/oauth2"
	. "authelia.com/provider/oauth2/handler/rfc8693"
)

func permittingOwner(client oauth2.Client) oauth2.Client {
	if _, ok := client.(Client); ok || client == nil {
		return client
	}

	return &permittingOwnerClient{Client: client}
}

type permittingOwnerClient struct {
	oauth2.Client
}

func (c *permittingOwnerClient) GetEffectiveLifespan(gt oauth2.GrantType, tt oauth2.TokenType, fallback time.Duration) time.Duration {
	return oauth2.GetEffectiveLifespan(c.Client, gt, tt, fallback)
}

func (c *permittingOwnerClient) GetSupportedSubjectTokenTypes() []string { return nil }

func (c *permittingOwnerClient) GetSupportedActorTokenTypes() []string { return nil }

func (c *permittingOwnerClient) GetSupportedRequestTokenTypes() []string { return nil }

func (c *permittingOwnerClient) GetSupportedSubjectTokenIssuers() []string { return nil }

func (c *permittingOwnerClient) GetSupportedActorTokenIssuers() []string { return nil }

func (c *permittingOwnerClient) GetTokenExchangePermitted(_ oauth2.Client, _ oauth2.RFC8693TokenType) bool {
	return true
}

func (c *permittingOwnerClient) GetAllowActorTokenWithoutMayAct() bool { return false }

func (c *permittingOwnerClient) GetAllowOwnAccessTokenExchange() bool { return false }

func (c *permittingOwnerClient) GetAllowTokenExchangeRefreshToken() bool { return true }

type basicClient struct {
	oauth2.Client
}

func (c *basicClient) GetSupportedSubjectTokenTypes() []string { return nil }

func (c *basicClient) GetSupportedActorTokenTypes() []string { return nil }

func (c *basicClient) GetSupportedRequestTokenTypes() []string { return nil }

func (c *basicClient) GetSupportedSubjectTokenIssuers() []string { return nil }

func (c *basicClient) GetSupportedActorTokenIssuers() []string { return nil }

func (c *basicClient) GetTokenExchangePermitted(_ oauth2.Client, _ oauth2.RFC8693TokenType) bool {
	return false
}

func (c *basicClient) GetAllowActorTokenWithoutMayAct() bool { return false }

var _ Client = (*basicClient)(nil)
