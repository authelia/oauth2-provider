// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package idjag

import (
	"context"

	"authelia.com/provider/oauth2"
)

// IssueConfig is the configuration interface for ID-JAG token issuance.
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-4.3
type IssueConfig interface {
	oauth2.RFC8693ConfigProvider
	oauth2.AuthorizationServerIssuerIdentificationProvider
	oauth2.IDJAGConfigProvider
	GetDPoPEnabled(ctx context.Context) (enabled bool)
}

// RedeemConfig is the configuration interface for ID-JAG token redemption.
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-4.4
type RedeemConfig interface {
	oauth2.AccessTokenLifespanProvider
	oauth2.AuthorizationServerIssuerIdentificationProvider
	oauth2.JWTClockSkewProvider
	oauth2.GetJWTMaxDurationProvider
	oauth2.JWKSFetcherStrategyProvider
	oauth2.ScopeStrategyProvider
	oauth2.ResourceStrategyProvider
	oauth2.IDJAGConfigProvider
	GetDPoPEnabled(ctx context.Context) (enabled bool)
	GetDPoPEnforce(ctx context.Context) (enforce bool)
}

var (
	_ IssueConfig  = (*oauth2.Config)(nil)
	_ RedeemConfig = (*oauth2.Config)(nil)
)
