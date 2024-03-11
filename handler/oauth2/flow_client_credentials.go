// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"time"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/errorsx"
)

type ClientCredentialsGrantHandler struct {
	*HandleHelper
	Config interface {
		oauth2.ScopeStrategyProvider
		oauth2.AudienceStrategyProvider
		oauth2.AccessTokenLifespanProvider
		oauth2.ClientCredentialsImplicitProvider
	}
}

// HandleTokenEndpointRequest implements https://datatracker.ietf.org/doc/html/rfc6749#section-4.4.2
func (c *ClientCredentialsGrantHandler) HandleTokenEndpointRequest(ctx context.Context, request oauth2.AccessRequester) error {
	if !c.CanHandleTokenEndpointRequest(ctx, request) {
		return errorsx.WithStack(oauth2.ErrUnknownRequest)
	}

	client := request.GetClient()

	// The client MUST authenticate with the authorization server as described in Section 3.2.1.
	// This requirement is already fulfilled because fosite requires all token requests to be authenticated as described
	// in https://tools.ietf.org/html/rfc6749#section-3.2.1
	if client.IsPublic() {
		return errorsx.WithStack(oauth2.ErrInvalidGrant.WithHint("The OAuth 2.0 Client is marked as public and is thus not allowed to use authorization grant 'client_credentials'."))
	}

	if !client.GetGrantTypes().Has(consts.GrantTypeClientCredentials) {
		return errorsx.WithStack(oauth2.ErrUnauthorizedClient.WithHint("The OAuth 2.0 Client is not allowed to use authorization grant 'client_credentials'."))
	}

	scopes := request.GetRequestedScopes()

	if len(scopes) == 0 {
		if pclient, ok := client.(oauth2.ClientCredentialsFlowRequestedScopeImplicitClient); ok && pclient.GetClientCredentialsFlowRequestedScopeImplicit() {
			scopes = client.GetScopes()
		}
	}

	for _, scope := range scopes {
		if !c.Config.GetScopeStrategy(ctx)(client.GetScopes(), scope) {
			return errorsx.WithStack(oauth2.ErrInvalidScope.WithHintf("The OAuth 2.0 Client is not allowed to request scope '%s'.", scope))
		}
	}

	if audience := request.GetRequestedAudience(); len(audience) == 0 {
		if ac, ok := client.(oauth2.RequestedAudienceImplicitClient); ok && ac.GetRequestedAudienceImplicit() {
			request.SetRequestedAudience(ac.GetAudience())
		}
	}

	if err := c.Config.GetAudienceStrategy(ctx)(client.GetAudience(), request.GetRequestedAudience()); err != nil {
		return err
	}

	lifespan := oauth2.GetEffectiveLifespan(client, oauth2.GrantTypeClientCredentials, oauth2.AccessToken, c.Config.GetAccessTokenLifespan(ctx))

	request.GetSession().SetExpiresAt(oauth2.AccessToken, time.Now().UTC().Add(lifespan))

	return nil
}

// PopulateTokenEndpointResponse implements https://datatracker.ietf.org/doc/html/rfc6749#section-4.4.3
func (c *ClientCredentialsGrantHandler) PopulateTokenEndpointResponse(ctx context.Context, request oauth2.AccessRequester, response oauth2.AccessResponder) error {
	if !c.CanHandleTokenEndpointRequest(ctx, request) {
		return errorsx.WithStack(oauth2.ErrUnknownRequest)
	}

	if !request.GetClient().GetGrantTypes().Has(consts.GrantTypeClientCredentials) {
		return errorsx.WithStack(oauth2.ErrUnauthorizedClient.WithHint("The OAuth 2.0 Client is not allowed to use authorization grant 'client_credentials'."))
	}

	if c.Config.GetClientCredentialsFlowImplicitGrantRequested(ctx) {
		if len(request.GetGrantedScopes()) == 0 {
			for _, scope := range request.GetRequestedScopes() {
				request.GrantScope(scope)
			}
		}

		if len(request.GetGrantedAudience()) == 0 {
			for _, audience := range request.GetRequestedAudience() {
				request.GrantAudience(audience)
			}
		}
	}

	lifespan := oauth2.GetEffectiveLifespan(request.GetClient(), oauth2.GrantTypeClientCredentials, oauth2.AccessToken, c.Config.GetAccessTokenLifespan(ctx))

	return c.IssueAccessToken(ctx, lifespan, request, response)
}

func (c *ClientCredentialsGrantHandler) CanSkipClientAuth(ctx context.Context, requester oauth2.AccessRequester) bool {
	return false
}

func (c *ClientCredentialsGrantHandler) CanHandleTokenEndpointRequest(ctx context.Context, requester oauth2.AccessRequester) bool {
	return requester.GetGrantTypes().ExactOne(consts.GrantTypeClientCredentials)
}

var (
	_ oauth2.TokenEndpointHandler = (*ClientCredentialsGrantHandler)(nil)
)
