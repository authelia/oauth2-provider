// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"time"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/x/errorsx"
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
func (c *ClientCredentialsGrantHandler) HandleTokenEndpointRequest(ctx context.Context, requester oauth2.AccessRequester) (err error) {
	if !c.CanHandleTokenEndpointRequest(ctx, requester) {
		return errorsx.WithStack(oauth2.ErrUnknownRequest)
	}

	client := requester.GetClient()

	// The client MUST authenticate with the authorization server as described in Section 3.2.1.
	// This requirement is already fulfilled because we require all token requests to be authenticated as described
	// in https://tools.ietf.org/html/rfc6749#section-3.2.1
	if client.IsPublic() {
		return errorsx.WithStack(oauth2.ErrInvalidGrant.WithHint("The OAuth 2.0 Client is marked as public and is thus not allowed to use authorization grant 'client_credentials'."))
	}

	if !client.GetGrantTypes().Has(consts.GrantTypeClientCredentials) {
		return errorsx.WithStack(oauth2.ErrUnauthorizedClient.WithHint("The OAuth 2.0 Client is not allowed to use authorization grant 'client_credentials'."))
	}

	scopes := requester.GetRequestedScopes()

	if len(scopes) == 0 && !requester.GetRequestForm().Has(consts.FormParameterScope) {
		if pclient, ok := client.(oauth2.ClientCredentialsFlowRequestedScopeImplicitClient); ok && pclient.GetClientCredentialsFlowRequestedScopeImplicit() {
			requester.SetRequestedScopes(client.GetScopes())
		}
	} else {
		for _, scope := range scopes {
			if !c.Config.GetScopeStrategy(ctx)(client.GetScopes(), scope) {
				return errorsx.WithStack(oauth2.ErrInvalidScope.WithHintf("The OAuth 2.0 Client is not allowed to request scope '%s'.", scope))
			}
		}
	}

	audience := requester.GetRequestedAudience()

	if len(audience) == 0 && !requester.GetRequestForm().Has(consts.FormParameterAudience) {
		if ac, ok := client.(oauth2.RequestedAudienceImplicitClient); ok && ac.GetRequestedAudienceImplicit() {
			requester.SetRequestedAudience(ac.GetAudience())
		}
	} else {
		if err = c.Config.GetAudienceStrategy(ctx)(client.GetAudience(), requester.GetRequestedAudience()); err != nil {
			return err
		}
	}

	lifespan := oauth2.GetEffectiveLifespan(client, oauth2.GrantTypeClientCredentials, oauth2.AccessToken, c.Config.GetAccessTokenLifespan(ctx))

	requester.GetSession().SetExpiresAt(oauth2.AccessToken, time.Now().UTC().Add(lifespan))

	return nil
}

// PopulateTokenEndpointResponse implements https://datatracker.ietf.org/doc/html/rfc6749#section-4.4.3
func (c *ClientCredentialsGrantHandler) PopulateTokenEndpointResponse(ctx context.Context, requester oauth2.AccessRequester, responder oauth2.AccessResponder) (err error) {
	if !c.CanHandleTokenEndpointRequest(ctx, requester) {
		return errorsx.WithStack(oauth2.ErrUnknownRequest)
	}

	if !requester.GetClient().GetGrantTypes().Has(consts.GrantTypeClientCredentials) {
		return errorsx.WithStack(oauth2.ErrUnauthorizedClient.WithHint("The OAuth 2.0 Client is not allowed to use authorization grant 'client_credentials'."))
	}

	if c.Config.GetClientCredentialsFlowImplicitGrantRequested(ctx) {
		if len(requester.GetGrantedScopes()) == 0 {
			for _, scope := range requester.GetRequestedScopes() {
				requester.GrantScope(scope)
			}
		}

		if len(requester.GetGrantedAudience()) == 0 {
			for _, audience := range requester.GetRequestedAudience() {
				requester.GrantAudience(audience)
			}
		}
	}

	lifespan := oauth2.GetEffectiveLifespan(requester.GetClient(), oauth2.GrantTypeClientCredentials, oauth2.AccessToken, c.Config.GetAccessTokenLifespan(ctx))

	_, err = c.IssueAccessToken(ctx, lifespan, requester, responder)

	return err
}

func (c *ClientCredentialsGrantHandler) CanSkipClientAuth(_ context.Context, _ oauth2.AccessRequester) bool {
	return false
}

func (c *ClientCredentialsGrantHandler) CanHandleTokenEndpointRequest(_ context.Context, requester oauth2.AccessRequester) bool {
	return requester.GetGrantTypes().ExactOne(consts.GrantTypeClientCredentials)
}

var (
	_ oauth2.TokenEndpointHandler = (*ClientCredentialsGrantHandler)(nil)
)
