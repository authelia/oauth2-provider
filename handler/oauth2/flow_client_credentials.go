// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"time"

	"github.com/ory/x/errorsx"

	"github.com/authelia/goauth2"
)

var _ goauth2.TokenEndpointHandler = (*ClientCredentialsGrantHandler)(nil)

type ClientCredentialsGrantHandler struct {
	*HandleHelper
	Config interface {
		goauth2.ScopeStrategyProvider
		goauth2.AudienceStrategyProvider
		goauth2.AccessTokenLifespanProvider
	}
}

// IntrospectTokenEndpointRequest implements https://tools.ietf.org/html/rfc6749#section-4.4.2
func (c *ClientCredentialsGrantHandler) HandleTokenEndpointRequest(ctx context.Context, request goauth2.AccessRequester) error {
	if !c.CanHandleTokenEndpointRequest(ctx, request) {
		return errorsx.WithStack(goauth2.ErrUnknownRequest)
	}

	client := request.GetClient()
	for _, scope := range request.GetRequestedScopes() {
		if !c.Config.GetScopeStrategy(ctx)(client.GetScopes(), scope) {
			return errorsx.WithStack(goauth2.ErrInvalidScope.WithHintf("The OAuth 2.0 Client is not allowed to request scope '%s'.", scope))
		}
	}

	if err := c.Config.GetAudienceStrategy(ctx)(client.GetAudience(), request.GetRequestedAudience()); err != nil {
		return err
	}

	// The client MUST authenticate with the authorization server as described in Section 3.2.1.
	// This requirement is already fulfilled because goauth2 requires all token requests to be authenticated as described
	// in https://tools.ietf.org/html/rfc6749#section-3.2.1
	if client.IsPublic() {
		return errorsx.WithStack(goauth2.ErrInvalidGrant.WithHint("The OAuth 2.0 Client is marked as public and is thus not allowed to use authorization grant 'client_credentials'."))
	}
	// if the client is not public, he has already been authenticated by the access request handler.

	atLifespan := goauth2.GetEffectiveLifespan(client, goauth2.GrantTypeClientCredentials, goauth2.AccessToken, c.Config.GetAccessTokenLifespan(ctx))
	request.GetSession().SetExpiresAt(goauth2.AccessToken, time.Now().UTC().Add(atLifespan))
	return nil
}

// PopulateTokenEndpointResponse implements https://tools.ietf.org/html/rfc6749#section-4.4.3
func (c *ClientCredentialsGrantHandler) PopulateTokenEndpointResponse(ctx context.Context, request goauth2.AccessRequester, response goauth2.AccessResponder) error {
	if !c.CanHandleTokenEndpointRequest(ctx, request) {
		return errorsx.WithStack(goauth2.ErrUnknownRequest)
	}

	if !request.GetClient().GetGrantTypes().Has("client_credentials") {
		return errorsx.WithStack(goauth2.ErrUnauthorizedClient.WithHint("The OAuth 2.0 Client is not allowed to use authorization grant 'client_credentials'."))
	}

	atLifespan := goauth2.GetEffectiveLifespan(request.GetClient(), goauth2.GrantTypeClientCredentials, goauth2.AccessToken, c.Config.GetAccessTokenLifespan(ctx))
	return c.IssueAccessToken(ctx, atLifespan, request, response)
}

func (c *ClientCredentialsGrantHandler) CanSkipClientAuth(ctx context.Context, requester goauth2.AccessRequester) bool {
	return false
}

func (c *ClientCredentialsGrantHandler) CanHandleTokenEndpointRequest(ctx context.Context, requester goauth2.AccessRequester) bool {
	// grant_type REQUIRED.
	// Value MUST be set to "client_credentials".
	return requester.GetGrantTypes().ExactOne("client_credentials")
}
