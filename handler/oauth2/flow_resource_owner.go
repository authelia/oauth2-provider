// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"time"

	"github.com/pkg/errors"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/x/errorsx"
)

// Deprecated: This handler is deprecated as a means to communicate that the ROPC grant type is widely discouraged and
// is at the time of this writing going to be omitted in the OAuth 2.1 spec. For more information on why this grant type
// is discouraged see: https://www.scottbrady91.com/oauth/why-the-resource-owner-password-credentials-grant-type-is-not-authentication-nor-suitable-for-modern-applications
type ResourceOwnerPasswordCredentialsGrantHandler struct {
	*HandleHelper
	// ResourceOwnerPasswordCredentialsGrantStorage is used to persist session data across requests.
	ResourceOwnerPasswordCredentialsGrantStorage ResourceOwnerPasswordCredentialsGrantStorage
	RefreshTokenStrategy                         RefreshTokenStrategy
	Config                                       interface {
		oauth2.ScopeStrategyProvider
		oauth2.AudienceStrategyProvider
		oauth2.RefreshTokenScopesProvider
		oauth2.RefreshTokenLifespanProvider
		oauth2.AccessTokenLifespanProvider
	}
}

var (
	_ oauth2.TokenEndpointHandler = (*ResourceOwnerPasswordCredentialsGrantHandler)(nil)
)

// HandleTokenEndpointRequest implements https://datatracker.ietf.org/doc/html/rfc6749#section-4.3.2
func (c *ResourceOwnerPasswordCredentialsGrantHandler) HandleTokenEndpointRequest(ctx context.Context, request oauth2.AccessRequester) error {
	if !c.CanHandleTokenEndpointRequest(ctx, request) {
		return errorsx.WithStack(oauth2.ErrUnknownRequest)
	}

	if !request.GetClient().GetGrantTypes().Has(consts.GrantTypeResourceOwnerPasswordCredentials) {
		return errorsx.WithStack(oauth2.ErrUnauthorizedClient.WithHint("The client is not allowed to use authorization grant 'password'."))
	}

	client := request.GetClient()
	for _, scope := range request.GetRequestedScopes() {
		if !c.Config.GetScopeStrategy(ctx)(client.GetScopes(), scope) {
			return errorsx.WithStack(oauth2.ErrInvalidScope.WithHintf("The OAuth 2.0 Client is not allowed to request scope '%s'.", scope))
		}
	}

	if err := c.Config.GetAudienceStrategy(ctx)(client.GetAudience(), request.GetRequestedAudience()); err != nil {
		return err
	}

	username := request.GetRequestForm().Get(consts.FormParameterUsername)
	password := request.GetRequestForm().Get(consts.FormParameterPassword)
	if username == "" || password == "" {
		return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHint("Username or password are missing from the POST body."))
	} else if err := c.ResourceOwnerPasswordCredentialsGrantStorage.Authenticate(ctx, username, password); errors.Is(err, oauth2.ErrNotFound) {
		return errorsx.WithStack(oauth2.ErrInvalidGrant.WithHint("Unable to authenticate the provided username and password credentials.").WithWrap(err).WithDebugError(err))
	} else if err != nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}

	// Credentials must not be passed around, potentially leaking to the database!
	delete(request.GetRequestForm(), consts.FormParameterPassword)

	atLifespan := oauth2.GetEffectiveLifespan(request.GetClient(), oauth2.GrantTypePassword, oauth2.AccessToken, c.Config.GetAccessTokenLifespan(ctx))
	request.GetSession().SetExpiresAt(oauth2.AccessToken, time.Now().UTC().Add(atLifespan).Round(time.Second))

	rtLifespan := oauth2.GetEffectiveLifespan(request.GetClient(), oauth2.GrantTypePassword, oauth2.RefreshToken, c.Config.GetRefreshTokenLifespan(ctx))
	if rtLifespan > -1 {
		request.GetSession().SetExpiresAt(oauth2.RefreshToken, time.Now().UTC().Add(rtLifespan).Round(time.Second))
	}

	return nil
}

// PopulateTokenEndpointResponse implements https://datatracker.ietf.org/doc/html/rfc6749#section-4.3.3
func (c *ResourceOwnerPasswordCredentialsGrantHandler) PopulateTokenEndpointResponse(ctx context.Context, requester oauth2.AccessRequester, responder oauth2.AccessResponder) error {
	if !c.CanHandleTokenEndpointRequest(ctx, requester) {
		return errorsx.WithStack(oauth2.ErrUnknownRequest)
	}

	var refresh, refreshSignature string
	if len(c.Config.GetRefreshTokenScopes(ctx)) == 0 || requester.GetGrantedScopes().HasOneOf(c.Config.GetRefreshTokenScopes(ctx)...) {
		var err error
		refresh, refreshSignature, err = c.RefreshTokenStrategy.GenerateRefreshToken(ctx, requester)
		if err != nil {
			return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
		} else if err = c.ResourceOwnerPasswordCredentialsGrantStorage.CreateRefreshTokenSession(ctx, refreshSignature, requester.Sanitize([]string{})); err != nil {
			return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
		}
	}

	atLifespan := oauth2.GetEffectiveLifespan(requester.GetClient(), oauth2.GrantTypePassword, oauth2.AccessToken, c.Config.GetAccessTokenLifespan(ctx))
	if err := c.IssueAccessToken(ctx, atLifespan, requester, responder); err != nil {
		return err
	}

	if refresh != "" {
		responder.SetExtra(consts.AccessResponseRefreshToken, refresh)
	}

	return nil
}

func (c *ResourceOwnerPasswordCredentialsGrantHandler) CanSkipClientAuth(ctx context.Context, _ oauth2.AccessRequester) bool {
	return false
}

func (c *ResourceOwnerPasswordCredentialsGrantHandler) CanHandleTokenEndpointRequest(ctx context.Context, requester oauth2.AccessRequester) bool {
	// grant_type REQUIRED.
	// Value MUST be set to "password".
	return requester.GetGrantTypes().ExactOne(consts.GrantTypeResourceOwnerPasswordCredentials)
}
