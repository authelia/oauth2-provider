// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"strconv"
	"strings"
	"time"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/errorsx"
)

// AuthorizeImplicitGrantTypeHandler is a response handler for the Authorize Code grant using the implicit grant type
// as defined in https://datatracker.ietf.org/doc/html/rfc6749#section-4.2
type AuthorizeImplicitGrantTypeHandler struct {
	AccessTokenStrategy AccessTokenStrategy
	// AccessTokenStorage is used to persist session data across requests.
	AccessTokenStorage AccessTokenStorage

	Config interface {
		oauth2.AccessTokenLifespanProvider
		oauth2.ScopeStrategyProvider
		oauth2.AudienceStrategyProvider
	}
}

var (
	_ oauth2.AuthorizeEndpointHandler = (*AuthorizeImplicitGrantTypeHandler)(nil)
)

func (c *AuthorizeImplicitGrantTypeHandler) HandleAuthorizeEndpointRequest(ctx context.Context, requester oauth2.AuthorizeRequester, responder oauth2.AuthorizeResponder) error {
	// This let's us define multiple response types, for example open id connect's id_token
	if !requester.GetResponseTypes().ExactOne(consts.ResponseTypeImplicitFlowToken) {
		return nil
	}

	requester.SetDefaultResponseMode(oauth2.ResponseModeFragment)

	// Disabled because this is already handled at the authorize_request_handler
	// if !requester.GetClient().GetResponseTypes().Has("token") {
	// 	 return errorsx.WithStack(oauth2.ErrInvalidGrant.WithDebug("The client is not allowed to use response type token"))
	// }

	if !requester.GetClient().GetGrantTypes().Has(consts.GrantTypeImplicit) {
		return errorsx.WithStack(oauth2.ErrInvalidGrant.WithHint("The OAuth 2.0 Client is not allowed to use the authorization grant 'implicit'."))
	}

	client := requester.GetClient()
	for _, scope := range requester.GetRequestedScopes() {
		if !c.Config.GetScopeStrategy(ctx)(client.GetScopes(), scope) {
			return errorsx.WithStack(oauth2.ErrInvalidScope.WithHintf("The OAuth 2.0 Client is not allowed to request scope '%s'.", scope))
		}
	}

	if err := c.Config.GetAudienceStrategy(ctx)(client.GetAudience(), requester.GetRequestedAudience()); err != nil {
		return err
	}

	// there is no need to check for https, because implicit flow does not require https
	// https://datatracker.ietf.org/doc/html/rfc6819#section-4.4.2

	return c.IssueImplicitAccessToken(ctx, requester, responder)
}

func (c *AuthorizeImplicitGrantTypeHandler) IssueImplicitAccessToken(ctx context.Context, requester oauth2.AuthorizeRequester, responder oauth2.AuthorizeResponder) error {
	// Only override expiry if none is set.
	atLifespan := oauth2.GetEffectiveLifespan(requester.GetClient(), oauth2.GrantTypeImplicit, oauth2.AccessToken, c.Config.GetAccessTokenLifespan(ctx))
	if requester.GetSession().GetExpiresAt(oauth2.AccessToken).IsZero() {
		requester.GetSession().SetExpiresAt(oauth2.AccessToken, time.Now().UTC().Add(atLifespan).Round(time.Second))
	}

	// Generate the code
	token, signature, err := c.AccessTokenStrategy.GenerateAccessToken(ctx, requester)
	if err != nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	if err = c.AccessTokenStorage.CreateAccessTokenSession(ctx, signature, requester.Sanitize([]string{})); err != nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}
	responder.AddParameter(consts.AccessResponseAccessToken, token)
	responder.AddParameter(consts.AccessResponseExpiresIn, strconv.FormatInt(int64(getExpiresIn(requester, oauth2.AccessToken, atLifespan, time.Now().UTC())/time.Second), 10))
	responder.AddParameter(consts.AccessResponseTokenType, oauth2.BearerAccessToken)
	responder.AddParameter(consts.FormParameterState, requester.GetState())
	responder.AddParameter(consts.AccessResponseScope, strings.Join(requester.GetGrantedScopes(), " "))

	requester.SetResponseTypeHandled(consts.ResponseTypeImplicitFlowToken)

	return nil
}
