// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"strconv"
	"strings"
	"time"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/token/jwt"
	"authelia.com/provider/oauth2/x/errorsx"
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
		oauth2.ResourceStrategyProvider
	}
}

var (
	_ oauth2.AuthorizeEndpointHandler = (*AuthorizeImplicitGrantTypeHandler)(nil)
)

func (c *AuthorizeImplicitGrantTypeHandler) HandleAuthorizeEndpointRequest(ctx context.Context, request oauth2.AuthorizeRequester, response oauth2.AuthorizeResponder) (err error) {
	// This let's us define multiple response types, for example open id connect's id_token
	if !request.GetResponseTypes().ExactOne(consts.ResponseTypeImplicitFlowToken) {
		return nil
	}

	request.SetDefaultResponseMode(oauth2.ResponseModeFragment)

	// Disabled because this is already handled at the authorize_request_handler
	// if !requester.GetClient().GetResponseTypes().Has("token") {
	// 	 return errorsx.WithStack(oauth2.ErrInvalidGrant.WithDebug("The client is not allowed to use response type token"))
	// }

	if !request.GetClient().GetGrantTypes().Has(consts.GrantTypeImplicit) {
		return errorsx.WithStack(oauth2.ErrInvalidGrant.WithHint("The OAuth 2.0 Client is not allowed to use the authorization grant 'implicit'."))
	}

	client := request.GetClient()
	strategy := oauth2.GetScopeStrategy(ctx, c.Config, client)

	for _, scope := range request.GetRequestedScopes() {
		if !strategy(client.GetScopes(), scope) {
			return errorsx.WithStack(oauth2.ErrInvalidScope.WithHintf("The OAuth 2.0 Client is not allowed to request scope '%s'.", scope))
		}
	}

	if err = oauth2.GetAudienceStrategy(ctx, c.Config, client)(client.GetAudience(), request.GetRequestedAudience()); err != nil {
		return err
	}

	if err = oauth2.GetResourceStrategy(ctx, c.Config, client)(client.GetAudience(), request.GetRequestedResource()); err != nil {
		return err
	}

	// There is no need to check for https, because implicit flow does not require https
	// See; https://datatracker.ietf.org/doc/html/rfc6819#section-4.4.2

	return c.IssueImplicitAccessToken(ctx, request, response)
}

func (c *AuthorizeImplicitGrantTypeHandler) IssueImplicitAccessToken(ctx context.Context, request oauth2.AuthorizeRequester, response oauth2.AuthorizeResponder) (err error) {
	// Only override expiry if none is set.
	atLifespan := oauth2.GetEffectiveLifespan(request.GetClient(), oauth2.GrantTypeImplicit, oauth2.AccessToken, c.Config.GetAccessTokenLifespan(ctx))
	if request.GetSession().GetExpiresAt(oauth2.AccessToken).IsZero() {
		request.GetSession().SetExpiresAt(oauth2.AccessToken, time.Now().UTC().Add(atLifespan).Truncate(jwt.TimePrecision))
	}

	// Generate the code
	token, signature, err := c.AccessTokenStrategy.GenerateAccessToken(ctx, request)
	if err != nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}

	if err = c.AccessTokenStorage.CreateAccessTokenSession(ctx, signature, request.Sanitize([]string{})); err != nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}

	response.AddParameter(consts.AccessResponseAccessToken, token)
	response.AddParameter(consts.AccessResponseExpiresIn, strconv.FormatInt(int64(getExpiresIn(request, oauth2.AccessToken, atLifespan, time.Now().UTC())/time.Second), 10))
	response.AddParameter(consts.AccessResponseTokenType, oauth2.BearerAccessToken)
	response.AddParameter(consts.FormParameterState, request.GetState())
	response.AddParameter(consts.AccessResponseScope, strings.Join(request.GetGrantedScopes(), " "))

	request.SetResponseTypeHandled(consts.ResponseTypeImplicitFlowToken)

	return nil
}
