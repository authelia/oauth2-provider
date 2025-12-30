package oauth2

import (
	"context"
	"net/url"
	"strings"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/x/errorsx"
)

// NoneResponseTypeHandler is a response handler for when the None response type is requested
// as defined in https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#none
type NoneResponseTypeHandler struct {
	Config interface {
		oauth2.ScopeStrategyProvider
		oauth2.AudienceStrategyProvider
		oauth2.RedirectSecureCheckerProvider
		oauth2.OmitRedirectScopeParamProvider
	}
}

var (
	_ oauth2.AuthorizeEndpointHandler = (*NoneResponseTypeHandler)(nil)
)

func (c *NoneResponseTypeHandler) HandleAuthorizeEndpointRequest(ctx context.Context, requester oauth2.AuthorizeRequester, responder oauth2.AuthorizeResponder) error {
	if !requester.GetResponseTypes().ExactOne(consts.ResponseTypeNone) {
		return nil
	}

	requester.SetDefaultResponseMode(oauth2.ResponseModeQuery)

	if !c.isRedirectURISecure(ctx, requester.GetRedirectURI()) {
		return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHint("Redirect URL is using an insecure protocol, http is only allowed for hosts with suffix 'localhost', for example: http://myapp.localhost/."))
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

	responder.AddParameter(consts.FormParameterState, requester.GetState())

	if !c.Config.GetOmitRedirectScopeParam(ctx) {
		responder.AddParameter(consts.FormParameterScope, strings.Join(requester.GetGrantedScopes(), " "))
	}

	requester.SetResponseTypeHandled(consts.ResponseTypeNone)

	return nil
}

func (c *NoneResponseTypeHandler) isRedirectURISecure(ctx context.Context, redirectURI *url.URL) (secure bool) {
	checker := c.Config.GetRedirectSecureChecker(ctx)

	if checker == nil {
		checker = oauth2.IsRedirectURISecure
	}

	return checker(ctx, redirectURI)
}
