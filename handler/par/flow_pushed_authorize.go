// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package par

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/url"
	"time"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/errorsx"
	"authelia.com/provider/oauth2/token/hmac"
)

const (
	defaultPARKeyLength = 32
)

// PushedAuthorizeHandler handles the PAR request
type PushedAuthorizeHandler struct {
	Storage any
	Config  oauth2.Configurator
}

// HandlePushedAuthorizeEndpointRequest handles a pushed authorize endpoint request. To extend the handler's capabilities, the http request
// is passed along, if further information retrieval is required. If the handler feels that he is not responsible for
// the pushed authorize request, he must return nil and NOT modify session nor responder neither requester.
func (c *PushedAuthorizeHandler) HandlePushedAuthorizeEndpointRequest(ctx context.Context, ar oauth2.AuthorizeRequester, resp oauth2.PushedAuthorizeResponder) error {
	configProvider, ok := c.Config.(oauth2.PushedAuthorizeRequestConfigProvider)
	if !ok {
		return errorsx.WithStack(oauth2.ErrServerError.WithHint(oauth2.ErrorPARNotSupported).WithDebug(oauth2.DebugPARConfigMissing))
	}

	storage, ok := c.Storage.(oauth2.PARStorage)
	if !ok {
		return errorsx.WithStack(oauth2.ErrServerError.WithHint(oauth2.ErrorPARNotSupported).WithDebug(oauth2.DebugPARStorageInvalid))
	}

	if !ar.GetResponseTypes().HasOneOf(consts.ResponseTypeImplicitFlowToken, consts.ResponseTypeAuthorizationCodeFlow, consts.ResponseTypeImplicitFlowIDToken) {
		return nil
	}

	if !c.secureChecker(ctx, ar.GetRedirectURI()) {
		return errorsx.WithStack(oauth2.ErrInvalidRequest.WithHint("Redirect URL is using an insecure protocol, http is only allowed for hosts with suffix 'localhost', for example: http://myapp.localhost/."))
	}

	client := ar.GetClient()
	for _, scope := range ar.GetRequestedScopes() {
		if !c.Config.GetScopeStrategy(ctx)(client.GetScopes(), scope) {
			return errorsx.WithStack(oauth2.ErrInvalidScope.WithHintf("The OAuth 2.0 Client is not allowed to request scope '%s'.", scope))
		}
	}

	if err := c.Config.GetAudienceStrategy(ctx)(client.GetAudience(), ar.GetRequestedAudience()); err != nil {
		return err
	}

	expiresIn := configProvider.GetPushedAuthorizeContextLifespan(ctx)
	if ar.GetSession() != nil {
		ar.GetSession().SetExpiresAt(oauth2.PushedAuthorizeRequestContext, time.Now().UTC().Add(expiresIn))
	}

	// generate an ID
	stateKey, err := hmac.RandomBytes(defaultPARKeyLength)
	if err != nil {
		return errorsx.WithStack(oauth2.ErrInsufficientEntropy.WithHint("Unable to generate the random part of the request_uri.").WithWrap(err).WithDebug(err.Error()))
	}

	requestURI := fmt.Sprintf("%s%s", configProvider.GetPushedAuthorizeRequestURIPrefix(ctx), base64.RawURLEncoding.EncodeToString(stateKey))

	// store
	if err = storage.CreatePARSession(ctx, requestURI, ar); err != nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithHint("Unable to store the PAR session").WithWrap(err).WithDebug(err.Error()))
	}

	resp.SetRequestURI(requestURI)
	resp.SetExpiresIn(int(expiresIn.Seconds()))
	return nil
}

func (c *PushedAuthorizeHandler) secureChecker(ctx context.Context, u *url.URL) bool {
	isRedirectURISecure := c.Config.GetRedirectSecureChecker(ctx)
	if isRedirectURISecure == nil {
		isRedirectURISecure = oauth2.IsRedirectURISecure
	}
	return isRedirectURISecure(ctx, u)
}
