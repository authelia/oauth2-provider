// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package openid

import (
	"context"
	"errors"

	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/x/errorsx"
)

// OpenIDConnectCIBAHandler issues the OpenID Connect ID Token for the Client Initiated Backchannel Authentication
// (CIBA) flow. It is registered as both an OpenIDCIBAEndpointHandler (to persist the OIDC session keyed by the
// auth_req_id signature when the request is granted the openid scope) and a TokenEndpointHandler (to attach the
// id_token to the token response when the client polls with grant_type=urn:openid:params:grant-type:ciba).
//
// See https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#token_response.
type OpenIDConnectCIBAHandler struct {
	OpenIDConnectRequestStorage   OpenIDConnectRequestStorage
	OpenIDConnectRequestValidator *OpenIDConnectRequestValidator
	hoauth2.CodeTokenEndpointHandler

	Config interface {
		oauth2.IDTokenLifespanProvider
	}

	*IDTokenHandleHelper
}

// HandleOpenIDCIBAEndpointRequest persists the OIDC session keyed by the auth_req_id signature for later retrieval at
// the token endpoint. Returns nil without modification when the request does not include the openid scope or when the
// client is not registered for the CIBA grant.
func (c *OpenIDConnectCIBAHandler) HandleOpenIDCIBAEndpointRequest(ctx context.Context, req oauth2.CIBARequester, _ oauth2.CIBAResponder) (err error) {
	if !req.GetGrantedScopes().Has(consts.ScopeOpenID) {
		return nil
	}

	if !req.GetClient().GetGrantTypes().Has(string(oauth2.GrantTypeOpenIDCIBA)) {
		return nil
	}

	if len(req.GetAuthRequestIDSignature()) == 0 {
		return errorsx.WithStack(oauth2.ErrMisconfiguration.WithDebug("The auth_req_id has not been issued yet, indicating a broken handler ordering."))
	}

	if err = c.OpenIDConnectRequestStorage.CreateOpenIDConnectSession(ctx, req.GetAuthRequestIDSignature(), req.Sanitize(oidcParameters)); err != nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}

	return nil
}

// HandleTokenEndpointRequest is a no-op for this handler; the id_token is produced in PopulateTokenEndpointResponse
// once the access token has been issued.
func (c *OpenIDConnectCIBAHandler) HandleTokenEndpointRequest(_ context.Context, _ oauth2.AccessRequester) (err error) {
	return errorsx.WithStack(oauth2.ErrUnknownRequest)
}

// PopulateTokenEndpointResponse retrieves the OIDC session persisted during the backchannel authentication request and
// attaches the id_token to the response. The session is deleted from storage once consumed so the auth_req_id cannot be
// reused to mint another id_token.
func (c *OpenIDConnectCIBAHandler) PopulateTokenEndpointResponse(ctx context.Context, request oauth2.AccessRequester, response oauth2.AccessResponder) (err error) {
	if !c.CanHandleTokenEndpointRequest(ctx, request) {
		return errorsx.WithStack(oauth2.ErrUnknownRequest)
	}

	var (
		signature string
		ar        oauth2.Requester
		session   Session
		ok        bool
	)

	if signature, err = c.DeviceCodeSignature(ctx, request.GetRequestForm().Get(consts.FormParameterAuthReqID)); err != nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}

	if ar, err = c.OpenIDConnectRequestStorage.GetOpenIDConnectSession(ctx, signature, request); errors.Is(err, ErrNoSessionFound) {
		return errorsx.WithStack(oauth2.ErrUnknownRequest.WithWrap(err).WithDebugError(err))
	} else if err != nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}

	if !ar.GetGrantedScopes().Has(consts.ScopeOpenID) {
		return errorsx.WithStack(oauth2.ErrMisconfiguration.WithDebug("An OpenID Connect session was found but the openid scope is missing, probably due to a broken handler configuration."))
	}

	if !request.GetClient().GetGrantTypes().Has(string(oauth2.GrantTypeOpenIDCIBA)) {
		return errorsx.WithStack(oauth2.ErrUnauthorizedClient.WithHintf("The OAuth 2.0 Client is not allowed to use the authorization grant '%s'.", consts.GrantTypeOpenIDCIBA))
	}

	if session, ok = ar.GetSession().(Session); !ok {
		return errorsx.WithStack(oauth2.ErrServerError.WithDebug("Failed to generate ID Token because the session must be of type 'openid.Session'."))
	}

	claims := session.IDTokenClaims()

	if claims.Subject == "" {
		return errorsx.WithStack(oauth2.ErrServerError.WithDebug("Failed to generate ID Token because subject is an empty string."))
	}

	if err = c.OpenIDConnectRequestStorage.DeleteOpenIDConnectSession(ctx, signature); err != nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}

	claims.AccessTokenHash = c.GetAccessTokenHash(ctx, request, response)

	lifespan := oauth2.GetEffectiveLifespan(request.GetClient(), oauth2.GrantTypeOpenIDCIBA, oauth2.IDToken, c.Config.GetIDTokenLifespan(ctx))

	return c.IssueExplicitIDToken(ctx, lifespan, ar, response)
}

// CanSkipClientAuth indicates that client authentication may never be skipped for the CIBA grant.
func (c *OpenIDConnectCIBAHandler) CanSkipClientAuth(_ context.Context, _ oauth2.AccessRequester) (skip bool) {
	return false
}

// CanHandleTokenEndpointRequest reports whether the request uses the OpenID Connect CIBA grant_type.
func (c *OpenIDConnectCIBAHandler) CanHandleTokenEndpointRequest(_ context.Context, request oauth2.AccessRequester) (handle bool) {
	return request.GetGrantTypes().ExactOne(string(oauth2.GrantTypeOpenIDCIBA))
}

var (
	_ oauth2.OpenIDCIBAEndpointHandler = (*OpenIDConnectCIBAHandler)(nil)
	_ oauth2.TokenEndpointHandler      = (*OpenIDConnectCIBAHandler)(nil)
)
