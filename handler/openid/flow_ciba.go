// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package openid

import (
	"context"
	"errors"
	"time"

	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/token/jwt"
	"authelia.com/provider/oauth2/x/errorsx"
)

// OpenIDConnectCIBAHandler issues the ID Token of an OpenID Connect CIBA authentication request. It writes the OpenID
// Connect 1.0 session when the end user approves the request, and issues the ID Token when the 'auth_req_id' is
// redeemed at the token endpoint. As a oauth2.BackChannelAuthenticationEndpointHandler it must be registered before
// ciba.EndpointHandler, so a reused 'nonce' is rejected before the request is persisted. As a
// oauth2.BackChannelAuthenticationDecisionHandler it must be registered after ciba.DecisionHandler, so only the
// decision which was recorded writes a session. As a oauth2.TokenEndpointHandler it must be registered after
// ciba.TokenEndpointHandler, so the granted scopes are set on the token request.
//
// See: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.10.1.1
type OpenIDConnectCIBAHandler struct {
	OpenIDConnectRequestStorage   OpenIDConnectRequestStorage
	OpenIDConnectRequestValidator *OpenIDConnectRequestValidator
	hoauth2.CodeTokenEndpointHandler

	Config interface {
		oauth2.IDTokenLifespanProvider
		oauth2.CIBAConfigProvider
	}

	*IDTokenHandleHelper
}

// HandleBackChannelAuthenticationEndpointRequest records the 'nonce' of a request for the 'openid' scope as used by the
// client until the 'auth_req_id' expires, and rejects a 'nonce' the client already used with oauth2.ErrInvalidRequest.
//
// See: https://www.rfc-editor.org/rfc/rfc9700#section-2.1.1
func (c *OpenIDConnectCIBAHandler) HandleBackChannelAuthenticationEndpointRequest(ctx context.Context, request oauth2.BackChannelAuthenticationRequester, _ oauth2.BackChannelAuthenticationResponder) (err error) {
	if !request.GetRequestedScopes().Has(consts.ScopeOpenID) {
		return nil
	}

	expiresAt := time.Now().UTC().Add(oauth2.GetCIBAAuthRequestLifespan(ctx, c.Config, request)).Truncate(jwt.TimePrecision)

	return setNonceUsed(ctx, c.OpenIDConnectRequestStorage, request, expiresAt)
}

// HandleBackChannelAuthenticationDecision persists the OpenID Connect 1.0 session under the 'auth_req_id' signature
// when the request is approved, the 'openid' scope was granted, and the request is in the push token delivery mode or
// the client is registered for the 'urn:openid:params:grant-type:ciba' grant type, and otherwise does nothing.
func (c *OpenIDConnectCIBAHandler) HandleBackChannelAuthenticationDecision(ctx context.Context, request oauth2.BackChannelAuthenticationRequester, _ *oauth2.BackChannelAuthenticationDecisionResult) (err error) {
	if request.GetStatus() != oauth2.CIBAStatusApproved {
		return nil
	}

	if !request.GetGrantedScopes().Has(consts.ScopeOpenID) {
		return nil
	}

	// A push client is not registered for the grant type, as its tokens are issued when the request is approved.
	//
	// See: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.4
	if request.GetDeliveryMode() != consts.CIBAModePush && !request.GetClient().GetGrantTypes().Has(consts.GrantTypeOpenIDCIBA) {
		return nil
	}

	signature := request.GetAuthRequestIDSignature()

	if len(signature) == 0 {
		return errorsx.WithStack(oauth2.ErrMisconfiguration.WithDebug("The 'auth_req_id' has not been issued yet, indicating a broken code configuration."))
	}

	if err = c.OpenIDConnectRequestStorage.CreateOpenIDConnectSession(ctx, signature, request.Sanitize(oidcParameters)); err != nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}

	return nil
}

// HandleTokenEndpointRequest always returns oauth2.ErrUnknownRequest as this handler only acts when the token response
// is populated.
func (c *OpenIDConnectCIBAHandler) HandleTokenEndpointRequest(_ context.Context, _ oauth2.AccessRequester) (err error) {
	return errorsx.WithStack(oauth2.ErrUnknownRequest)
}

// PopulateTokenEndpointResponse issues an ID Token for the 'urn:openid:params:grant-type:ciba' grant. It loads the
// OpenID Connect 1.0 session stored under the 'auth_req_id' signature, deletes it, and adds the 'id_token' with an
// 'at_hash' claim to the response. It returns oauth2.ErrServerError when the 'openid' scope was requested but not
// granted. When no such session exists it returns oauth2.ErrServerError if the 'openid' scope was granted, and
// otherwise oauth2.ErrUnknownRequest.
//
// Tokens issued internally for an approved push request always carry an ID Token, which also has the
// 'urn:openid:params:jwt:claim:auth_req_id' claim and, when a refresh token is issued, the
// 'urn:openid:params:jwt:claim:rt_hash' claim. Without the 'openid' scope it returns oauth2.ErrTransactionFailed.
//
// See: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.10.1.1
// See: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.10.3.1
func (c *OpenIDConnectCIBAHandler) PopulateTokenEndpointResponse(ctx context.Context, request oauth2.AccessRequester, response oauth2.AccessResponder) (err error) {
	if !c.CanHandleTokenEndpointRequest(ctx, request) {
		return errorsx.WithStack(oauth2.ErrUnknownRequest)
	}

	push := oauth2.IsInternalIssuance(ctx)

	// The ID Token is the detached signature of the push token notification.
	//
	// See: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.10.3.1
	if push && !request.GetGrantedScopes().Has(consts.ScopeOpenID) {
		return errorsx.WithStack(oauth2.ErrTransactionFailed.WithDebug("The 'push' token delivery mode requires the 'openid' scope to be granted."))
	}

	// The Client receives an ID Token in every token delivery mode, so tokens are never issued without one when the
	// 'openid' scope was requested.
	//
	// See: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.3
	if request.GetRequestedScopes().Has(consts.ScopeOpenID) && !request.GetGrantedScopes().Has(consts.ScopeOpenID) {
		return errorsx.WithStack(oauth2.ErrServerError.WithDebug("The 'openid' scope was requested but not granted, so no ID Token can be issued."))
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
		if request.GetGrantedScopes().Has(consts.ScopeOpenID) {
			return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebug("OpenID Connect session missing for an approved CIBA request that granted openid"))
		}

		return errorsx.WithStack(oauth2.ErrUnknownRequest.WithWrap(err).WithDebugError(err))
	} else if err != nil {
		return errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
	}

	if !ar.GetGrantedScopes().Has(consts.ScopeOpenID) {
		return errorsx.WithStack(oauth2.ErrMisconfiguration.WithDebug("An OpenID Connect session was found but the openid scope is missing, probably due to a broken code configuration."))
	}

	if !push && !request.GetClient().GetGrantTypes().Has(consts.GrantTypeOpenIDCIBA) {
		return errorsx.WithStack(oauth2.ErrUnauthorizedClient.WithHint("The OAuth 2.0 Client is not allowed to use the authorization grant 'urn:openid:params:grant-type:ciba'."))
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

	var cleanup func()

	if cleanup, err = c.setPushClaims(ctx, push, request, response, claims); err != nil {
		return err
	}

	defer cleanup()

	lifespan := oauth2.GetEffectiveLifespan(request.GetClient(), oauth2.GrantTypeCIBA, oauth2.IDToken, c.Config.GetIDTokenLifespan(ctx))

	// The 'id_token_hint' was validated when the request was made, so it is not decoded again at issuance.
	//
	// See: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.1
	return c.IssueExplicitIDToken(ctx, lifespan, ar.Sanitize(cibaIDTokenParameters), response)
}

// setPushClaims adds the 'urn:openid:params:jwt:claim:auth_req_id' claim and, when a refresh token is issued, the
// 'urn:openid:params:jwt:claim:rt_hash' claim when push is true, as they are only required in the push token delivery
// mode. The returned function removes them once the ID Token is issued, so a session shared with the refresh token
// never carries them into a later ID Token.
//
// See: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.10.3.1
func (c *OpenIDConnectCIBAHandler) setPushClaims(ctx context.Context, push bool, request oauth2.AccessRequester, response oauth2.AccessResponder, claims *jwt.IDTokenClaims) (cleanup func(), err error) {
	if !push {
		return func() {}, nil
	}

	if claims.Extra == nil {
		claims.Extra = map[string]any{}
	}

	claims.Extra[consts.ClaimCIBAAuthReqID] = request.GetRequestForm().Get(consts.FormParameterAuthReqID)

	cleanup = func() {
		delete(claims.Extra, consts.ClaimCIBAAuthReqID)
		delete(claims.Extra, consts.ClaimRefreshTokenHash)
	}

	if refresh, _ := response.GetExtra(consts.AccessResponseRefreshToken).(string); refresh != "" {
		var hash string

		if hash, err = c.ComputeHash(ctx, request.GetClient(), refresh); err != nil {
			cleanup()

			return nil, errorsx.WithStack(oauth2.ErrServerError.WithWrap(err).WithDebugError(err))
		}

		claims.Extra[consts.ClaimRefreshTokenHash] = hash
	}

	return cleanup, nil
}

// CanSkipClientAuth always returns false, client authentication is never skipped by this handler.
func (c *OpenIDConnectCIBAHandler) CanSkipClientAuth(_ context.Context, _ oauth2.AccessRequester) (skip bool) {
	return false
}

// CanHandleTokenEndpointRequest reports whether the 'grant_type' is exactly 'urn:openid:params:grant-type:ciba'.
func (c *OpenIDConnectCIBAHandler) CanHandleTokenEndpointRequest(_ context.Context, request oauth2.AccessRequester) (handle bool) {
	return request.GetGrantTypes().ExactOne(consts.GrantTypeOpenIDCIBA)
}

// GrantTypesSupported returns nil because the handler only augments another grant.
//
// See: https://datatracker.ietf.org/doc/html/rfc8414#section-2
func (c *OpenIDConnectCIBAHandler) GrantTypesSupported(_ context.Context) (types []string) {
	return nil
}

// CodeChallengeMethodsSupported returns nil because the handler does not enforce PKCE.
//
// See: https://datatracker.ietf.org/doc/html/rfc7636#section-4.3
func (c *OpenIDConnectCIBAHandler) CodeChallengeMethodsSupported(_ context.Context) (methods []string) {
	return nil
}

// RFC8693TokenTypesSupported returns nil because the handler does not issue RFC 8693 tokens.
//
// See: https://datatracker.ietf.org/doc/html/rfc8693#section-3
func (c *OpenIDConnectCIBAHandler) RFC8693TokenTypesSupported(_ context.Context) (types []string) {
	return nil
}

var cibaIDTokenParameters = []string{
	consts.FormParameterGrantType,
	consts.FormParameterMaximumAge,
	consts.FormParameterPrompt,
	consts.FormParameterAuthenticationContextClassReferenceValues,
	consts.FormParameterNonce,
}

var (
	_ oauth2.BackChannelAuthenticationEndpointHandler = (*OpenIDConnectCIBAHandler)(nil)
	_ oauth2.BackChannelAuthenticationDecisionHandler = (*OpenIDConnectCIBAHandler)(nil)
	_ oauth2.TokenEndpointHandler                     = (*OpenIDConnectCIBAHandler)(nil)
)
