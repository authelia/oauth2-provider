// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/go-jose/go-jose/v3"
	"github.com/pkg/errors"

	"authelia.com/provider/oauth2/i18n"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/errorsx"
	"authelia.com/provider/oauth2/internal/stringslice"
	"authelia.com/provider/oauth2/token/jwt"
)

func wrapSigningKeyFailure(outer *RFC6749Error, inner error) *RFC6749Error {
	outer = outer.WithWrap(inner).WithDebugError(inner)
	if e := new(RFC6749Error); errors.As(inner, &e) {
		return outer.WithHintf("%s %s", outer.Reason(), e.Reason())
	}
	return outer
}

// TODO: Refactor time permitting.
//
//nolint:gocyclo
func (f *Fosite) authorizeRequestParametersFromOpenIDConnectRequest(ctx context.Context, request *AuthorizeRequest, isPARRequest bool) error {
	var scope Arguments = RemoveEmpty(strings.Split(request.Form.Get(consts.FormParameterScope), " "))

	// Even if a scope parameter is present in the Request Object value, a scope parameter MUST always be passed using
	// the OAuth 2.0 request syntax containing the openid scope value to indicate to the underlying OAuth 2.0 logic that this is an OpenID Connect request.
	// Source: http://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth
	if !scope.Has(consts.ScopeOpenID) {
		return nil
	}

	if len(request.Form.Get(consts.FormParameterRequest)+request.Form.Get(consts.FormParameterRequestURI)) == 0 {
		return nil
	} else if len(request.Form.Get(consts.FormParameterRequest)) > 0 && len(request.Form.Get(consts.FormParameterRequestURI)) > 0 {
		return errorsx.WithStack(ErrInvalidRequest.WithHint("OpenID Connect parameters 'request' and 'request_uri' were both given, but you can use at most one."))
	}

	oidcClient, ok := request.Client.(OpenIDConnectClient)
	if !ok {
		if len(request.Form.Get(consts.FormParameterRequestURI)) > 0 {
			return errorsx.WithStack(ErrRequestURINotSupported.WithHint("OpenID Connect 'request_uri' context was given, but the OAuth 2.0 Client does not implement advanced OpenID Connect capabilities."))
		}
		return errorsx.WithStack(ErrRequestNotSupported.WithHint("OpenID Connect 'request' context was given, but the OAuth 2.0 Client does not implement advanced OpenID Connect capabilities."))
	}

	if oidcClient.GetJSONWebKeys() == nil && len(oidcClient.GetJSONWebKeysURI()) == 0 {
		return errorsx.WithStack(ErrInvalidRequest.WithHint("OpenID Connect 'request' or 'request_uri' context was given, but the OAuth 2.0 Client does not have any JSON Web Keys registered."))
	}

	assertion := request.Form.Get(consts.FormParameterRequest)
	if location := request.Form.Get(consts.FormParameterRequestURI); len(location) > 0 {
		if !stringslice.Has(oidcClient.GetRequestURIs(), location) {
			return errorsx.WithStack(ErrInvalidRequestURI.WithHintf("Request URI '%s' is not whitelisted by the OAuth 2.0 Client.", location))
		}

		hc := f.Config.GetHTTPClient(ctx)
		response, err := hc.Get(location)
		if err != nil {
			return errorsx.WithStack(ErrInvalidRequestURI.WithHintf("Unable to fetch OpenID Connect request parameters from 'request_uri' because: %s.", err.Error()).WithWrap(err).WithDebugError(err))
		}
		defer response.Body.Close()

		if response.StatusCode != http.StatusOK {
			return errorsx.WithStack(ErrInvalidRequestURI.WithHintf("Unable to fetch OpenID Connect request parameters from 'request_uri' because status code '%d' was expected, but got '%d'.", http.StatusOK, response.StatusCode))
		}

		body, err := io.ReadAll(response.Body)
		if err != nil {
			return errorsx.WithStack(ErrInvalidRequestURI.WithHintf("Unable to fetch OpenID Connect request parameters from 'request_uri' because body parsing failed with: %s.", err).WithWrap(err).WithDebugError(err))
		}

		assertion = string(body)
	}

	token, err := jwt.ParseWithClaims(assertion, jwt.MapClaims{}, func(t *jwt.Token) (any, error) {
		// request_object_signing_alg - OPTIONAL.
		//  JWS [JWS] alg algorithm [JWA] that MUST be used for signing Request Objects sent to the OP. All Request Objects from this Client MUST be rejected,
		// 	if not signed with this algorithm. Request Objects are described in Section 6.1 of OpenID Connect Core 1.0 [OpenID.Core]. This algorithm MUST
		//	be used both when the Request Object is passed by value (using the request parameter) and when it is passed by reference (using the request_uri parameter).
		//	Servers SHOULD support RS256. The value none MAY be used. The default, if omitted, is that any algorithm supported by the OP and the RP MAY be used.
		if oidcClient.GetRequestObjectSigningAlgorithm() != "" && oidcClient.GetRequestObjectSigningAlgorithm() != fmt.Sprintf("%s", t.Header[consts.JSONWebTokenHeaderAlgorithm]) {
			return nil, errorsx.WithStack(ErrInvalidRequestObject.WithHintf("The request object uses signing algorithm '%s', but the requested OAuth 2.0 Client enforces signing algorithm '%s'.", t.Header[consts.JSONWebTokenHeaderAlgorithm], oidcClient.GetRequestObjectSigningAlgorithm()))
		}

		if t.Method == jwt.SigningMethodNone {
			return jwt.UnsafeAllowNoneSignatureType, nil
		}

		switch t.Method {
		case jose.RS256, jose.RS384, jose.RS512:
			key, err := f.findClientPublicJWK(ctx, oidcClient, t, true)
			if err != nil {
				return nil, wrapSigningKeyFailure(
					ErrInvalidRequestObject.WithHint("Unable to retrieve RSA signing key from OAuth 2.0 Client."), err)
			}
			return key, nil
		case jose.ES256, jose.ES384, jose.ES512:
			key, err := f.findClientPublicJWK(ctx, oidcClient, t, false)
			if err != nil {
				return nil, wrapSigningKeyFailure(
					ErrInvalidRequestObject.WithHint("Unable to retrieve ECDSA signing key from OAuth 2.0 Client."), err)
			}
			return key, nil
		case jose.PS256, jose.PS384, jose.PS512:
			key, err := f.findClientPublicJWK(ctx, oidcClient, t, true)
			if err != nil {
				return nil, wrapSigningKeyFailure(
					ErrInvalidRequestObject.WithHint("Unable to retrieve RSA signing key from OAuth 2.0 Client."), err)
			}
			return key, nil
		default:
			return nil, errorsx.WithStack(ErrInvalidRequestObject.WithHintf("This request object uses unsupported signing algorithm '%s'.", t.Header["alg"]))
		}
	})
	if err != nil {
		// Do not re-process already enhanced errors
		var e *jwt.ValidationError
		if errors.As(err, &e) {
			if e.Inner != nil {
				return e.Inner
			}
			return errorsx.WithStack(ErrInvalidRequestObject.WithHint("Unable to verify the request object's signature.").WithWrap(err).WithDebugError(err))
		}
		return err
	} else if err := token.Claims.Valid(); err != nil {
		return errorsx.WithStack(ErrInvalidRequestObject.WithHint("Unable to verify the request object because its claims could not be validated, check if the expiry time is set correctly.").WithWrap(err).WithDebugError(err))
	}

	claims := token.Claims
	// Reject the request if the "request_uri" authorization request
	// parameter is provided.
	if requestURI, _ := claims[consts.FormParameterRequestURI].(string); isPARRequest && requestURI != "" {
		return errorsx.WithStack(ErrInvalidRequestObject.WithHint("Pushed Authorization Requests can not contain the 'request_uri' parameter."))
	}

	for k, v := range claims {
		request.Form.Set(k, fmt.Sprintf("%s", v))
	}

	claimScope := RemoveEmpty(strings.Split(request.Form.Get(consts.FormParameterScope), " "))
	for _, s := range scope {
		if !stringslice.Has(claimScope, s) {
			claimScope = append(claimScope, s)
		}
	}

	request.State = request.Form.Get(consts.FormParameterState)
	request.Form.Set(consts.FormParameterScope, strings.Join(claimScope, " "))
	return nil
}

func (f *Fosite) validateAuthorizeRedirectURI(_ *http.Request, request *AuthorizeRequest) error {
	// Fetch redirect URI from request
	rawRedirURI := request.Form.Get(consts.FormParameterRedirectURI)

	// This ensures that the 'redirect_uri' parameter is present for OpenID Connect 1.0 authorization requests as per:
	//
	// Authorization Code Flow - https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
	// Implicit Flow - https://openid.net/specs/openid-connect-core-1_0.html#ImplicitAuthRequest
	// Hybrid Flow - https://openid.net/specs/openid-connect-core-1_0.html#HybridAuthRequest
	//
	// Note: as per the Hybrid Flow documentation the Hybrid Flow has the same requirements as the Authorization Code Flow.
	if len(rawRedirURI) == 0 && request.GetRequestedScopes().Has(consts.ScopeOpenID) {
		return errorsx.WithStack(ErrInvalidRequest.WithHint("The 'redirect_uri' parameter is required when using OpenID Connect 1.0."))
	}

	// Validate redirect uri
	redirectURI, err := MatchRedirectURIWithClientRedirectURIs(rawRedirURI, request.Client)
	if err != nil {
		return err
	} else if !IsValidRedirectURI(redirectURI) {
		return errorsx.WithStack(ErrInvalidRequest.WithHintf("The redirect URI '%s' contains an illegal character (for example #) or is otherwise invalid.", redirectURI))
	}
	request.RedirectURI = redirectURI
	return nil
}

//nolint:unparam
func (f *Fosite) parseAuthorizeScope(_ *http.Request, request *AuthorizeRequest) error {
	request.SetRequestedScopes(RemoveEmpty(strings.Split(request.Form.Get(consts.FormParameterScope), " ")))

	return nil
}

func (f *Fosite) validateAuthorizeScope(ctx context.Context, _ *http.Request, request *AuthorizeRequest) error {
	for _, permission := range request.GetRequestedScopes() {
		if !f.Config.GetScopeStrategy(ctx)(request.Client.GetScopes(), permission) {
			return errorsx.WithStack(ErrInvalidScope.WithHintf("The OAuth 2.0 Client is not allowed to request scope '%s'.", permission))
		}
	}

	return nil
}

func (f *Fosite) validateResponseTypes(r *http.Request, request *AuthorizeRequest) error {
	// https://datatracker.ietf.org/doc/html/rfc6749#section-3.1.1
	// Extension response types MAY contain a space-delimited (%x20) list of
	// values, where the order of values does not matter (e.g., response
	// type "a b" is the same as "b a").  The meaning of such composite
	// response types is defined by their respective specifications.
	responseTypes := RemoveEmpty(strings.Split(r.Form.Get(consts.FormParameterResponseType), " "))
	if len(responseTypes) == 0 {
		return errorsx.WithStack(ErrUnsupportedResponseType.WithHint("`The request is missing the 'response_type' parameter."))
	}

	var found bool
	for _, t := range request.GetClient().GetResponseTypes() {
		if Arguments(responseTypes).Matches(RemoveEmpty(strings.Split(t, " "))...) {
			found = true
			break
		}
	}

	if !found {
		return errorsx.WithStack(ErrUnsupportedResponseType.WithHintf("The client is not allowed to request response_type '%s'.", r.Form.Get(consts.FormParameterResponseType)))
	}

	request.ResponseTypes = responseTypes
	return nil
}

func (f *Fosite) ParseResponseMode(ctx context.Context, r *http.Request, request *AuthorizeRequest) error {
	m := r.Form.Get(consts.FormParameterResponseMode)

	for _, handler := range f.ResponseModeHandlers(ctx) {
		mode := ResponseModeType(m)

		if handler.ResponseModes().Has(mode) {
			request.ResponseMode = mode

			return nil
		}
	}

	return errorsx.WithStack(ErrUnsupportedResponseMode.WithHintf("Request with unsupported response_mode \"%s\".", m))
}

func (f *Fosite) validateResponseMode(r *http.Request, request *AuthorizeRequest) error {
	if request.ResponseMode == ResponseModeDefault {
		return nil
	}

	responseModeClient, ok := request.GetClient().(ResponseModeClient)
	if !ok {
		return errorsx.WithStack(ErrUnsupportedResponseMode.WithHintf("The request has response_mode \"%s\". set but registered OAuth 2.0 client doesn't support response_mode", r.Form.Get(consts.FormParameterResponseMode)))
	}

	var found bool
	for _, t := range responseModeClient.GetResponseModes() {
		if request.ResponseMode == t {
			found = true
			break
		}
	}

	if !found {
		return errorsx.WithStack(ErrUnsupportedResponseMode.WithHintf("The client is not allowed to request response_mode '%s'.", r.Form.Get(consts.FormParameterResponseMode)))
	}

	return nil
}

func (f *Fosite) authorizeRequestFromPAR(ctx context.Context, r *http.Request, request *AuthorizeRequest) (bool, error) {
	configProvider, ok := f.Config.(PushedAuthorizeRequestConfigProvider)
	if !ok {
		// If the config provider is not implemented, PAR cannot be used.
		return false, nil
	}

	requestURI := r.Form.Get(consts.FormParameterRequestURI)
	if requestURI == "" || !strings.HasPrefix(requestURI, configProvider.GetPushedAuthorizeRequestURIPrefix(ctx)) {
		// nothing to do here
		return false, nil
	}

	clientID := r.Form.Get(consts.FormParameterClientID)

	storage, ok := f.Store.(PARStorage)
	if !ok {
		return false, errorsx.WithStack(ErrServerError.WithHint(ErrorPARNotSupported).WithDebug(DebugPARStorageInvalid))
	}

	// hydrate the requester
	var parRequest AuthorizeRequester
	var err error
	if parRequest, err = storage.GetPARSession(ctx, requestURI); err != nil {
		return false, errorsx.WithStack(ErrInvalidRequestURI.WithHint("Invalid PAR session").WithWrap(err).WithDebugError(err))
	}

	// hydrate the request object
	request.Merge(parRequest)
	request.RedirectURI = parRequest.GetRedirectURI()
	request.ResponseTypes = parRequest.GetResponseTypes()
	request.State = parRequest.GetState()
	request.ResponseMode = parRequest.GetResponseMode()

	if err = storage.DeletePARSession(ctx, requestURI); err != nil {
		return false, errorsx.WithStack(ErrServerError.WithWrap(err).WithDebugError(err))
	}

	// validate the clients match
	if clientID != request.GetClient().GetID() {
		return false, errorsx.WithStack(ErrInvalidRequest.WithHint("The 'client_id' must match the one sent in the pushed authorization request."))
	}

	return true, nil
}

func (f *Fosite) NewAuthorizeRequest(ctx context.Context, r *http.Request) (AuthorizeRequester, error) {
	return f.newAuthorizeRequest(ctx, r, false)
}

// TODO: Refactor time permitting.
//
//nolint:gocyclo
func (f *Fosite) newAuthorizeRequest(ctx context.Context, r *http.Request, isPARRequest bool) (AuthorizeRequester, error) {
	request := NewAuthorizeRequest()
	request.Request.Lang = i18n.GetLangFromRequest(f.Config.GetMessageCatalog(ctx), r)

	ctx = context.WithValue(ctx, RequestContextKey, r)
	ctx = context.WithValue(ctx, AuthorizeRequestContextKey, request)

	if err := r.ParseMultipartForm(1 << 20); err != nil && err != http.ErrNotMultipart {
		return request, errorsx.WithStack(ErrInvalidRequest.WithHint("Unable to parse HTTP body, make sure to send a properly formatted form request body.").WithWrap(err).WithDebugError(err))
	}

	request.Form = r.Form

	// Save state to the request to be returned in error conditions (https://github.com/ory/hydra/issues/1642)
	request.State = request.Form.Get(consts.FormParameterState)

	// Check if this is a continuation from a pushed authorization request
	if !isPARRequest {
		if isPAR, err := f.authorizeRequestFromPAR(ctx, r, request); err != nil {
			return request, err
		} else if isPAR {
			// No need to continue
			return request, nil
		} else if configProvider, ok := f.Config.(PushedAuthorizeRequestConfigProvider); ok && configProvider.EnforcePushedAuthorize(ctx) {
			return request, errorsx.WithStack(ErrInvalidRequest.WithHint("Pushed Authorization Requests are enforced but no such request was sent."))
		}
	}

	client, err := f.Store.GetClient(ctx, request.GetRequestForm().Get(consts.FormParameterClientID))
	if err != nil {
		return request, errorsx.WithStack(ErrInvalidClient.WithHint("The requested OAuth 2.0 Client does not exist.").WithWrap(err).WithDebugError(err))
	}

	request.Client = client

	// Now that the base fields (state and client) are populated, we extract all the information
	// from the request object or request object uri, if one is set.
	//
	// All other parse methods should come afterwards so that we ensure that the data is taken
	// from the request_object if set.
	if err = f.authorizeRequestParametersFromOpenIDConnectRequest(ctx, request, isPARRequest); err != nil {
		return request, err
	}

	// The request context is now fully available and we can start processing the individual
	// fields.
	if err = f.ParseResponseMode(ctx, r, request); err != nil {
		return request, err
	}

	if err = f.parseAuthorizeScope(r, request); err != nil {
		return request, err
	}

	if err = f.validateAuthorizeRedirectURI(r, request); err != nil {
		return request, err
	}

	if err = f.validateAuthorizeScope(ctx, r, request); err != nil {
		return request, err
	}

	if err = f.validateAuthorizeAudience(ctx, r, request); err != nil {
		return request, err
	}

	if len(request.Form.Get(consts.FormParameterRegistration)) > 0 {
		return request, errorsx.WithStack(ErrRegistrationNotSupported)
	}

	if err = f.validateResponseTypes(r, request); err != nil {
		return request, err
	}

	if err = f.validateResponseMode(r, request); err != nil {
		return request, err
	}

	// A fallback handler to set the default response mode in cases where we can not reach the Authorize Handlers
	// but still need the e.g. correct error response mode.
	if request.GetResponseMode() == ResponseModeDefault {
		if request.ResponseTypes.ExactOne(consts.ResponseTypeAuthorizationCodeFlow) || request.ResponseTypes.ExactOne(consts.ResponseTypeNone) {
			request.SetDefaultResponseMode(ResponseModeQuery)
		} else {
			// If the response type is not `code` it is an implicit/hybrid (fragment) response mode.
			request.SetDefaultResponseMode(ResponseModeFragment)
		}
	}

	// rfc6819 4.4.1.8.  Threat: CSRF Attack against redirect-uri
	// The "state" parameter should be used to link the authorization
	// request with the redirect URI used to deliver the access token (Section 5.3.5).
	//
	// https://datatracker.ietf.org/doc/html/rfc6819#section-4.4.1.8
	// The "state" parameter should not	be guessable
	if len(request.State) < f.GetMinParameterEntropy(ctx) {
		// We're assuming that using less then, by default, 8 characters for the state can not be considered "unguessable"
		return request, errorsx.WithStack(ErrInvalidState.WithHintf("Request parameter 'state' must be at least be %d characters long to ensure sufficient entropy.", f.GetMinParameterEntropy(ctx)))
	}

	return request, nil
}
