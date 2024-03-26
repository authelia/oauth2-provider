// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/go-jose/go-jose/v4"
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
func (f *Fosite) authorizeRequestParametersFromOpenIDConnectRequestObject(ctx context.Context, request *AuthorizeRequest, isPARRequest bool) error {
	var scope Arguments = RemoveEmpty(strings.Split(request.Form.Get(consts.FormParameterScope), " "))

	// Even if a scope parameter is present in the Request Object value, a scope parameter MUST always be passed using
	// the OAuth 2.0 request syntax containing the openid scope value to indicate to the underlying OAuth 2.0 logic that this is an OpenID Connect request.
	// Source: http://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth
	if !scope.Has(consts.ScopeOpenID) {
		return nil
	}

	var (
		nrequest, nrequestURI int
	)

	switch nrequest, nrequestURI = len(request.Form.Get(consts.FormParameterRequest)), len(request.Form.Get(consts.FormParameterRequestURI)); {
	case nrequest+nrequestURI == 0:
		return nil
	case nrequest > 0 && nrequestURI > 0:
		return errorsx.WithStack(ErrInvalidRequest.WithHint("OpenID Connect 1.0 parameters 'request' and 'request_uri' were both given, but you can use at most one."))
	}

	client, ok := request.Client.(OpenIDConnectClient)
	if !ok {
		if nrequestURI > 0 {
			return errorsx.WithStack(ErrRequestURINotSupported.WithHint("OpenID Connect 1.0 'request_uri' context was given, but the OAuth 2.0 Client does not implement advanced OpenID Connect 1.0 capabilities.").WithDebugf("The OAuth 2.0 client with id '%s' doesn't implement the correct methods for this request.", request.GetClient().GetID()))
		}

		return errorsx.WithStack(ErrRequestNotSupported.WithHint("OpenID Connect 1.0 'request' context was given, but the OAuth 2.0 Client does not implement advanced OpenID Connect 1.0 capabilities.").WithDebugf("The OAuth 2.0 client with id '%s' doesn't implement the correct methods for this request.", request.GetClient().GetID()))
	}

	if request.Form.Get(consts.FormParameterResponseType) == "" || request.Form.Get(consts.FormParameterClientID) == "" {
		// So that the request is a valid OAuth 2.0 Authorization Request, values for the response_type and client_id
		// parameters MUST be included using the OAuth 2.0 request syntax, since they are REQUIRED by OAuth 2.0.
		return errorsx.WithStack(ErrInvalidRequest.WithHint("OpenID Connect 1.0 parameters 'request' and 'request_uri' must be accompanied by the `client_id' and 'response_type' in the request syntax."))
	}

	var (
		algAny, algNone bool
	)

	switch alg := client.GetRequestObjectSigningAlg(); alg {
	case "none":
		algNone = true
	case "":
		algAny = true
	default:
		if client.GetJSONWebKeys() == nil && len(client.GetJSONWebKeysURI()) == 0 {
			if nrequestURI > 0 {
				return errorsx.WithStack(ErrInvalidRequest.WithHint("OpenID Connect 1.0 'request_uri' context was given, but the OAuth 2.0 Client does not have any JSON Web Keys registered.").WithDebugf("The OAuth 2.0 client with id '%s' doesn't have any known JSON Web Keys but requires them when not explicitly registered with a 'request_object_signing_alg' with the value of 'none' but it's registered with '%s'.", request.GetClient().GetID(), alg))
			}

			return errorsx.WithStack(ErrInvalidRequest.WithHint("OpenID Connect 1.0 'request' context was given, but the OAuth 2.0 Client does not have any JSON Web Keys registered.").WithDebugf("The OAuth 2.0 client with id '%s' doesn't have any known JSON Web Keys but requires them when not explicitly registered with a 'request_object_signing_alg' with the value of 'none' but it's registered with '%s'.", request.GetClient().GetID(), alg))
		}
	}

	var assertion string

	if nrequestURI > 0 {
		// Reject the request if the "request_uri" authorization request parameter is provided.
		if isPARRequest {
			return errorsx.WithStack(ErrInvalidRequest.WithHint("Pushed Authorization Requests can not contain the 'request_uri' parameter."))
		}

		requestURI := request.Form.Get(consts.FormParameterRequestURI)

		if !stringslice.Has(client.GetRequestURIs(), requestURI) {
			return errorsx.WithStack(ErrInvalidRequestURI.WithHintf("Request URI '%s' is not whitelisted by the OAuth 2.0 Client.", requestURI).WithDebugf(""))
		}

		hc := f.Config.GetHTTPClient(ctx)
		response, err := hc.Get(requestURI)
		if err != nil {
			return errorsx.WithStack(ErrInvalidRequestURI.WithHintf("Unable to fetch OpenID Connect 1.0 request parameters from 'request_uri' because: %s.", err.Error()).WithWrap(err).WithDebugError(err))
		}
		defer response.Body.Close()

		if response.StatusCode != http.StatusOK {
			return errorsx.WithStack(ErrInvalidRequestURI.WithHintf("Unable to fetch OpenID Connect 1.0 request parameters from 'request_uri' because status code '%d' was expected, but got '%d'.", http.StatusOK, response.StatusCode))
		}

		body, err := io.ReadAll(response.Body)
		if err != nil {
			return errorsx.WithStack(ErrInvalidRequestURI.WithHintf("Unable to fetch OpenID Connect 1.0 request parameters from 'request_uri' because body parsing failed with: %s.", err).WithWrap(err).WithDebugError(err))
		}

		assertion = string(body)
	} else {
		assertion = request.Form.Get(consts.FormParameterRequest)
	}

	token, err := jwt.ParseWithClaims(assertion, jwt.MapClaims{}, func(t *jwt.Token) (any, error) {
		// request_object_signing_alg - OPTIONAL.
		//  JWS [JWS] alg algorithm [JWA] that MUST be used for signing Request Objects sent to the OP. All Request Objects from this Client MUST be rejected,
		// 	if not signed with this algorithm. Request Objects are described in Section 6.1 of OpenID Connect Core 1.0 [OpenID.Core]. This algorithm MUST
		//	be used both when the Request Object is passed by value (using the request parameter) and when it is passed by reference (using the request_uri parameter).
		//	Servers SHOULD support RS256. The value none MAY be used. The default, if omitted, is that any algorithm supported by the OP and the RP MAY be used.
		if !algAny && client.GetRequestObjectSigningAlg() != fmt.Sprintf("%s", t.Header[consts.JSONWebTokenHeaderAlgorithm]) {
			return nil, errorsx.WithStack(ErrInvalidRequestObject.WithHintf("The request object uses signing algorithm '%s', but the requested OAuth 2.0 Client enforces signing algorithm '%s'.", t.Header[consts.JSONWebTokenHeaderAlgorithm], client.GetRequestObjectSigningAlg()))
		}

		if t.Method == jwt.SigningMethodNone {
			algNone = true

			return jwt.UnsafeAllowNoneSignatureType, nil
		} else if algNone {
			return nil, errorsx.WithStack(ErrInvalidRequestObject.WithHintf("The request object uses signing algorithm '%s', but the requested OAuth 2.0 Client enforces signing algorithm '%s'.", t.Header[consts.JSONWebTokenHeaderAlgorithm], client.GetRequestObjectSigningAlg()))
		}

		switch t.Method {
		case jose.RS256, jose.RS384, jose.RS512:
			key, err := f.findClientPublicJWK(ctx, client, t, true)
			if err != nil {
				return nil, wrapSigningKeyFailure(
					ErrInvalidRequestObject.WithHint("Unable to retrieve RSA signing key from OAuth 2.0 Client."), err)
			}
			return key, nil
		case jose.ES256, jose.ES384, jose.ES512:
			key, err := f.findClientPublicJWK(ctx, client, t, false)
			if err != nil {
				return nil, wrapSigningKeyFailure(
					ErrInvalidRequestObject.WithHint("Unable to retrieve ECDSA signing key from OAuth 2.0 Client."), err)
			}
			return key, nil
		case jose.PS256, jose.PS384, jose.PS512:
			key, err := f.findClientPublicJWK(ctx, client, t, true)
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
	} else if err = token.Claims.Valid(); err != nil {
		return errorsx.WithStack(ErrInvalidRequestObject.WithHint("Unable to verify the request object because its claims could not be validated, check if the expiry time is set correctly.").WithWrap(err).WithDebugError(err))
	}

	claims := token.Claims

	var (
		k, value string
		v        any
	)

	for k, v = range claims {
		switch k {
		case consts.FormParameterRequest, consts.FormParameterRequestURI:
			// The request and request_uri parameters MUST NOT be included in Request Objects.
			return errorsx.WithStack(ErrInvalidRequestObject.WithHint("OpenID Connect 1.0 request object must not contain the 'request' or 'request_uri' claims."))
		case consts.ClaimIssuer, consts.ClaimAudience, consts.ClaimSubject:
			// The subject is not relevant, and the issuer and audience are validated below.
			continue
		case consts.FormParameterClientID:
			// So that the request is a valid OAuth 2.0 Authorization Request, values for the response_type and
			// client_id parameters MUST be included using the OAuth 2.0 request syntax, since they are REQUIRED by
			// OAuth 2.0. The values for these parameters MUST match those in the Request Object, if present.
			if value, ok = v.(string); !ok {
				return errorsx.WithStack(ErrInvalidRequestObject.WithHint("OpenID Connect 1.0 request object's `client_id' claim must match the values provided in the standard OAuth 2.0 request syntax if provided."))
			}

			if request.Form.Get(consts.FormParameterClientID) != value {
				return errorsx.WithStack(ErrInvalidRequestObject.WithHint("OpenID Connect 1.0 request object's `client_id' claim must match the values provided in the standard OAuth 2.0 request syntax if provided."))
			}
		case consts.FormParameterResponseType:
			// So that the request is a valid OAuth 2.0 Authorization Request, values for the response_type and
			// client_id parameters MUST be included using the OAuth 2.0 request syntax, since they are REQUIRED by
			// OAuth 2.0. The values for these parameters MUST match those in the Request Object, if present.
			if value, ok = v.(string); !ok {
				return errorsx.WithStack(ErrInvalidRequestObject.WithHint("OpenID Connect 1.0 request object's `response_type' claim must match the values provided in the standard OAuth 2.0 request syntax if provided."))
			}

			if request.Form.Get(consts.FormParameterResponseType) != value {
				return errorsx.WithStack(ErrInvalidRequestObject.WithHint("OpenID Connect 1.0 request object's `response_type' claim must match the values provided in the standard OAuth 2.0 request syntax if provided."))
			}
		default:
			request.Form.Set(k, fmt.Sprintf("%s", v))
		}
	}

	if !algNone {
		if v, ok = claims[consts.ClaimIssuer]; !ok {
			return errorsx.WithStack(ErrInvalidRequestObject.WithHint("OpenID Connect 1.0 request object's `iss' claim must be present when using signed or encrypted request objects."))
		}

		if value, ok = v.(string); !ok {
			return errorsx.WithStack(ErrInvalidRequestObject.WithHint("OpenID Connect 1.0 request object's `iss' claim must contain the `client_id` when using signed or encrypted request objects."))
		}

		if value != request.Client.GetID() {
			return errorsx.WithStack(ErrInvalidRequestObject.WithHint("OpenID Connect 1.0 request object's `iss' claim must contain the `client_id` when using signed or encrypted request objects."))
		}

		if v, ok = claims[consts.ClaimAudience]; !ok {
			return errorsx.WithStack(ErrInvalidRequestObject.WithHint("OpenID Connect 1.0 request object's `aud' claim must be present when using signed or encrypted request objects."))
		}

		var valid bool

		switch t := v.(type) {
		case string:
			valid = strings.EqualFold(t, f.Config.GetIDTokenIssuer(ctx))
		case []string:
			for _, value = range t {
				if strings.EqualFold(value, f.Config.GetIDTokenIssuer(ctx)) {
					valid = true

					break
				}
			}
		case []any:
			for _, x := range t {
				if value, ok = x.(string); ok && strings.EqualFold(value, f.Config.GetIDTokenIssuer(ctx)) {
					valid = true

					break
				}
			}
		}

		if !valid {
			return errorsx.WithStack(ErrInvalidRequestObject.WithHint("OpenID Connect 1.0 request object's `aud' claim must be the Authorization Server's issuer when using signed or encrypted request objects."))
		}
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
func (f *Fosite) newAuthorizeRequest(ctx context.Context, r *http.Request, isPARRequest bool) (requester AuthorizeRequester, err error) {
	request := NewAuthorizeRequest()
	request.Request.Lang = i18n.GetLangFromRequest(f.Config.GetMessageCatalog(ctx), r)

	ctx = context.WithValue(ctx, RequestContextKey, r)
	ctx = context.WithValue(ctx, AuthorizeRequestContextKey, request)

	if err = r.ParseMultipartForm(1 << 20); err != nil && err != http.ErrNotMultipart {
		return request, errorsx.WithStack(ErrInvalidRequest.WithHint("Unable to parse HTTP body, make sure to send a properly formatted form request body.").WithWrap(err).WithDebugError(err))
	}

	request.Form = r.Form

	// Save state to the request to be returned in error conditions (https://github.com/ory/hydra/issues/1642)
	request.State = request.Form.Get(consts.FormParameterState)

	// Check if this is a continuation from a pushed authorization request
	if !isPARRequest {
		var isPAR bool

		if isPAR, err = f.authorizeRequestFromPAR(ctx, r, request); err != nil {
			return request, err
		}

		if isPAR {
			// No need to continue.
			return request, nil
		}

		if config, ok := f.Config.(PushedAuthorizeRequestConfigProvider); ok && config.GetRequirePushedAuthorizationRequests(ctx) {
			return request, errorsx.WithStack(ErrInvalidRequest.WithHint("Pushed Authorization Requests are required but this Authorization Request was not made as a Pushed Authorization Request.").WithDebug("The Authorization Server policy requires Pushed Authorization Requests be used for all clients."))
		}
	}

	client, err := f.Store.GetClient(ctx, request.GetRequestForm().Get(consts.FormParameterClientID))
	if err != nil {
		return request, errorsx.WithStack(ErrInvalidClient.WithHint("The requested OAuth 2.0 Client does not exist.").WithWrap(err).WithDebugError(err))
	}

	if !isPARRequest {
		if parc, ok := client.(PushedAuthorizationRequestClient); ok && parc.GetRequirePushedAuthorizationRequests() {
			return request, errorsx.WithStack(ErrInvalidRequest.WithHint("Pushed Authorization Requests are required but this Authorization Request was not made as a Pushed Authorization Request.").WithDebugf("The Registered Client policy for client with id '%s' requires Pushed Authorization Requests for be used for this client.", parc.GetID()))
		}
	}

	request.Client = client

	// Now that the base fields (state and client) are populated, we extract all the information
	// from the request object or request object uri, if one is set.
	//
	// All other parse methods should come afterwards so that we ensure that the data is taken
	// from the request_object if set.
	if err = f.authorizeRequestParametersFromOpenIDConnectRequestObject(ctx, request, isPARRequest); err != nil {
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
