// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/pkg/errors"

	"authelia.com/provider/oauth2/i18n"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/stringslice"
	"authelia.com/provider/oauth2/token/jwt"
	"authelia.com/provider/oauth2/x/errorsx"
)

// TODO: Refactor time permitting.
//
//nolint:gocyclo
func (f *Fosite) authorizeRequestParametersFromOpenIDConnectRequestObject(ctx context.Context, request *AuthorizeRequest, isPARRequest bool) error {
	var scope Arguments = RemoveEmpty(strings.Split(request.Form.Get(consts.FormParameterScope), " "))

	openid := scope.Has(consts.ScopeOpenID)

	var (
		parameter             string
		nrequest, nrequestURI int
	)

	switch nrequest, nrequestURI = len(request.Form.Get(consts.FormParameterRequest)), len(request.Form.Get(consts.FormParameterRequestURI)); {
	case nrequest+nrequestURI == 0:
		return nil
	case nrequest > 0 && nrequestURI > 0:
		return errorsx.WithStack(ErrInvalidRequest.WithHintf("%s parameters 'request' and 'request_uri' were both used, but only one may be used in any given request.", hintRequestObjectPrefix(openid)))
	case nrequest > 0:
		parameter = consts.FormParameterRequest
	case nrequestURI > 0:
		parameter = consts.FormParameterRequestURI
	}

	client, ok := request.Client.(JARClient)
	if !ok {
		if nrequestURI > 0 {
			return errorsx.WithStack(ErrRequestURINotSupported.WithHintf(hintRequestObjectClientCapabilities, hintRequestObjectPrefix(openid), parameter).WithDebugf("The OAuth 2.0 client with id '%s' doesn't implement the correct functionality for this request.", request.GetClient().GetID()))
		}

		return errorsx.WithStack(ErrRequestNotSupported.WithHintf(hintRequestObjectClientCapabilities, hintRequestObjectPrefix(openid), parameter).WithDebugf("The OAuth 2.0 client with id '%s' doesn't implement the correct functionality for this request.", request.GetClient().GetID()))
	}

	if request.Form.Get(consts.FormParameterClientID) == "" {
		// So that the request is a valid OAuth 2.0 Authorization Request, values for the response_type and client_id
		// parameters MUST be included using the OAuth 2.0 request syntax, since they are REQUIRED by OAuth 2.0.
		return errorsx.WithStack(ErrInvalidRequest.WithHintf(hintRequestObjectRequiredRequestSyntaxParameter, hintRequestObjectPrefix(openid), parameter, consts.FormParameterClientID).WithDebugf("The OAuth 2.0 client with id '%s' provided the '%s' with value but did not include the 'client_id' parameter.", request.GetClient().GetID(), parameter))
	}

	if openid && request.Form.Get(consts.FormParameterResponseType) == "" {
		// So that the request is a valid OAuth 2.0 Authorization Request, values for the response_type and client_id
		// parameters MUST be included using the OAuth 2.0 request syntax, since they are REQUIRED by OAuth 2.0.
		return errorsx.WithStack(ErrInvalidRequest.WithHintf(hintRequestObjectRequiredRequestSyntaxParameter, hintRequestObjectPrefix(openid), parameter, consts.FormParameterResponseType).WithDebugf("The OAuth 2.0 client with id '%s' provided the '%s' with value but did not include the 'response_type' parameter.", request.GetClient().GetID(), parameter))
	}

	var (
		alg    string
		algAny bool
	)

	switch alg = client.GetRequestObjectSigningAlg(); alg {
	case consts.JSONWebTokenAlgNone:
		break
	case "":
		algAny = true
	default:
		if client.GetJSONWebKeys() == nil && len(client.GetJSONWebKeysURI()) == 0 {
			return errorsx.WithStack(ErrInvalidRequest.WithHintf("%s parameter '%s' was used, but the OAuth 2.0 Client does not have any JSON Web Keys registered.", hintRequestObjectPrefix(openid), parameter).WithDebugf("The OAuth 2.0 client with id '%s' doesn't have any known JSON Web Keys but requires them when not explicitly registered with a 'request_object_signing_alg' with the value of 'none' or an empty value but it's registered with '%s'.", request.GetClient().GetID(), alg))
		}
	}

	var assertion string

	if nrequestURI > 0 {
		// Reject the request if the "request_uri" authorization request parameter is provided.
		if isPARRequest {
			return errorsx.WithStack(ErrInvalidRequest.WithHintf(hintRequestObjectFetchRequestURI, hintRequestObjectPrefix(openid)).WithDebugf("The OAuth 2.0 client with id '%s' provided the 'request_uri' parameter within a Pushed Authorization Request which is invalid.", request.GetClient().GetID()))
		}

		requestURI := request.Form.Get(consts.FormParameterRequestURI)

		if !stringslice.Has(client.GetRequestURIs(), requestURI) {
			return errorsx.WithStack(ErrInvalidRequestURI.WithHintf(hintRequestObjectFetchRequestURI, hintRequestObjectPrefix(openid)).WithDebugf("The OAuth 2.0 client with id '%s' provided the 'request_uri' parameter with value '%s' which is not whitelisted.", request.GetClient().GetID(), requestURI))
		}

		hc := f.Config.GetHTTPClient(ctx)
		response, err := hc.Get(requestURI)
		if err != nil {
			return errorsx.WithStack(ErrInvalidRequestURI.WithHintf(hintRequestObjectFetchRequestURI, hintRequestObjectPrefix(openid)).WithWrap(err).WithDebugf("The OAuth 2.0 client with id '%s' failed to fetch the request object from the URI '%s' with an error: %+v.", request.GetClient().GetID(), requestURI, err))
		}
		defer response.Body.Close()

		if response.StatusCode != http.StatusOK {
			return errorsx.WithStack(ErrInvalidRequestURI.WithHintf(hintRequestObjectFetchRequestURI, hintRequestObjectPrefix(openid)).WithDebugf("The OAuth 2.0 client with id '%s' failed to fetch the request object as the response code was %d %s but a 200 OK is expected.", request.GetClient().GetID(), response.StatusCode, http.StatusText(response.StatusCode)))
		}

		body, err := io.ReadAll(response.Body)
		if err != nil {
			return errorsx.WithStack(ErrInvalidRequestURI.WithHintf(hintRequestObjectFetchRequestURI, hintRequestObjectPrefix(openid)).WithWrap(err).WithDebugf("The OAuth 2.0 client with id '%s' provided a response body that could not be read with error: %+v.", request.GetClient().GetID(), err))
		}

		assertion = string(body)
	} else {
		assertion = request.Form.Get(consts.FormParameterRequest)
	}

	issuer := f.Config.GetIDTokenIssuer(ctx)

	strategy := f.Config.GetJWTStrategy(ctx)

	token, err := strategy.Decode(ctx, assertion, jwt.WithSigAlgorithm(jwt.SignatureAlgorithmsNone...), jwt.WithJARClient(client))
	if err != nil {
		return errorsx.WithStack(fmtRequestObjectDecodeError(token, client, issuer, openid, err))
	}

	optsValidHeader := []jwt.HeaderValidationOption{
		jwt.ValidateKeyID(client.GetRequestObjectSigningKeyID()),
		jwt.ValidateAlgorithm(client.GetRequestObjectSigningAlg()),
		jwt.ValidateEncryptionKeyID(client.GetRequestObjectEncryptionKeyID()),
		jwt.ValidateKeyAlgorithm(client.GetRequestObjectEncryptionAlg()),
		jwt.ValidateContentEncryption(client.GetRequestObjectEncryptionEnc()),
	}

	if err = token.Valid(optsValidHeader...); err != nil {
		return errorsx.WithStack(fmtRequestObjectDecodeError(token, client, issuer, openid, err))
	}

	if algAny && token.SignatureAlgorithm == consts.JSONWebTokenAlgNone {
		return errorsx.WithStack(
			ErrInvalidRequestObject.
				WithHintf("%s client provided a request object that has an invalid 'kid' or 'alg' header value.", hintRequestObjectPrefix(openid)).
				WithDebugf("%s client with id '%s' was not explicitly registered with a 'request_object_signing_alg' value of 'none' but the request object had the 'alg' value 'none' in the header.", hintRequestObjectPrefix(openid), client.GetID()))
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
			return errorsx.WithStack(ErrInvalidRequestObject.WithHintf(hintRequestObjectInvalidAuthorizationClaim, hintRequestObjectPrefix(openid)).WithDebugf("The OAuth 2.0 client with id '%s' included a request object which contained the 'request' or 'request_uri' claims but this is not permitted.", request.GetClient().GetID()))
		case consts.ClaimIssuer, consts.ClaimAudience, consts.ClaimSubject:
			// The subject is not relevant, and the issuer and audience are validated below.
			continue
		case consts.FormParameterClientID:
			// So that the request is a valid OAuth 2.0 Authorization Request, values for the response_type and
			// client_id parameters MUST be included using the OAuth 2.0 request syntax, since they are REQUIRED by
			// OAuth 2.0. The values for these parameters MUST match those in the Request Object, if present.
			rsyntax := request.Form.Get(consts.FormParameterClientID)

			if value, ok = v.(string); !ok {
				return errorsx.WithStack(ErrInvalidRequestObject.WithHintf(hintRequestObjectInvalidAuthorizationClaim, hintRequestObjectPrefix(openid)).WithDebugf(debugRequestObjectValueTypeNotString, request.GetClient().GetID(), consts.FormParameterClientID, v, rsyntax, v))
			}

			if rsyntax != value {
				return errorsx.WithStack(ErrInvalidRequestObject.WithHintf(hintRequestObjectInvalidAuthorizationClaim, hintRequestObjectPrefix(openid)).WithDebugf(debugRequestObjectValueMismatch, request.GetClient().GetID(), consts.FormParameterClientID, value, rsyntax))
			}
		case consts.FormParameterResponseType:
			// So that the request is a valid OAuth 2.0 Authorization Request, values for the response_type and
			// client_id parameters MUST be included using the OAuth 2.0 request syntax, since they are REQUIRED by
			// OAuth 2.0. The values for these parameters MUST match those in the Request Object, if present.
			rsyntax := request.Form.Get(consts.FormParameterResponseType)

			if value, ok = v.(string); !ok {
				return errorsx.WithStack(ErrInvalidRequestObject.WithHintf(hintRequestObjectInvalidAuthorizationClaim, hintRequestObjectPrefix(openid)).WithDebugf(debugRequestObjectValueTypeNotString, request.GetClient().GetID(), consts.FormParameterResponseType, v, rsyntax, v))
			}

			if rsyntax != value {
				return errorsx.WithStack(ErrInvalidRequestObject.WithHintf(hintRequestObjectInvalidAuthorizationClaim, hintRequestObjectPrefix(openid)).WithDebugf(debugRequestObjectValueMismatch, request.GetClient().GetID(), consts.FormParameterResponseType, value, rsyntax))
			}
		default:
			request.Form.Set(k, fmt.Sprintf("%s", v))
		}
	}

	if len(issuer) == 0 {
		return errorsx.WithStack(ErrServerError.WithHintf("%s request could not be processed due to an authorization server configuration issue.", hintRequestObjectPrefix(openid)).WithDebugf("The OAuth 2.0 client with id '%s' provided a request object that was signed but the issuer for this authorization server is not known.", request.GetClient().GetID()))
	}

	optsValidClaims := []jwt.ClaimValidationOption{
		jwt.ValidateTimeFunc(func() time.Time {
			return time.Now().UTC()
		}),
		jwt.ValidateIssuer(client.GetID()),
		jwt.ValidateAudienceAny(issuer),
	}

	if err = claims.Valid(optsValidClaims...); err != nil {
		return errorsx.WithStack(fmtRequestObjectDecodeError(token, client, issuer, openid, err))
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

func hintRequestObjectPrefix(openid bool) string {
	if openid {
		return hintRequestObjectPrefixOpenID
	}

	return hintRequestObjectPrefixJAR
}

const (
	hintRequestObjectClientCapabilities             = "%s parameter '%s' was used, but the OAuth 2.0 Client does not implement advanced authorization capabilities."
	hintRequestObjectPrefixOpenID                   = "OpenID Connect 1.0"
	hintRequestObjectPrefixJAR                      = "OAuth 2.0 JWT-Secured Authorization Request"
	hintRequestObjectRequiredRequestSyntaxParameter = "%s parameter '%s' must be accompanied by the '%s' parameter in the request syntax."
	hintRequestObjectFetchRequestURI                = "%s request failed to fetch request parameters from the provided 'request_uri'."
	hintRequestObjectValidate                       = "%s request failed with an error attempting to validate the request object."
	hintRequestObjectInvalidAuthorizationClaim      = "%s request included a request object which excluded claims that are required or included claims that did not match the OAuth 2.0 request syntax or are generally not permitted."
	debugRequestObjectValueMismatch                 = "The OAuth 2.0 client with id '%s' included a request object with a '%s' claim with a value of '%s' which is required to match the value '%s' in the parameter with the same name from the OAuth 2.0 request syntax."
	debugRequestObjectValueTypeNotString            = "The OAuth 2.0 client with id '%s' included a request object with a '%s' claim with a value of '%v' which is required to match the value '%s' in the parameter with the same name from the OAuth 2.0 request syntax but instead of a string it had the %T type."
	debugRequestObjectSignedAbsentClaim             = "The OAuth 2.0 client with id '%s' provided a request object that was signed but it did not include the '%s' claim which is required."
)

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

	for _, handler := range f.Config.GetResponseModeHandlers(ctx) {
		mode := ResponseModeType(m)

		if handler.ResponseModes().Has(mode) {
			request.ResponseMode = mode

			return nil
		}
	}

	return errorsx.WithStack(ErrUnsupportedResponseMode.WithHintf("Request with unsupported response_mode '%s'.", m))
}

func (f *Fosite) validateResponseMode(r *http.Request, request *AuthorizeRequest) error {
	if request.ResponseMode == ResponseModeDefault {
		return nil
	}

	client, ok := request.GetClient().(ResponseModeClient)
	if !ok {
		return errorsx.WithStack(ErrUnsupportedResponseMode.WithHintf("The 'response_mode' requested was '%s', but the Authorization Server or registered OAuth 2.0 client doesn't allow or support this mode.", request.ResponseMode).WithDebugf("The registered OAuth 2.0 Client with id '%s' does not the 'response_mode' type '%s', as it's not registered to support any.", request.GetClient().GetID(), request.ResponseMode))
	}

	var found bool
	for _, t := range client.GetResponseModes() {
		if request.ResponseMode == t {
			found = true
			break
		}
	}

	if !found {
		return errorsx.WithStack(ErrUnsupportedResponseMode.WithHintf("The 'response_mode' requested was '%s', but the Authorization Server or registered OAuth 2.0 client doesn't allow or support this mode.", request.ResponseMode).WithDebugf("The registered OAuth 2.0 Client with id '%s' does not the 'response_mode' type '%s'.", client.GetID(), request.ResponseMode))
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
			return request, errorsx.WithStack(ErrInvalidRequest.WithHint("Pushed Authorization Requests are required but this Authorization Request was not made as a Pushed Authorization Request.").WithDebugf("The registered OAuth 2.0 client with id '%s' is registered with a policy which requires Pushed Authorization Requests be used.", parc.GetID()))
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

func fmtRequestObjectDecodeError(token *jwt.Token, client JARClient, issuer string, openid bool, inner error) (outer *RFC6749Error) {
	outer = ErrInvalidRequestObject.WithWrap(inner).WithHintf("%s request object could not be decoded or validated.", hintRequestObjectPrefix(openid))

	if errJWTValidation := new(jwt.ValidationError); errors.As(inner, &errJWTValidation) {
		switch {
		case errJWTValidation.Has(jwt.ValidationErrorHeaderKeyIDInvalid):
			return outer.WithDebugf("%s client with id '%s' expects request objects to be signed with the 'kid' header value '%s' due to the client registration 'request_object_signing_key_id' value but the request object was signed with the 'kid' header value '%s'.", hintRequestObjectPrefix(openid), client.GetID(), client.GetRequestObjectSigningKeyID(), token.KeyID)
		case errJWTValidation.Has(jwt.ValidationErrorHeaderAlgorithmInvalid):
			return outer.WithDebugf("%s client with id '%s' expects request objects to be signed with the 'alg' header value '%s' due to the client registration 'request_object_signing_alg' value but the request object was signed with the 'alg' header value '%s'.", hintRequestObjectPrefix(openid), client.GetID(), client.GetRequestObjectSigningAlg(), token.SignatureAlgorithm)
		case errJWTValidation.Has(jwt.ValidationErrorHeaderTypeInvalid):
			return outer.WithDebugf("%s client with id '%s' expects request objects to be signed with the 'typ' header value '%s' but the request object was signed with the 'typ' header value '%s'.", hintRequestObjectPrefix(openid), client.GetID(), consts.JSONWebTokenTypeJWT, token.Header[consts.JSONWebTokenHeaderType])
		case errJWTValidation.Has(jwt.ValidationErrorHeaderEncryptionTypeInvalid):
			return outer.WithDebugf("%s client with id '%s' expects request objects to be encrypted with the 'typ' header value '%s' but the request object was encrypted with the 'typ' header value '%s'.", hintRequestObjectPrefix(openid), client.GetID(), consts.JSONWebTokenTypeJWT, token.HeaderJWE[consts.JSONWebTokenHeaderType])
		case errJWTValidation.Has(jwt.ValidationErrorHeaderContentTypeInvalid):
			return outer.WithDebugf("%s client with id '%s' expects request objects to be encrypted with the 'cty' header value '%s' but the request object was encrypted with the 'cty' header value '%s'.", hintRequestObjectPrefix(openid), client.GetID(), consts.JSONWebTokenTypeJWT, token.HeaderJWE[consts.JSONWebTokenHeaderContentType])
		case errJWTValidation.Has(jwt.ValidationErrorHeaderEncryptionKeyIDInvalid):
			return outer.WithDebugf("%s client with id '%s' expects request objects to be encrypted with the 'kid' header value '%s' due to the client registration 'request_object_encryption_key_id' value but the request object was encrypted with the 'kid' header value '%s'.", hintRequestObjectPrefix(openid), client.GetID(), client.GetRequestObjectEncryptionKeyID(), token.EncryptionKeyID)
		case errJWTValidation.Has(jwt.ValidationErrorHeaderKeyAlgorithmInvalid):
			return outer.WithDebugf("%s client with id '%s' expects request objects to be encrypted with the 'alg' header value '%s' due to the client registration 'request_object_encryption_alg' value but the request object was encrypted with the 'alg' header value '%s'.", hintRequestObjectPrefix(openid), client.GetID(), client.GetRequestObjectEncryptionAlg(), token.KeyAlgorithm)
		case errJWTValidation.Has(jwt.ValidationErrorHeaderContentEncryptionInvalid):
			return outer.WithDebugf("%s client with id '%s' expects request objects to be encrypted with the 'enc' header value '%s' due to the client registration 'request_object_encryption_enc' value but the request object was encrypted with the 'enc' header value '%s'.", hintRequestObjectPrefix(openid), client.GetID(), client.GetRequestObjectEncryptionEnc(), token.ContentEncryption)
		case errJWTValidation.Has(jwt.ValidationErrorMalformedNotCompactSerialized):
			return outer.WithDebugf("%s client with id '%s' provided a request object that was malformed. The request object does not appear to be a JWE or JWS compact serialized JWT.", hintRequestObjectPrefix(openid), client.GetID())
		case errJWTValidation.Has(jwt.ValidationErrorMalformed):
			return outer.WithDebugf("%s client with id '%s' provided a request object that was malformed. %s.", hintRequestObjectPrefix(openid), client.GetID(), strings.TrimPrefix(errJWTValidation.Error(), "go-jose/go-jose: "))
		case errJWTValidation.Has(jwt.ValidationErrorUnverifiable):
			return outer.WithDebugf("%s client with id '%s' provided a request object that was not able to be verified. %s.", hintRequestObjectPrefix(openid), client.GetID(), strings.TrimPrefix(errJWTValidation.Error(), "go-jose/go-jose: "))
		case errJWTValidation.Has(jwt.ValidationErrorSignatureInvalid):
			return outer.WithDebugf("%s client with id '%s' provided a request object that has an invalid signature.", hintRequestObjectPrefix(openid), client.GetID())
		case errJWTValidation.Has(jwt.ValidationErrorExpired):
			exp, ok := token.Claims.GetExpiresAt()
			if ok {
				return outer.WithDebugf("%s client with id '%s' provided a request object that was expired. The request object expired at %d.", hintRequestObjectPrefix(openid), client.GetID(), exp)
			} else {
				return outer.WithDebugf("%s client with id '%s' provided a request object that was expired. The request object does not have an 'exp' claim or it has an invalid type.", hintRequestObjectPrefix(openid), client.GetID())
			}
		case errJWTValidation.Has(jwt.ValidationErrorIssuedAt):
			iat, ok := token.Claims.GetIssuedAt()
			if ok {
				return outer.WithDebugf("%s client with id '%s' provided a request object that was issued in the future. The request object was issued at %d.", hintRequestObjectPrefix(openid), client.GetID(), iat)
			} else {
				return outer.WithDebugf("%s client with id '%s' provided a request object that was issued in the future. The request object does not have an 'iat' claim or it has an invalid type.", hintRequestObjectPrefix(openid), client.GetID())
			}
		case errJWTValidation.Has(jwt.ValidationErrorNotValidYet):
			nbf, ok := token.Claims.GetNotBefore()
			if ok {
				return outer.WithDebugf("%s client with id '%s' provided a request object that was issued in the future. The request object is not valid before %d.", hintRequestObjectPrefix(openid), client.GetID(), nbf)
			} else {
				return outer.WithDebugf("%s client with id '%s' provided a request object that was issued in the future. The request object does not have an 'nbf' claim or it has an invalid type.", hintRequestObjectPrefix(openid), client.GetID())
			}
		case errJWTValidation.Has(jwt.ValidationErrorIssuer):
			iss, ok := token.Claims.GetIssuer()
			if ok {
				return outer.WithDebugf("%s client with id '%s' provided a request object that has an invalid issuer. The request object was expected to have an 'iss' claim which matches the value '%s' but the 'iss' claim had the value '%s'.", hintRequestObjectPrefix(openid), client.GetID(), client.GetID(), iss)
			} else {
				return outer.WithDebugf("%s client with id '%s' provided a request object that has an invalid issuer. The request object does not have an 'iss' claim or it has an invalid type.", hintRequestObjectPrefix(openid), client.GetID())
			}
		case errJWTValidation.Has(jwt.ValidationErrorAudience):
			aud, ok := token.Claims.GetAudience()
			if ok {
				return outer.WithDebugf("%s client with id '%s' provided a request object that has an invalid audience. The request object was expected to have an 'aud' claim which matches the issuer value of '%s' but the 'aud' claim had the values '%s'.", hintRequestObjectPrefix(openid), client.GetID(), issuer, strings.Join(aud, "', '"))
			} else {
				return outer.WithDebugf("%s client with id '%s' provided a request object that has an invalid audience. The request object does not have an 'aud' claim or it has an invalid type.", hintRequestObjectPrefix(openid), client.GetID())
			}
		case errJWTValidation.Has(jwt.ValidationErrorClaimsInvalid):
			return outer.WithDebugf("%s client with id '%s' provided a request object that had one or more invalid claims. Error occurred trying to validate the request objects claims: %s", hintRequestObjectPrefix(openid), client.GetID(), strings.TrimPrefix(errJWTValidation.Error(), "go-jose/go-jose: "))
		default:
			return outer.WithDebugf("%s client with id '%s' provided a request object that could not be validated. Error occurred trying to validate the request object: %s", hintRequestObjectPrefix(openid), client.GetID(), strings.TrimPrefix(errJWTValidation.Error(), "go-jose/go-jose: "))
		}
	} else if errJWKLookup := new(jwt.JWKLookupError); errors.As(inner, &errJWKLookup) {
		return outer.WithDebugf("%s client with id '%s' provided a request object that could not be validated due to a key lookup error. %s.", hintRequestObjectPrefix(openid), client.GetID(), errJWKLookup.Description)
	} else {
		return outer.WithDebugf("%s client with id '%s' provided a request object that could not be validated. %s.", hintRequestObjectPrefix(openid), client.GetID(), ErrorToDebugRFC6749Error(inner).Error())
	}
}
