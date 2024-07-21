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
	"authelia.com/provider/oauth2/internal/stringslice"
	"authelia.com/provider/oauth2/token/jwt"
	"authelia.com/provider/oauth2/x/errorsx"
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
		algAny, algNone bool
	)

	switch alg := client.GetRequestObjectSigningAlg(); alg {
	case consts.JSONWebTokenAlgNone:
		algNone = true
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

	token, err := jwt.ParseWithClaims(assertion, jwt.MapClaims{}, func(t *jwt.Token) (key any, err error) {
		// request_object_signing_alg - OPTIONAL.
		//  JWS [JWS] alg algorithm [JWA] that MUST be used for signing Request Objects sent to the OP. All Request Objects from this Client MUST be rejected,
		// 	if not signed with this algorithm. Request Objects are described in Section 6.1 of OpenID Connect Core 1.0 [OpenID.Core]. This algorithm MUST
		//	be used both when the Request Object is passed by value (using the request parameter) and when it is passed by reference (using the request_uri parameter).
		//	Servers SHOULD support RS256. The value none MAY be used. The default, if omitted, is that any algorithm supported by the OP and the RP MAY be used.
		if !algAny && client.GetRequestObjectSigningAlg() != fmt.Sprintf("%s", t.Header[consts.JSONWebTokenHeaderAlgorithm]) {
			return nil, errorsx.WithStack(ErrInvalidRequestObject.WithHintf(hintRequestObjectValidate, hintRequestObjectPrefix(openid)).WithDebugf("The OAuth 2.0 client with id '%s' expects request objects to be signed with the '%s' algorithm but the request object was signed with the '%s' algorithm.", request.GetClient().GetID(), client.GetRequestObjectSigningAlg(), t.Header[consts.JSONWebTokenHeaderAlgorithm]))
		}

		if t.SignatureAlgorithm == jwt.SigningMethodNone {
			algNone = true

			return jwt.UnsafeAllowNoneSignatureType, nil
		} else if algNone {
			return nil, errorsx.WithStack(ErrInvalidRequestObject.WithHintf(hintRequestObjectValidate, hintRequestObjectPrefix(openid)).WithDebugf("The OAuth 2.0 client with id '%s' expects request objects to be signed with the '%s' algorithm but the request object was signed with the '%s' algorithm.", request.GetClient().GetID(), client.GetRequestObjectSigningAlg(), t.Header[consts.JSONWebTokenHeaderAlgorithm]))
		}

		switch t.SignatureAlgorithm {
		case jose.RS256, jose.RS384, jose.RS512:
			if key, err = f.findClientPublicJWK(ctx, client, t, true); err != nil {
				return nil, wrapSigningKeyFailure(
					ErrInvalidRequestObject.WithHint("Unable to retrieve RSA signing key from OAuth 2.0 Client."), err)
			}

			return key, nil
		case jose.ES256, jose.ES384, jose.ES512:
			if key, err = f.findClientPublicJWK(ctx, client, t, false); err != nil {
				return nil, wrapSigningKeyFailure(
					ErrInvalidRequestObject.WithHint("Unable to retrieve ECDSA signing key from OAuth 2.0 Client."), err)
			}

			return key, nil
		case jose.PS256, jose.PS384, jose.PS512:
			if key, err = f.findClientPublicJWK(ctx, client, t, true); err != nil {
				return nil, wrapSigningKeyFailure(
					ErrInvalidRequestObject.WithHint("Unable to retrieve RSA signing key from OAuth 2.0 Client."), err)
			}

			return key, nil
		default:
			return nil, errorsx.WithStack(ErrInvalidRequestObject.WithHintf(hintRequestObjectValidate, hintRequestObjectPrefix(openid)).WithDebugf("The OAuth 2.0 client with id '%s' provided a request object that uses the unsupported signing algorithm '%s'.", request.GetClient().GetID(), t.Header[consts.JSONWebTokenHeaderAlgorithm]))
		}
	})

	if err != nil {
		// Do not re-process already enhanced errors
		var e *jwt.ValidationError
		if errors.As(err, &e) {
			if e.Inner != nil {
				return e.Inner
			}

			return errorsx.WithStack(ErrInvalidRequestObject.WithHintf(hintRequestObjectValidate, hintRequestObjectPrefix(openid)).WithDebugf("The OAuth 2.0 client with id '%s' provided a request object which failed to validate with error: %+v.", request.GetClient().GetID(), err).WithWrap(err))
		}

		return err
	} else if err = token.Claims.Valid(); err != nil {
		return errorsx.WithStack(ErrInvalidRequestObject.WithHintf(hintRequestObjectValidate, hintRequestObjectPrefix(openid)).WithDebugf("The OAuth 2.0 client with id '%s' provided a request object which could not be validated because its claims could not be validated with error: %+v.", request.GetClient().GetID(), err).WithWrap(err))
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

	if !algNone {
		issuer := f.Config.GetIDTokenIssuer(ctx)

		if len(issuer) == 0 {
			return errorsx.WithStack(ErrServerError.WithHintf("%s request could not be processed due to an authorization server configuration issue.", hintRequestObjectPrefix(openid)).WithDebugf("The OAuth 2.0 client with id '%s' provided a request object that was signed but the issuer for this authorization server is not known.", request.GetClient().GetID()))
		}

		if v, ok = claims[consts.ClaimIssuer]; !ok {
			return errorsx.WithStack(ErrInvalidRequestObject.WithHintf(hintRequestObjectInvalidAuthorizationClaim, hintRequestObjectPrefix(openid)).WithDebugf(debugRequestObjectSignedAbsentClaim, request.GetClient().GetID(), consts.ClaimIssuer))
		}

		clientID := request.GetClient().GetID()

		if value, ok = v.(string); !ok {
			return errorsx.WithStack(ErrInvalidRequestObject.WithHintf(hintRequestObjectInvalidAuthorizationClaim, hintRequestObjectPrefix(openid)).WithDebugf(debugRequestObjectValueTypeNotString, request.GetClient().GetID(), consts.ClaimIssuer, v, clientID, v))
		}

		if value != clientID {
			return errorsx.WithStack(ErrInvalidRequestObject.WithHintf(hintRequestObjectInvalidAuthorizationClaim, hintRequestObjectPrefix(openid)).WithDebugf(debugRequestObjectValueMismatch, clientID, consts.ClaimIssuer, value, clientID))
		}

		if v, ok = claims[consts.ClaimAudience]; !ok {
			return errorsx.WithStack(ErrInvalidRequestObject.WithHintf(hintRequestObjectInvalidAuthorizationClaim, hintRequestObjectPrefix(openid)).WithDebugf(debugRequestObjectSignedAbsentClaim, request.GetClient().GetID(), consts.ClaimAudience))
		}

		var valid bool

		switch t := v.(type) {
		case string:
			valid = t == issuer
		case []string:
			for _, value = range t {
				if value == issuer {
					valid = true

					break
				}
			}
		case []any:
			for _, x := range t {
				if value, ok = x.(string); ok && value == issuer {
					valid = true

					break
				}
			}
		}

		if !valid {
			return errorsx.WithStack(ErrInvalidRequestObject.WithHintf(hintRequestObjectInvalidAuthorizationClaim, hintRequestObjectPrefix(openid)).WithDebugf("The OAuth 2.0 client with id '%s' included a request object with a 'aud' claim with the values '%s' which is required match the issuer '%s'.", request.GetClient().GetID(), value, issuer))
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
