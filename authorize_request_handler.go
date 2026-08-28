// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/pkg/errors"

	"authelia.com/provider/oauth2/i18n"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/internal/stringslice"
	"authelia.com/provider/oauth2/token/jwt"
	"authelia.com/provider/oauth2/x/errorsx"
)

// NewAuthorizeRequest parses and validates an authorization endpoint request per RFC 6749 section 3.1 and OpenID
// Connect 1.0. The HTTP method must be GET or POST as defined by the specification; any other method results in
// ErrInvalidRequest. The returned AuthorizeRequester carries the parsed client, scopes, audience, redirect URI and
// response type. Errors from this method should be sent to the client via WriteAuthorizeError.
func (f *Fosite) NewAuthorizeRequest(ctx context.Context, r *http.Request) (AuthorizeRequester, error) {
	switch r.Method {
	case http.MethodGet, http.MethodPost:
		return f.newAuthorizeRequest(ctx, r, false)
	default:
		request := NewAuthorizeRequest()
		request.Lang = i18n.GetLangFromRequest(f.Config.GetMessageCatalog(ctx), r)

		return request, errorsx.WithStack(ErrInvalidRequest.WithHintf("HTTP method is '%s', expected 'GET' or 'POST'.", r.Method))
	}
}

// TODO: Refactor time permitting.
//
//nolint:gocyclo
func (f *Fosite) newAuthorizeRequest(ctx context.Context, r *http.Request, isPARRequest bool) (requester AuthorizeRequester, err error) {
	request := NewAuthorizeRequest()
	request.Lang = i18n.GetLangFromRequest(f.Config.GetMessageCatalog(ctx), r)

	ctx = context.WithValue(ctx, RequestContextKey, r)
	ctx = context.WithValue(ctx, AuthorizeRequestContextKey, request)

	if err = r.ParseMultipartForm(1 << 20); err != nil && err != http.ErrNotMultipart {
		return request, errorsx.WithStack(ErrInvalidRequest.WithHint("Unable to parse HTTP body, make sure to send a properly formatted form request body.").WithWrap(err).WithDebugError(err))
	}

	request.Form = r.Form

	request.State = request.Form.Get(consts.FormParameterState)

	if !isPARRequest {
		var isPAR bool

		if isPAR, err = f.authorizeRequestFromPAR(ctx, r, request); err != nil {
			return request, err
		}

		if isPAR {
			return request, nil
		}

		if config, ok := f.Config.(PushedAuthorizeRequestConfigProvider); ok && config.GetRequirePushedAuthorizationRequests(ctx) {
			return request, errorsx.WithStack(ErrInvalidRequest.WithHint("Pushed Authorization Requests are required but this Authorization Request was not made as a Pushed Authorization Request.").WithDebug("The Authorization Server policy requires Pushed Authorization Requests be used for all clients."))
		}
	}

	var client Client

	if client, err = f.Store.GetClient(ctx, request.GetRequestForm().Get(consts.FormParameterClientID)); err != nil {
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
	if err = f.authorizeRequestParametersFromJAR(ctx, request, isPARRequest); err != nil {
		return request, err
	}

	// The request context is now fully available and we can start processing the individual
	// fields.
	if err = f.ParseResponseMode(ctx, r, request); err != nil {
		return request, err
	}

	if err = f.validateAuthorizeRedirectURI(ctx, r, request); err != nil {
		return request, err
	}

	if err = f.validateScope(ctx, r, request); err != nil {
		return request, err
	}

	if err = ValidateResourceIndicators(request.Form); err != nil {
		return request, err
	}

	if err = f.validateAudience(ctx, r, request); err != nil {
		return request, err
	}

	if len(request.Form.Get(consts.FormParameterRegistration)) > 0 {
		return request, errorsx.WithStack(ErrRegistrationNotSupported)
	}

	if err = f.validateResponseTypes(ctx, r, request); err != nil {
		return request, err
	}

	if err = f.validateResponseMode(ctx, r, request); err != nil {
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
		return request, errorsx.WithStack(ErrInvalidState.WithHintf("Request parameter 'state' must be at least be %d characters long to ensure sufficient entropy.", f.GetMinParameterEntropy(ctx)))
	}

	return request, nil
}

// TODO: Refactor time permitting.
//
//nolint:gocyclo
func (f *Fosite) authorizeRequestParametersFromJAR(ctx context.Context, request *AuthorizeRequest, isPARRequest bool) (err error) {
	var scope Arguments = RemoveEmpty(strings.Split(request.Form.Get(consts.FormParameterScope), " "))

	openid := scope.Has(consts.ScopeOpenID)

	var (
		parameter             string
		nrequest, nrequestURI int
	)

	// The 'require_signed_request_object' authorization server and client metadata values indicate the authorization
	// request must be protected as a Request Object provided by either the 'request' or 'request_uri' parameter.
	//
	// See: https://www.rfc-editor.org/rfc/rfc9101#section-9.2 and https://www.rfc-editor.org/rfc/rfc9101#section-9.3
	required := f.requireSignedRequestObject(ctx, request.Client, isPARRequest)

	switch nrequest, nrequestURI = len(request.Form.Get(consts.FormParameterRequest)), len(request.Form.Get(consts.FormParameterRequestURI)); {
	case nrequest+nrequestURI == 0:
		if required {
			return errorsx.WithStack(ErrInvalidRequest.WithHintf(hintRequestObjectRequired, hintRequestObjectPrefix(openid)).WithDebugf("The OAuth 2.0 client with id '%s' is subject to a policy which requires a signed request object but neither the 'request' nor 'request_uri' parameter was included in the request.", request.GetClient().GetID()))
		}

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
		// A client explicitly registered with a 'request_object_signing_alg' of 'none' can only ever produce an
		// unsigned request object as the registered value is strictly enforced by the header validation below, so this
		// requirement can never be satisfied by such a client.
		if required {
			return errorsx.WithStack(ErrInvalidRequest.WithHintf(hintRequestObjectRequiredSigned, hintRequestObjectPrefix(openid)).WithDebugf("The OAuth 2.0 client with id '%s' is subject to a policy which requires a signed request object but the client is registered with a 'request_object_signing_alg' value of 'none'.", request.GetClient().GetID()))
		}
	case "":
		algAny = true
	case consts.JSONWebTokenAlgHMACSHA256, consts.JSONWebTokenAlgHMACSHA384, consts.JSONWebTokenAlgHMACSHA512:
		if _, ok, err = client.GetClientSecretPlainText(); err != nil {
			return errorsx.WithStack(ErrInvalidRequest.WithHintf("%s parameter '%s' was used, but the OAuth 2.0 Client does not have a compatible secret for the 'request_object_signing_alg' value registered for this client.", hintRequestObjectPrefix(openid), parameter).WithDebugf("The OAuth 2.0 client with id '%s' doesn't have a secret or the secret is a digest which is not compatible with a 'request_object_signing_alg' value of '%s'. Error occurred retrieving the client secret: %+v", request.GetClient().GetID(), alg, err))
		} else if !ok {
			return errorsx.WithStack(ErrInvalidRequest.WithHintf("%s parameter '%s' was used, but the OAuth 2.0 Client does not have a compatible secret for the 'request_object_signing_alg' value registered for this client.", hintRequestObjectPrefix(openid), parameter).WithDebugf("The OAuth 2.0 client with id '%s' doesn't have a secret or the secret is a digest which is not compatible with a 'request_object_signing_alg' value of '%s'.", request.GetClient().GetID(), alg))
		}
	default:
		if client.GetJSONWebKeys() == nil && len(client.GetJSONWebKeysURI()) == 0 {
			return errorsx.WithStack(ErrInvalidRequest.WithHintf("%s parameter '%s' was used, but the OAuth 2.0 Client does not have any JSON Web Keys registered which is required for the 'request_object_signing_alg' value registered for this client.", hintRequestObjectPrefix(openid), parameter).WithDebugf("The OAuth 2.0 client with id '%s' doesn't have any known JSON Web Keys but requires them when not explicitly registered with a 'request_object_signing_alg' with the value of 'none' or an empty value but it's registered with '%s'.", request.GetClient().GetID(), alg))
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

		// RFC9101 Section 10.4.1 requires that a 'request_uri' fetch not become a denial of service or a probe: the
		// location is checked against the registered set above, the request carries the caller's context so a slow
		// origin cannot outlive it, redirects are refused so a registered location cannot hand the fetch to an
		// unregistered one, and the body is bounded.
		//
		// The same section also suggests checking that the response media type is 'application/oauth-authz-req+jwt'.
		// That is not done: the origin chooses the header, so it stops no attack the other three controls do not,
		// while 'text/plain' is what a request object is commonly served as and rejecting it would break those
		// deployments. The content is a JWS verified against the client's registered key regardless.
		//
		// See: https://www.rfc-editor.org/rfc/rfc9101#section-10.4.1
		hc := HTTPClientWithoutRedirects(f.Config.GetHTTPClient(ctx))

		req, err := retryablehttp.NewRequest(http.MethodGet, requestURI, nil)
		if err != nil {
			return errorsx.WithStack(ErrInvalidRequestURI.WithHintf(hintRequestObjectFetchRequestURI, hintRequestObjectPrefix(openid)).WithWrap(err).WithDebugf("The OAuth 2.0 client with id '%s' provided the 'request_uri' parameter with value '%s' which could not be used to build a request: %+v.", request.GetClient().GetID(), requestURI, err))
		}

		response, err := hc.Do(req.WithContext(ctx))
		if err != nil {
			return errorsx.WithStack(ErrInvalidRequestURI.WithHintf(hintRequestObjectFetchRequestURI, hintRequestObjectPrefix(openid)).WithWrap(err).WithDebugf("The OAuth 2.0 client with id '%s' failed to fetch the request object from the URI '%s' with an error: %+v.", request.GetClient().GetID(), requestURI, err))
		}
		defer response.Body.Close()

		if response.StatusCode != http.StatusOK {
			return errorsx.WithStack(ErrInvalidRequestURI.WithHintf(hintRequestObjectFetchRequestURI, hintRequestObjectPrefix(openid)).WithDebugf("The OAuth 2.0 client with id '%s' failed to fetch the request object as the response code was %d %s but a 200 OK is expected.", request.GetClient().GetID(), response.StatusCode, http.StatusText(response.StatusCode)))
		}

		body, err := io.ReadAll(io.LimitReader(response.Body, MaxFetchedBodyBytes))
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

	var (
		allowEmptyType bool
		types          []string
	)

	if vclient, ok := client.(JWTSecuredAuthorizationRequestJWTValidationOptionsClient); ok {
		allowEmptyType = vclient.GetJWTSecuredAuthorizationRequestJWTValidationHeaderAllowEmptyType()
		types = vclient.GetJWTSecuredAuthorizationRequestJWTValidationHeaderAllowTypes()

		if len(types) == 0 {
			types = []string{jwt.JSONWebTokenTypeJWTSecuredAuthorizationRequest, jwt.JSONWebTokenTypeJWT}
		}
	} else {
		allowEmptyType = false
		types = []string{jwt.JSONWebTokenTypeJWTSecuredAuthorizationRequest, jwt.JSONWebTokenTypeJWT}
	}

	optsHeader := []jwt.HeaderValidationOption{
		jwt.ValidateTypes(types...),
		jwt.ValidateAllowEmptyType(allowEmptyType),
		jwt.ValidateKeyID(client.GetRequestObjectSigningKeyID()),
		jwt.ValidateAlgorithm(client.GetRequestObjectSigningAlg()),
		jwt.ValidateEncryptionKeyID(client.GetRequestObjectEncryptionKeyID()),
		jwt.ValidateKeyAlgorithm(client.GetRequestObjectEncryptionAlg()),
		jwt.ValidateContentEncryption(client.GetRequestObjectEncryptionEnc()),
	}

	// This check precedes token.Valid so a client that did not explicitly register 'none' receives the specific
	// reason its unsigned request object was refused. An unsigned token is never marked as having a verified
	// signature, so token.Valid would otherwise reject it first with a generic signature error.
	if algAny && token.SignatureAlgorithm == consts.JSONWebTokenAlgNone {
		return errorsx.WithStack(
			ErrInvalidRequestObject.
				WithHintf("%s client provided a request object that has an invalid 'kid' or 'alg' header value.", hintRequestObjectPrefix(openid)).
				WithDebugf("%s client with id '%s' was not explicitly registered with a 'request_object_signing_alg' value of 'none' but the request object had the 'alg' value 'none' in the header.", hintRequestObjectPrefix(openid), client.GetID()))
	}

	if err = token.Valid(optsHeader...); err != nil {
		return errorsx.WithStack(fmtRequestObjectDecodeError(token, client, issuer, openid, err))
	}

	claims := token.Claims

	var (
		k, value string
		v        any
	)

	for k, v = range claims.ToMapClaims() {
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
			if value, err = requestObjectFormValue(v); err != nil {
				return errorsx.WithStack(ErrInvalidRequestObject.WithHintf(hintRequestObjectInvalidAuthorizationClaim, hintRequestObjectPrefix(openid)).WithDebugf("The OAuth 2.0 client with id '%s' provided a request object with a '%s' claim whose value could not be represented as an authorization request parameter: %v.", request.GetClient().GetID(), k, err))
			}

			request.Form.Set(k, value)
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
		jwt.ValidateDoNotRequireIssuer(),
		jwt.ValidateAudienceAny(issuer),
		jwt.ValidateDoNotRequireAudience(),
	}

	if err = claims.Valid(optsValidClaims...); err != nil {
		return errorsx.WithStack(fmtRequestObjectDecodeError(token, client, issuer, openid, err))
	}

	// RFC9101 Section 6.3 requires the authorization server "MUST only use the parameters in the Request Object,
	// even if the same parameter is provided in the query parameter", so the Request Object's scope is authoritative
	// and the outer query values are discarded rather than merged into it. Unioning them would let any party able to
	// rewrite the authorization URL - a malicious application, an open redirect, a hostile browser extension - add
	// scopes to a signed request, bounded only by the client's registered scope set, defeating the integrity
	// guarantee a signed request object exists to provide.
	//
	// The 'openid' value is the sole exception. OpenID Connect Core 1.0 Section 6.1 requires that "Even if a scope
	// parameter is present in the Request Object value, a scope parameter MUST always be passed using the OAuth 2.0
	// request syntax containing the openid scope value to indicate to the underlying OAuth 2.0 logic that this is an
	// OpenID Connect request", making it a marker for the OAuth 2.0 layer rather than a scope the outer syntax gets
	// to request. It is therefore carried over when the outer syntax marked the request as OpenID Connect, and
	// nothing else is.
	//
	// See: https://www.rfc-editor.org/rfc/rfc9101#section-6.3
	claimScope := RemoveEmpty(strings.Split(request.Form.Get(consts.FormParameterScope), " "))

	if openid && !stringslice.Has(claimScope, consts.ScopeOpenID) {
		claimScope = append(claimScope, consts.ScopeOpenID)
	}

	request.State = request.Form.Get(consts.FormParameterState)
	request.Form.Set(consts.FormParameterScope, strings.Join(claimScope, " "))

	return nil
}

// requestObjectFormValue renders a Request Object claim value as the string the equivalent OAuth 2.0 request syntax
// parameter would have carried.
//
// A claim is not necessarily a string: RFC9101 Section 4 requires that "Numerical values MUST be included as JSON
// numbers", and OpenID Connect Core 1.0 Section 5.5 defines 'claims' as a JSON object, as RFC9396 Section 2 does
// 'authorization_details'. Rendering every value with the %s verb turns the numeric 'max_age' of the specification's
// own example into the literal string '%!s(float64=86400)' and an object into Go map syntax, neither of which any
// consumer can parse - and because the 'max_age' call sites treat a parse failure as absent, that silently disables
// the re-authentication the parameter was sent to demand.
func requestObjectFormValue(v any) (value string, err error) {
	switch t := v.(type) {
	case string:
		return t, nil
	case bool:
		return strconv.FormatBool(t), nil
	case json.Number:
		return t.String(), nil
	case float64:
		// JSON numbers decode to float64, so this is the path a conformant numeric claim takes. The 'f' format with
		// precision -1 renders an integral value without a fractional part or an exponent, so 86400 formats as
		// "86400" rather than "86400.000000" or "8.64e+04".
		return strconv.FormatFloat(t, 'f', -1, 64), nil
	case float32:
		return strconv.FormatFloat(float64(t), 'f', -1, 32), nil
	case int:
		return strconv.Itoa(t), nil
	case int32:
		return strconv.FormatInt(int64(t), 10), nil
	case int64:
		return strconv.FormatInt(t, 10), nil
	case uint:
		return strconv.FormatUint(uint64(t), 10), nil
	case uint32:
		return strconv.FormatUint(uint64(t), 10), nil
	case uint64:
		return strconv.FormatUint(t, 10), nil
	case nil:
		return "", nil
	default:
		// Objects and arrays are carried as JSON text in the OAuth 2.0 request syntax, which is how a client sending
		// 'claims' or 'authorization_details' as a query parameter would have encoded them.
		var data []byte

		if data, err = json.Marshal(t); err != nil {
			return "", err
		}

		return string(data), nil
	}
}

// requireSignedRequestObject determines if the 'require_signed_request_object' policy applies to this request. It
// applies when either the authorization server metadata value of the same name is set, or when the individual client
// is registered with the client metadata value of the same name. The policy is skipped for requests made directly to
// the Pushed Authorization Request endpoint if the authorization server is configured to do so.
//
// See: https://www.rfc-editor.org/rfc/rfc9101#section-9.2 and https://www.rfc-editor.org/rfc/rfc9101#section-9.3
func (f *Fosite) requireSignedRequestObject(ctx context.Context, client Client, isPARRequest bool) (require bool) {
	config, hasConfig := f.Config.(JWTSecuredAuthorizationRequestConfigProvider)

	if isPARRequest && hasConfig && config.GetRequireSignedRequestObjectSkipPushedAuthorizationRequests(ctx) {
		return false
	}

	if hasConfig && config.GetRequireSignedRequestObject(ctx) {
		return true
	}

	if jarc, ok := client.(JARClient); ok && jarc.GetRequireSignedRequestObject() {
		return true
	}

	return false
}

func hintRequestObjectPrefix(openid bool) string {
	if openid {
		return hintRequestObjectPrefixOpenID
	}

	return hintRequestObjectPrefixJAR
}

func (f *Fosite) validateAuthorizeRedirectURI(_ context.Context, _ *http.Request, request *AuthorizeRequest) (err error) {
	raw := request.GetRequestForm().Get(consts.FormParameterRedirectURI)

	// This ensures that the 'redirect_uri' parameter is present for OpenID Connect 1.0 authorization requests as per:
	//
	// Authorization Code Flow - https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
	// Implicit Flow - https://openid.net/specs/openid-connect-core-1_0.html#ImplicitAuthRequest
	// Hybrid Flow - https://openid.net/specs/openid-connect-core-1_0.html#HybridAuthRequest
	//
	// Note: As per the Hybrid Flow documentation the Hybrid Flow has the same requirements as the Authorization Code Flow.
	if len(raw) == 0 && Arguments(RemoveEmpty(strings.Split(request.GetRequestForm().Get(consts.FormParameterScope), " "))).Has(consts.ScopeOpenID) {
		return errorsx.WithStack(ErrInvalidRequest.WithHint("The 'redirect_uri' parameter is required when using OpenID Connect 1.0."))
	}

	var redirectURI *url.URL

	if redirectURI, err = MatchRedirectURIWithClientRedirectURIs(raw, request.Client); err != nil {
		return err
	} else if !IsValidRedirectURI(redirectURI) {
		return errorsx.WithStack(ErrInvalidRequest.WithHintf("The redirect URI '%s' contains an illegal character (for example #) or is otherwise invalid.", redirectURI))
	}

	request.RedirectURI = redirectURI

	return nil
}

func (f *Fosite) validateScope(ctx context.Context, _ *http.Request, request Requester) error {
	requested := RemoveEmpty(strings.Split(request.GetRequestForm().Get(consts.FormParameterScope), " "))

	client := request.GetClient()
	strategy := GetScopeStrategy(ctx, f.Config, client)
	scopes := client.GetScopes()

	for _, scope := range requested {
		if !strategy(scopes, scope) {
			return errorsx.WithStack(ErrInvalidScope.WithHintf("The OAuth 2.0 Client is not allowed to request scope '%s'.", scope))
		}
	}

	request.SetRequestedScopes(requested)

	return nil
}

func (f *Fosite) validateResponseTypes(_ context.Context, r *http.Request, request *AuthorizeRequest) error {
	// https://datatracker.ietf.org/doc/html/rfc6749#section-3.1.1
	// Extension response types MAY contain a space-delimited (%x20) list of
	// values, where the order of values does not matter (e.g., response
	// type "a b" is the same as "b a").  The meaning of such composite
	// response types is defined by their respective specifications.
	responseTypes := RemoveEmpty(strings.Split(r.Form.Get(consts.FormParameterResponseType), " "))
	if len(responseTypes) == 0 {
		return errorsx.WithStack(ErrUnsupportedResponseType.WithHint("The request is missing the 'response_type' parameter."))
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

// ParseResponseMode reads the 'response_mode' query parameter from r and, if a configured ResponseModeHandler supports
// it, records it on the request. It returns ErrInsufficientEntropy if the form parameter has insufficient entropy and
// ErrUnsupportedResponseMode for unrecognized values.
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

func (f *Fosite) validateResponseMode(_ context.Context, _ *http.Request, request *AuthorizeRequest) error {
	if request.ResponseMode == ResponseModeDefault {
		return nil
	}

	client, ok := request.GetClient().(ResponseModeClient)
	if !ok {
		return errorsx.WithStack(ErrUnsupportedResponseMode.WithHintf("The 'response_mode' requested was '%s', but the Authorization Server or registered OAuth 2.0 client doesn't allow or support this mode.", request.ResponseMode).WithDebugf("The registered OAuth 2.0 Client with id '%s' does not the 'response_mode' type '%s', as it's not registered to support any.", request.GetClient().GetID(), request.ResponseMode))
	}

	if !slices.Contains(client.GetResponseModes(), request.ResponseMode) {
		return errorsx.WithStack(ErrUnsupportedResponseMode.WithHintf("The 'response_mode' requested was '%s', but the Authorization Server or registered OAuth 2.0 client doesn't allow or support this mode.", request.ResponseMode).WithDebugf("The registered OAuth 2.0 Client with id '%s' does not the 'response_mode' type '%s'.", client.GetID(), request.ResponseMode))
	}

	return nil
}

func (f *Fosite) authorizeRequestFromPAR(ctx context.Context, r *http.Request, request *AuthorizeRequest) (isPAR bool, err error) {
	var (
		config     PushedAuthorizeRequestConfigProvider
		storage    PARStorage
		requestURI string
		ok         bool
	)

	if config, ok = f.Config.(PushedAuthorizeRequestConfigProvider); !ok {
		return false, nil
	}

	if requestURI = r.Form.Get(consts.FormParameterRequestURI); requestURI == "" {
		return false, nil
	}

	if !strings.HasPrefix(requestURI, config.GetPushedAuthorizeRequestURIPrefix(ctx)) {
		return false, nil
	}

	if storage, ok = f.Store.(PARStorage); !ok {
		return false, errorsx.WithStack(ErrServerError.WithHint(ErrorPARNotSupported).WithDebug(DebugPARStorageInvalid))
	}

	clientID := r.Form.Get(consts.FormParameterClientID)

	var par AuthorizeRequester
	if par, err = storage.GetPARSession(ctx, requestURI); err != nil {
		return false, errorsx.WithStack(ErrInvalidRequestURI.WithHint("The 'request_uri' provided is invalid, expired, or otherwise incorrect.").WithWrap(err).WithDebugError(err))
	} else if par == nil {
		return false, errorsx.WithStack(ErrServerError.WithHint("OAuth 2.0 request could not be processed due to an authorization server configuration issue.").WithDebug("The Pushed Authorization Request is nil."))
	}

	request.Merge(par)
	request.RedirectURI = par.GetRedirectURI()
	request.ResponseTypes = par.GetResponseTypes()
	request.State = par.GetState()
	request.ResponseMode = par.GetResponseMode()

	if err = storage.DeletePARSession(ctx, requestURI); err != nil {
		return false, errorsx.WithStack(ErrServerError.WithWrap(err).WithDebugError(err))
	}

	if session := par.GetSession(); session == nil || session.GetExpiresAt(PushedAuthorizeRequestContext).Before(time.Now()) {
		return false, errorsx.WithStack(ErrInvalidRequestURI.WithHint("The 'request_uri' provided is invalid, expired, or otherwise incorrect.").WithDebug("The Pushed Authorization Request session is expired."))
	}

	if clientID != request.GetClient().GetID() {
		return false, errorsx.WithStack(ErrInvalidRequest.WithHint("The 'client_id' must match the one sent in the pushed authorization request."))
	}

	return true, nil
}

//nolint:gocyclo
func fmtRequestObjectDecodeError(token *jwt.Token, client JARClient, issuer string, openid bool, inner error) (outer *RFC6749Error) {
	outer = ErrInvalidRequestObject.WithWrap(inner).WithHintf("%s request object could not be decoded or validated.", hintRequestObjectPrefix(openid))

	if errJWTValidation := new(jwt.ValidationError); errors.As(inner, &errJWTValidation) {
		switch {
		case errJWTValidation.Has(jwt.ValidationErrorHeaderKeyIDInvalid):
			return outer.WithDebugf("%s client with id '%s' expects request objects to be signed with the 'kid' header value '%s' due to the client registration 'request_object_signing_key_id' value but the request object was signed with the 'kid' header value '%s'.", hintRequestObjectPrefix(openid), client.GetID(), client.GetRequestObjectSigningKeyID(), token.KeyID)
		case errJWTValidation.Has(jwt.ValidationErrorHeaderAlgorithmInvalid):
			return outer.WithDebugf("%s client with id '%s' expects request objects to be signed with the 'alg' header value '%s' due to the client registration 'request_object_signing_alg' value but the request object was signed with the 'alg' header value '%s'.", hintRequestObjectPrefix(openid), client.GetID(), client.GetRequestObjectSigningAlg(), token.SignatureAlgorithm)
		case errJWTValidation.Has(jwt.ValidationErrorHeaderTypeInvalid):
			return outer.WithDebugf("%s client with id '%s' expects request objects to be signed with the 'typ' header value '%s' but the request object was signed with the 'typ' header value '%s'.", hintRequestObjectPrefix(openid), client.GetID(), consts.JSONWebTokenTypeJWT, headerValueString(consts.JSONWebTokenHeaderType, token.Header))
		case errJWTValidation.Has(jwt.ValidationErrorHeaderEncryptionTypeInvalid):
			return outer.WithDebugf("%s client with id '%s' expects request objects to be encrypted with the 'typ' header value '%s' but the request object was encrypted with the 'typ' header value '%s'.", hintRequestObjectPrefix(openid), client.GetID(), consts.JSONWebTokenTypeJWT, headerValueString(consts.JSONWebTokenHeaderType, token.HeaderJWE))
		case errJWTValidation.Has(jwt.ValidationErrorHeaderContentTypeInvalidMismatch):
			return outer.WithDebugf("%s client with id '%s' expects request objects to be encrypted with a 'cty' header value and signed with a 'typ' value that match but the request object was encrypted with the 'cty' header value '%s' and signed with the 'typ' header value '%s'.", hintRequestObjectPrefix(openid), client.GetID(), headerValueString(consts.JSONWebTokenHeaderContentType, token.HeaderJWE), headerValueString(consts.JSONWebTokenHeaderType, token.HeaderJWE))
		case errJWTValidation.Has(jwt.ValidationErrorHeaderContentTypeInvalid):
			return outer.WithDebugf("%s client with id '%s' expects request objects to be encrypted with the 'cty' header value '%s' but the request object was encrypted with the 'cty' header value '%s'.", hintRequestObjectPrefix(openid), client.GetID(), consts.JSONWebTokenTypeJWT, headerValueString(consts.JSONWebTokenHeaderContentType, token.HeaderJWE))
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
			exp, err := token.Claims.GetExpirationTime()
			if err == nil {
				return outer.WithDebugf("%s client with id '%s' provided a request object that was expired. The request object expired at %d.", hintRequestObjectPrefix(openid), client.GetID(), exp.Int64())
			} else {
				return outer.WithDebugf("%s client with id '%s' provided a request object that was expired. The request object does not have an 'exp' claim or it has an invalid type.", hintRequestObjectPrefix(openid), client.GetID())
			}
		case errJWTValidation.Has(jwt.ValidationErrorIssuedAt):
			iat, err := token.Claims.GetIssuedAt()
			if err == nil {
				return outer.WithDebugf("%s client with id '%s' provided a request object that was issued in the future. The request object was issued at %d.", hintRequestObjectPrefix(openid), client.GetID(), iat.Int64())
			} else {
				return outer.WithDebugf("%s client with id '%s' provided a request object that was issued in the future. The request object does not have an 'iat' claim or it has an invalid type.", hintRequestObjectPrefix(openid), client.GetID())
			}
		case errJWTValidation.Has(jwt.ValidationErrorNotValidYet):
			nbf, err := token.Claims.GetNotBefore()
			if err == nil {
				return outer.WithDebugf("%s client with id '%s' provided a request object that was issued in the future. The request object is not valid before %d.", hintRequestObjectPrefix(openid), client.GetID(), nbf.Int64())
			} else {
				return outer.WithDebugf("%s client with id '%s' provided a request object that was issued in the future. The request object does not have an 'nbf' claim or it has an invalid type.", hintRequestObjectPrefix(openid), client.GetID())
			}
		case errJWTValidation.Has(jwt.ValidationErrorIssuer):
			iss, err := token.Claims.GetIssuer()
			if err == nil {
				return outer.WithDebugf("%s client with id '%s' provided a request object that has an invalid issuer. The request object was expected to have an 'iss' claim which matches the value '%s' but the 'iss' claim had the value '%s'.", hintRequestObjectPrefix(openid), client.GetID(), client.GetID(), iss)
			} else {
				return outer.WithDebugf("%s client with id '%s' provided a request object that has an invalid issuer. The request object does not have an 'iss' claim or it has an invalid type.", hintRequestObjectPrefix(openid), client.GetID())
			}
		case errJWTValidation.Has(jwt.ValidationErrorAudience):
			aud, err := token.Claims.GetAudience()
			if err == nil {
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

func headerValueString(key string, headers map[string]any) string {
	if value, ok := headers[key]; !ok || value == nil {
		return ""
	} else {
		return fmt.Sprintf("%s", value)
	}
}
