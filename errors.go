// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"encoding/json"
	stderr "errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/pkg/errors"
	"golang.org/x/text/language"

	"authelia.com/provider/oauth2/i18n"
	"authelia.com/provider/oauth2/x/errorsx"
)

var (
	// ErrInvalidatedAuthorizeCode is a library-internal storage sentinel indicating that an authorization code has been
	// used previously.
	ErrInvalidatedAuthorizeCode = errors.New("Authorization code has ben invalidated")

	// ErrInvalidatedDeviceCode is a library-internal storage sentinel indicating that a device_code has been used
	// previously.
	ErrInvalidatedDeviceCode = errors.New("Device code has been invalidated")

	// ErrInvalidatedUserCode is a library-internal storage sentinel indicating that a user_code has been used
	// previously.
	ErrInvalidatedUserCode = errors.New("user code has been invalidated")

	// ErrSerializationFailure is a library-internal storage sentinel indicating that the transactional storage backend
	// could not guarantee Read-Modify-Write consistency across concurrent sessions.
	ErrSerializationFailure = errors.New("The request could not be completed due to concurrent access")

	// ErrUnknownRequest is the library-internal sentinel returned by handlers to signal that they are not responsible
	// for the current request. It is not defined by any specification.
	ErrUnknownRequest = &RFC6749Error{
		ErrorField:       errUnknownErrorName,
		DescriptionField: "The handler is not responsible for this request.",
		CodeField:        http.StatusBadRequest,
	}

	// ErrRequestForbidden is a library-internal error returned when a request is rejected at policy level. It is not
	// defined by any specification.
	ErrRequestForbidden = &RFC6749Error{
		ErrorField:       errRequestForbiddenName,
		DescriptionField: "The request is not allowed.",
		HintField:        "You are not allowed to perform this action.",
		CodeField:        http.StatusForbidden,
	}

	// ErrInvalidRequest is the standard 'invalid_request' error code.
	//
	// See:
	//   - OAuth 2.0 Authorization Endpoint:	https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1
	//   - OAuth 2.0 Token Endpoint:		https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
	//   - OAuth 2.0 Bearer Token Usage:	https://datatracker.ietf.org/doc/html/rfc6750#section-3.1
	ErrInvalidRequest = &RFC6749Error{
		ErrorField:       errInvalidRequestName,
		DescriptionField: "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed.",
		HintField:        "Make sure that the various parameters are correct, be aware of case sensitivity and trim your parameters. Make sure that the client you are using has exactly whitelisted the redirect_uri you specified.",
		CodeField:        http.StatusBadRequest,
	}

	// ErrUnauthorizedClient is the standard 'unauthorized_client' error code returned when the authenticated client is
	// not permitted to use the requested grant type or response type.
	//
	// See:
	//   - OAuth 2.0 Authorization Endpoint:	https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1
	//   - OAuth 2.0 Token Endpoint:		https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
	ErrUnauthorizedClient = &RFC6749Error{
		ErrorField:       errUnauthorizedClientName,
		DescriptionField: "The client is not authorized to request a token using this method.",
		HintField:        "Make sure that client id and secret are correctly specified and that the client exists.",
		CodeField:        http.StatusBadRequest,
	}

	// ErrAccessDenied is the standard 'access_denied' error code returned when the resource owner or the authorization
	// server denied the request. It is reused by OpenID Connect, CIBA and the Device Authorization Grant.
	//
	// See:
	//   - OAuth 2.0 Authorization Endpoint:	https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1
	//   - Device Authorization Grant:		https://datatracker.ietf.org/doc/html/rfc8628#section-3.5
	//   - CIBA Token Endpoint:		https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#token_error_response
	ErrAccessDenied = &RFC6749Error{
		ErrorField:       errAccessDeniedName,
		DescriptionField: "The resource owner or authorization server denied the request.",
		HintField:        "Make sure that the request you are making is valid. Maybe the credential or request parameters you are using are limited in scope or otherwise restricted.",
		CodeField:        http.StatusForbidden,
	}

	// ErrUnsupportedResponseType is the standard 'unsupported_response_type' error code returned when the authorization
	// server does not support obtaining a response using the requested response_type.
	//
	// See OAuth 2.0 Authorization Endpoint: https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1.
	ErrUnsupportedResponseType = &RFC6749Error{
		ErrorField:       errUnsupportedResponseTypeName,
		DescriptionField: "The authorization server does not support obtaining a token using this method.",
		CodeField:        http.StatusBadRequest,
	}

	// ErrUnsupportedResponseMode is the standard 'unsupported_response_mode' error code returned when the authorization
	// server does not support the requested response_mode value.
	//
	// See OAuth 2.0 Multiple Response Type Encoding Practices §5:
	// https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#Terminology
	ErrUnsupportedResponseMode = &RFC6749Error{
		ErrorField:       errUnsupportedResponseModeName,
		DescriptionField: "The authorization server does not support obtaining a response using this response mode.",
		CodeField:        http.StatusBadRequest,
	}

	// ErrInvalidScope is the standard 'invalid_scope' error code returned when the requested scope is invalid, unknown,
	// or malformed (and, at the token endpoint, when it exceeds the granted scope).
	//
	// See:
	//   - OAuth 2.0 Authorization Endpoint:	https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1
	//   - OAuth 2.0 Token Endpoint:		https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
	ErrInvalidScope = &RFC6749Error{
		ErrorField:       errInvalidScopeName,
		DescriptionField: "The requested scope is invalid, unknown, or malformed.",
		CodeField:        http.StatusBadRequest,
	}

	// ErrInsufficientScope is the standard 'insufficient_scope' error code returned by a protected resource when the
	// access token does not contain the scope necessary to access the resource.
	//
	// See OAuth 2.0 Bearer Token Usage §3.1: https://datatracker.ietf.org/doc/html/rfc6750#section-3.1.
	ErrInsufficientScope = &RFC6749Error{
		ErrorField:       errInsufficientScopeName,
		DescriptionField: "The request requires higher privileges than provided by the Access Token.",
		CodeField:        http.StatusForbidden,
	}

	// ErrServerError is the standard 'server_error' error code returned when the authorization server encountered an
	// unexpected condition. The HTTP 500 status code is used for direct responses; the code itself exists because that
	// status cannot be returned to the client via an HTTP redirect.
	//
	// See OAuth 2.0 Authorization Endpoint: https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1.
	ErrServerError = &RFC6749Error{
		ErrorField:       errServerErrorName,
		DescriptionField: errServerErrorDescription,
		CodeField:        http.StatusInternalServerError,
	}

	// ErrTemporarilyUnavailable is the standard 'temporarily_unavailable' error code returned when the authorization
	// server is overloaded or undergoing maintenance.
	//
	// See OAuth 2.0 Authorization Endpoint: https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1.
	ErrTemporarilyUnavailable = &RFC6749Error{
		ErrorField:       errTemporarilyUnavailableName,
		DescriptionField: "The authorization server is currently unable to handle the request due to a temporary overloading or maintenance of the server.",
		CodeField:        http.StatusServiceUnavailable,
	}

	// ErrUnsupportedGrantType is the standard 'unsupported_grant_type' error code returned when the requested
	// grant_type value is not supported by the authorization server.
	//
	// See OAuth 2.0 Token Endpoint: https://datatracker.ietf.org/doc/html/rfc6749#section-5.2.
	ErrUnsupportedGrantType = &RFC6749Error{
		ErrorField:       errUnsupportedGrantTypeName,
		DescriptionField: "The authorization grant type is not supported by the authorization server.",
		CodeField:        http.StatusBadRequest,
	}

	// ErrInvalidGrant is the standard 'invalid_grant' error code returned when the provided authorization grant or
	// refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request,
	// or was issued to another client.
	//
	// See OAuth 2.0 Token Endpoint: https://datatracker.ietf.org/doc/html/rfc6749#section-5.2.
	ErrInvalidGrant = &RFC6749Error{
		ErrorField:       errInvalidGrantName,
		DescriptionField: "The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client.",
		CodeField:        http.StatusBadRequest,
	}

	// ErrInvalidClient is the standard 'invalid_client' error code returned when client authentication failed at the
	// token endpoint. The HTTP 401 (Unauthorized) status code is mandated when the request includes Authorization
	// header credentials per OAuth 2.0 §5.2.
	//
	// See OAuth 2.0 Token Endpoint: https://datatracker.ietf.org/doc/html/rfc6749#section-5.2.
	ErrInvalidClient = &RFC6749Error{
		ErrorField:       errInvalidClientName,
		DescriptionField: "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method).",
		CodeField:        http.StatusUnauthorized,
	}
	// ErrInvalidState is a library-internal error returned when the state parameter is missing or has insufficient
	// entropy. It is not defined by any specification (RFC 6749 only describes the parameter, not a dedicated error
	// code).
	ErrInvalidState = &RFC6749Error{
		ErrorField:       errInvalidStateName,
		DescriptionField: "The state is missing or does not have enough characters and is therefore considered too weak.",
		CodeField:        http.StatusBadRequest,
	}

	// ErrMisconfiguration is a library-internal error indicating broken handler wiring or configuration. It is not
	// defined by any specification.
	ErrMisconfiguration = &RFC6749Error{
		ErrorField:       errMisconfigurationName,
		DescriptionField: "The request failed because of an internal error that is probably caused by misconfiguration.",
		CodeField:        http.StatusInternalServerError,
	}

	// ErrInsufficientEntropy is a library-internal error returned when a security parameter such as 'state' or 'nonce'
	// has insufficient entropy. It is not defined by any specification.
	ErrInsufficientEntropy = &RFC6749Error{
		ErrorField:       errInsufficientEntropyName,
		DescriptionField: "The request used a security parameter (e.g., anti-replay, anti-csrf) with insufficient entropy.",
		CodeField:        http.StatusBadRequest,
	}

	// ErrNotFound is a library-internal error returned when a requested resource (e.g. a stored session) cannot be
	// found. It is not defined by any specification.
	ErrNotFound = &RFC6749Error{
		ErrorField:       errNotFoundName,
		DescriptionField: "Could not find the requested resource(s).",
		CodeField:        http.StatusNotFound,
	}

	// ErrRequestUnauthorized is a library-internal error returned when a request cannot be authorized. It is not
	// defined by any specification.
	ErrRequestUnauthorized = &RFC6749Error{
		ErrorField:       errRequestUnauthorizedName,
		DescriptionField: "The request could not be authorized.",
		HintField:        "Check that you provided valid credentials in the right format.",
		CodeField:        http.StatusUnauthorized,
	}

	// ErrTokenSignatureMismatch is a library-internal error returned when a token's signature fails verification. It is
	// not defined by any specification.
	ErrTokenSignatureMismatch = &RFC6749Error{
		ErrorField:       errTokenSignatureMismatchName,
		DescriptionField: "Token signature mismatch.",
		HintField:        "Check that you provided a valid token in the right format.",
		CodeField:        http.StatusBadRequest,
	}

	// ErrInvalidTokenFormat uses the standard 'invalid_token' error code from OAuth 2.0 Bearer Token Usage to signal a
	// malformed token. The 401 status mandated by RFC 6750 is applied by ErrTokenExpired instead; this variant is
	// retained at 400 for use outside the protected-resource context where a malformed request body or token parameter
	// triggers the error.
	//
	// See OAuth 2.0 Bearer Token Usage §3.1: https://datatracker.ietf.org/doc/html/rfc6750#section-3.1.
	ErrInvalidTokenFormat = &RFC6749Error{
		ErrorField:       errInvalidTokenFormatName,
		DescriptionField: "The token provided is expired, revoked, malformed, or invalid for other reasons.",
		HintField:        "Check that you provided a valid token in the right format.",
		CodeField:        http.StatusBadRequest,
	}

	// ErrTokenExpired uses the standard 'invalid_token' error code from OAuth 2.0 Bearer Token Usage. The 401 status
	// matches the SHOULD requirement in RFC 6750 §3.1 for protected-resource responses.
	//
	// See OAuth 2.0 Bearer Token Usage §3.1: https://datatracker.ietf.org/doc/html/rfc6750#section-3.1.
	ErrTokenExpired = &RFC6749Error{
		ErrorField:       errTokenExpiredName,
		DescriptionField: "Token expired.",
		HintField:        "The token expired.",
		CodeField:        http.StatusUnauthorized,
	}

	// ErrScopeNotGranted is a library-internal error returned when the token was not granted a requested scope. It is
	// not defined by any specification (cf. ErrInsufficientScope which is the spec-defined code for protected
	// resources).
	ErrScopeNotGranted = &RFC6749Error{
		ErrorField:       errScopeNotGrantedName,
		DescriptionField: "The token was not granted the requested scope.",
		HintField:        "The resource owner did not grant the requested scope.",
		CodeField:        http.StatusForbidden,
	}

	// ErrTokenClaim is a library-internal error returned when a token claim fails validation. It is not defined by any
	// specification.
	ErrTokenClaim = &RFC6749Error{
		ErrorField:       errTokenClaimName,
		DescriptionField: "The token failed validation due to a claim mismatch.",
		HintField:        "One or more token claims failed validation.",
		CodeField:        http.StatusUnauthorized,
	}

	// ErrInactiveToken is a library-internal error returned during token introspection when the introspected token is
	// not active. RFC 7662 conveys inactivity via {"active": false} on the introspection response itself rather than a
	// dedicated error code, so this code is library-specific.
	//
	// See OAuth 2.0 Token Introspection: https://datatracker.ietf.org/doc/html/rfc7662#section-2.2.
	ErrInactiveToken = &RFC6749Error{
		ErrorField:       errTokenInactiveName,
		DescriptionField: "Token is inactive because it is malformed, expired or otherwise invalid.",
		HintField:        "Token validation failed.",
		CodeField:        http.StatusUnauthorized,
	}
	// ErrLoginRequired is the OpenID Connect 'login_required' error code returned when the Authorization Server requires
	// End-User authentication and 'prompt=none' was requested.
	//
	// See OpenID Connect Core §3.1.2.6: https://openid.net/specs/openid-connect-core-1_0.html#AuthError.
	ErrLoginRequired = &RFC6749Error{
		ErrorField:       errLoginRequiredName,
		DescriptionField: "The Authorization Server requires End-User authentication.",
		CodeField:        http.StatusBadRequest,
	}

	// ErrInteractionRequired is the OpenID Connect 'interaction_required' error code returned when the Authorization
	// Server requires End-User interaction of some form and 'prompt=none' was requested.
	//
	// See OpenID Connect Core §3.1.2.6: https://openid.net/specs/openid-connect-core-1_0.html#AuthError.
	ErrInteractionRequired = &RFC6749Error{
		DescriptionField: "The Authorization Server requires End-User interaction of some form to proceed.",
		ErrorField:       errInteractionRequiredName,
		CodeField:        http.StatusBadRequest,
	}

	// ErrConsentRequired is the OpenID Connect 'consent_required' error code returned when the Authorization Server
	// requires End-User consent and 'prompt=none' was requested.
	//
	// See OpenID Connect Core §3.1.2.6: https://openid.net/specs/openid-connect-core-1_0.html#AuthError.
	ErrConsentRequired = &RFC6749Error{
		ErrorField:       errConsentRequiredName,
		DescriptionField: "The Authorization Server requires End-User consent.",
		CodeField:        http.StatusBadRequest,
	}

	// ErrAccountSelectionRequired is the OpenID Connect 'account_selection_required' error code returned when the
	// End-User is required to select a session at the Authorization Server (typically when 'prompt=none' was used and
	// multiple sessions are active).
	//
	// See OpenID Connect Core §3.1.2.6: https://openid.net/specs/openid-connect-core-1_0.html#AuthError.
	ErrAccountSelectionRequired = &RFC6749Error{
		ErrorField:       errAccountSelectionRequiredName,
		DescriptionField: "The End-User is required to select a session at the Authorization Server.",
		CodeField:        http.StatusBadRequest,
	}

	// ErrRequestNotSupported is the OpenID Connect 'request_not_supported' error code returned when the OP does not
	// support the 'request' authorization request parameter.
	//
	// See OpenID Connect Core §3.1.2.6: https://openid.net/specs/openid-connect-core-1_0.html#AuthError.
	ErrRequestNotSupported = &RFC6749Error{
		ErrorField:       errRequestNotSupportedName,
		DescriptionField: "The authorization server does not support the use of the request parameter.",
		CodeField:        http.StatusBadRequest,
	}

	// ErrRequestURINotSupported is the OpenID Connect 'request_uri_not_supported' error code returned when the OP does
	// not support the 'request_uri' authorization request parameter.
	//
	// See OpenID Connect Core §3.1.2.6: https://openid.net/specs/openid-connect-core-1_0.html#AuthError.
	ErrRequestURINotSupported = &RFC6749Error{
		ErrorField:       errRequestURINotSupportedName,
		DescriptionField: "The authorization server does not support the use of the request_uri parameter.",
		CodeField:        http.StatusBadRequest,
	}

	// ErrRegistrationNotSupported is the OpenID Connect 'registration_not_supported' error code returned when the OP
	// does not support the 'registration' authorization request parameter.
	//
	// See OpenID Connect Core §3.1.2.6: https://openid.net/specs/openid-connect-core-1_0.html#AuthError.
	ErrRegistrationNotSupported = &RFC6749Error{
		ErrorField:       errRegistrationNotSupportedName,
		DescriptionField: "The OP does not support use of the registration parameter.",
		CodeField:        http.StatusBadRequest,
	}

	// ErrInvalidRequestURI is the OpenID Connect 'invalid_request_uri' error code returned when the request_uri in the
	// authorization request returns an error or contains invalid data.
	//
	// See:
	//   - OpenID Connect Core §6.3.2:	https://openid.net/specs/openid-connect-core-1_0.html#RequestUriRationale
	//   - OAuth 2.0 PAR §2.3:		https://datatracker.ietf.org/doc/html/rfc9126#section-2.3
	ErrInvalidRequestURI = &RFC6749Error{
		ErrorField:       errInvalidRequestURIName,
		DescriptionField: "The request_uri in the authorization request returns an error or contains invalid data.",
		CodeField:        http.StatusBadRequest,
	}

	// ErrInvalidRequestObject is the OpenID Connect 'invalid_request_object' error code returned when the 'request'
	// parameter contains an invalid Request Object.
	//
	// See OpenID Connect Core §6.3.2: https://openid.net/specs/openid-connect-core-1_0.html#RequestUriRationale.
	ErrInvalidRequestObject = &RFC6749Error{
		ErrorField:       errInvalidRequestObjectName,
		DescriptionField: "The request parameter contains an invalid Request Object.",
		CodeField:        http.StatusBadRequest,
	}

	// ErrJTIKnown is a library-internal error returned when a previously-seen 'jti' is replayed in an RFC 7523 JWT
	// client assertion or JWT bearer grant. It is not defined by a specification; RFC 7523 §3 requires servers to
	// detect replay but does not mandate a specific error code (typically 'invalid_grant' is used).
	//
	// See OAuth 2.0 JWT Profile for Client Authentication and Grants §3: https://datatracker.ietf.org/doc/html/rfc7523#section-3.
	ErrJTIKnown = &RFC6749Error{
		ErrorField:       errJTIKnownName,
		DescriptionField: "The jti was already used.",
		CodeField:        http.StatusBadRequest,
	}
	// ErrAuthorizationPending is the standard 'authorization_pending' error code returned at the token endpoint while
	// the end user has not yet completed the user-interaction steps. It applies to both the Device Authorization Grant
	// and OpenID Connect CIBA polling.
	//
	// See:
	//   - RFC 8628 §3.5:	https://datatracker.ietf.org/doc/html/rfc8628#section-3.5
	//   - CIBA §11:	https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#token_error_response
	ErrAuthorizationPending = &RFC6749Error{
		ErrorField:       errAuthorizationPendingName,
		DescriptionField: "The authorization request is still pending as the end user hasn't yet completed the user-interaction steps.",
		CodeField:        http.StatusBadRequest,
	}

	// ErrDeviceExpiredToken is the standard 'expired_token' error code returned at the token endpoint when the
	// device_code or auth_req_id has expired and the authorization session has concluded. It applies to both the
	// Device Authorization Grant and OpenID Connect CIBA.
	//
	// See:
	//   - RFC 8628 §3.5:	https://datatracker.ietf.org/doc/html/rfc8628#section-3.5
	//   - CIBA §11:	https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#token_error_response
	ErrDeviceExpiredToken = &RFC6749Error{
		ErrorField:       errDeviceExpiredTokenName,
		DescriptionField: "The device_code has expired, and the device authorization session has concluded.",
		CodeField:        http.StatusBadRequest,
	}

	// ErrSlowDown is the standard 'slow_down' error code returned at the token endpoint to instruct the polling client
	// to increase its polling interval by 5 seconds. It applies to both the Device Authorization Grant and OpenID
	// Connect CIBA.
	//
	// See:
	//   - RFC 8628 §3.5:	https://datatracker.ietf.org/doc/html/rfc8628#section-3.5
	//   - CIBA §11:	https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#token_error_response
	ErrSlowDown = &RFC6749Error{
		ErrorField:       errSlowDownName,
		DescriptionField: "Too many requests within a short time period.",
		CodeField:        http.StatusBadRequest,
	}

	// ErrInvalidTarget is the standard 'invalid_target' error code from OAuth 2.0 Resource Indicators returned when the
	// requested 'resource' parameter is unknown, malformed, or not permitted for the client.
	//
	// See OAuth 2.0 Resource Indicators §2: https://datatracker.ietf.org/doc/html/rfc8707#section-2.
	ErrInvalidTarget = &RFC6749Error{
		ErrorField:       errInvalidTargetName,
		DescriptionField: "The requested resource is invalid, missing, unknown, or malformed.",
		HintField:        "Ensure the requested resource is an absolute URI without a fragment component that identifies a resource server known to the authorization server and that it is permitted for this client.",
		CodeField:        http.StatusBadRequest,
	}

	// ErrExpiredLoginHintToken is the OpenID Connect CIBA 'expired_login_hint_token' error code returned at the
	// backchannel authentication endpoint when the supplied login_hint_token has expired.
	//
	// See OpenID Connect CIBA §13: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#auth_error_response.
	ErrExpiredLoginHintToken = &RFC6749Error{
		ErrorField:       errExpiredLoginHintTokenName,
		DescriptionField: "The login_hint_token provided in the authentication request is not valid because it has expired.",
		CodeField:        http.StatusBadRequest,
	}

	// ErrUnknownUserID is the OpenID Connect CIBA 'unknown_user_id' error code returned at the backchannel
	// authentication endpoint when the OP cannot identify the end user from the supplied hint.
	//
	// See OpenID Connect CIBA §13: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#auth_error_response.
	ErrUnknownUserID = &RFC6749Error{
		ErrorField:       errUnknownUserIDName,
		DescriptionField: "The OpenID Provider is not able to identify which end-user the client wishes to be authenticated by means of the hint provided in the request.",
		CodeField:        http.StatusBadRequest,
	}

	// ErrMissingUserCode is the OpenID Connect CIBA 'missing_user_code' error code returned at the backchannel
	// authentication endpoint when the OP requires a user_code and the client did not supply one.
	//
	// See OpenID Connect CIBA §13: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#auth_error_response.
	ErrMissingUserCode = &RFC6749Error{
		ErrorField:       errMissingUserCodeName,
		DescriptionField: "User code is required but was missing from the request.",
		CodeField:        http.StatusBadRequest,
	}

	// ErrInvalidUserCode is the OpenID Connect CIBA 'invalid_user_code' error code returned at the backchannel
	// authentication endpoint when the supplied user_code does not match.
	//
	// See OpenID Connect CIBA §13: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#auth_error_response.
	ErrInvalidUserCode = &RFC6749Error{
		ErrorField:       errInvalidUserCodeName,
		DescriptionField: "The user code was invalid.",
		CodeField:        http.StatusBadRequest,
	}

	// ErrInvalidBindingMessage is the OpenID Connect CIBA 'invalid_binding_message' error code returned at the
	// backchannel authentication endpoint when the supplied binding_message contains characters or has a length the OP
	// finds unacceptable.
	//
	// See OpenID Connect CIBA §13: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#auth_error_response.
	ErrInvalidBindingMessage = &RFC6749Error{
		ErrorField:       errInvalidBindingMessageName,
		DescriptionField: "The binding message is invalid or unacceptable for use in the context of the given request.",
		CodeField:        http.StatusBadRequest,
	}

	// ErrTransactionFailed is the OpenID Connect CIBA 'transaction_failed' error code returned at the token endpoint or
	// in a push notification when the authorization request fails for a reason other than user denial or auth_req_id
	// expiry.
	//
	// See OpenID Connect CIBA §11: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#token_error_response.
	ErrTransactionFailed = &RFC6749Error{
		ErrorField:       errTransactionFailedName,
		DescriptionField: "The authorization request cannot be completed because it has failed for a reason other than the end user denying it or the auth_req_id expiring.",
		CodeField:        http.StatusBadRequest,
	}

	// ErrUnsupportedTokenType is the standard 'unsupported_token_type' error code defined by OAuth 2.0 Token Revocation
	// for the revocation endpoint when the server does not support revocation of the presented token type.
	//
	// See OAuth 2.0 Token Revocation §2.2.1: https://datatracker.ietf.org/doc/html/rfc7009#section-2.2.1.
	ErrUnsupportedTokenType = &RFC6749Error{
		ErrorField:       errUnsupportedTokenTypeName,
		DescriptionField: "The authorization server does not support the revocation of the presented token type.",
		CodeField:        http.StatusServiceUnavailable,
	}
)

const (
	errInvalidRequestURIName       = "invalid_request_uri"
	errInvalidRequestObjectName    = "invalid_request_object"
	errConsentRequiredName         = "consent_required"
	errInteractionRequiredName     = "interaction_required"
	errLoginRequiredName           = "login_required"
	errRequestUnauthorizedName     = "request_unauthorized"
	errRequestForbiddenName        = "request_forbidden"
	errInvalidRequestName          = "invalid_request"
	errUnauthorizedClientName      = "unauthorized_client"
	errAccessDeniedName            = "access_denied"
	errUnsupportedResponseTypeName = "unsupported_response_type"
	errUnsupportedResponseModeName = "unsupported_response_mode"
	errInvalidScopeName            = "invalid_scope"
	errInsufficientScopeName       = "insufficient_scope"
	errServerErrorName             = "server_error"
	errTemporarilyUnavailableName  = "temporarily_unavailable"
	errUnsupportedGrantTypeName    = "unsupported_grant_type"
	errInvalidGrantName            = "invalid_grant"
	errInvalidClientName           = "invalid_client"
	errNotFoundName                = "not_found"
	errInvalidStateName            = "invalid_state"
	errMisconfigurationName        = "misconfiguration"
	errInsufficientEntropyName     = "insufficient_entropy"
	errInvalidTokenFormatName      = "invalid_token"
	errTokenSignatureMismatchName  = "token_signature_mismatch"
	errTokenExpiredName            = "invalid_token" // https://datatracker.ietf.org/doc/html/rfc6750#section-3.1
	errScopeNotGrantedName         = "scope_not_granted"
	errTokenClaimName              = "token_claim"
	errTokenInactiveName           = "token_inactive"
	// errAuthorizationCodeInactiveName = "authorization_code_inactive"
	errUnknownErrorName             = "error"
	errRequestNotSupportedName      = "request_not_supported"
	errRequestURINotSupportedName   = "request_uri_not_supported"
	errRegistrationNotSupportedName = "registration_not_supported"
	errJTIKnownName                 = "jti_known"
	errAuthorizationPendingName     = "authorization_pending"
	errDeviceExpiredTokenName       = "expired_token"
	errSlowDownName                 = "slow_down"
	errInvalidTargetName            = "invalid_target"
	errExpiredLoginHintTokenName    = "expired_login_hint_token"
	errUnknownUserIDName            = "unknown_user_id"
	errMissingUserCodeName          = "missing_user_code"
	errInvalidUserCodeName          = "invalid_user_code"
	errInvalidBindingMessageName    = "invalid_binding_message"
	errTransactionFailedName        = "transaction_failed"
	errAccountSelectionRequiredName = "account_selection_required"
	errUnsupportedTokenTypeName     = "unsupported_token_type"

	errServerErrorDescription = "The authorization server encountered an unexpected condition that prevented it from fulfilling the request."
)

const (
	errJSONFormat      = `{"error":"%s","error_description":"%s"}`
	errJSONFormatDebug = `{"error":"%s","error_description":"%s","error_debug":"%s"}`
)

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

type (
	RFC6749Error struct {
		ErrorField       string
		DescriptionField string
		HintField        string
		CodeField        int
		DebugField       string
		cause            error
		useLegacyFormat  bool
		exposeDebug      bool

		// Fields for globalization
		hintIDField string
		hintArgs    []any
		catalog     i18n.MessageCatalog
		lang        language.Tag
	}
)

var (
	_ errorsx.DebugCarrier      = new(RFC6749Error)
	_ errorsx.ReasonCarrier     = new(RFC6749Error)
	_ errorsx.RequestIDCarrier  = new(RFC6749Error)
	_ errorsx.StatusCarrier     = new(RFC6749Error)
	_ errorsx.StatusCodeCarrier = new(RFC6749Error)
	_ errorsx.DetailsCarrier    = new(RFC6749Error)
)

// ErrorToRFC6749Error returns the *RFC6749Error wrapped by err if one is present, otherwise it returns a synthetic
// RFC6749Error with the 'unknown_error' code and a 500 status, preserving the original err as the cause and debug
// message.
func ErrorToRFC6749Error(err error) *RFC6749Error {
	var e *RFC6749Error

	if stderr.As(err, &e) {
		return e
	}

	return &RFC6749Error{
		ErrorField:       errUnknownErrorName,
		DescriptionField: "The error is unrecognizable",
		DebugField:       err.Error(),
		CodeField:        http.StatusInternalServerError,
		cause:            err,
	}
}

// StackTrace returns the error's stack trace.
func (e *RFC6749Error) StackTrace() (trace errors.StackTrace) {
	if e.cause == e || e.cause == nil {
		return
	}

	if st := errorsx.StackTracer(nil); stderr.As(e.cause, &st) {
		trace = st.StackTrace()
	}

	return
}

// Unwrap returns the underlying cause of the error to support errors.Is and errors.As traversal.
func (e RFC6749Error) Unwrap() error {
	return e.cause
}

// Wrap records err as the underlying cause of the receiver in place. Use WithWrap to keep the receiver immutable.
func (e *RFC6749Error) Wrap(err error) {
	e.cause = err
}

// WithWrap returns a copy of the receiver with cause recorded as the underlying error.
func (e RFC6749Error) WithWrap(cause error) *RFC6749Error {
	e.cause = cause

	return &e
}

// WithLegacyFormat returns a copy of the receiver configured to emit the legacy JSON error format (with separate
// 'error_hint', 'error_debug' and 'status_code' fields) when set to true.
func (e RFC6749Error) WithLegacyFormat(useLegacyFormat bool) *RFC6749Error {
	e.useLegacyFormat = useLegacyFormat
	return &e
}

// WithTrace attaches a stack trace for err to the error chain. If no stack tracer is present in the existing cause, the
// error is wrapped with one before being recorded.
func (e *RFC6749Error) WithTrace(err error) *RFC6749Error {
	if st := errorsx.StackTracer(nil); !stderr.As(e.cause, &st) {
		e.Wrap(errorsx.WithStack(err))
	} else {
		e.Wrap(err)
	}
	return e
}

// Is reports whether err is equivalent to the receiver. Two RFC6749Errors are considered equal when their ErrorField
// and CodeField match, supporting use with errors.Is.
func (e RFC6749Error) Is(err error) bool {
	switch te := err.(type) {
	case RFC6749Error:
		if te.IsEmpty() {
			return true
		}

		return e.ErrorField == te.ErrorField &&
			e.CodeField == te.CodeField
	case *RFC6749Error:
		if te.IsEmpty() {
			return true
		}

		return e.ErrorField == te.ErrorField &&
			e.CodeField == te.CodeField
	}
	return false
}

// IsEmpty returns true if the error is an empty error.
func (e RFC6749Error) IsEmpty() bool {
	return e.ErrorField == "" && e.DescriptionField == "" && e.HintField == "" && e.DebugField == "" && e.CodeField == 0 && e.cause == nil
}

// Status returns the HTTP status text corresponding to CodeField.
func (e *RFC6749Error) Status() string {
	return http.StatusText(e.CodeField)
}

// Error implements the builtin error interface and returns the RFC 6749 error code (e.g. 'invalid_request').
func (e RFC6749Error) Error() string {
	return e.ErrorField
}

// RequestID satisfies the errorsx.RequestIDCarrier interface and always returns the empty string for RFC6749Errors.
func (e *RFC6749Error) RequestID() string {
	return ""
}

// Reason satisfies the errorsx.ReasonCarrier interface and returns the hint field as the human readable reason.
func (e *RFC6749Error) Reason() string {
	return e.HintField
}

// Details satisfies the errorsx.DetailsCarrier interface; RFC6749Errors carry no structured details so nil is returned.
func (e *RFC6749Error) Details() map[string]any {
	return nil
}

// StatusCode returns the HTTP status code associated with the error.
func (e *RFC6749Error) StatusCode() int {
	return e.CodeField
}

// Cause returns the underlying error that produced this one, equivalent to errors.Unwrap.
func (e *RFC6749Error) Cause() error {
	return e.cause
}

// WithHintf returns a copy of the receiver with the hint set to the formatted string. The first call also records the
// unformatted hint as the translation ID so future calls to WithLocalizer can localize the message.
func (e *RFC6749Error) WithHintf(hint string, args ...any) *RFC6749Error {
	err := *e
	if err.hintIDField == "" {
		err.hintIDField = hint
	}

	err.hintArgs = args
	err.HintField = fmt.Sprintf(hint, args...)
	return &err
}

// WithHint returns a copy of the receiver with the hint set to the supplied static string. The first call also records
// the hint as the translation ID so future calls to WithLocalizer can localize the message.
func (e *RFC6749Error) WithHint(hint string) *RFC6749Error {
	err := *e
	if err.hintIDField == "" {
		err.hintIDField = hint
	}

	err.HintField = hint
	return &err
}

// WithHintIDOrDefaultf accepts the ID of the hint message
func (e *RFC6749Error) WithHintIDOrDefaultf(id string, def string, args ...any) *RFC6749Error {
	err := *e
	err.hintIDField = id
	err.hintArgs = args
	err.HintField = fmt.Sprintf(def, args...)
	return &err
}

// WithHintTranslationID accepts the ID of the hint message and should be paired with
// WithHint and WithHintf to add a default message and vaargs.
func (e *RFC6749Error) WithHintTranslationID(id string) *RFC6749Error {
	err := *e
	err.hintIDField = id
	return &err
}

// Debug returns the debug message attached to the error. The value is only ever exposed to clients when
// WithExposeDebug(true) has been set on the error.
func (e *RFC6749Error) Debug() string {
	return e.DebugField
}

// WithDebug returns a copy of the receiver with the debug message set. Debug information is only ever sent to clients
// when WithExposeDebug(true) is configured.
func (e *RFC6749Error) WithDebug(debug string) *RFC6749Error {
	err := *e
	err.DebugField = debug

	return &err
}

// WithDebugError returns a copy of the receiver whose debug message is derived from the given error's debug-rendered
// description. The receiver is returned unchanged when debug is nil.
func (e *RFC6749Error) WithDebugError(debug error) *RFC6749Error {
	if debug == nil {
		return e
	}

	return e.WithDebug(ErrorToDebugRFC6749Error(debug).Error())
}

// WithDebugf returns a copy of the receiver with the debug message set to the formatted string.
func (e *RFC6749Error) WithDebugf(debug string, args ...any) *RFC6749Error {
	return e.WithDebug(fmt.Sprintf(debug, args...))
}

// WithDescription returns a copy of the receiver with its top-level description overwritten. The description is the
// human-readable text returned in the 'error_description' field of the response payload.
func (e *RFC6749Error) WithDescription(description string) *RFC6749Error {
	err := *e
	err.DescriptionField = description
	return &err
}

// WithLocalizer returns a copy of the receiver bound to the given message catalog and language tag so descriptions and
// hints are translated when serialized.
func (e *RFC6749Error) WithLocalizer(catalog i18n.MessageCatalog, lang language.Tag) *RFC6749Error {
	err := *e
	err.catalog = catalog
	err.lang = lang
	return &err
}

// Sanitize strips the debug field
//
// Deprecated: Use WithExposeDebug instead.
func (e *RFC6749Error) Sanitize() *RFC6749Error {
	err := *e
	err.DebugField = ""
	return &err
}

// WithExposeDebug if set to true exposes debug messages.
func (e *RFC6749Error) WithExposeDebug(exposeDebug bool) *RFC6749Error {
	err := *e
	err.exposeDebug = exposeDebug

	return &err
}

// GetDescription returns a more descriptive description, combined with hint and debug (when available).
func (e *RFC6749Error) GetDescription() string {
	description := i18n.GetMessageOrDefault(e.catalog, e.ErrorField, e.lang, e.DescriptionField)
	e.computeHintField()

	if e.HintField != "" {
		description += " " + e.HintField
	}

	if e.exposeDebug && e.DebugField != "" {
		description += " " + e.DebugField
	}

	return strings.ReplaceAll(description, "\"", "'")
}

// RFC6749ErrorJson is a helper struct for JSON encoding/decoding of RFC6749Error.
type RFC6749ErrorJson struct {
	Name        string `json:"error"`
	Description string `json:"error_description"`
	Hint        string `json:"error_hint,omitempty"`
	Code        int    `json:"status_code,omitempty"`
	Debug       string `json:"error_debug,omitempty"`
}

// UnmarshalJSON decodes a JSON-encoded error response into the receiver, automatically enabling legacy formatting when
// the payload contains the legacy 'error_hint' or 'error_debug' fields.
func (e *RFC6749Error) UnmarshalJSON(b []byte) error {
	var data RFC6749ErrorJson

	if err := json.Unmarshal(b, &data); err != nil {
		return err
	}

	e.ErrorField = data.Name
	e.CodeField = data.Code
	e.DescriptionField = data.Description

	if len(data.Hint+data.Debug) > 0 {
		e.HintField = data.Hint
		e.DebugField = data.Debug
		e.useLegacyFormat = true
	}

	return nil
}

// MarshalJSON encodes the error using either the RFC 6749 short form ('error' and 'error_description') or the legacy
// long form depending on the receiver's configured format. Debug information is only included when WithExposeDebug has
// been set.
func (e RFC6749Error) MarshalJSON() ([]byte, error) {
	if !e.useLegacyFormat {
		return json.Marshal(&RFC6749ErrorJson{
			Name:        e.ErrorField,
			Description: e.GetDescription(),
		})
	}

	var debug string
	if e.exposeDebug {
		debug = e.DebugField
	}

	return json.Marshal(&RFC6749ErrorJson{
		Name:        e.ErrorField,
		Description: e.DescriptionField,
		Hint:        e.HintField,
		Code:        e.CodeField,
		Debug:       debug,
	})
}

// ToValues serializes the error into url.Values suitable for use as an authorize endpoint error response in either the
// 'query' or 'fragment' response mode. Legacy-format errors produce additional 'error_hint' and 'error_debug' fields.
func (e *RFC6749Error) ToValues() url.Values {
	values := url.Values{}
	values.Set("error", e.ErrorField)
	values.Set("error_description", e.GetDescription())

	if e.useLegacyFormat {
		values.Set("error_description", e.DescriptionField)
		if e.HintField != "" {
			values.Set("error_hint", e.HintField)
		}

		if e.DebugField != "" && e.exposeDebug {
			values.Set("error_debug", e.DebugField)
		}
	}

	return values
}

func (e *RFC6749Error) computeHintField() {
	if e.hintIDField == "" {
		return
	}

	e.HintField = i18n.GetMessageOrDefault(e.catalog, e.hintIDField, e.lang, e.HintField, e.hintArgs...)
}

// ErrorToRFC6749ErrorFallback behaves like ErrorToRFC6749Error but returns a copy of fallback (wrapping err) instead of
// the generic 'unknown_error' when err is not already a known RFC6749Error.
func ErrorToRFC6749ErrorFallback(err error, fallback *RFC6749Error) *RFC6749Error {
	var e *RFC6749Error
	if stderr.As(err, &e) {
		return e
	}

	return fallback.WithWrap(err).WithDebugError(err)
}

// ErrorToDebugRFC6749Error converts the provided error to a *DebugRFC6749Error provided it is not nil and can be
// cast as a *RFC6749Error.
func ErrorToDebugRFC6749Error(err error) (rfc error) {
	if err == nil {
		return nil
	}

	var e *RFC6749Error

	if stderr.As(err, &e) {
		return &DebugRFC6749Error{e}
	}

	return err
}

// DebugRFC6749Error is a decorator type which makes the underlying *RFC6749Error expose debug information and
// show the full error description.
type DebugRFC6749Error struct {
	*RFC6749Error
}

// Error implements the builtin error interface and shows the error with its debug info and description.
func (err *DebugRFC6749Error) Error() string {
	return err.WithExposeDebug(true).GetDescription()
}

func (f *Fosite) writeFallbackJSONError(ctx context.Context, rw http.ResponseWriter, err error) {
	writeFallbackJSONError(ctx, f.Config, rw, err)
}

func writeFallbackJSONError(ctx context.Context, config SendDebugMessagesToClientsProvider, rw http.ResponseWriter, err error) {
	if config.GetSendDebugMessagesToClients(ctx) {
		http.Error(rw, fmt.Sprintf(errJSONFormatDebug, errServerErrorName, errServerErrorDescription, EscapeJSONString(err.Error())), http.StatusInternalServerError)
	} else {
		http.Error(rw, fmt.Sprintf(errJSONFormat, errServerErrorName, errServerErrorDescription), http.StatusInternalServerError)
	}
}
