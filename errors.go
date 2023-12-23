// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"encoding/json"
	stderr "errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/pkg/errors"
	"golang.org/x/text/language"

	"authelia.com/provider/oauth2/i18n"
	"authelia.com/provider/oauth2/internal/errorsx"
)

var (
	// ErrInvalidRequest represents the 'invalid_request' error from RFC6749 for the Authorize Code and Implicit Grant.
	//
	// See:
	//    - https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1
	//    - https://datatracker.ietf.org/doc/html/rfc6749#section-4.2.2.1.
	ErrInvalidRequest = &RFC6749Error{
		ErrorField:       errInvalidRequestName,
		DescriptionField: "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed.",
		HintField:        "Make sure that the various parameters are correct, be aware of case sensitivity and trim your parameters. Make sure that the client you are using has exactly whitelisted the redirect_uri you specified.",
		CodeField:        http.StatusBadRequest,
	}

	// ErrAccessTokenResponseInvalidRequest represents the 'invalid_request' error from RFC6749 for the Access Token Exchange.
	//
	// See: https://datatracker.ietf.org/doc/html/rfc6749#section-5.2.
	ErrAccessTokenResponseInvalidRequest = &RFC6749Error{
		ErrorField:       errInvalidRequestName,
		DescriptionField: "The request is missing a required parameter, includes an unsupported parameter value (other than grant type), repeats a parameter, includes multiple credentials, utilizes more than one mechanism for authenticating the client, or is otherwise malformed.",
		HintField:        "Make sure that the various parameters are correct, be aware of case sensitivity and trim your parameters. Make sure that the client you are using has exactly whitelisted the redirect_uri you specified.",
		CodeField:        http.StatusBadRequest,
	}

	// ErrUnauthorizedClient represents the 'unauthorized_client' error from RFC6749.
	//
	// TODO: This is a legacy error which is not specific to any specification sections.
	ErrUnauthorizedClient = &RFC6749Error{
		ErrorField:       errUnauthorizedClientName,
		DescriptionField: "The client is not authorized to request a token using this method.",
		HintField:        "Make sure that client id and secret are correctly specified and that the client exists.",
		CodeField:        http.StatusBadRequest,
	}

	// ErrAuthorizeCodeGrantUnauthorizedClient represents the 'unauthorized_client' error from RFC6749 for the Authorization Code Grant.
	//
	// See: https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1.
	ErrAuthorizeCodeGrantUnauthorizedClient = &RFC6749Error{
		ErrorField:       errUnauthorizedClientName,
		DescriptionField: "The client is not authorized to request an authorization code using this method.",
		HintField:        "Make sure that client id and secret are correctly specified and that the client exists.",
		CodeField:        http.StatusBadRequest,
	}

	// ErrImplicitGrantUnauthorizedClient represents the 'unauthorized_client' error from RFC6749 for the Implicit Grant.
	//
	// See: https://datatracker.ietf.org/doc/html/rfc6749#section-4.2.2.1.
	ErrImplicitGrantUnauthorizedClient = &RFC6749Error{
		ErrorField:       errUnauthorizedClientName,
		DescriptionField: "The client is not authorized to request an access token using this method.",
		HintField:        "Make sure that client id and secret are correctly specified and that the client exists.",
		CodeField:        http.StatusBadRequest,
	}

	// ErrAccessTokenResponseUnauthorizedClient represents the 'unauthorized_client' error from RFC6749 for the Access Token Exchange.
	//
	// See: https://datatracker.ietf.org/doc/html/rfc6749#section-5.2.
	ErrAccessTokenResponseUnauthorizedClient = &RFC6749Error{
		ErrorField:       errUnauthorizedClientName,
		DescriptionField: "The authenticated client is not authorized to use this authorization grant type.",
		HintField:        "Make sure that client id and secret are correctly specified and that the client exists.",
		CodeField:        http.StatusBadRequest,
	}

	// ErrAccessDenied represents the 'access_denied' error from RFC6749 for the Authorization Code and Implicit Grant.
	//
	// See: https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1.
	ErrAccessDenied = &RFC6749Error{
		ErrorField:       errAccessDeniedName,
		DescriptionField: "The resource owner or authorization server denied the request.",
		HintField:        "Make sure that the request you are making is valid. Maybe the credential or request parameters you are using are limited in scope or otherwise restricted.",
		CodeField:        http.StatusForbidden,
	}

	// ErrUnsupportedResponseType represents the 'unsupported_response_type' error from RFC6749.
	//
	// TODO: This is a legacy error which is not specific to any specification sections.
	ErrUnsupportedResponseType = &RFC6749Error{
		ErrorField:       errUnsupportedResponseTypeName,
		DescriptionField: "The authorization server does not support obtaining a token using this method.",
		CodeField:        http.StatusBadRequest,
	}

	// ErrAuthorizeCodeGrantUnsupportedResponseType represents the 'unsupported_response_type' error from RFC6749 for the Authorization Code Grant.
	//
	// See: https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1.
	ErrAuthorizeCodeGrantUnsupportedResponseType = &RFC6749Error{
		ErrorField:       errUnsupportedResponseTypeName,
		DescriptionField: "The authorization server does not support obtaining an authorization code using this method.",
		CodeField:        http.StatusBadRequest,
	}

	// ErrImplicitGrantUnsupportedResponseType represents the 'unsupported_response_type' error from RFC6749 for the Implicit Grant.
	//
	// See: https://datatracker.ietf.org/doc/html/rfc6749#section-4.2.2.1.
	ErrImplicitGrantUnsupportedResponseType = &RFC6749Error{
		ErrorField:       errUnsupportedResponseTypeName,
		DescriptionField: "The authorization server does not support obtaining an access token using this method.",
		CodeField:        http.StatusBadRequest,
	}

	// ErrInvalidScope represents the 'invalid_scope' error from RFC6749 for the Authorize Code and Implicit Grant.
	//
	// See:
	//    - https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1
	//    - https://datatracker.ietf.org/doc/html/rfc6749#section-4.2.2.1.
	ErrInvalidScope = &RFC6749Error{
		ErrorField:       errInvalidScopeName,
		DescriptionField: "The requested scope is invalid, unknown, or malformed.",
		CodeField:        http.StatusBadRequest,
	}

	// ErrAccessTokenResponseInvalidScope represents the 'invalid_scope' error from RFC6749 for the Access Token Response.
	//
	// See: https://datatracker.ietf.org/doc/html/rfc6749#section-5.2.
	ErrAccessTokenResponseInvalidScope = &RFC6749Error{
		ErrorField:       errInvalidScopeName,
		DescriptionField: "The requested scope is invalid, unknown, malformed, or exceeds the scope granted by the resource owner.",
		CodeField:        http.StatusBadRequest,
	}

	// ErrServerError represents the 'server_error' error from RFC6749 for the Authorize Code and Implicit Grant.
	//
	// See:
	//    - https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1
	//    - https://datatracker.ietf.org/doc/html/rfc6749#section-4.2.2.1.
	ErrServerError = &RFC6749Error{
		ErrorField:       errServerErrorName,
		DescriptionField: "The authorization server encountered an unexpected condition that prevented it from fulfilling the request.",
		CodeField:        http.StatusInternalServerError,
	}

	// ErrTemporarilyUnavailable represents the 'temporarily_unavailable' error from RFC6749 for the Authorize Code and Implicit Grant.
	//
	// See:
	//    - https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1
	//    - https://datatracker.ietf.org/doc/html/rfc6749#section-4.2.2.1.
	ErrTemporarilyUnavailable = &RFC6749Error{
		ErrorField:       errTemporarilyUnavailableName,
		DescriptionField: "The authorization server is currently unable to handle the request due to a temporary overloading or maintenance of the server.",
		CodeField:        http.StatusServiceUnavailable,
	}

	// ErrUnsupportedGrantType represents the 'unsupported_grant_type' error from RFC6749 for the Access Token Exchange.
	//
	// See: https://datatracker.ietf.org/doc/html/rfc6749#section-5.2.
	ErrUnsupportedGrantType = &RFC6749Error{
		ErrorField:       errUnsupportedGrantTypeName,
		DescriptionField: "The authorization grant type is not supported by the authorization server.",
		CodeField:        http.StatusBadRequest,
	}

	// ErrInvalidClient represents the 'invalid_client' error from RFC6749 for the Access Token Exchange.
	//
	// See:
	//	- https://datatracker.ietf.org/doc/html/rfc6749#section-5.2.
	//	- https://datatracker.ietf.org/doc/html/rfc7521#section-4.2.1
	ErrInvalidClient = &RFC6749Error{
		ErrorField:       errInvalidClientName,
		DescriptionField: "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method).",
		CodeField:        http.StatusUnauthorized,
	}

	// ErrInvalidGrant represents the 'invalid_grant' error from RFC6749 for the Access Token Exchange.
	//
	// See:
	//	- https://datatracker.ietf.org/doc/html/rfc6749#section-5.2.
	//  - https://datatracker.ietf.org/doc/html/rfc7523#section-3.1.
	ErrInvalidGrant = &RFC6749Error{
		ErrorField:       errInvalidGrantName,
		DescriptionField: "The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client.",
		CodeField:        http.StatusBadRequest,
	}

	// ErrInsufficientUserAuth represents the 'insufficient_user_authentication' error from RFC9470.
	//
	// See: https://datatracker.ietf.org/doc/html/rfc9470#section-3.
	ErrInsufficientUserAuth = &RFC6749Error{
		ErrorField:       errInsufficientUserAuthName,
		DescriptionField: "The authentication event associated with the access token presented with the request does not meet the authentication requirements of the protected resource.",
		CodeField:        http.StatusUnauthorized,
	}

	// ErrInvalidDPoPProof represents the 'invalid_dpop_proof' error from RFC9449.
	//
	// See: https://datatracker.ietf.org/doc/html/rfc9449#section-5
	ErrInvalidDPoPProof = &RFC6749Error{
		ErrorField:       errInvalidDPoPProofName,
		DescriptionField: "The authentication event associated with the access token presented with the request does not meet the authentication requirements of the protected resource.",
		CodeField:        http.StatusUnauthorized,
	}

	// ErrUseDPoPNonce represents the 'use_dpop_nonce' error from RFC9449.
	//
	// See: https://datatracker.ietf.org/doc/html/rfc9449#section-9.
	ErrUseDPoPNonce = &RFC6749Error{
		ErrorField:       errUseDPoPNonceName,
		DescriptionField: "Authorization server requires nonce in DPoP proof.",
		CodeField:        http.StatusBadRequest,
	}

	// ErrInvalidAuthDetails represents the 'invalid_authorization_details' error from RFC9396.
	//
	// See: https://datatracker.ietf.org/doc/html/rfc9396#section-5.
	ErrInvalidAuthDetails = &RFC6749Error{
		ErrorField:       errInvalidAuthDetailsName,
		DescriptionField: "The authorization details contains an unknown authorization details type value, is an object of known type but containing unknown fields, contains fields of the wrong type for the authorization details type, contains fields with invalid values for the authorization details type, or is missing required fields for the authorization details type.",
		CodeField:        http.StatusBadRequest,
	}

	// ErrInvalidTarget represents the 'invalid_target' error from RFC8707 and RFC8693.
	//
	// See:
	//	- https://datatracker.ietf.org/doc/html/rfc8707#section-2.
	//  - https://datatracker.ietf.org/doc/html/rfc8693#section-2.2.2.
	ErrInvalidTarget = &RFC6749Error{
		ErrorField:       errInvalidTargetName,
		DescriptionField: "The requested resource is invalid, missing, unknown, or malformed.",
		CodeField:        http.StatusBadRequest,
	}

	// ErrAuthPending represents the 'authorization_pending' error from RFC8628.
	//
	// See: https://datatracker.ietf.org/doc/html/rfc8628#section-3.5.
	ErrAuthPending = &RFC6749Error{
		ErrorField:       errAuthPendingName,
		DescriptionField: "The authorization request is still pending as the end user hasn't yet completed the user-interaction steps.",
		CodeField:        http.StatusBadRequest,
	}

	// ErrSlowDown represents the 'slow_down' error from RFC8628.
	//
	// See: https://datatracker.ietf.org/doc/html/rfc8628#section-3.5.
	ErrSlowDown = &RFC6749Error{
		ErrorField:       errSlowDownName,
		DescriptionField: "The authorization request is still pending as the end user hasn't yet completed the user-interaction steps.",
		HintField:        "The polling interval must be increased by 5 seconds for this and all subsequent requests.",
		CodeField:        http.StatusBadRequest,
	}

	// ErrExpiredToken represents the 'expired_token' error from RFC8628.
	//
	// See: https://datatracker.ietf.org/doc/html/rfc8628#section-3.5.
	ErrExpiredToken = &RFC6749Error{
		ErrorField:       errExpiredTokenName,
		DescriptionField: "The device code has expired, and the device authorization session has concluded.",
		CodeField:        http.StatusBadRequest,
	}

	// ErrUnsupportedTokenType represents the 'unsupported_token_type' error from RFC7009.
	//
	// See: https://datatracker.ietf.org/doc/html/rfc6750#section-3.1.
	ErrUnsupportedTokenType = &RFC6749Error{
		ErrorField:       errUnsupportedTokenTypeName,
		DescriptionField: "The authorization server does not support the revocation of the presented token type.",
		CodeField:        http.StatusServiceUnavailable,
	}

	// ErrTokenExpired represents the 'invalid_token' error from RFC6750.
	//
	// See:
	//	- https://datatracker.ietf.org/doc/html/rfc6750#section-3.1.
	//	- https://openid.net/specs/openid-connect-core-1_0.html#UserInfoError
	ErrTokenExpired = &RFC6749Error{
		ErrorField:       errTokenExpiredName,
		DescriptionField: "The access token provided is expired, revoked, malformed, or invalid for other reasons.",
		CodeField:        http.StatusUnauthorized,
	}

	// ErrInsufficientScope represents the 'insufficient_scope' error from RFC6750.
	//
	// See: https://datatracker.ietf.org/doc/html/rfc6750#section-3.1.
	ErrInsufficientScope = &RFC6749Error{
		ErrorField:       errInsufficientScopeName,
		DescriptionField: "The request requires higher privileges than provided by the access token.",
		CodeField:        http.StatusForbidden,
	}

	// ErrInteractionRequired represents the 'interaction_required' error from OpenID Connect 1.0 for the Authorization Code Grant.
	//
	// See: https://openid.net/specs/openid-connect-core-1_0.html#AuthError.
	ErrInteractionRequired = &RFC6749Error{
		DescriptionField: "The Authorization Server requires End-User interaction of some form to proceed.",
		ErrorField:       errInteractionRequiredName,
		CodeField:        http.StatusBadRequest,
	}

	// ErrLoginRequired represents the 'login_required' error from OpenID Connect 1.0 for the Authorization Code Grant.
	//
	// See: https://openid.net/specs/openid-connect-core-1_0.html#AuthError.
	ErrLoginRequired = &RFC6749Error{
		ErrorField:       errLoginRequiredName,
		DescriptionField: "The Authorization Server requires End-User authentication.",
		CodeField:        http.StatusBadRequest,
	}

	// ErrAccountSelectionRequired represents the 'account_selection_required' error from OpenID Connect 1.0 for the Authorization Code Grant.
	//
	// See: https://openid.net/specs/openid-connect-core-1_0.html#AuthError.
	ErrAccountSelectionRequired = &RFC6749Error{
		DescriptionField: "The End-User is REQUIRED to select a session at the Authorization Server.",
		ErrorField:       errAccountSelectionRequiredName,
		CodeField:        http.StatusBadRequest,
	}

	// ErrInvalidRequestURI represents the 'invalid_request_uri' error from OpenID Connect 1.0 for the Authorization Code Grant.
	//
	// See: https://openid.net/specs/openid-connect-core-1_0.html#AuthError.
	ErrInvalidRequestURI = &RFC6749Error{
		DescriptionField: "The request_uri in the Authorization Request returns an error or contains invalid data.",
		ErrorField:       errInvalidRequestURIName,
		CodeField:        http.StatusBadRequest,
	}

	// ErrConsentRequired represents the 'consent_required' error from OpenID Connect 1.0 for the Authorization Code Grant.
	//
	// See: https://openid.net/specs/openid-connect-core-1_0.html#AuthError.
	ErrConsentRequired = &RFC6749Error{
		DescriptionField: "The Authorization Server requires End-User consent.",
		ErrorField:       errConsentRequiredName,
		CodeField:        http.StatusBadRequest,
	}

	// ErrInvalidRequestObject represents the 'invalid_request_object' error from OpenID Connect 1.0 for the Authorization Code Grant.
	//
	// See: https://openid.net/specs/openid-connect-core-1_0.html#AuthError.
	ErrInvalidRequestObject = &RFC6749Error{
		DescriptionField: "The request parameter contains an invalid Request Object.",
		ErrorField:       errInvalidRequestObjectName,
		CodeField:        http.StatusBadRequest,
	}

	// ErrRequestNotSupported represents the 'request_not_supported' error from OpenID Connect 1.0 for the Authorization Code Grant.
	//
	// See: https://openid.net/specs/openid-connect-core-1_0.html#AuthError.
	ErrRequestNotSupported = &RFC6749Error{
		DescriptionField: "The OP does not support use of the request parameter.",
		ErrorField:       errRequestNotSupportedName,
		CodeField:        http.StatusBadRequest,
	}

	// ErrRequestURINotSupported represents the 'request_uri_not_supported' error from OpenID Connect 1.0 for the Authorization Code Grant.
	//
	// See: https://openid.net/specs/openid-connect-core-1_0.html#AuthError.
	ErrRequestURINotSupported = &RFC6749Error{
		DescriptionField: "The OP does not support use of the request_uri parameter.",
		ErrorField:       errRequestURINotSupportedName,
		CodeField:        http.StatusBadRequest,
	}

	// ErrRegistrationNotSupported represents the 'registration_not_supported' error from OpenID Connect 1.0 for the Authorization Code Grant.
	//
	// See: https://openid.net/specs/openid-connect-core-1_0.html#AuthError.
	ErrRegistrationNotSupported = &RFC6749Error{
		DescriptionField: "The OP does not support use of the registration parameter.",
		ErrorField:       errRegistrationNotSupportedName,
		CodeField:        http.StatusBadRequest,
	}

	// ErrInvalidRedirectURI represents the 'registration_not_supported' error from OpenID Connect Dynamic Client Registration 1.0 and RFC7591.
	//
	// See:
	//	- https://openid.net/specs/openid-connect-registration-1_0.html#RegistrationError.
	//  - https://datatracker.ietf.org/doc/html/rfc7591#section-3.2.2.
	ErrInvalidRedirectURI = &RFC6749Error{
		DescriptionField: "The value of one or more redirect_uris is invalid.",
		ErrorField:       errInvalidRedirectURIName,
		CodeField:        http.StatusBadRequest,
	}

	// ErrInvalidClientMetadata represents the 'invalid_client_metadata' error from OpenID Connect Dynamic Client Registration 1.0.
	//
	// See: https://openid.net/specs/openid-connect-registration-1_0.html#RegistrationError.
	ErrInvalidClientMetadata = &RFC6749Error{
		DescriptionField: "The value of one of the Client Metadata fields is invalid and the server has rejected this request.",
		ErrorField:       errInvalidClientMetadataName,
		CodeField:        http.StatusBadRequest,
	}

	// ErrUnmetAuthRequirements represents the 'unmet_authentication_requirements' error from OpenID Connect Dynamic Client Registration 1.0.
	//
	// See: https://openid.net/specs/openid-connect-unmet-authentication-requirements-1_0.html.
	ErrUnmetAuthRequirements = &RFC6749Error{
		DescriptionField: "The Authorization Server is unable to meet the requirements of the Relying Party for the authentication of the End-User.",
		ErrorField:       errUnmetAuthRequirementsName,
		CodeField:        http.StatusBadRequest,
	}

	// ErrInvalidatedAuthorizeCode is an error indicating that an authorization code has been
	// used previously.
	ErrInvalidatedAuthorizeCode = errors.New("Authorization code has ben invalidated")
	// ErrSerializationFailure is an error indicating that the transactional capable storage could not guarantee
	// consistency of Update & Delete operations on the same rows between multiple sessions.
	ErrSerializationFailure = errors.New("The request could not be completed due to concurrent access")
	ErrUnknownRequest       = &RFC6749Error{
		ErrorField:       errUnknownErrorName,
		DescriptionField: "The handler is not responsible for this request.",
		CodeField:        http.StatusBadRequest,
	}
	ErrRequestForbidden = &RFC6749Error{
		ErrorField:       errRequestForbiddenName,
		DescriptionField: "The request is not allowed.",
		HintField:        "You are not allowed to perform this action.",
		CodeField:        http.StatusForbidden,
	}

	// ErrUnsupportedResponseMode does not appear to be a spec error.
	//
	// TODO: Determine a spec location, if this error is appropriate, or a more appropriate error.
	ErrUnsupportedResponseMode = &RFC6749Error{
		ErrorField:       errUnsupportedResponseModeName,
		DescriptionField: "The authorization server does not support obtaining a response using this response mode.",
		CodeField:        http.StatusBadRequest,
	}

	// ErrInvalidState does not appear to be a spec error. Seems commonly used.
	//
	// TODO: Determine a spec location, if this error is appropriate, or a more appropriate error.
	ErrInvalidState = &RFC6749Error{
		ErrorField:       errInvalidStateName,
		DescriptionField: "The state is missing or does not have enough characters and is therefore considered too weak.",
		CodeField:        http.StatusBadRequest,
	}

	// ErrMisconfiguration does not appear to be a spec error.
	//
	// TODO: Determine a spec location, if this error is appropriate, or a more appropriate error.
	ErrMisconfiguration = &RFC6749Error{
		ErrorField:       errMisconfigurationName,
		DescriptionField: "The request failed because of an internal error that is probably caused by misconfiguration.",
		CodeField:        http.StatusInternalServerError,
	}

	// ErrInsufficientEntropy does not appear to be a spec error.
	//
	// TODO: Determine a spec location, if this error is appropriate, or a more appropriate error.
	ErrInsufficientEntropy = &RFC6749Error{
		ErrorField:       errInsufficientEntropyName,
		DescriptionField: "The request used a security parameter (e.g., anti-replay, anti-csrf) with insufficient entropy.",
		CodeField:        http.StatusBadRequest,
	}

	// ErrNotFound does not appear to be a spec error.
	//
	// TODO: Determine a spec location, if this error is appropriate, or a more appropriate error.
	ErrNotFound = &RFC6749Error{
		ErrorField:       errNotFoundName,
		DescriptionField: "Could not find the requested resource(s).",
		CodeField:        http.StatusNotFound,
	}

	// ErrRequestUnauthorized does not appear to be a spec error.
	//
	// TODO: Determine a spec location, if this error is appropriate, or a more appropriate error.
	ErrRequestUnauthorized = &RFC6749Error{
		ErrorField:       errRequestUnauthorizedName,
		DescriptionField: "The request could not be authorized.",
		HintField:        "Check that you provided valid credentials in the right format.",
		CodeField:        http.StatusUnauthorized,
	}

	// ErrTokenSignatureMismatch does not appear to be a spec error.
	//
	// TODO: Determine a spec location, if this error is appropriate, or a more appropriate error.
	ErrTokenSignatureMismatch = &RFC6749Error{
		ErrorField:       errTokenSignatureMismatchName,
		DescriptionField: "Token signature mismatch.",
		HintField:        "Check that you provided  a valid token in the right format.",
		CodeField:        http.StatusBadRequest,
	}

	// ErrInvalidTokenFormat does not appear to be a spec error with information.
	// Might be part of https://openid.net/specs/openid-connect-core-1_0.html#UserInfoError.
	//
	// TODO: Determine a spec location, if this error is appropriate, or a more appropriate error.
	ErrInvalidTokenFormat = &RFC6749Error{
		ErrorField:       errInvalidTokenFormatName,
		DescriptionField: "Invalid token format.",
		HintField:        "Check that you provided a valid token in the right format.",
		CodeField:        http.StatusBadRequest,
	}

	// ErrTokenExpired does not appear to be a spec error with information.
	// Might be part of https://openid.net/specs/openid-connect-core-1_0.html#UserInfoError.
	// aaaa
	// See: https://www.rfc-editor.org/rfc/rfc6750#section-3.1.

	// ErrScopeNotGranted does not appear to be a spec error with information.
	//
	// TODO: Determine a spec location, if this error is appropriate, or a more appropriate error.
	ErrScopeNotGranted = &RFC6749Error{
		ErrorField:       errScopeNotGrantedName,
		DescriptionField: "The token was not granted the requested scope.",
		HintField:        "The resource owner did not grant the requested scope.",
		CodeField:        http.StatusForbidden,
	}

	// ErrTokenClaim does not appear to be a spec error with information.
	//
	// TODO: Determine a spec location, if this error is appropriate, or a more appropriate error.
	ErrTokenClaim = &RFC6749Error{
		ErrorField:       errTokenClaimName,
		DescriptionField: "The token failed validation due to a claim mismatch.",
		HintField:        "One or more token claims failed validation.",
		CodeField:        http.StatusUnauthorized,
	}

	// ErrInactiveToken does not appear to be a spec error with information.
	//
	// TODO: Determine a spec location, if this error is appropriate, or a more appropriate error.
	ErrInactiveToken = &RFC6749Error{
		ErrorField:       errTokenInactiveName,
		DescriptionField: "Token is inactive because it is malformed, expired or otherwise invalid.",
		HintField:        "Token validation failed.",
		CodeField:        http.StatusUnauthorized,
	}

	// ErrJTIKnown does not appear to be a spec error with information.
	//
	// TODO: Determine a spec location, if this error is appropriate, or a more appropriate error.
	ErrJTIKnown = &RFC6749Error{
		DescriptionField: "The jti was already used.",
		ErrorField:       errJTIKnownName,
		CodeField:        http.StatusBadRequest,
	}
)

const (
	errInvalidRequestURIName        = "invalid_request_uri"
	errInvalidRequestObjectName     = "invalid_request_object"
	errConsentRequiredName          = "consent_required"
	errInteractionRequiredName      = "interaction_required"
	errAccountSelectionRequiredName = "account_selection_required"
	errLoginRequiredName            = "login_required"
	errRequestUnauthorizedName      = "request_unauthorized"
	errRequestForbiddenName         = "request_forbidden"
	errInvalidRequestName           = "invalid_request"
	errUnauthorizedClientName       = "unauthorized_client"
	errAccessDeniedName             = "access_denied"
	errUnsupportedResponseTypeName  = "unsupported_response_type"
	errUnsupportedResponseModeName  = "unsupported_response_mode"
	errInvalidScopeName             = "invalid_scope"
	errServerErrorName              = "server_error"
	errTemporarilyUnavailableName   = "temporarily_unavailable"
	errUnsupportedGrantTypeName     = "unsupported_grant_type"
	errInvalidGrantName             = "invalid_grant"
	errInvalidClientName            = "invalid_client"
	errNotFoundName                 = "not_found"
	errInvalidStateName             = "invalid_state"
	errMisconfigurationName         = "misconfiguration"
	errInsufficientEntropyName      = "insufficient_entropy"
	errInvalidTokenFormatName       = "invalid_token"
	errTokenSignatureMismatchName   = "token_signature_mismatch"
	errTokenExpiredName             = "invalid_token" // https://datatracker.ietf.org/doc/html/rfc6750#section-3.1
	errScopeNotGrantedName          = "scope_not_granted"
	errTokenClaimName               = "token_claim"
	errTokenInactiveName            = "token_inactive"
	// errAuthorizationCodeInactiveName = "authorization_code_inactive"
	errUnknownErrorName             = "error"
	errRequestNotSupportedName      = "request_not_supported"
	errRequestURINotSupportedName   = "request_uri_not_supported"
	errRegistrationNotSupportedName = "registration_not_supported"
	errInvalidRedirectURIName       = "invalid_redirect_uri"
	errInvalidClientMetadataName    = "invalid_client_metadata"
	errUnmetAuthRequirementsName    = "unmet_authentication_requirements"
	errInsufficientUserAuthName     = "insufficient_user_authentication"
	errInvalidDPoPProofName         = "invalid_dpop_proof"
	errUseDPoPNonceName             = "use_dpop_nonce"
	errInvalidAuthDetailsName       = "invalid_authorization_details"
	errInvalidTargetName            = "invalid_target"
	errAuthPendingName              = "authorization_pending"
	errSlowDownName                 = "slow_down"
	errExpiredTokenName             = "expired_token"
	errUnsupportedTokenTypeName     = "unsupported_token_type"
	errInsufficientScopeName        = "insufficient_scope"
	errJTIKnownName                 = "jti_known"
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

func ErrorToRFC6749Error(err error) *RFC6749Error {
	var e *RFC6749Error

	if errors.As(err, &e) {
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

func (e RFC6749Error) Unwrap() error {
	return e.cause
}

func (e *RFC6749Error) Wrap(err error) {
	e.cause = err
}

func (e RFC6749Error) WithWrap(cause error) *RFC6749Error {
	e.cause = cause

	return &e
}

func (e RFC6749Error) WithLegacyFormat(useLegacyFormat bool) *RFC6749Error {
	e.useLegacyFormat = useLegacyFormat
	return &e
}

func (e *RFC6749Error) WithTrace(err error) *RFC6749Error {
	if st := errorsx.StackTracer(nil); !stderr.As(e.cause, &st) {
		e.Wrap(errorsx.WithStack(err))
	} else {
		e.Wrap(err)
	}
	return e
}

func (e RFC6749Error) Is(err error) bool {
	switch te := err.(type) {
	case RFC6749Error:
		return e.ErrorField == te.ErrorField &&
			e.CodeField == te.CodeField
	case *RFC6749Error:
		return e.ErrorField == te.ErrorField &&
			e.CodeField == te.CodeField
	}
	return false
}

func (e *RFC6749Error) Status() string {
	return http.StatusText(e.CodeField)
}

func (e RFC6749Error) Error() string {
	return e.ErrorField
}

func (e *RFC6749Error) RequestID() string {
	return ""
}

func (e *RFC6749Error) Reason() string {
	return e.HintField
}

func (e *RFC6749Error) Details() map[string]any {
	return nil
}

func (e *RFC6749Error) StatusCode() int {
	return e.CodeField
}

func (e *RFC6749Error) Cause() error {
	return e.cause
}

func (e *RFC6749Error) WithHintf(hint string, args ...any) *RFC6749Error {
	err := *e
	if err.hintIDField == "" {
		err.hintIDField = hint
	}

	err.hintArgs = args
	err.HintField = fmt.Sprintf(hint, args...)
	return &err
}

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

func (e *RFC6749Error) Debug() string {
	return e.DebugField
}

func (e *RFC6749Error) WithDebug(debug string) *RFC6749Error {
	err := *e
	err.DebugField = debug

	return &err
}

func (e *RFC6749Error) WithDebugError(debug error) *RFC6749Error {
	return e.WithDebug(ErrorToDebugRFC6749Error(debug).Error())
}

func (e *RFC6749Error) WithDebugf(debug string, args ...any) *RFC6749Error {
	return e.WithDebug(fmt.Sprintf(debug, args...))
}

func (e *RFC6749Error) WithDescription(description string) *RFC6749Error {
	err := *e
	err.DescriptionField = description
	return &err
}

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

func ErrorToRFC6749ErrorFallback(err error, fallback *RFC6749Error) *RFC6749Error {
	var e *RFC6749Error
	if errors.As(err, &e) {
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

	if errors.As(err, &e) {
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
