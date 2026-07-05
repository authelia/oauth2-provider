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
	// ErrInvalidatedAuthorizeCode is an error indicating that an authorization code has been
	// used previously.
	ErrInvalidatedAuthorizeCode = errors.New("Authorization code has ben invalidated")

	// ErrInvalidatedDeviceCode is an error indicating that a device code has been used previously.
	ErrInvalidatedDeviceCode = errors.New("Device code has been invalidated")

	// ErrInvalidatedUserCode is an error indicating that a user code has been used previously.
	ErrInvalidatedUserCode = errors.New("user code has been invalidated")

	// ErrSerializationFailure is an error indicating that the transactional capable storage could not guarantee
	// consistency of Update & Delete operations on the same rows between multiple sessions.
	ErrSerializationFailure = errors.New("The request could not be completed due to concurrent access")

	ErrUnknownRequest = &RFC6749Error{
		ErrorField:       errUnknownErrorName,
		DescriptionField: "The handler is not responsible for this request.",
		CodeField:        http.StatusBadRequest,
	}
	ErrInvalidRequest = &RFC6749Error{
		ErrorField:       errInvalidRequestName,
		DescriptionField: "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed.",
		HintField:        "Make sure that the various parameters are correct, be aware of case sensitivity and trim your parameters. Make sure that the client you are using has exactly whitelisted the redirect_uri you specified.",
		CodeField:        http.StatusBadRequest,
	}
	ErrUnauthorizedClient = &RFC6749Error{
		ErrorField:       errUnauthorizedClientName,
		DescriptionField: "The client is not authorized to request a token using this method.",
		HintField:        "Make sure that client id and secret are correctly specified and that the client exists.",
		CodeField:        http.StatusBadRequest,
	}
	ErrAccessDenied = &RFC6749Error{
		ErrorField:       errAccessDeniedName,
		DescriptionField: "The resource owner or authorization server denied the request.",
		HintField:        "Make sure that the request you are making is valid. Maybe the credential or request parameters you are using are limited in scope or otherwise restricted.",
		CodeField:        http.StatusForbidden,
	}
	ErrUnsupportedResponseType = &RFC6749Error{
		ErrorField:       errUnsupportedResponseTypeName,
		DescriptionField: "The authorization server does not support obtaining a token using this method.",
		CodeField:        http.StatusBadRequest,
	}
	ErrUnsupportedResponseMode = &RFC6749Error{
		ErrorField:       errUnsupportedResponseModeName,
		DescriptionField: "The authorization server does not support obtaining a response using this response mode.",
		CodeField:        http.StatusBadRequest,
	}
	ErrInvalidScope = &RFC6749Error{
		ErrorField:       errInvalidScopeName,
		DescriptionField: "The requested scope is invalid, unknown, or malformed.",
		CodeField:        http.StatusBadRequest,
	}
	ErrInsufficientScope = &RFC6749Error{
		ErrorField:       errInsufficientScopeName,
		DescriptionField: "The request requires higher privileges than provided by the Access Token.",
		CodeField:        http.StatusForbidden,
	}
	ErrServerError = &RFC6749Error{
		ErrorField:       errServerErrorName,
		DescriptionField: errServerErrorDescription,
		CodeField:        http.StatusInternalServerError,
	}
	ErrTemporarilyUnavailable = &RFC6749Error{
		ErrorField:       errTemporarilyUnavailableName,
		DescriptionField: "The authorization server is currently unable to handle the request due to a temporary overloading or maintenance of the server.",
		CodeField:        http.StatusServiceUnavailable,
	}
	ErrUnsupportedGrantType = &RFC6749Error{
		ErrorField:       errUnsupportedGrantTypeName,
		DescriptionField: "The authorization grant type is not supported by the authorization server.",
		CodeField:        http.StatusBadRequest,
	}
	ErrInvalidGrant = &RFC6749Error{
		ErrorField:       errInvalidGrantName,
		DescriptionField: "The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client.",
		CodeField:        http.StatusBadRequest,
	}
	ErrInvalidClient = &RFC6749Error{
		ErrorField:       errInvalidClientName,
		DescriptionField: "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method).",
		CodeField:        http.StatusUnauthorized,
	}
	ErrInvalidState = &RFC6749Error{
		ErrorField:       errInvalidStateName,
		DescriptionField: "The state is missing or does not have enough characters and is therefore considered too weak.",
		CodeField:        http.StatusBadRequest,
	}
	ErrMisconfiguration = &RFC6749Error{
		ErrorField:       errMisconfigurationName,
		DescriptionField: "The request failed because of an internal error that is probably caused by misconfiguration.",
		CodeField:        http.StatusInternalServerError,
	}
	ErrInsufficientEntropy = &RFC6749Error{
		ErrorField:       errInsufficientEntropyName,
		DescriptionField: "The request used a security parameter (e.g., anti-replay, anti-csrf) with insufficient entropy.",
		CodeField:        http.StatusBadRequest,
	}
	ErrNotFound = &RFC6749Error{
		ErrorField:       errNotFoundName,
		DescriptionField: "Could not find the requested resource(s).",
		CodeField:        http.StatusNotFound,
	}
	ErrRequestUnauthorized = &RFC6749Error{
		ErrorField:       errRequestUnauthorizedName,
		DescriptionField: "The request could not be authorized.",
		HintField:        "Check that you provided valid credentials in the right format.",
		CodeField:        http.StatusUnauthorized,
	}
	ErrTokenSignatureMismatch = &RFC6749Error{
		ErrorField:       errTokenSignatureMismatchName,
		DescriptionField: "Token signature mismatch.",
		HintField:        "Check that you provided a valid token in the right format.",
		CodeField:        http.StatusBadRequest,
	}
	ErrInvalidTokenFormat = &RFC6749Error{
		ErrorField:       errInvalidTokenFormatName,
		DescriptionField: "The token provided is expired, revoked, malformed, or invalid for other reasons.",
		HintField:        "Check that you provided a valid token in the right format.",
		CodeField:        http.StatusBadRequest,
	}
	ErrInvalidDPoPProof = &RFC6749Error{
		ErrorField:       errInvalidDPoPProofName,
		DescriptionField: "The DPoP proof is missing or invalid.",
		HintField:        "The request was made with an invalid, malformed, expired, or missing DPoP proof JWT.",
		CodeField:        http.StatusBadRequest,
	}
	ErrUseDPoPNonce = &RFC6749Error{
		ErrorField:       errUseDPoPNonceName,
		DescriptionField: "Authorization server requires nonce in DPoP proof.",
		HintField:        "Retry the request including a 'nonce' claim in the DPoP proof using the value from the most recent 'DPoP-Nonce' response header.",
		CodeField:        http.StatusBadRequest,
	}
	ErrTokenExpired = &RFC6749Error{
		ErrorField:       errTokenExpiredName,
		DescriptionField: "Token expired.",
		HintField:        "The token expired.",
		CodeField:        http.StatusUnauthorized,
	}
	ErrScopeNotGranted = &RFC6749Error{
		ErrorField:       errScopeNotGrantedName,
		DescriptionField: "The token was not granted the requested scope.",
		HintField:        "The resource owner did not grant the requested scope.",
		CodeField:        http.StatusForbidden,
	}
	ErrTokenClaim = &RFC6749Error{
		ErrorField:       errTokenClaimName,
		DescriptionField: "The token failed validation due to a claim mismatch.",
		HintField:        "One or more token claims failed validation.",
		CodeField:        http.StatusUnauthorized,
	}
	ErrInactiveToken = &RFC6749Error{
		ErrorField:       errTokenInactiveName,
		DescriptionField: "Token is inactive because it is malformed, expired or otherwise invalid.",
		HintField:        "Token validation failed.",
		CodeField:        http.StatusUnauthorized,
	}
	ErrLoginRequired = &RFC6749Error{
		ErrorField:       errLoginRequiredName,
		DescriptionField: "The Authorization Server requires End-User authentication.",
		CodeField:        http.StatusBadRequest,
	}
	ErrInteractionRequired = &RFC6749Error{
		DescriptionField: "The Authorization Server requires End-User interaction of some form to proceed.",
		ErrorField:       errInteractionRequiredName,
		CodeField:        http.StatusBadRequest,
	}
	ErrConsentRequired = &RFC6749Error{
		ErrorField:       errConsentRequiredName,
		DescriptionField: "The Authorization Server requires End-User consent.",
		CodeField:        http.StatusBadRequest,
	}
	ErrRequestNotSupported = &RFC6749Error{
		ErrorField:       errRequestNotSupportedName,
		DescriptionField: "The authorization server does not support the use of the request parameter.",
		CodeField:        http.StatusBadRequest,
	}
	ErrRequestURINotSupported = &RFC6749Error{
		ErrorField:       errRequestURINotSupportedName,
		DescriptionField: "The authorization server does not support the use of the request_uri parameter.",
		CodeField:        http.StatusBadRequest,
	}
	ErrRegistrationNotSupported = &RFC6749Error{
		ErrorField:       errRegistrationNotSupportedName,
		DescriptionField: "The OP does not support use of the registration parameter.",
		CodeField:        http.StatusBadRequest,
	}
	ErrInvalidRequestURI = &RFC6749Error{
		ErrorField:       errInvalidRequestURIName,
		DescriptionField: "The request_uri in the authorization request returns an error or contains invalid data.",
		CodeField:        http.StatusBadRequest,
	}
	ErrInvalidRequestObject = &RFC6749Error{
		ErrorField:       errInvalidRequestObjectName,
		DescriptionField: "The request parameter contains an invalid Request Object.",
		CodeField:        http.StatusBadRequest,
	}
	ErrJTIKnown = &RFC6749Error{
		ErrorField:       errJTIKnownName,
		DescriptionField: "The jti was already used.",
		CodeField:        http.StatusBadRequest,
	}
	ErrAuthorizationPending = &RFC6749Error{
		ErrorField:       errAuthorizationPendingName,
		DescriptionField: "The authorization request is still pending as the end user hasn't yet completed the user-interaction steps.",
		CodeField:        http.StatusBadRequest,
	}
	ErrDeviceExpiredToken = &RFC6749Error{
		ErrorField:       errDeviceExpiredTokenName,
		DescriptionField: "The device_code has expired, and the device authorization session has concluded.",
		CodeField:        http.StatusBadRequest,
	}
	ErrSlowDown = &RFC6749Error{
		ErrorField:       errSlowDownName,
		DescriptionField: "Too many requests within a short time period.",
		CodeField:        http.StatusBadRequest,
	}
	ErrInvalidTarget = &RFC6749Error{
		ErrorField:       errInvalidTargetName,
		DescriptionField: "The requested resource is invalid, missing, unknown, or malformed.",
		HintField:        "Ensure the requested resource is an absolute URI without a fragment component that identifies a resource server known to the authorization server and that it is permitted for this client.",
		CodeField:        http.StatusBadRequest,
	}
)

const (
	errInvalidRequestURIName       = "invalid_request_uri"
	errInvalidRequestObjectName    = "invalid_request_object"
	errConsentRequiredName         = "consent_required"
	errInteractionRequiredName     = "interaction_required"
	errLoginRequiredName           = "login_required"
	errRequestUnauthorizedName     = "request_unauthorized"
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
	errInvalidDPoPProofName         = "invalid_dpop_proof"
	errUseDPoPNonceName             = "use_dpop_nonce"

	errServerErrorDescription = "The authorization server encountered an unexpected condition that prevented it from fulfilling the request."
)

const (
	errJSONFormat      = `{"error":"%s","error_description":"%s"}`
	errJSONFormatDebug = `{"error":"%s","error_description":"%s","error_debug":"%s"}`
)

const (
	hintClientCredentialsInvalid                    = "The required credentials were not found, used an unknown method, could not be parsed, were otherwise malformed, or were otherwise incorrect."
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

// RFC6749ErrorJSON is a helper struct for JSON encoding/decoding of RFC6749Error.
type RFC6749ErrorJSON struct {
	Name        string `json:"error"`
	Description string `json:"error_description"`
	Hint        string `json:"error_hint,omitempty"`
	Code        int    `json:"status_code,omitempty"`
	Debug       string `json:"error_debug,omitempty"`
}

// UnmarshalJSON decodes a JSON-encoded error response into the receiver, automatically enabling legacy formatting when
// the payload contains the legacy 'error_hint' or 'error_debug' fields.
func (e *RFC6749Error) UnmarshalJSON(b []byte) error {
	var data RFC6749ErrorJSON

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
		return json.Marshal(&RFC6749ErrorJSON{
			Name:        e.ErrorField,
			Description: e.GetDescription(),
		})
	}

	var debug string
	if e.exposeDebug {
		debug = e.DebugField
	}

	return json.Marshal(&RFC6749ErrorJSON{
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
