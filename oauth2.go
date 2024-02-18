// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/text/language"

	"authelia.com/provider/oauth2/internal/consts"
)

type TokenUse = TokenType

type TokenType string

type GrantType string

const (
	AccessToken  TokenType = consts.TokenTypeAccessToken
	RefreshToken TokenType = consts.TokenTypeRefreshToken
	DeviceCode   TokenType = consts.CodeDevice
	UserCode     TokenType = consts.CodeUser

	// PushedAuthorizeRequestContext represents the PAR context object
	PushedAuthorizeRequestContext TokenType = "par_context"

	AuthorizeCode TokenType = "authorize_code"
	IDToken       TokenType = "id_token"

	GrantTypeImplicit          GrantType = consts.GrantTypeImplicit
	GrantTypeRefreshToken      GrantType = consts.GrantTypeRefreshToken
	GrantTypeAuthorizationCode GrantType = consts.GrantTypeAuthorizationCode
	GrantTypePassword          GrantType = consts.GrantTypeResourceOwnerPasswordCredentials
	GrantTypeClientCredentials GrantType = consts.GrantTypeClientCredentials
	GrantTypeJWTBearer         GrantType = consts.GrantTypeOAuthJWTBearer
	GrantTypeDeviceCode        GrantType = consts.GrantTypeOAuthDeviceCode
	GrantTypeTokenExchange     GrantType = consts.GrantTypeOAuthTokenExchange

	BearerAccessToken string = "bearer"
)

// Provider is an interface that enables you to write OAuth2 handlers with only a few lines of code.
// Check Fosite for an implementation of this interface.
type Provider interface {
	// NewAuthorizeRequest returns an AuthorizeRequest.
	//
	// The following specs must be considered in any implementation of this method:
	// * https://datatracker.ietf.org/doc/html/rfc6749#section-3.1
	//	 Extension response types MAY contain a space-delimited (%x20) list of
	//	 values, where the order of values does not matter (e.g., response
	//	 type "a b" is the same as "b a").  The meaning of such composite
	//	 response types is defined by their respective specifications.
	// * https://datatracker.ietf.org/doc/html/rfc6749#section-3.1.2
	//   The redirection endpoint URI MUST be an absolute URI as defined by
	//   [RFC3986] Section 4.3.  The endpoint URI MAY include an
	//   "application/x-www-form-urlencoded" formatted (per Appendix B) query
	//   component ([RFC3986] Section 3.4), which MUST be retained when adding
	//   additional query parameters.  The endpoint URI MUST NOT include a
	//   fragment component.
	// * https://datatracker.ietf.org/doc/html/rfc6749#section-3.1.2.2 (everything MUST be implemented)
	NewAuthorizeRequest(ctx context.Context, r *http.Request) (AuthorizeRequester, error)

	// NewAuthorizeResponse iterates through all response type handlers and returns their result or
	// ErrUnsupportedResponseType if none of the handlers were able to handle it.
	//
	// The following specs must be considered in any implementation of this method:
	// * https://datatracker.ietf.org/doc/html/rfc6749#section-3.1.1
	//	 Extension response types MAY contain a space-delimited (%x20) list of
	//	 values, where the order of values does not matter (e.g., response
	//	 type "a b" is the same as "b a").  The meaning of such composite
	//	 response types is defined by their respective specifications.
	//	 If an authorization request is missing the "response_type" parameter,
	//	 or if the response type is not understood, the authorization server
	//	 MUST return an error response as described in Section 4.1.2.1.
	NewAuthorizeResponse(ctx context.Context, requester AuthorizeRequester, session Session) (AuthorizeResponder, error)

	// WriteAuthorizeError returns the error codes to the redirection endpoint or shows the error to the user, if no valid
	// redirect uri was given. Implements rfc6749#section-4.1.2.1
	//
	// The following specs must be considered in any implementation of this method:
	// * https://datatracker.ietf.org/doc/html/rfc6749#section-3.1.2
	//   The redirection endpoint URI MUST be an absolute URI as defined by
	//   [RFC3986] Section 4.3.  The endpoint URI MAY include an
	//   "application/x-www-form-urlencoded" formatted (per Appendix B) query
	//   component ([RFC3986] Section 3.4), which MUST be retained when adding
	//   additional query parameters.  The endpoint URI MUST NOT include a
	//   fragment component.
	// * https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1 (everything)
	// * https://datatracker.ietf.org/doc/html/rfc6749#section-3.1.2.2 (everything MUST be implemented)
	WriteAuthorizeError(ctx context.Context, rw http.ResponseWriter, requester AuthorizeRequester, err error)

	// WriteAuthorizeResponse persists the AuthorizeSession in the store and redirects the user agent to the provided
	// redirect url or returns an error if storage failed.
	//
	// The following specs must be considered in any implementation of this method:
	// * https://datatracker.ietf.org/doc/html/rfc6749#rfc6749#section-4.1.2.1
	//   After completing its interaction with the resource owner, the
	//   authorization server directs the resource owner's user-agent back to
	//   the client.  The authorization server redirects the user-agent to the
	//   client's redirection endpoint previously established with the
	//   authorization server during the client registration process or when
	//   making the authorization request.
	// * https://datatracker.ietf.org/doc/html/rfc6749#section-3.1.2.2 (everything MUST be implemented)
	WriteAuthorizeResponse(ctx context.Context, rw http.ResponseWriter, requester AuthorizeRequester, responder AuthorizeResponder)

	// NewAccessRequest creates a new access request object and validates
	// various parameters.
	//
	// The following specs must be considered in any implementation of this method:
	// * https://datatracker.ietf.org/doc/html/rfc6749#section-3.2 (everything)
	// * https://datatracker.ietf.org/doc/html/rfc6749#section-3.2.1 (everything)
	//
	// Furthermore the registered handlers should implement their specs accordingly.
	NewAccessRequest(ctx context.Context, r *http.Request, session Session) (AccessRequester, error)

	// NewAccessResponse creates a new access response and validates that access_token and token_type are set.
	//
	// The following specs must be considered in any implementation of this method:
	// https://datatracker.ietf.org/doc/html/rfc6749#section-5.1
	NewAccessResponse(ctx context.Context, requester AccessRequester) (AccessResponder, error)

	// WriteAccessError writes an access request error response.
	//
	// The following specs must be considered in any implementation of this method:
	// * https://datatracker.ietf.org/doc/html/rfc6749#section-5.2 (everything)
	WriteAccessError(ctx context.Context, rw http.ResponseWriter, requester AccessRequester, err error)

	// WriteAccessResponse writes the access response.
	//
	// The following specs must be considered in any implementation of this method:
	// https://datatracker.ietf.org/doc/html/rfc6749#section-5.1
	WriteAccessResponse(ctx context.Context, rw http.ResponseWriter, requester AccessRequester, responder AccessResponder)

	// NewRevocationRequest handles incoming token revocation requests and validates various parameters.
	//
	// The following specs must be considered in any implementation of this method:
	// https://datatracker.ietf.org/doc/html/rfc7009#section-2.1
	NewRevocationRequest(ctx context.Context, r *http.Request) error

	// WriteRevocationResponse writes the revoke response.
	//
	// The following specs must be considered in any implementation of this method:
	// https://datatracker.ietf.org/doc/html/rfc7009#section-2.2
	WriteRevocationResponse(ctx context.Context, rw http.ResponseWriter, err error)

	// IntrospectToken returns token metadata, if the token is valid. Tokens generated by the authorization endpoint,
	// such as the authorization code, can not be introspected.
	IntrospectToken(ctx context.Context, token string, tokenUse TokenUse, session Session, scope ...string) (TokenUse, AccessRequester, error)

	// NewIntrospectionRequest initiates token introspection as defined in
	//https://datatracker.ietf.org/doc/html/rfc7662#section-2.1
	NewIntrospectionRequest(ctx context.Context, r *http.Request, session Session) (IntrospectionResponder, error)

	// WriteIntrospectionError responds with an error if token introspection failed as defined in
	//https://datatracker.ietf.org/doc/html/rfc7662#section-2.3
	WriteIntrospectionError(ctx context.Context, rw http.ResponseWriter, err error)

	// WriteIntrospectionResponse responds with token metadata discovered by token introspection as defined in
	//https://datatracker.ietf.org/doc/html/rfc7662#section-2.2
	WriteIntrospectionResponse(ctx context.Context, rw http.ResponseWriter, r IntrospectionResponder)

	// NewPushedAuthorizeRequest validates the request and produces an AuthorizeRequester object that can be stored
	NewPushedAuthorizeRequest(ctx context.Context, r *http.Request) (AuthorizeRequester, error)

	// NewPushedAuthorizeResponse executes the handlers and builds the response
	NewPushedAuthorizeResponse(ctx context.Context, requester AuthorizeRequester, session Session) (PushedAuthorizeResponder, error)

	// WritePushedAuthorizeResponse writes the PAR response
	WritePushedAuthorizeResponse(ctx context.Context, rw http.ResponseWriter, requester AuthorizeRequester, responder PushedAuthorizeResponder)

	// WritePushedAuthorizeError writes the PAR error
	WritePushedAuthorizeError(ctx context.Context, rw http.ResponseWriter, requester AuthorizeRequester, err error)

	// NewRFC862DeviceAuthorizeRequest validate the OAuth 2.0 Device Authorization Flow Request
	//
	// The following specs must be considered in any implementation of this method:
	// * https://www.rfc-editor.org/rfc/rfc8628#section-3.1 (everything MUST be implemented)
	// Parameters sent without a value MUST be treated as if they were
	// omitted from the request.  The authorization server MUST ignore
	// unrecognized request parameters.  Request and response parameters
	// MUST NOT be included more than once.
	NewRFC862DeviceAuthorizeRequest(ctx context.Context, req *http.Request) (DeviceAuthorizeRequester, error)

	// NewRFC862DeviceAuthorizeResponse persists the DeviceCodeSession and UserCodeSession in the store
	//
	// The following specs must be considered in any implementation of this method:
	// * https://www.rfc-editor.org/rfc/rfc8628#section-3.2 (everything MUST be implemented)
	// In response, the authorization server generates a unique device
	// verification code and an end-user code that are valid for a limited
	// time
	NewRFC862DeviceAuthorizeResponse(ctx context.Context, requester DeviceAuthorizeRequester, session Session) (DeviceAuthorizeResponder, error)

	// WriteRFC862DeviceAuthorizeResponse return to the user both codes and
	// some configuration information in a JSON formatted manner
	//
	// The following specs must be considered in any implementation of this method:
	// * https://www.rfc-editor.org/rfc/rfc8628#section-3.2 (everything MUST be implemented)
	// Response is a HTTP response body using the
	// "application/json" format [RFC8259] with a 200 (OK) status code.
	WriteRFC862DeviceAuthorizeResponse(ctx context.Context, rw http.ResponseWriter, requester DeviceAuthorizeRequester, responder DeviceAuthorizeResponder)

	// WriteRFC8628UserAuthorizeResponse returns the device grant user verification result in a JSON formatted manner.
	//
	// The following specs must be considered in any implementation of this method:
	// * https://www.rfc-editor.org/rfc/rfc8628#section-3.3 (everything MUST be implemented)
	// Response is a HTTP response body using the
	// "application/json" format [RFC8259] with a 200 (OK) status code.
	WriteRFC8628UserAuthorizeResponse(cxt context.Context, rw http.ResponseWriter, requester DeviceAuthorizeRequester, responder RFC8628UserAuthorizeResponder)

	// WriteRFC8628UserAuthorizeError returns the device grant user verification error in a JSON formatted manner.
	//
	// The following specs must be considered in any implementation of this method:
	// * https://www.rfc-editor.org/rfc/rfc8628#section-3.3 (everything MUST be implemented)
	// Response is a HTTP response body using the
	// "application/json" format [RFC8259] with a 200 (OK) status code.
	WriteRFC8628UserAuthorizeError(_ context.Context, rw http.ResponseWriter, requester DeviceAuthorizeRequester, err error)

	// NewRFC8628UserAuthorizeRequest validate the OAuth 2.0 Device Authorization Flow - User interaction Request
	//
	// The following specs must be considered in any implementation of this method:
	// * https://www.rfc-editor.org/rfc/rfc8628#section-3.3 (everything MUST be implemented)
	// Parameters sent without a value MUST be treated as if they were
	// omitted from the request. The authorization server MUST ignore
	// unrecognized request parameters. Request and response parameters
	// MUST NOT be included more than once.
	NewRFC8628UserAuthorizeRequest(ctx context.Context, req *http.Request) (DeviceAuthorizeRequester, error)

	// NewRFC8628UserAuthorizeResponse persists the DeviceCodeSession and UserCodeSession in the store
	//
	// The following specs must be considered in any implementation of this method:
	// * https://www.rfc-editor.org/rfc/rfc8628#section-3.2 (everything MUST be implemented)
	// In response, the authorization server generates a unique device
	// verification code and an end-user code that are valid for a limited
	// time
	NewRFC8628UserAuthorizeResponse(ctx context.Context, requester DeviceAuthorizeRequester, session Session) (RFC8628UserAuthorizeResponder, error)
}

// IntrospectionResponder is the response object that will be returned when token introspection was successful,
// for example when the client is allowed to perform token introspection. Refer to
// https://datatracker.ietf.org/doc/html/rfc7662#section-2.2 for more details.
type IntrospectionResponder interface {
	// IsActive returns true if the introspected token is active and false otherwise.
	IsActive() bool

	// GetAccessRequester returns the AccessRequester which returns nil when IsActive() is false and the original access request object otherwise.
	GetAccessRequester() AccessRequester

	// GetTokenUse optionally returns the type of the token that was introspected. This could be "access_token", "refresh_token",
	// or if the type can not be determined an empty string.
	GetTokenUse() TokenUse

	// GetAccessTokenType optionally returns the type of the access token that was introspected. This could be "bearer", "mac",
	// or empty string if the type of the token is refresh token.
	GetAccessTokenType() string
}

// Requester is an abstract interface for handling requests in Fosite.
type Requester interface {
	// SetID sets the unique identifier.
	SetID(id string)

	// GetID returns a unique identifier.
	GetID() string

	// GetRequestedAt returns the time the request was created.
	GetRequestedAt() (requestedAt time.Time)

	// GetClient returns the request's client.
	GetClient() (client Client)

	// GetRequestedScopes returns the request's scopes.
	GetRequestedScopes() (scopes Arguments)

	// GetRequestedAudience returns the requested audiences for this request.
	GetRequestedAudience() (audience Arguments)

	// SetRequestedScopes sets the request's scopes.
	SetRequestedScopes(scopes Arguments)

	// SetRequestedAudience sets the requested audience.
	SetRequestedAudience(audience Arguments)

	// AppendRequestedScope appends a scope to the request.
	AppendRequestedScope(scope string)

	// GetGrantedScopes returns all granted scopes.
	GetGrantedScopes() (grantedScopes Arguments)

	// GetGrantedAudience returns all granted audiences.
	GetGrantedAudience() (grantedAudience Arguments)

	// GrantScope marks a request's scope as granted.
	GrantScope(scope string)

	// GrantAudience marks a request's audience as granted.
	GrantAudience(audience string)

	// GetSession returns a pointer to the request's session or nil if none is set.
	GetSession() (session Session)

	// SetSession sets the request's session pointer.
	SetSession(session Session)

	// GetRequestForm returns the request's form input.
	GetRequestForm() url.Values

	// Merge merges the argument into the method receiver.
	Merge(requester Requester)

	// Sanitize returns a sanitized clone of the request which can be used for storage.
	Sanitize(allowedParameters []string) Requester
}

// AccessRequester is a token endpoint's request context.
type AccessRequester interface {
	// GetGrantTypes returns the requests grant type.
	GetGrantTypes() (grantTypes Arguments)

	Requester
}

// RefreshTokenAccessRequester is an extended AccessRequester implementation that allows preserving
// the original Requester.
type RefreshTokenAccessRequester interface {
	// SanitizeRestoreRefreshTokenOriginalRequester returns a sanitized copy of this Requester and mutates the relevant
	// values from the provided Requester which is the original refresh token session Requester.
	SanitizeRestoreRefreshTokenOriginalRequester(requester Requester) Requester

	AccessRequester
}

// AuthorizeRequester is an authorize endpoint's request context.
type AuthorizeRequester interface {
	// GetResponseTypes returns the requested response types
	GetResponseTypes() (responseTypes Arguments)

	// SetResponseTypeHandled marks a response_type (e.g. token or code) as handled indicating that the response type
	// is supported.
	SetResponseTypeHandled(responseType string)

	// DidHandleAllResponseTypes returns if all requested response types have been handled correctly
	DidHandleAllResponseTypes() (didHandle bool)

	// GetRedirectURI returns the requested redirect URI
	GetRedirectURI() (redirectURL *url.URL)

	// IsRedirectURIValid returns false if the redirect is not rfc-conform (i.e. missing client, not on white list,
	// or malformed)
	IsRedirectURIValid() (isValid bool)

	// GetState returns the request's state.
	GetState() (state string)

	// GetResponseMode returns response_mode of the authorization request
	GetResponseMode() ResponseModeType

	// SetDefaultResponseMode sets default response mode for a response type in a flow
	SetDefaultResponseMode(responseMode ResponseModeType)

	// GetDefaultResponseMode gets default response mode for a response type in a flow
	GetDefaultResponseMode() ResponseModeType

	Requester
}

// DeviceAuthorizeRequester is a device authorization endpoint's request context.
type DeviceAuthorizeRequester interface {
	// SetDeviceCodeSignature set the device code signature
	SetDeviceCodeSignature(signature string)

	// GetDeviceCodeSignature returns the device code signature
	GetDeviceCodeSignature() string

	// SetUserCodeSignature set the user code signature
	SetUserCodeSignature(signature string)

	// GetUserCodeSignature returns the user code signature
	GetUserCodeSignature() string

	SetStatus(status DeviceAuthorizeStatus)

	GetStatus() DeviceAuthorizeStatus

	SetLastChecked(lastChecked time.Time)

	GetLastChecked() time.Time

	Requester
}

// AccessResponder is a token endpoint's response.
type AccessResponder interface {
	// SetExtra sets a key value pair for the access response.
	SetExtra(key string, value any)

	// GetExtra returns a key's value.
	GetExtra(key string) any

	SetExpiresIn(time.Duration)

	SetScopes(scopes Arguments)

	// SetAccessToken sets the responses mandatory access token.
	SetAccessToken(token string)

	// SetTokenType set's the responses mandatory token type
	SetTokenType(tokenType string)

	// GetAccessToken returns the responses access token.
	GetAccessToken() (token string)

	// GetTokenType returns the responses token type.
	GetTokenType() (token string)

	// ToMap converts the response to a map.
	ToMap() map[string]any
}

// AuthorizeResponder is an authorization endpoint's response.
type AuthorizeResponder interface {
	// GetCode returns the response's authorize code if set.
	GetCode() string

	// GetHeader returns the response's header
	GetHeader() (header http.Header)

	// AddHeader adds a header key value pair to the response
	AddHeader(key, value string)

	// GetParameters returns the response's parameters
	GetParameters() (query url.Values)

	// AddParameter adds key value pair to the response
	AddParameter(key, value string)
}

// PushedAuthorizeResponder is the response object for PAR
type PushedAuthorizeResponder interface {
	// GetRequestURI returns the request_uri
	GetRequestURI() string

	// SetRequestURI sets the request_uri
	SetRequestURI(requestURI string)

	// GetExpiresIn gets the expires_in
	GetExpiresIn() int

	// SetExpiresIn sets the expires_in
	SetExpiresIn(seconds int)

	// GetHeader returns the response's header
	GetHeader() (header http.Header)

	// AddHeader adds a header key value pair to the response
	AddHeader(key, value string)

	// SetExtra sets a key value pair for the response.
	SetExtra(key string, value any)

	// GetExtra returns a key's value.
	GetExtra(key string) any

	// ToMap converts the response to a map.
	ToMap() map[string]any
}

type DeviceAuthorizeResponder interface {
	GetDeviceCode() string

	SetDeviceCode(code string)

	// GetHeader returns the response's header
	GetHeader() (header http.Header)

	// AddHeader adds an header key value pair to the response
	AddHeader(key, value string)

	GetUserCode() string

	SetUserCode(code string)

	GetVerificationURI() string

	SetVerificationURI(uri string)

	GetVerificationURIComplete() string

	SetVerificationURIComplete(uri string)

	GetExpiresIn() int64

	SetExpiresIn(seconds int64)

	GetInterval() int

	SetInterval(seconds int)

	// SetExtra sets a key value pair for the access response.
	SetExtra(key string, value any)

	// GetExtra returns a key's value.
	GetExtra(key string) any

	// ToMap converts the response to a map.
	ToMap() map[string]any
}

// RFC8628UserAuthorizeResponder is device grant user verification endpoint response.
type RFC8628UserAuthorizeResponder interface {
	// GetHeader returns the response's header
	GetHeader() (header http.Header)

	// AddHeader adds an header key value pair to the response
	AddHeader(key, value string)

	// GetParameters returns the response's parameters
	GetParameters() (query url.Values)

	// AddParameter adds key value pair to the response
	AddParameter(key, value string)

	// GetStatus returns the device grant user verification status
	GetStatus() string

	// SetStatus sets the device grant user verification status
	SetStatus(status string)

	// SetExtra sets a key value pair for the access response.
	SetExtra(key string, value any)

	// GetExtra returns a key's value.
	GetExtra(key string) any

	// ToMap converts the response to a map.
	ToMap() map[string]any
}

// G11NContext is the globalization context
type G11NContext interface {
	// GetLang returns the current language in the context
	GetLang() language.Tag
}

type RFC8693TokenType interface {
	GetName(ctx context.Context) string

	GetType(ctx context.Context) string
}
