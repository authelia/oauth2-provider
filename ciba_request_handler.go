// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"authelia.com/provider/jose"

	"authelia.com/provider/oauth2/i18n"
	"authelia.com/provider/oauth2/internal/consts"
	"authelia.com/provider/oauth2/token/jwt"
	"authelia.com/provider/oauth2/x/errorsx"
)

const cibaClientNotificationTokenMaximumLength = 1024

var (
	// regexCIBAClientNotificationToken matches the RFC 6750 Section 2.1 b64token syntax.
	//
	// See: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.1
	regexCIBAClientNotificationToken = regexp.MustCompile(`^[A-Za-z0-9\-._~+/]+=*$`)

	// cibaSingleValueParameters are the authentication request parameters which must not be included more than once.
	//
	// See: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.13
	cibaSingleValueParameters = []string{
		consts.FormParameterScope,
		consts.FormParameterAuthenticationContextClassReferenceValues,
		consts.FormParameterLoginHint,
		consts.FormParameterIDTokenHint,
		consts.FormParameterLoginHintToken,
		consts.FormParameterBindingMessage,
		consts.FormParameterUserCode,
		consts.FormParameterRequestedExpiry,
		consts.FormParameterClientNotificationToken,
		consts.FormParameterRequest,
		consts.FormParameterRequestContext,
		consts.FormParameterClientID,
		consts.FormParameterClientAssertion,
		consts.FormParameterClientAssertionType,
		consts.FormParameterClientSecret,
		consts.FormParameterAuthorizationDetails,
		consts.FormParameterDPoPJKT,
	}

	// cibaIgnoredParameters are the authorization endpoint parameters which are not CIBA authentication request
	// parameters but which ID Token issuance reads from the request form.
	//
	// See: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.2
	cibaIgnoredParameters = []string{
		consts.FormParameterPrompt,
		consts.FormParameterMaximumAge,
	}
)

// NewBackChannelAuthenticationRequest parses and validates an OpenID Connect CIBA authentication request at the
// backchannel authentication endpoint. The client is authenticated as at the token endpoint, must have a token
// delivery mode the server supports, and the request parameters are validated against its registration.
//
// The application then resolves the end user from the hint, verifies the 'user_code' when one is present, and sets
// the subject on the session before calling NewBackChannelAuthenticationResponse.
//
// See: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7
//
//nolint:gocyclo
func (f *Fosite) NewBackChannelAuthenticationRequest(ctx context.Context, r *http.Request, session Session) (requester BackChannelAuthenticationRequester, err error) {
	request := NewBackChannelAuthenticationRequest()
	request.Lang = i18n.GetLangFromRequest(f.Config.GetMessageCatalog(ctx), r)
	request.Session = session
	request.httpRequest = r

	// See: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.1
	if r.Method != http.MethodPost {
		return request, errorsx.WithStack(ErrInvalidRequest.WithHintf("HTTP method is '%s', expected 'POST'.", r.Method))
	}

	if err = r.ParseForm(); err != nil {
		return request, errorsx.WithStack(ErrInvalidRequest.WithHint("Unable to parse HTTP body, make sure to send a properly formatted form request body.").WithWrap(err).WithDebugError(err))
	}

	for _, parameter := range cibaSingleValueParameters {
		if len(r.PostForm[parameter]) > 1 {
			return request, errorsx.WithStack(ErrInvalidRequest.WithHintf("The '%s' parameter must not be included more than once.", parameter))
		}
	}

	request.Form = withoutClientCredentials(r.PostForm)

	// See: https://datatracker.ietf.org/doc/html/rfc8725#section-3.2
	if isCIBARSA15Encrypted(r.PostForm.Get(consts.FormParameterClientAssertion)) {
		return request, withClientAuthenticationChallenge(r, errorsx.WithStack(ErrInvalidClient.WithHintf("The client assertion must not be encrypted with the '%s' key management algorithm.", jose.RSA1_5)), f.Config.GetClientAuthenticationRealm(ctx))
	}

	// See: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.1
	client, method, err := f.AuthenticateClientWithAuthHandler(ctx, r, r.PostForm, &BackChannelAuthenticationEndpointClientAuthStrategy{})
	if err != nil {
		if rfcerr, ok := errors.AsType[*RFC6749Error](err); ok && rfcerr.ErrorField != ErrInvalidClient.ErrorField {
			return request, withClientAuthenticationChallenge(r, errorsx.WithStack(ErrInvalidClient.WithHint("The requested OAuth 2.0 Client could not be authenticated.").WithWrap(err).WithDebugError(err)), f.Config.GetClientAuthenticationRealm(ctx))
		}

		return request, err
	}

	request.Client = client

	mode := GetCIBADeliveryMode(client)

	if mode == "" || !slices.Contains(f.Config.GetCIBATokenDeliveryModes(ctx), mode) {
		return request, errorsx.WithStack(ErrUnauthorizedClient.WithHint("The OAuth 2.0 Client is not registered for a token delivery mode the server supports.").WithDebugf("The client with id '%s' has the token delivery mode '%s'.", client.GetID(), mode))
	}

	request.DeliveryMode = mode

	// See: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.4
	if mode != consts.CIBAModePush && !client.GetGrantTypes().Has(consts.GrantTypeOpenIDCIBA) {
		return request, errorsx.WithStack(ErrUnauthorizedClient.WithHintf("The OAuth 2.0 Client is not allowed to use the '%s' grant type.", consts.GrantTypeOpenIDCIBA).WithDebugf("The client with id '%s' uses the token delivery mode '%s' without registering the grant type.", client.GetID(), mode))
	}

	// See: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.4
	if mode == consts.CIBAModePing || mode == consts.CIBAModePush {
		if c, ok := client.(CIBAClient); !ok || !isCIBANotificationEndpointSecure(c.GetBackChannelClientNotificationEndpoint()) {
			return request, errorsx.WithStack(ErrUnauthorizedClient.WithHint("The OAuth 2.0 Client must register an https 'backchannel_client_notification_endpoint' to use the ping or push token delivery mode.").WithDebugf("The client with id '%s' uses the token delivery mode '%s' without an https client notification endpoint.", client.GetID(), mode))
		}
	}

	// See: https://datatracker.ietf.org/doc/html/rfc8725#section-3.2
	if err = validateCIBAResponseEncryption(client); err != nil {
		return request, err
	}

	// A pairwise poll or ping client proves ownership of its 'jwks_uri' host by authenticating or signing with its keys.
	//
	// See: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.4
	if c, ok := client.(SubjectTypeClient); ok && c.GetSubjectType() == consts.SubjectTypePairwise && mode != consts.CIBAModePush &&
		method != consts.ClientAuthMethodPrivateKeyJWT && method != consts.ClientAuthMethodSelfSignedTLSClientAuth && !r.PostForm.Has(consts.FormParameterRequest) {
		return request, withClientAuthenticationChallenge(r, errorsx.WithStack(ErrInvalidClient.WithHint("A pairwise OAuth 2.0 Client using the poll or ping token delivery mode must authenticate with 'private_key_jwt' or 'self_signed_tls_client_auth', or send a signed authentication request.").WithDebugf("The client with id '%s' authenticated using '%s'.", client.GetID(), method)), f.Config.GetClientAuthenticationRealm(ctx))
	}

	signed := request.Form.Has(consts.FormParameterRequest)

	if c, ok := client.(CIBAClient); ok && c.GetBackChannelAuthenticationRequestSigningAlg() != "" {
		signed = true
	}

	if signed {
		params, requestContext, err := f.decodeBackChannelSignedRequest(ctx, client, r.PostForm)
		if err != nil {
			return request, err
		}

		// See: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.2
		request.Form = cibaSignedRequestForm(request.Form, params)

		request.RequestContext = requestContext
	}

	for _, parameter := range cibaIgnoredParameters {
		delete(request.Form, parameter)
	}

	if err = f.validateCIBAScope(ctx, r, request); err != nil {
		return request, err
	}

	if err = f.validateCIBAHint(ctx, request); err != nil {
		return request, err
	}

	if err = f.validateCIBAClientNotificationToken(request); err != nil {
		return request, err
	}

	if err = f.validateCIBABindingMessage(ctx, request); err != nil {
		return request, err
	}

	f.validateCIBAUserCode(ctx, request)

	if err = validateCIBARequestedExpiry(request); err != nil {
		return request, err
	}

	if err = ValidateResourceIndicators(request.Form); err != nil {
		return request, err
	}

	if err = f.validateAudience(ctx, r, request); err != nil {
		return request, err
	}

	// See: https://www.rfc-editor.org/rfc/rfc9396#section-3
	if err = f.validateAuthorizationDetails(ctx, request); err != nil {
		return request, err
	}

	if err = f.validateCIBABindingMessageRequired(ctx, request); err != nil {
		return request, err
	}

	if err = f.validateNonceEntropy(ctx, request.Form); err != nil {
		return request, err
	}

	if !signed {
		if err = validateCIBARequestContext(request); err != nil {
			return request, err
		}
	}

	// See: https://openid.net/specs/fapi-ciba.html#section-4.1.1
	if len(request.RequestContext) == 0 && f.Config.GetCIBARequireRequestContext(ctx) {
		return request, errorsx.WithStack(ErrInvalidRequest.WithHint("The 'request_context' parameter is required."))
	}

	return request, nil
}

// cibaSignedRequestForm returns the form of a signed authentication request: the parameters of the JWT and the client
// authentication parameters kept in the form. Any other parameter outside of the JWT is unrecognised and ignored.
//
// See: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.1.1
func cibaSignedRequestForm(form, params url.Values) (signed url.Values) {
	signed = url.Values{}

	for key, values := range form {
		if key != consts.FormParameterRequest && slices.Contains(cibaSignedRequestFormParameters, key) {
			signed[key] = values
		}
	}

	maps.Copy(signed, params)

	return signed
}

// validateCIBAResponseEncryption refuses a client which registered the 'RSA1_5' key management algorithm for the ID
// Token or the access token, as no token this flow delivers is encrypted with it.
//
// See: https://datatracker.ietf.org/doc/html/rfc8725#section-3.2
func validateCIBAResponseEncryption(client Client) (err error) {
	if c, ok := client.(IDTokenClient); ok && c.GetIDTokenEncryptedResponseAlg() == string(jose.RSA1_5) {
		return errorsx.WithStack(ErrUnauthorizedClient.WithHintf("The OAuth 2.0 Client must not register the '%s' key management algorithm for the 'id_token_encrypted_response_alg' to use this authentication flow.", jose.RSA1_5).WithDebugf("The client with id '%s' registered the 'id_token_encrypted_response_alg' value '%s'.", client.GetID(), jose.RSA1_5))
	}

	if c, ok := client.(JWTProfileClient); ok && c.GetAccessTokenEncryptedResponseAlg() == string(jose.RSA1_5) {
		return errorsx.WithStack(ErrUnauthorizedClient.WithHintf("The OAuth 2.0 Client must not register the '%s' key management algorithm for the 'access_token_encrypted_response_alg' to use this authentication flow.", jose.RSA1_5).WithDebugf("The client with id '%s' registered the 'access_token_encrypted_response_alg' value '%s'.", client.GetID(), jose.RSA1_5))
	}

	return nil
}

// isCIBARSA15Encrypted reports whether the token is a JWE whose protected header uses the 'RSA1_5' key management
// algorithm. The header is read without decrypting the token.
//
// See: https://datatracker.ietf.org/doc/html/rfc8725#section-3.2
func isCIBARSA15Encrypted(token string) (encrypted bool) {
	if !jwt.IsEncryptedJWT(token) {
		return false
	}

	jwe, err := jose.ParseEncryptedCompact(token, []jose.KeyAlgorithm{jose.RSA1_5}, jwt.ContentEncryptionAlgorithms)
	if err != nil {
		return false
	}

	return jwe.Header.Algorithm == string(jose.RSA1_5)
}

// validateCIBAScope requires the 'scope' parameter, and the 'openid' scope unless the requirement is disabled and the
// client does not use the push mode, then checks the scopes against the client.
//
// See: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.1
func (f *Fosite) validateCIBAScope(ctx context.Context, r *http.Request, request *BackChannelAuthenticationRequest) (err error) {
	scopes := Arguments(RemoveEmpty(strings.Split(request.Form.Get(consts.FormParameterScope), " ")))

	if len(scopes) == 0 {
		return errorsx.WithStack(ErrInvalidRequest.WithHint("The 'scope' parameter is required."))
	}

	if !scopes.Has(consts.ScopeOpenID) && (f.Config.GetCIBARequireOpenIDScope(ctx) || request.DeliveryMode == consts.CIBAModePush) {
		return errorsx.WithStack(ErrInvalidRequest.WithHint("The 'scope' parameter must include the 'openid' scope."))
	}

	return f.validateScope(ctx, r, request)
}

// validateCIBAHint requires exactly one of 'login_hint_token', 'id_token_hint' and 'login_hint', and validates an
// 'id_token_hint'.
//
// See: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.1
func (f *Fosite) validateCIBAHint(ctx context.Context, request *BackChannelAuthenticationRequest) (err error) {
	var count int

	for _, kind := range []CIBAHintKind{CIBAHintKindLoginHintToken, CIBAHintKindIDTokenHint, CIBAHintKindLoginHint} {
		if value := request.Form.Get(string(kind)); value != "" {
			count++

			request.HintKind, request.HintValue = kind, value
		}
	}

	if count != 1 {
		request.HintKind, request.HintValue = "", ""

		return errorsx.WithStack(ErrInvalidRequest.WithHint("Exactly one of the 'login_hint_token', 'id_token_hint' or 'login_hint' parameters is required."))
	}

	if request.HintKind != CIBAHintKindIDTokenHint {
		return nil
	}

	// An unlimited grace period is never applied; a configuration which returns none gets the default.
	//
	// See: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.14
	maxAge := f.Config.GetCIBAIDTokenHintMaximumAge(ctx)
	if maxAge <= 0 {
		maxAge = defaultCIBAIDTokenHintMaximumAge
	}

	if request.IDTokenHintClaims, err = f.validateIDTokenHintForClient(ctx, request.Client, request.HintValue, maxAge); err != nil {
		return err
	}

	return nil
}

// validateCIBAClientNotificationToken requires a 'client_notification_token' of at most 1024 characters in the RFC 6750
// Section 2.1 b64token syntax for the ping and push modes. The poll mode ignores it. The token is a credential, so it is
// removed from the form whatever the mode and kept only in the ClientNotificationToken field.
//
// See: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.1
func (f *Fosite) validateCIBAClientNotificationToken(request *BackChannelAuthenticationRequest) (err error) {
	token := request.Form.Get(consts.FormParameterClientNotificationToken)

	delete(request.Form, consts.FormParameterClientNotificationToken)

	if request.DeliveryMode != consts.CIBAModePing && request.DeliveryMode != consts.CIBAModePush {
		return nil
	}

	switch {
	case token == "":
		return errorsx.WithStack(ErrInvalidRequest.WithHint("The 'client_notification_token' parameter is required for the ping and push token delivery modes."))
	case len(token) > cibaClientNotificationTokenMaximumLength:
		return errorsx.WithStack(ErrInvalidRequest.WithHintf("The 'client_notification_token' parameter must not exceed %d characters.", cibaClientNotificationTokenMaximumLength))
	case !regexCIBAClientNotificationToken.MatchString(token):
		return errorsx.WithStack(ErrInvalidRequest.WithHint("The 'client_notification_token' parameter must use the RFC 6750 b64token syntax."))
	}

	request.ClientNotificationToken = token

	return nil
}

// validateCIBABindingMessage bounds the 'binding_message' length and requires printable characters.
//
// See: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.1
func (f *Fosite) validateCIBABindingMessage(ctx context.Context, request *BackChannelAuthenticationRequest) (err error) {
	message := request.Form.Get(consts.FormParameterBindingMessage)

	if message == "" {
		return nil
	}

	if maximum := f.Config.GetCIBAMaximumBindingMessageLength(ctx); utf8.RuneCountInString(message) > maximum {
		return errorsx.WithStack(ErrInvalidBindingMessage.WithHintf("The 'binding_message' parameter must not exceed %d characters.", maximum))
	}

	for _, char := range message {
		if char == utf8.RuneError || !unicode.IsPrint(char) {
			return errorsx.WithStack(ErrInvalidBindingMessage.WithHint("The 'binding_message' parameter must only contain printable characters."))
		}
	}

	request.BindingMessage = message

	return nil
}

// validateCIBABindingMessageRequired requires the 'binding_message' parameter when configured, unless the request
// carries an authorization detail whose AuthorizationDetailsTypeUniqueContextHandler reports it identifies a unique
// authorization context.
//
// See: https://openid.net/specs/fapi-ciba.html#section-4.1.1
func (f *Fosite) validateCIBABindingMessageRequired(ctx context.Context, request *BackChannelAuthenticationRequest) (err error) {
	if request.BindingMessage != "" || !f.Config.GetCIBARequireBindingMessage(ctx) {
		return nil
	}

	handlers := GetAuthorizationDetailsTypeHandlers(ctx, f.Config)

	for _, detail := range request.GetRequestedAuthorizationDetails() {
		if handler, ok := handlers[detail.Type].(AuthorizationDetailsTypeUniqueContextHandler); ok && handler.IsUniqueAuthorizationContext(ctx, request, detail) {
			return nil
		}
	}

	return errorsx.WithStack(ErrInvalidRequest.WithHint("The 'binding_message' parameter is required."))
}

// validateCIBAUserCode keeps the 'user_code' in the UserCode field only when both the server and the client support it.
// The code is a credential, so it is always removed from the form.
//
// See: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.1
func (f *Fosite) validateCIBAUserCode(ctx context.Context, request *BackChannelAuthenticationRequest) {
	if c, ok := request.Client.(CIBAClient); ok && c.GetBackChannelUserCodeParameter() && f.Config.GetCIBAUserCodeSupported(ctx) {
		request.UserCode = request.Form.Get(consts.FormParameterUserCode)
	}

	delete(request.Form, consts.FormParameterUserCode)
}

// validateCIBARequestedExpiry requires a 'requested_expiry' to be a positive integer number of seconds. A value too
// large to represent is kept as the largest representable number of seconds, which the lifespan is clamped from.
//
// See: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7.1
func validateCIBARequestedExpiry(request *BackChannelAuthenticationRequest) (err error) {
	raw := request.Form.Get(consts.FormParameterRequestedExpiry)

	if raw == "" {
		return nil
	}

	for _, char := range raw {
		if char < '0' || char > '9' {
			return errorsx.WithStack(ErrInvalidRequest.WithHint("The 'requested_expiry' parameter must be a positive integer."))
		}
	}

	const maximum = math.MaxInt64 / int64(time.Second)

	seconds, err := strconv.ParseInt(raw, 10, 64)

	switch {
	case errors.Is(err, strconv.ErrRange), seconds > maximum:
		seconds = maximum
	case err != nil, seconds <= 0:
		return errorsx.WithStack(ErrInvalidRequest.WithHint("The 'requested_expiry' parameter must be a positive integer."))
	}

	request.RequestedExpiry = time.Duration(seconds) * time.Second

	return nil
}

// validateCIBARequestContext requires a 'request_context' to be a JSON object and keeps it raw.
//
// See: https://openid.net/specs/fapi-ciba.html#section-4.1.3
func validateCIBARequestContext(request *BackChannelAuthenticationRequest) (err error) {
	raw := request.Form.Get(consts.FormParameterRequestContext)

	if raw == "" {
		return nil
	}

	var object map[string]json.RawMessage

	if err = json.Unmarshal([]byte(raw), &object); err != nil {
		return errorsx.WithStack(ErrInvalidRequest.WithHint("The 'request_context' parameter must be a JSON object.").WithWrap(err).WithDebugError(err))
	}

	if object == nil {
		return errorsx.WithStack(ErrInvalidRequest.WithHint("The 'request_context' parameter must be a JSON object."))
	}

	request.RequestContext = json.RawMessage(raw)

	return nil
}
